//! The worker's side of the gate: each run asked for over the gate's
//! socket, its bundle and files streamed in, or a company's image with the
//! login the gate pulls it with and its input, its answer read back.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{CodeRan, CodeRequest, CodeRunner, PullLogin};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::image::OwnImage;
use ianua_domain::domains::workflows::sandbox::recipe::Program;
use ianua_domain::types::UntrustedText;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use crate::files::{FileName, FileStore, StoredFile};
use crate::sandbox::entry::entry_of;
use crate::sandbox::gate::wire::{Answer, Ask, ImageAsk, ImageRun, Reach, read_answer};
use crate::sandbox::output::code_outcome;
use crate::sandbox::proxy::{ProxyAccess, RunNetwork, run_network};
use crate::sandbox::streamed::{Header, run_files};

/// How code runs reach the gate.
#[derive(Debug, Clone)]
pub struct GateSettings {
    /// The gate's socket.
    pub socket: PathBuf,
    /// How long the gate may take to pull an image and hand a run its
    /// input, beyond the version's own time limit.
    pub start_grace: Duration,
}

/// Runs each version's code through the gate, which starts its container.
pub struct GateCodeRunner {
    files: Arc<dyn FileStore>,
    settings: GateSettings,
    network: Option<ProxyAccess>,
}

/// One run asked of the gate: the ask, the proxy it reaches its hosts
/// through, and its own files.
struct GateRun {
    ask: Ask,
    proxy: Option<String>,
    files: Vec<u8>,
    limit: Duration,
}

impl GateCodeRunner {
    /// A runner reading bundles from `files`, asking the gate `settings`
    /// names, and giving runs whose versions name hosts the network filter
    /// `network` reaches; with none, such runs do not run.
    #[must_use]
    pub fn new(
        files: Arc<dyn FileStore>,
        settings: GateSettings,
        network: Option<ProxyAccess>,
    ) -> Self {
        Self {
            files,
            settings,
            network,
        }
    }

    /// The version's bundle, or what to answer without it.
    async fn bundle(
        &self,
        tenant: &ScopedTenant,
        request: &CodeRequest<'_>,
    ) -> Result<StoredFile, CodeRan> {
        let name = FileName::sandbox_bundle(tenant, request.version.id());
        match self.files.open(&name).await {
            Ok(Some(bundle)) => Ok(bundle),
            Ok(None) => Err(CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
                UntrustedText::record("the version's bundle is not kept"),
            )))),
            Err(error) => Err(unavailable(&format!(
                "the bundle could not be read: {error}"
            ))),
        }
    }

    /// Asks the gate for `run`, streaming it `bundle` and the run's files,
    /// and reads its answer.
    async fn asked(&self, run: &GateRun, bundle: StoredFile) -> std::io::Result<Answer> {
        let stream = UnixStream::connect(&self.settings.socket).await?;
        let (read, mut write) = stream.into_split();
        let length = bundle.length();
        let header = Header {
            bundle_bytes: length,
            files_bytes: u64::try_from(run.files.len()).unwrap_or(u64::MAX),
            seconds: run.ask.budget.seconds(),
            proxy: run.proxy.clone(),
        };
        let written = async move {
            write.write_all(run.ask.line().as_bytes()).await?;
            write.write_all(header.line().as_bytes()).await?;
            tokio::io::copy(&mut bundle.into_reader().take(length), &mut write).await?;
            write.write_all(&run.files).await?;
            write.flush().await
        };
        let (written, answer) = tokio::join!(written, read_answer(read));
        if let Err(error) = written {
            tracing::debug!(%error, "the gate stopped reading the run");
        }
        answer
    }

    /// Resolves the permitted network and packs the input before contacting the gate.
    fn plan_run(&self, request: CodeRequest<'_>) -> Result<GateRun, CodeRan> {
        let recipe = request.version.recipe();
        let limit = Duration::from_secs(u64::from(recipe.budget().seconds()))
            .saturating_add(self.settings.start_grace.saturating_mul(2));
        let network = run_network(self.network.as_ref(), recipe.network(), limit)?;
        let Some(code) = recipe.program().code() else {
            return Err(unavailable("the version holds no code"));
        };
        let entry = entry_of(code.runtime());
        let Ok(files) = run_files(&entry, code.code().as_str(), &request.input.render()) else {
            return Err(unavailable("the run's files could not be packed"));
        };
        let (reach, proxy) = reach_of(network);
        Ok(GateRun {
            ask: Ask {
                runtime: code.runtime(),
                image: code.image().clone(),
                budget: recipe.budget(),
                reach,
            },
            proxy,
            files,
            limit,
        })
    }
}

impl GateCodeRunner {
    /// Asks the gate to pull `own`, the image of `request`'s version, with
    /// its login and run it on the request's input.
    async fn run_image(&self, request: CodeRequest<'_>, own: &OwnImage) -> CodeRan {
        let recipe = request.version.recipe();
        let limit = Duration::from_secs(u64::from(recipe.budget().seconds()))
            .saturating_add(self.settings.start_grace.saturating_mul(2));
        let network = match run_network(self.network.as_ref(), recipe.network(), limit) {
            Ok(network) => network,
            Err(answer) => return answer,
        };
        let (reach, proxy) = reach_of(network);
        let input = request.input.render();
        let ask = ImageAsk {
            image: own.image().clone(),
            budget: recipe.budget(),
            reach,
        };
        let run = ImageRun {
            input_bytes: u64::try_from(input.len()).unwrap_or(u64::MAX),
            proxy,
            login: engine_login(own, request.login),
        };
        match tokio::time::timeout(limit, self.asked_image(&ask, &run, &input)).await {
            Ok(Ok(Answer::Ran(exit))) => CodeRan::Ran(code_outcome(&exit)),
            Ok(Ok(Answer::Unpulled(why))) => CodeRan::Ran(CodeOutcome::Failed(
                CodeFailure::NotRun(UntrustedText::record(&why)),
            )),
            Ok(Ok(Answer::NotStarted(why))) => unavailable(&why),
            Ok(Err(error)) => unavailable(&format!("the gate could not be asked: {error}")),
            Err(_) => unavailable("the gate did not answer in time"),
        }
    }

    /// Asks the gate for `ask`, sending `run`'s lines and `input`, and
    /// reads its answer.
    async fn asked_image(
        &self,
        ask: &ImageAsk,
        run: &ImageRun,
        input: &str,
    ) -> std::io::Result<Answer> {
        let stream = UnixStream::connect(&self.settings.socket).await?;
        let (read, mut write) = stream.into_split();
        let written = async move {
            write.write_all(ask.line().as_bytes()).await?;
            write.write_all(run.lines().as_bytes()).await?;
            write.write_all(input.as_bytes()).await?;
            write.flush().await
        };
        let (written, answer) = tokio::join!(written, read_answer(read));
        if let Err(error) = written {
            tracing::debug!(%error, "the gate stopped reading the run");
        }
        answer
    }
}

impl TenantScoped for GateCodeRunner {}

#[async_trait]
impl CodeRunner for GateCodeRunner {
    async fn run(&self, tenant_id: &ScopedTenant, request: CodeRequest<'_>) -> CodeRan {
        if let Program::Image(own) = request.version.recipe().program() {
            return self.run_image(request, own).await;
        }
        let bundle = match self.bundle(tenant_id, &request).await {
            Ok(bundle) => bundle,
            Err(answer) => return answer,
        };
        let run = match self.plan_run(request) {
            Ok(run) => run,
            Err(answer) => return answer,
        };
        match tokio::time::timeout(run.limit, self.asked(&run, bundle)).await {
            Ok(Ok(Answer::Ran(exit))) => CodeRan::Ran(code_outcome(&exit)),
            Ok(Ok(Answer::NotStarted(why) | Answer::Unpulled(why))) => unavailable(&why),
            Ok(Err(error)) => unavailable(&format!("the gate could not be asked: {error}")),
            Err(_) => unavailable("the gate did not answer in time"),
        }
    }
}

/// `login` for `own`'s registry, as the engine's `X-Registry-Auth` header
/// takes it: URL-safe base64 of its JSON; `None` for no login.
fn engine_login(own: &OwnImage, login: &PullLogin) -> Option<String> {
    let PullLogin::Password { username, password } = login else {
        return None;
    };
    let auth = serde_json::json!({
        "username": username.as_str(),
        "password": password.expose(),
        "serveraddress": own.image().registry().as_str(),
    });
    Some(base64::engine::general_purpose::URL_SAFE.encode(auth.to_string()))
}

/// What a run getting `network` asks the gate for: its reach, and the
/// filter's address when it reaches it.
fn reach_of(network: RunNetwork) -> (Reach, Option<String>) {
    match network {
        RunNetwork::Closed => (Reach::Closed, None),
        RunNetwork::Proxied(proxy) => (Reach::Proxied, Some(proxy)),
    }
}

/// A run the gate could not take, for `why`.
fn unavailable(why: &str) -> CodeRan {
    CodeRan::Unavailable(UntrustedText::record(why))
}
