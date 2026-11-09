//! Sandboxes that run a sandbox version's code, in the exact image the
//! version keeps, with its bundle of packages and nothing else: one
//! container per run started through a container command such as `docker`
//! or `podman` on a single server, one started by the sandbox gate where
//! the worker must not hold the container engine ([`GateCodeRunner`]), or
//! one pod per run on Kubernetes ([`ClusterCodeRunner`]); and the runtimes
//! offered for new versions.
//!
//! On a server, each run gets a folder of its own, unpacked from the
//! version's bundle, mounted read-only and removed with the run. A
//! company's image is pulled with its registry's login, within the
//! start-up grace, and run as it is; one that cannot be pulled fails the
//! run as not run. The
//! container reaches no network and is stopped at the version's limits. A
//! runtime such as gVisor (`runsc`) may be named to put the container's
//! system calls behind a second kernel. A container command that cannot
//! start a container is reported as no sandbox being free, so the run is
//! tried again.

mod cluster;
mod container;
mod entry;
mod folder;
mod gate;
mod images;
mod output;
mod proxy;
mod runtimes;
mod streamed;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
pub use cluster::{ClusterCodeRunner, ClusterSettings, WarmPods};
pub use gate::{GateCodeRunner, GateServing, GateSettings, SandboxGate};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{CodeRan, CodeRequest, CodeRunner};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::recipe::Program;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UntrustedText;
pub use images::{CommandImageScanner, NoImageScanner, RegistryImageResolver, ScanSettings};
pub use proxy::{ProxyAccess, ProxyServing, SandboxProxy, TicketKey, Upstreams};
pub use runtimes::{ConfiguredRuntimes, DEFAULT_IMAGES};
use tempfile::TempDir;

use crate::files::FileStore;
use crate::sandbox::container::{Launch, Proxied, Runs};
use crate::sandbox::entry::entry_of;
use crate::sandbox::folder::{Prepared, prepared};
use crate::sandbox::output::Ended;
use crate::sandbox::proxy::{RunNetwork, run_network};

/// How runs are started in containers.
#[derive(Debug, Clone)]
pub struct ContainerSettings {
    /// The container command, such as `docker` or `podman`.
    pub command: String,
    /// The container runtime to run under, such as `runsc` for gVisor;
    /// `None` for the command's own default.
    pub runtime: Option<String>,
    /// How long a container may take to start, or its image to be pulled,
    /// beyond the version's own time limit.
    pub start_grace: Duration,
    /// Where each run's folder is made: a place the container command can
    /// mount from.
    pub work_folder: PathBuf,
    /// The container command's network that reaches only the network
    /// filter, which a run reaching its allowed hosts joins; `None` gives
    /// code no network.
    pub proxy_network: Option<String>,
}

impl ContainerSettings {
    /// Runs started through `command`, under its default runtime, with two
    /// minutes to start, folders in the system's temporary folder, and no
    /// network.
    #[must_use]
    pub fn with_command(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            runtime: None,
            start_grace: Duration::from_secs(120),
            work_folder: std::env::temp_dir(),
            proxy_network: None,
        }
    }
}

/// Runs each version's code in a container of its own.
pub struct ContainerCodeRunner {
    files: Arc<dyn FileStore>,
    settings: ContainerSettings,
    network: Option<ProxyAccess>,
}

impl ContainerCodeRunner {
    /// A runner reading bundles from `files`, starting containers as
    /// `settings` says, and giving runs whose versions name hosts the
    /// network filter `network` reaches over the settings' network to it;
    /// with either missing, such runs do not run.
    #[must_use]
    pub fn new(
        files: Arc<dyn FileStore>,
        settings: ContainerSettings,
        network: Option<ProxyAccess>,
    ) -> Self {
        Self {
            files,
            settings,
            network,
        }
    }

    /// Issues network access only when both the filter and its container network are configured.
    fn network_for(&self, request: CodeRequest<'_>) -> Result<RunNetwork, CodeRan> {
        let recipe = request.version.recipe();
        let lasts = Duration::from_secs(u64::from(recipe.budget().seconds()))
            .saturating_add(self.settings.start_grace);
        let access = self
            .network
            .as_ref()
            .filter(|_| self.settings.proxy_network.is_some());
        run_network(access, recipe.network(), lasts)
    }

    /// Prepares the mounted files, distinguishing a missing bundle from unavailable storage.
    async fn prepare_folder(
        &self,
        tenant: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<TempDir, CodeRan> {
        match prepared(
            self.files.as_ref(),
            &self.settings.work_folder,
            tenant,
            version,
        )
        .await
        {
            Ok(Prepared::Ready(folder)) => Ok(folder),
            Ok(Prepared::NoBundle) => Err(CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
                UntrustedText::record("the version's bundle is not kept"),
            )))),
            Err(error) => Err(CodeRan::Unavailable(UntrustedText::record(&format!(
                "the run's files could not be laid out: {error}"
            )))),
        }
    }
}

impl TenantScoped for ContainerCodeRunner {}

#[async_trait]
impl CodeRunner for ContainerCodeRunner {
    async fn run(&self, tenant_id: &ScopedTenant, request: CodeRequest<'_>) -> CodeRan {
        let network = match self.network_for(request) {
            Ok(network) => network,
            Err(answer) => return answer,
        };
        match request.version.recipe().program() {
            Program::Code(_) => self.run_code(tenant_id, request, &network).await,
            Program::Image(_) => self.run_image(request, &network).await,
        }
    }
}

impl ContainerCodeRunner {
    /// Runs the code of `request`'s version from a folder of its own.
    async fn run_code(
        &self,
        tenant: &ScopedTenant,
        request: CodeRequest<'_>,
        network: &RunNetwork,
    ) -> CodeRan {
        let Some(code) = request.version.recipe().program().code() else {
            return CodeRan::Ran(CodeOutcome::not_run("the version holds no code"));
        };
        let folder = match self.prepare_folder(tenant, request.version).await {
            Ok(folder) => folder,
            Err(answer) => return answer,
        };
        let entry = entry_of(code.runtime());
        let runs = Runs::Code {
            folder: folder.path(),
            entry: &entry,
        };
        self.launched(request, runs, network).await
    }

    /// Pulls the company's image of `request`'s version with its login,
    /// then runs it; one that cannot be pulled did not run.
    async fn run_image(&self, request: CodeRequest<'_>, network: &RunNetwork) -> CodeRan {
        let image = request.version.recipe().program().image();
        let pulled = match tempfile::Builder::new()
            .prefix("ianua-pull-")
            .tempdir_in(&self.settings.work_folder)
        {
            Ok(config) => {
                container::pull(&self.settings, image, request.login, config.path()).await
            }
            Err(error) => {
                return CodeRan::Unavailable(UntrustedText::record(&format!(
                    "the pull's folder could not be made: {error}"
                )));
            }
        };
        if let Err(why) = pulled {
            return CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
                UntrustedText::record(&why),
            )));
        }
        self.launched(request, Runs::Image, network).await
    }

    /// Starts a container running `runs` for `request`, reaching `network`,
    /// and reads how it ended.
    async fn launched(
        &self,
        request: CodeRequest<'_>,
        runs: Runs<'_>,
        network: &RunNetwork,
    ) -> CodeRan {
        let recipe = request.version.recipe();
        let name = format!(
            "ianua-code-{}-{:08x}",
            request.run_id,
            rand::random::<u32>()
        );
        let launch = Launch {
            name: &name,
            image: recipe.program().image(),
            runs,
            seconds: recipe.budget().seconds(),
            memory_mib: recipe.budget().memory_mib(),
            proxied: proxied_of(network, self.settings.proxy_network.as_deref()),
        };
        match container::run(&self.settings, &launch, &request.input.render()).await {
            Ended::Ran(outcome) => CodeRan::Ran(outcome),
            Ended::NotStarted(why) => CodeRan::Unavailable(UntrustedText::record(&why)),
        }
    }
}

/// How a run getting `network` reaches the filter over `proxy_network`, or
/// `None` for a run that reaches no network.
fn proxied_of<'a>(network: &'a RunNetwork, proxy_network: Option<&'a str>) -> Option<Proxied<'a>> {
    match (network, proxy_network) {
        (RunNetwork::Proxied(proxy), Some(network)) => Some(Proxied { network, proxy }),
        (RunNetwork::Closed, _) | (RunNetwork::Proxied(_), None) => None,
    }
}

/// The runner of a deployment that runs no code: no sandbox will ever
/// take a run, so a code step fails at once.
pub struct NoCodeRunner;

impl TenantScoped for NoCodeRunner {}

#[async_trait]
impl CodeRunner for NoCodeRunner {
    async fn run(&self, _tenant_id: &ScopedTenant, _request: CodeRequest<'_>) -> CodeRan {
        CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
            UntrustedText::record("this deployment runs no code: no sandbox runner is set up"),
        )))
    }
}
