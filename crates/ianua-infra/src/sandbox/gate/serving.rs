//! The gate itself: the only holder of the container engine's socket,
//! starting nothing but locked-down code containers.
//!
//! The worker asks over the gate's own socket. The gate reads the ask and
//! refuses anything a version could not hold: a runtime that is none, an
//! image not named by its content or from a repository it does not serve,
//! limits past a version's, sizes past a bundle's. The container's lockdown
//! is the gate's own and cannot be asked for: no network, a read-only root,
//! no capabilities and no way to gain any, nobody as its user, its memory,
//! one CPU and a bounded number of processes, under the runtime the gate is
//! set up with, such as gVisor's. A run whose version names hosts joins
//! instead the one network the gate is given that reaches only the network
//! filter, and only when the gate is given one. The run is streamed in as a
//! pod's is, and the container is removed however the run went. At its
//! start the gate removes the containers a gate that stopped mid-run left.
//!
//! A company's image is taken only pinned to its digest and only from a
//! registry the operator lists for the gate, beside the runtimes'
//! repositories. The gate pulls it with the login the worker hands over,
//! within the start-up grace, and runs it locked down alike as its own
//! entry point starts it, its input on standard input, which is then
//! closed; it is killed a moment after its time limit.

use std::future::Future;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ianua_domain::domains::workflows::data::MAX_SIZE;
use ianua_domain::domains::workflows::sandbox::build::MAX_BUNDLE_BYTES;
use ianua_domain::domains::workflows::sandbox::runtime::RuntimeImage;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::sandbox::container::IMAGE_KILL_MARGIN;
use crate::sandbox::entry::{Entry, MOUNTED_AT, entry_of};
use crate::sandbox::gate::engine::{Engine, SANDBOX_LABEL, demuxed};
use crate::sandbox::gate::wire::{
    Answer, Ask, IMAGE, ImageAsk, ImageRun, MAX_LINE, MAX_LOGIN_LINE, Reach, line_of, write_answer,
};
use crate::sandbox::output::{
    ERRORS_HELD, Exit, KILLED, Memory, NOT_STARTED, STOPPED_AT_LIMIT, ignore_closed_input, tail,
};
use crate::sandbox::streamed::{Header, MAX_RUN_FILES_BYTES, start_script};

/// How long the worker may take to send its ask and its header.
const ASKED_WITHIN: Duration = Duration::from_secs(10);

/// The room, in MiB, a container is given on top of the version's memory
/// for its unpacked files, which a container's memory holds.
pub(super) const FILES_ROOM_MIB: u64 = 300;

/// How the gate is set up.
#[derive(Debug, Clone)]
pub struct GateServing {
    /// The socket the gate listens on, which only the worker reaches.
    pub listen: PathBuf,
    /// The container engine's socket, such as `/var/run/docker.sock`.
    pub engine: PathBuf,
    /// The runtime containers run under, such as `runsc` for gVisor;
    /// `None` for the engine's default.
    pub runtime: Option<String>,
    /// The image repositories the gate starts containers from, such as
    /// `python` or `registry.example.com/ianua/python`.
    pub repositories: Vec<String>,
    /// The registries the gate pulls companies' own images from, such as
    /// `registry.acme.example`; none takes no company image.
    pub tenant_registries: Vec<String>,
    /// The engine's network that reaches only the network filter, which a
    /// run reaching its allowed hosts joins; `None` gives code no network.
    pub proxy_network: Option<String>,
    /// How long an image may take to be pulled, and a run to be handed its
    /// input, beyond the version's own time limit.
    pub start_grace: Duration,
    /// The most runs the gate holds at once.
    pub most_at_once: usize,
}

/// The gate, serving the worker's asks.
pub struct SandboxGate {
    serving: GateServing,
    repositories: Vec<String>,
    engine: Engine,
    slots: Semaphore,
}

impl SandboxGate {
    /// A gate set up as `serving` says.
    #[must_use]
    pub fn new(serving: GateServing) -> Self {
        let repositories = serving
            .repositories
            .iter()
            .map(|repository| repository_of(repository))
            .collect();
        Self {
            engine: Engine::new(serving.engine.clone()),
            slots: Semaphore::new(serving.most_at_once.max(1)),
            repositories,
            serving,
        }
    }

    /// Removes what an earlier gate left, then serves asks on the gate's
    /// socket until `stopping` resolves, and lets the runs under way end
    /// within the start-up grace.
    ///
    /// # Errors
    ///
    /// When the gate's socket cannot be listened on.
    pub async fn serve(self: Arc<Self>, stopping: impl Future<Output = ()>) -> std::io::Result<()> {
        self.remove_leftovers().await;
        let listener = listening(&self.serving.listen)?;
        let most_connections = self.serving.most_at_once.max(1).saturating_mul(2);
        let mut served = JoinSet::new();
        tokio::pin!(stopping);
        loop {
            while served.try_join_next().is_some() {}
            let accepted = tokio::select! {
                () = &mut stopping => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else {
                continue;
            };
            if served.len() >= most_connections {
                drop(stream);
                continue;
            }
            let gate = Arc::clone(&self);
            served.spawn(async move { gate.serve_connection(stream).await });
        }
        self.finish_connections(&mut served).await;
        Ok(())
    }

    /// Gives active connections the shutdown grace, aborts remaining work and removes the socket.
    async fn finish_connections(&self, served: &mut JoinSet<()>) {
        let ended = tokio::time::timeout(self.serving.start_grace, async {
            while served.join_next().await.is_some() {}
        });
        if ended.await.is_err() {
            served.abort_all();
        }
        if let Err(error) = std::fs::remove_file(&self.serving.listen) {
            tracing::debug!(%error, "the gate's socket was not removed");
        }
    }

    /// Answers the one ask `stream` brings.
    async fn serve_connection(&self, stream: UnixStream) {
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let answer = self.answer(&mut reader).await;
        if let Answer::NotStarted(why) = &answer {
            tracing::warn!(%why, "the gate started no container");
        }
        if let Err(error) = write_answer(&mut write, &answer).await {
            tracing::warn!(%error, "the gate's answer could not be sent");
        }
    }

    /// What the ask `reader` brings comes to.
    async fn answer(&self, reader: &mut (impl AsyncBufRead + Unpin + Send)) -> Answer {
        let asked = tokio::time::timeout(ASKED_WITHIN, self.asked(reader));
        let asked = match asked.await {
            Ok(Ok(asked)) => asked,
            Ok(Err(why)) => return Answer::NotStarted(why),
            Err(_) => return Answer::NotStarted("no ask came in time".to_owned()),
        };
        let waited = tokio::time::timeout(self.serving.start_grace, self.slots.acquire()).await;
        let Ok(Ok(_slot)) = waited else {
            return Answer::NotStarted("every run the gate may hold is under way".to_owned());
        };
        match asked {
            Asked::Code(ask, header) => self.ran(&ask, &header, reader).await,
            Asked::Image(ask, run) => self.ran_image(&ask, &run, reader).await,
        }
    }

    /// The ask `reader` brings and what follows it, each checked: code
    /// under a runtime, or a company's image.
    async fn asked(&self, reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Asked, String> {
        let line = line_of(reader, MAX_LINE)
            .await
            .map_err(|error| unread(&error))?
            .ok_or("the ask is not one")?;
        if line.split(' ').next() == Some(IMAGE) {
            let ask = ImageAsk::read(&line)?;
            self.ensure_registry_served(&ask)?;
            self.ensure_reachable(ask.reach)?;
            let run = image_run_of(reader, ask.reach).await?;
            return Ok(Asked::Image(ask, run));
        }
        let ask = Ask::read(&line)?;
        self.ensure_served(&ask.image)?;
        self.ensure_reachable(ask.reach)?;
        let header = header_of(reader, &ask).await?;
        Ok(Asked::Code(ask, header))
    }

    /// Refuses a company's image from a registry the gate does not pull
    /// from.
    fn ensure_registry_served(&self, ask: &ImageAsk) -> Result<(), String> {
        let registry = ask.image.registry().as_str();
        if self
            .serving
            .tenant_registries
            .iter()
            .any(|served| served.eq_ignore_ascii_case(registry))
        {
            return Ok(());
        }
        Err(format!("the gate pulls no company images from {registry}"))
    }

    /// Pulls `image` with `login` within the start-up grace; what to answer
    /// when it cannot be pulled.
    async fn pull(&self, image: &str, login: Option<&str>) -> Result<(), Answer> {
        let pulled =
            tokio::time::timeout(self.serving.start_grace, self.engine.pull(image, login)).await;
        match pulled {
            Ok(Ok(())) => Ok(()),
            Ok(Err(why)) => Err(Answer::Unpulled(why)),
            Err(_) => Err(Answer::Unpulled(
                "the image was not pulled in time".to_owned(),
            )),
        }
    }

    /// Pulls `ask`'s image with `run`'s login and runs it in a container of
    /// its own, handed the input `reader` brings, and removes the
    /// container. An image that cannot be pulled is answered so.
    async fn ran_image(
        &self,
        ask: &ImageAsk,
        run: &ImageRun,
        reader: &mut (impl AsyncBufRead + Unpin + Send),
    ) -> Answer {
        if let Err(unpulled) = self.pull(ask.image.as_str(), run.login.as_deref()).await {
            return unpulled;
        }
        let name = format!("ianua-code-{:016x}", rand::random::<u64>());
        let spec = image_container_spec(
            ask,
            run,
            self.serving.runtime.as_deref(),
            self.network_of(ask.reach),
        );
        let id = match self
            .engine
            .create(&name, &spec, self.serving.start_grace)
            .await
        {
            Ok(id) => id,
            Err(why) => return Answer::NotStarted(why),
        };
        let answer = self.image_ran_in(&id, ImageWork { ask, run }, reader).await;
        self.engine.remove(&id).await;
        answer
    }

    /// Starts container `id`, hands it `run`'s input and closes it, and
    /// reads how it ended, killing it a moment past its time limit.
    async fn image_ran_in(
        &self,
        id: &str,
        work: ImageWork<'_>,
        reader: &mut (impl AsyncBufRead + Unpin + Send),
    ) -> Answer {
        let ImageWork { ask, run } = work;
        let attached = match self.engine.attach(id).await {
            Ok(attached) => attached,
            Err(why) => return Answer::NotStarted(why),
        };
        if let Err(why) = self.engine.start(id).await {
            return Answer::NotStarted(why);
        }
        let (output, input) = tokio::io::split(attached);
        let written = async {
            write_input(reader, input, run.input_bytes)
                .await
                .or_else(ignore_closed_input)
        };
        let limit =
            Duration::from_secs(u64::from(ask.budget.seconds())).saturating_add(IMAGE_KILL_MARGIN);
        let streamed = tokio::time::timeout(limit, async {
            tokio::try_join!(written, demuxed(output, MAX_SIZE, ERRORS_HELD))
        })
        .await;
        match streamed {
            Ok(Ok(((), (answer, errors)))) => self.ended(id, answer, errors).await,
            Ok(Err(error)) => Answer::NotStarted(format!("the input was not handed over: {error}")),
            Err(_) => self.stop_at_limit(id).await,
        }
    }

    /// Refuses `image` unless it is from a repository the gate serves.
    fn ensure_served(&self, image: &RuntimeImage) -> Result<(), String> {
        let repository = repository_of(image.as_str());
        if self.repositories.contains(&repository) {
            return Ok(());
        }
        Err(format!("the gate serves no images from {repository}"))
    }

    /// Refuses a run reaching the network filter when the gate has no
    /// network that reaches only the filter.
    fn ensure_reachable(&self, reach: Reach) -> Result<(), String> {
        match (reach, &self.serving.proxy_network) {
            (Reach::Closed, _) | (Reach::Proxied, Some(_)) => Ok(()),
            (Reach::Proxied, None) => Err("the gate gives code no network".to_owned()),
        }
    }

    /// The network a run reaching `reach` joins: none, or the one that
    /// reaches only the filter.
    fn network_of(&self, reach: Reach) -> Option<&str> {
        match reach {
            Reach::Closed => None,
            Reach::Proxied => self.serving.proxy_network.as_deref(),
        }
    }

    /// Runs `ask` in a container of its own, streaming it `header` and
    /// the run `reader` brings after it, and removes the container.
    async fn ran(
        &self,
        ask: &Ask,
        header: &Streamed,
        reader: &mut (impl AsyncBufRead + Unpin + Send),
    ) -> Answer {
        let name = format!("ianua-code-{:016x}", rand::random::<u64>());
        let spec = container_spec(
            ask,
            self.serving.runtime.as_deref(),
            self.network_of(ask.reach),
        );
        let made = self
            .engine
            .create(&name, &spec, self.serving.start_grace)
            .await;
        let id = match made {
            Ok(id) => id,
            Err(why) => return Answer::NotStarted(why),
        };
        let answer = self.ran_in(&id, header, reader).await;
        self.engine.remove(&id).await;
        answer
    }

    /// Starts container `id`, streams it its run and reads how it ended,
    /// killing it when it outlives its time and the grace.
    async fn ran_in(
        &self,
        id: &str,
        header: &Streamed,
        reader: &mut (impl AsyncBufRead + Unpin + Send),
    ) -> Answer {
        let attached = match self.engine.attach(id).await {
            Ok(attached) => attached,
            Err(why) => return Answer::NotStarted(why),
        };
        if let Err(why) = self.engine.start(id).await {
            return Answer::NotStarted(why);
        }
        let (output, input) = tokio::io::split(attached);
        let written = write_run(reader, input, header);
        let written = async { written.await.or_else(ignore_closed_input) };
        let limit =
            Duration::from_secs(u64::from(header.seconds)).saturating_add(self.serving.start_grace);
        let streamed = tokio::time::timeout(limit, async {
            tokio::try_join!(written, demuxed(output, MAX_SIZE, ERRORS_HELD))
        })
        .await;
        match streamed {
            Ok(Ok(((), (answer, errors)))) => self.ended(id, answer, errors).await,
            Ok(Err(error)) => Answer::NotStarted(format!("the run was not streamed: {error}")),
            Err(_) => self.stop_at_limit(id).await,
        }
    }

    /// Kills a container that outlived its deadline and reports the timeout as its exit.
    async fn stop_at_limit(&self, id: &str) -> Answer {
        self.engine.kill(id).await;
        Answer::Ran(Exit {
            status: Some(STOPPED_AT_LIMIT),
            answer: Vec::new(),
            errors: Vec::new(),
            memory: Memory::WithinItsLimit,
        })
    }

    /// How container `id` ended, having written `answer` and `errors`.
    async fn ended(&self, id: &str, answer: Vec<u8>, errors: Vec<u8>) -> Answer {
        let status = match self.engine.wait(id).await {
            Ok(status) => status,
            Err(why) => return Answer::NotStarted(why),
        };
        if status.is_some_and(|status| NOT_STARTED.contains(&status)) {
            return Answer::NotStarted(tail(&errors));
        }
        let memory = match status {
            Some(KILLED) => self.engine.memory(id).await,
            _ => Memory::WithinItsLimit,
        };
        Answer::Ran(Exit {
            status,
            answer,
            errors,
            memory,
        })
    }

    /// Removes every container an earlier gate left.
    async fn remove_leftovers(&self) {
        let leftovers = match self.engine.leftovers().await {
            Ok(leftovers) => leftovers,
            Err(why) => {
                tracing::warn!(%why, "the containers an earlier gate left were not listed");
                return;
            }
        };
        for id in leftovers {
            self.engine.remove(&id).await;
        }
    }
}

/// An ask read whole: code under a runtime with its header, or a company's
/// image with what follows it.
enum Asked {
    Code(Ask, Streamed),
    Image(ImageAsk, ImageRun),
}

/// The lines after an image's ask, checked against it: a proxy exactly
/// when it reaches the filter.
async fn image_run_of(
    reader: &mut (impl AsyncBufRead + Unpin),
    reach: Reach,
) -> Result<ImageRun, String> {
    let sizes = line_of(reader, MAX_LINE)
        .await
        .map_err(|error| unread(&error))?;
    let login = line_of(reader, MAX_LOGIN_LINE)
        .await
        .map_err(|error| unread(&error))?;
    let (Some(sizes), Some(login)) = (sizes, login) else {
        return Err("the run's lines are not given".to_owned());
    };
    let run = ImageRun::read(&sizes, &login)?;
    if run.proxy.is_some() != (reach == Reach::Proxied) {
        return Err("the run names another network".to_owned());
    }
    Ok(run)
}

/// Hands the container exactly `length` bytes of input from `reader`, then
/// closes its input, as the image reads until it ends.
async fn write_input(
    reader: &mut (impl AsyncBufRead + Unpin),
    mut input: impl AsyncWrite + Unpin,
    length: u64,
) -> std::io::Result<()> {
    let copied = tokio::io::copy(&mut reader.take(length), &mut input).await?;
    if copied != length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the run's input ended early",
        ));
    }
    input.shutdown().await
}

/// The header line a run starts with, and how many bytes follow it.
struct Streamed {
    line: String,
    length: u64,
    seconds: u32,
}

/// Sends the validated header and exactly its declared input bytes to the container.
async fn write_run(
    reader: &mut (impl AsyncBufRead + Unpin),
    mut input: impl AsyncWrite + Unpin,
    header: &Streamed,
) -> std::io::Result<()> {
    input.write_all(header.line.as_bytes()).await?;
    let copied = tokio::io::copy(&mut reader.take(header.length), &mut input).await?;
    if copied != header.length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the run's input ended early",
        ));
    }
    input.flush().await
}

/// The header `reader` brings after `ask`, checked against it: its time,
/// whether it holds a proxy, and its sizes.
async fn header_of(
    reader: &mut (impl AsyncBufRead + Unpin),
    ask: &Ask,
) -> Result<Streamed, String> {
    let line = line_of(reader, MAX_LINE)
        .await
        .map_err(|error| unread(&error))?;
    let header = line
        .as_deref()
        .and_then(Header::read)
        .ok_or("the run's header is not one")?;
    if header.seconds != ask.budget.seconds() {
        return Err("the run's header names another time limit".to_owned());
    }
    if header.proxy.is_some() != (ask.reach == Reach::Proxied) {
        return Err("the run's header names another network".to_owned());
    }
    if header.bundle_bytes > MAX_BUNDLE_BYTES || header.files_bytes > MAX_RUN_FILES_BYTES {
        return Err("the run is larger than a run may be".to_owned());
    }
    Ok(Streamed {
        line: header.line(),
        length: header.bundle_bytes.saturating_add(header.files_bytes),
        seconds: header.seconds,
    })
}

/// Why the ask could not be read, from `error`.
fn unread(error: &std::io::Error) -> String {
    format!("the ask could not be read: {error}")
}

/// The gate's socket, listened on, reachable by the worker: an old socket
/// left at its path is replaced.
fn listening(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

/// The container `ask` runs in, locked down as the gate always locks it,
/// under `runtime`, on `network` when it reaches the filter and on none
/// otherwise.
fn container_spec(ask: &Ask, runtime: Option<&str>, network: Option<&str>) -> Value {
    let entry = entry_of(ask.runtime);
    json!({
        "Image": ask.image.as_str(),
        "Cmd": ["sh", "-c", start_script(&entry)],
        "User": "65534:65534",
        "WorkingDir": "/tmp",
        "Env": environment(&entry),
        "OpenStdin": true,
        "StdinOnce": true,
        "AttachStdin": true,
        "AttachStdout": true,
        "AttachStderr": true,
        "Tty": false,
        "NetworkDisabled": network.is_none(),
        "Labels": {SANDBOX_LABEL.0: SANDBOX_LABEL.1},
        "HostConfig": host_config(ask, runtime, network),
    })
}

/// The fixed home directory followed by the selected runtime's environment.
fn environment(entry: &Entry) -> Vec<String> {
    let mut environment = vec!["HOME=/tmp".to_owned()];
    environment.extend(
        entry
            .environment
            .iter()
            .map(|(name, value)| format!("{name}={value}")),
    );
    environment
}

/// The container a company's image of `ask` runs in, locked down as the
/// gate always locks it, as the image's own entry point starts it, with
/// `run`'s proxy when it reaches the filter.
fn image_container_spec(
    ask: &ImageAsk,
    run: &ImageRun,
    runtime: Option<&str>,
    network: Option<&str>,
) -> Value {
    let mut environment = vec!["HOME=/tmp".to_owned()];
    if let Some(proxy) = &run.proxy {
        environment.extend([
            format!("HTTPS_PROXY={proxy}"),
            format!("https_proxy={proxy}"),
        ]);
    }
    let memory = u64::from(ask.budget.memory_mib()).saturating_mul(1024 * 1024);
    json!({
        "Image": ask.image.as_str(),
        "User": "65534:65534",
        "WorkingDir": "/tmp",
        "Env": environment,
        "OpenStdin": true,
        "StdinOnce": true,
        "AttachStdin": true,
        "AttachStdout": true,
        "AttachStderr": true,
        "Tty": false,
        "NetworkDisabled": network.is_none(),
        "Labels": {SANDBOX_LABEL.0: SANDBOX_LABEL.1},
        "HostConfig": locked_host(memory, runtime, network),
    })
}

/// Applies the gate's isolation and resource limits independently of the worker.
fn host_config(ask: &Ask, runtime: Option<&str>, network: Option<&str>) -> Value {
    let memory = u64::from(ask.budget.memory_mib())
        .saturating_add(FILES_ROOM_MIB)
        .saturating_mul(1024 * 1024);
    let mut host = locked_host(memory, runtime, network);
    if let Some(tmpfs) = host.get_mut("Tmpfs").and_then(Value::as_object_mut) {
        tmpfs.insert(
            MOUNTED_AT.to_owned(),
            json!(format!("rw,nosuid,nodev,size={FILES_ROOM_MIB}m,mode=1777")),
        );
    }
    host
}

/// The lockdown every container the gate starts gets: no network but the
/// filter's, a read-only root with a small `/tmp`, no capabilities, `memory`
/// bytes with no swap, one CPU and a bounded number of processes, under
/// `runtime`.
fn locked_host(memory: u64, runtime: Option<&str>, network: Option<&str>) -> Value {
    let mut host = json!({
        "NetworkMode": network.unwrap_or("none"),
        "ReadonlyRootfs": true,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"],
        "Privileged": false,
        "Memory": memory,
        "MemorySwap": memory,
        "NanoCpus": 1_000_000_000_u64,
        "PidsLimit": 128,
        "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
    });
    if let (Some(runtime), Some(host)) = (runtime, host.as_object_mut()) {
        host.insert("Runtime".to_owned(), json!(runtime));
    }
    host
}

/// The repository `reference` names, as the engine fully names it: its
/// registry and path, without a tag or digest.
fn repository_of(reference: &str) -> String {
    let named = reference.split('@').next().unwrap_or_default();
    let (path, last) = named.rsplit_once('/').unwrap_or(("", named));
    let last = last.split(':').next().unwrap_or_default();
    let named = match path {
        "" => last.to_owned(),
        path => format!("{path}/{last}"),
    };
    let first = named.split('/').next().unwrap_or_default();
    let has_registry =
        named.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    match (has_registry, named.contains('/')) {
        (true, _) => named,
        (false, true) => format!("docker.io/{named}"),
        (false, false) => format!("docker.io/library/{named}"),
    }
}

/// A company image's run as the gate was asked for it, and how to run it.
#[derive(Clone, Copy)]
struct ImageWork<'a> {
    ask: &'a ImageAsk,
    run: &'a ImageRun,
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::recipe::RunBudget;
    use ianua_domain::domains::workflows::sandbox::runtime::Runtime;

    use super::*;

    const IMAGE: &str =
        "python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1";

    fn ask() -> Ask {
        Ask {
            runtime: Runtime::Python313,
            image: RuntimeImage::new(IMAGE).unwrap(),
            budget: RunBudget::new(20, 128).unwrap(),
            reach: Reach::Closed,
        }
    }

    fn gate(repositories: &[&str], proxy_network: Option<&str>) -> SandboxGate {
        SandboxGate::new(GateServing {
            listen: PathBuf::from("/nowhere/gate.sock"),
            engine: PathBuf::from("/nowhere/docker.sock"),
            runtime: Some("runsc".to_owned()),
            repositories: repositories.iter().map(|name| (*name).to_owned()).collect(),
            tenant_registries: vec!["registry.acme.example".to_owned()],
            proxy_network: proxy_network.map(str::to_owned),
            start_grace: Duration::from_secs(120),
            most_at_once: 2,
        })
    }

    /// The container is locked down as the gate locks it: no network, a
    /// read-only root, no capabilities, nobody as its user, the version's
    /// memory and the files' room, under the gate's runtime.
    #[test]
    fn the_container_is_locked_down() {
        let spec = container_spec(&ask(), Some("runsc"), None);
        let host = &spec["HostConfig"];

        assert_eq!(host["NetworkMode"], "none");
        assert_eq!(spec["NetworkDisabled"], true);
        assert_eq!(host["ReadonlyRootfs"], true);
        assert_eq!(host["CapDrop"][0], "ALL");
        assert_eq!(host["SecurityOpt"][0], "no-new-privileges");
        assert_eq!(host["Privileged"], false);
        assert_eq!(spec["User"], "65534:65534");
        assert_eq!(host["Memory"], (128 + 300) * 1024 * 1024);
        assert_eq!(host["Memory"], host["MemorySwap"]);
        assert_eq!(host["Runtime"], "runsc");
        assert_eq!(spec["Cmd"][2], start_script(&entry_of(Runtime::Python313)));
    }

    /// A run reaching the filter joins the gate's network to it, and no
    /// other; a gate given none refuses the run, and a closed run joins no
    /// network either way.
    #[test]
    fn a_networked_run_joins_only_the_filter_network() {
        let proxied = Ask {
            reach: Reach::Proxied,
            ..ask()
        };
        let networked = gate(&["python"], Some("ianua-sandbox-egress"));
        let closed_only = gate(&["python"], None);

        let spec = container_spec(&proxied, None, networked.network_of(proxied.reach));

        assert_eq!(spec["HostConfig"]["NetworkMode"], "ianua-sandbox-egress");
        assert_eq!(spec["NetworkDisabled"], false);
        assert_eq!(networked.network_of(Reach::Closed), None);
        assert!(closed_only.ensure_reachable(Reach::Proxied).is_err());
        assert!(closed_only.ensure_reachable(Reach::Closed).is_ok());
    }

    /// An image's repository is named as the engine names it, so `python`
    /// and `docker.io/library/python` are one repository and another
    /// registry's is not.
    #[test]
    fn repositories_are_named_in_full() {
        assert_eq!(repository_of(IMAGE), "docker.io/library/python");
        assert_eq!(
            repository_of("docker.io/library/python:3.13-slim"),
            "docker.io/library/python"
        );
        assert_eq!(
            repository_of("registry.example.com:5000/ianua/node@sha256:ab"),
            "registry.example.com:5000/ianua/node"
        );
        assert_eq!(repository_of("bitnami/node"), "docker.io/bitnami/node");
    }

    /// The gate accepts a configured Python image but rejects Python from another registry.
    #[test]
    fn an_image_from_another_repository_is_refused() {
        let served = gate(&["python", "node"], None);
        let other = RuntimeImage::new(
            "evil.example.com/python@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1",
        )
        .unwrap();

        assert!(served.ensure_served(&ask().image).is_ok());
        assert!(served.ensure_served(&other).is_err());
    }

    /// Headers with mismatched time or network settings and oversized bundles
    /// are refused; a matching header preserves its line and combined length.
    #[tokio::test]
    async fn a_header_beyond_the_ask_is_refused() {
        let refused = [
            "100 10 30 -\n".to_owned(),
            "100 10 20 http://run:t@10.0.0.2:3128\n".to_owned(),
            format!("{} 10 20 -\n", MAX_BUNDLE_BYTES + 1),
        ];

        let fine = header_of(&mut BufReader::new(&b"100 10 20 -\n"[..]), &ask())
            .await
            .unwrap();

        for header in refused {
            let read = header_of(&mut BufReader::new(header.as_bytes()), &ask()).await;
            assert!(read.is_err(), "{header} was taken");
        }
        assert_eq!((fine.line.as_str(), fine.length), ("100 10 20 -\n", 110));
    }

    /// The ask is read on its own, then the run's header after it; an
    /// image's ask is read with the two lines after it.
    #[tokio::test]
    async fn the_ask_is_read_before_what_follows() {
        let served = gate(&["python"], None);
        let code = format!("{}100 10 20 -\n", ask().line());
        let image = format!("{}2 -\n-\n", image_ask("registry.acme.example").line());

        let code = served
            .asked(&mut BufReader::new(code.as_bytes()))
            .await
            .unwrap();
        let image = served
            .asked(&mut BufReader::new(image.as_bytes()))
            .await
            .unwrap();

        assert!(matches!(code, Asked::Code(read, _) if read == ask()));
        assert!(matches!(image, Asked::Image(_, run) if run.input_bytes == 2));
    }

    fn image_ask(registry: &str) -> ImageAsk {
        ImageAsk {
            image: ianua_domain::domains::workflows::sandbox::image::PinnedImage::parse(&format!(
                "{registry}/codegen@sha256:{}",
                "ab".repeat(32)
            ))
            .unwrap(),
            budget: RunBudget::new(60, 512).unwrap(),
            reach: Reach::Closed,
        }
    }

    /// A company's image runs locked down as code does, with its memory and
    /// no room for files, as its own entry point starts it.
    #[test]
    fn an_image_container_is_locked_down() {
        let run = ImageRun {
            input_bytes: 2,
            proxy: None,
            login: None,
        };

        let spec = image_container_spec(
            &image_ask("registry.acme.example"),
            &run,
            Some("runsc"),
            None,
        );
        let host = &spec["HostConfig"];

        assert_eq!(host["ReadonlyRootfs"], true);
        assert_eq!(host["CapDrop"][0], "ALL");
        assert_eq!(spec["User"], "65534:65534");
        assert_eq!(host["Memory"], 512 * 1024 * 1024);
        assert_eq!(host["Runtime"], "runsc");
        assert!(spec.get("Cmd").is_none());
        assert!(host["Tmpfs"].get(MOUNTED_AT).is_none());
    }

    /// An image is taken only from a registry the gate pulls from.
    #[test]
    fn an_image_from_another_registry_is_refused() {
        let served = gate(&["python"], None);

        assert!(
            served
                .ensure_registry_served(&image_ask("registry.acme.example"))
                .is_ok()
        );
        assert!(
            served
                .ensure_registry_served(&image_ask("evil.example.com"))
                .is_err()
        );
    }
}
