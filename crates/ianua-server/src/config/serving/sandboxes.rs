//! Where a sandbox version's packages are fetched from, the public npm
//! registry and Python package index or the mirrors the operator names,
//! and how its code is run: in containers on this server, in containers
//! the sandbox gate starts, in pods on a Kubernetes cluster, or not at
//! all; and what the gate itself runs with.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ianua_app::ports::workflows::{OfferedRuntime, OwnImages};
use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::logging::LoggingConfig;
use ianua_domain::domains::workflows::sandbox::runtime::{Runtime, RuntimeImage};
use ianua_infra::packages::PackageRegistries;
use ianua_infra::sandbox::{
    ClusterSettings, ConfiguredRuntimes, ContainerSettings, DEFAULT_IMAGES, GateServing,
    GateSettings, ProxyAccess, ProxyServing, ScanSettings, TicketKey, Upstreams, WarmPods,
};

/// The public npm registry.
const NPM_PUBLIC: &str = "https://registry.npmjs.org";

/// The public Python package index.
const PYPI_PUBLIC: &str = "https://pypi.org";

/// The host the public Python index serves its files from.
const PYPI_PUBLIC_FILES: &str = "files.pythonhosted.org";

/// Where packages are fetched from.
#[derive(Debug, Clone)]
pub(crate) struct SandboxesConfig {
    /// `NPM_REGISTRY_URL` (`https://registry.npmjs.org`) and
    /// `PYPI_INDEX_URL` (`https://pypi.org`): the registries, or mirrors of
    /// them, each `https` in production. `PYPI_FILE_HOSTS`
    /// (`files.pythonhosted.org`): the hosts the index's files may come
    /// from, comma-separated. `PACKAGE_FETCH_TIMEOUT_SECONDS` (120): the
    /// longest one fetch may take.
    pub registries: PackageRegistries,
    /// Where code runs: through a container command, on a cluster, or
    /// nowhere when neither is set.
    pub running: CodeRunning,
    /// The runtimes offered for new versions: each in
    /// `SANDBOX_IMAGE_<RUNTIME>`, such as `SANDBOX_IMAGE_PYTHON_3_13`, named
    /// by its content, or the image pinned for it; but those named in
    /// `SANDBOX_RETIRED_RUNTIMES`, comma-separated, such as `python-3.11`.
    pub runtimes: ConfiguredRuntimes,
    /// The network filter a version naming hosts reaches them through:
    /// `SANDBOX_PROXY_ADDRESS`, its `host:port` as sandboxes reach it, and
    /// `SANDBOX_PROXY_KEY` (or `_FILE`), the key shared with it, both or
    /// neither. With neither, a version naming hosts does not run.
    pub network: Option<ProxyAccess>,
    /// `SANDBOX_OWN_IMAGES` (`false`): whether tenants may run their own
    /// container images from registries their administrators allow.
    pub own_images: OwnImages,
    /// `IMAGE_SCAN_COMMAND`, the scanner command run as `<command> <image>`
    /// that prints SARIF, and `IMAGE_SCAN_TIMEOUT_SECONDS` (600). With no
    /// command, no company image is cleared to run.
    pub scanner: Option<ScanSettings>,
}

impl SandboxesConfig {
    /// The registries and containers `vars` names, in `environment`.
    ///
    /// # Errors
    ///
    /// A registry address that is no URL, or is not `https` in production;
    /// a container command in production with no container runtime named;
    /// an image not named by its content, or a retired runtime that is no
    /// runtime.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let pypi_file_hosts = vars.list("PYPI_FILE_HOSTS")?;
        let pypi_file_hosts = if pypi_file_hosts.is_empty() {
            vec![PYPI_PUBLIC_FILES.to_owned()]
        } else {
            pypi_file_hosts
        };
        Ok(Self {
            registries: PackageRegistries {
                npm: registry(vars, environment, "NPM_REGISTRY_URL", NPM_PUBLIC)?,
                pypi: registry(vars, environment, "PYPI_INDEX_URL", PYPI_PUBLIC)?,
                pypi_file_hosts,
                timeout: vars.seconds("PACKAGE_FETCH_TIMEOUT_SECONDS", Duration::from_secs(120))?,
            },
            running: code_running(vars, environment)?,
            runtimes: runtimes(vars)?,
            network: proxy_access(vars)?,
            own_images: own_images(vars)?,
            scanner: scanner(vars)?,
        })
    }
}

/// Whether `vars` lets tenants run their own images; off unless turned on.
fn own_images(vars: &Env) -> Read<OwnImages> {
    Ok(match vars.flag("SANDBOX_OWN_IMAGES", false)? {
        true => OwnImages::On,
        false => OwnImages::Off,
    })
}

/// The scanner command `vars` names, if any.
fn scanner(vars: &Env) -> Read<Option<ScanSettings>> {
    let Some(command) = vars.path("IMAGE_SCAN_COMMAND")? else {
        return Ok(None);
    };
    Ok(Some(ScanSettings {
        command,
        within: vars.seconds("IMAGE_SCAN_TIMEOUT_SECONDS", Duration::from_secs(600))?,
    }))
}

/// How runs reach the network filter, when `vars` names it: its address and
/// the key shared with it, both or neither.
fn proxy_access(vars: &Env) -> Read<Option<ProxyAccess>> {
    let address = vars.optional("SANDBOX_PROXY_ADDRESS")?;
    let key = vars.secret("SANDBOX_PROXY_KEY")?;
    match (address, key) {
        (None, None) => Ok(None),
        (Some(address), Some(key)) => Ok(Some(ProxyAccess {
            address,
            key: ticket_key(key.expose())?,
        })),
        (Some(_), None) => Err(ConfigError::missing(
            "SANDBOX_PROXY_KEY or SANDBOX_PROXY_KEY_FILE",
        )),
        (None, Some(_)) => Err(ConfigError::missing("SANDBOX_PROXY_ADDRESS")),
    }
}

/// The ticket key `value` writes.
fn ticket_key(value: &str) -> Read<TicketKey> {
    TicketKey::parse(value).ok_or_else(|| {
        ConfigError::invalid(
            "SANDBOX_PROXY_KEY",
            "32 bytes, written as 64 hex characters or as base64",
        )
    })
}

/// Where a deployment runs code.
#[derive(Debug, Clone)]
pub(crate) enum CodeRunning {
    /// Nowhere: every code step fails at once as not run.
    Nowhere,
    /// In containers on this server: `SANDBOX_CONTAINER_COMMAND`, such as
    /// `docker`; `SANDBOX_CONTAINER_RUNTIME` (required in production), such
    /// as `runsc`; `SANDBOX_START_GRACE_SECONDS` (120); and
    /// `SANDBOX_WORK_DIR` (the system's temporary folder), where each run's
    /// files are laid out for the container command to mount.
    Containers(ContainerSettings),
    /// In pods on Kubernetes: `SANDBOX_CLUSTER_NAMESPACE`, the namespace
    /// that holds nothing but them; `SANDBOX_CLUSTER_RUNTIME_CLASS`
    /// (required in production), such as `gvisor`;
    /// `SANDBOX_CLUSTER_CONTEXT`, the kubeconfig context of a worker outside
    /// the cluster, required there; `SANDBOX_START_GRACE_SECONDS` (120); and
    /// `SANDBOX_CLUSTER_MOST_AT_ONCE` (8), the most runs one worker holds.
    Cluster(ClusterSettings),
    /// In containers the sandbox gate starts, the worker holding no
    /// container engine: `SANDBOX_GATE_SOCKET`, the gate's socket, and
    /// `SANDBOX_START_GRACE_SECONDS` (120).
    Gate(GateSettings),
}

/// What the sandbox gate runs with: its logs and how it serves.
#[derive(Debug, Clone)]
pub(crate) struct GateConfig {
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// `SANDBOX_GATE_SOCKET`, the socket listened on;
    /// `SANDBOX_ENGINE_SOCKET` (`/var/run/docker.sock`), the container
    /// engine's; `SANDBOX_CONTAINER_RUNTIME` (required in production), such
    /// as `runsc`; `SANDBOX_GATE_MOST_AT_ONCE` (8); and
    /// `SANDBOX_START_GRACE_SECONDS` (120). The gate starts images from the
    /// repositories of the runtimes' pinned images and of every
    /// `SANDBOX_IMAGE_<RUNTIME>`, and companies' own images, pinned by
    /// digest, from the registries `SANDBOX_GATE_TENANT_REGISTRIES` lists,
    /// comma-separated; none by default.
    pub serving: GateServing,
}

impl GateConfig {
    /// The gate's settings in `vars`.
    ///
    /// # Errors
    ///
    /// No socket to listen on, no runtime named in production, or a setting
    /// out of its range.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let environment = Environment::read(vars)?;
        let runtime = vars.optional("SANDBOX_CONTAINER_RUNTIME")?;
        if runtime.is_none() && environment.is_production() {
            return Err(ConfigError::contradicts(
                "SANDBOX_GATE_SOCKET",
                "is served in production with no SANDBOX_CONTAINER_RUNTIME, such as runsc, to keep tenants' code off the host's kernel",
            ));
        }
        let most = vars.number_in("SANDBOX_GATE_MOST_AT_ONCE", 8_u32, 1..=256)?;
        let serving = GateServing {
            listen: vars
                .path("SANDBOX_GATE_SOCKET")?
                .ok_or_else(|| ConfigError::missing("SANDBOX_GATE_SOCKET"))?,
            engine: vars
                .path("SANDBOX_ENGINE_SOCKET")?
                .unwrap_or_else(|| PathBuf::from("/var/run/docker.sock")),
            runtime,
            repositories: gate_repositories(vars)?,
            tenant_registries: vars.list("SANDBOX_GATE_TENANT_REGISTRIES")?,
            proxy_network: vars.optional("SANDBOX_GATE_PROXY_NETWORK")?,
            start_grace: vars.seconds("SANDBOX_START_GRACE_SECONDS", Duration::from_secs(120))?,
            most_at_once: usize::try_from(most).unwrap_or(1),
        };
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            serving,
        })
    }
}

/// What the network filter runs with: its logs and how it serves.
#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// `SANDBOX_PROXY_LISTEN` (`0.0.0.0:3128`), where sandboxes reach it;
    /// `SANDBOX_PROXY_KEY` (or `_FILE`, required), the key shared with the
    /// worker; and `SANDBOX_PROXY_MOST_AT_ONCE` (256), the most tunnels it
    /// holds. It reaches each host at the public addresses its name leads
    /// to, on port 443, and no setting changes that.
    pub serving: ProxyServing,
}

impl ProxyConfig {
    /// The filter's settings in `vars`.
    ///
    /// # Errors
    ///
    /// No key, a key that is not 32 bytes, an address that is none, or a
    /// setting out of its range.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let environment = Environment::read(vars)?;
        let listen = vars
            .parsed("SANDBOX_PROXY_LISTEN", |address| {
                address.parse::<SocketAddr>()
            })?
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3128)));
        let most = vars.number_in("SANDBOX_PROXY_MOST_AT_ONCE", 256_u32, 1..=4096)?;
        let serving = ProxyServing {
            listen,
            key: ticket_key(vars.required_secret("SANDBOX_PROXY_KEY")?.expose())?,
            most_at_once: usize::try_from(most).unwrap_or(1),
            upstreams: Upstreams::Public,
        };
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            serving,
        })
    }
}

/// The images whose repositories the gate serves: each runtime's pinned
/// one and the one `vars` sets, so versions saved under either still run.
fn gate_repositories(vars: &Env) -> Read<Vec<String>> {
    let mut images = Vec::new();
    for (runtime, pinned) in DEFAULT_IMAGES {
        images.push(pinned.to_owned());
        images.push(vars.text(&image_setting(runtime), pinned)?);
    }
    Ok(images)
}

/// Where `vars` says code runs: one way at most.
fn code_running(vars: &Env, environment: Environment) -> Read<CodeRunning> {
    match (containers(vars, environment)?, cluster(vars, environment)?) {
        (Some(_), Some(_)) => Err(ConfigError::contradicts(
            "SANDBOX_CLUSTER_NAMESPACE",
            "is set beside SANDBOX_CONTAINER_COMMAND; code runs one way",
        )),
        (Some(containers), None) => through_gate_or(vars, CodeRunning::Containers(containers)),
        (None, Some(cluster)) => through_gate_or(vars, CodeRunning::Cluster(cluster)),
        (None, None) => through_gate_or(vars, CodeRunning::Nowhere),
    }
}

/// Code run through the gate when `vars` names its socket, or `otherwise`
/// when it does not; the gate beside another way is refused.
fn through_gate_or(vars: &Env, otherwise: CodeRunning) -> Read<CodeRunning> {
    let Some(socket) = vars.path("SANDBOX_GATE_SOCKET")? else {
        return Ok(otherwise);
    };
    if !matches!(otherwise, CodeRunning::Nowhere) {
        return Err(ConfigError::contradicts(
            "SANDBOX_GATE_SOCKET",
            "is set beside SANDBOX_CONTAINER_COMMAND or SANDBOX_CLUSTER_NAMESPACE; code runs one way",
        ));
    }
    Ok(CodeRunning::Gate(GateSettings {
        socket,
        start_grace: vars.seconds("SANDBOX_START_GRACE_SECONDS", Duration::from_secs(120))?,
    }))
}

/// How code runs on a cluster, when `vars` names its namespace. In
/// production a runtime class must be named, as for containers. A worker
/// outside the cluster names its kubeconfig context, so it never reaches
/// whichever cluster happens to be current, production among them.
fn cluster(vars: &Env, environment: Environment) -> Read<Option<ClusterSettings>> {
    let Some(namespace) = vars.optional("SANDBOX_CLUSTER_NAMESPACE")? else {
        return Ok(None);
    };
    let runtime_class = vars.optional("SANDBOX_CLUSTER_RUNTIME_CLASS")?;
    if runtime_class.is_none() && environment.is_production() {
        return Err(ConfigError::contradicts(
            "SANDBOX_CLUSTER_NAMESPACE",
            "is set in production with no SANDBOX_CLUSTER_RUNTIME_CLASS, such as gvisor, to keep tenants' code off the node's kernel",
        ));
    }
    let context = vars.optional("SANDBOX_CLUSTER_CONTEXT")?;
    if context.is_none() && vars.optional("KUBERNETES_SERVICE_HOST")?.is_none() {
        return Err(ConfigError::contradicts(
            "SANDBOX_CLUSTER_NAMESPACE",
            "is set outside a cluster with no SANDBOX_CLUSTER_CONTEXT; name the kubeconfig context, so no other cluster is reached",
        ));
    }
    let most = vars.number_in("SANDBOX_CLUSTER_MOST_AT_ONCE", 8_u32, 1..=256)?;
    Ok(Some(ClusterSettings {
        namespace,
        runtime_class,
        context,
        start_grace: vars.seconds("SANDBOX_START_GRACE_SECONDS", Duration::from_secs(120))?,
        most_at_once: usize::try_from(most).unwrap_or(1),
        warm: warm_pods(vars)?,
    }))
}

/// How many pods of each kind wait warm, zero for none, and how many
/// minutes each waits to be claimed.
fn warm_pods(vars: &Env) -> Read<WarmPods> {
    let per_kind = vars.number_in("SANDBOX_CLUSTER_WARM", 2_u32, 0..=16)?;
    let minutes = vars.number_in("SANDBOX_CLUSTER_WARM_MINUTES", 15_u64, 1..=120)?;
    Ok(WarmPods {
        per_kind: usize::try_from(per_kind).unwrap_or(0),
        waiting_for: Duration::from_secs(minutes.saturating_mul(60)),
    })
}

/// The runtimes offered, each in the image `vars` sets or the pinned one,
/// but the retired.
fn runtimes(vars: &Env) -> Read<ConfiguredRuntimes> {
    let retired = vars
        .list("SANDBOX_RETIRED_RUNTIMES")?
        .iter()
        .map(|name| {
            Runtime::parse(name).map_err(|_| {
                ConfigError::invalid("SANDBOX_RETIRED_RUNTIMES", "runtimes such as python-3.11")
            })
        })
        .collect::<Read<Vec<_>>>()?;
    let mut offered = Vec::new();
    for (runtime, pinned) in DEFAULT_IMAGES {
        if retired.contains(&runtime) {
            continue;
        }
        let name = image_setting(runtime);
        let image = vars.text(&name, pinned)?;
        let image = RuntimeImage::new(image).map_err(|_| {
            ConfigError::invalid(
                &name,
                "an image named by its content, name@sha256:<64 hex digits>",
            )
        })?;
        offered.push(OfferedRuntime { runtime, image });
    }
    Ok(ConfiguredRuntimes::new(offered))
}

/// The setting naming `runtime`'s image: `python-3.13` is read from
/// `SANDBOX_IMAGE_PYTHON_3_13`.
fn image_setting(runtime: Runtime) -> String {
    format!(
        "SANDBOX_IMAGE_{}",
        runtime
            .as_str()
            .to_ascii_uppercase()
            .replace(['-', '.'], "_")
    )
}

/// How code runs in containers, when `vars` names a container command. In
/// production a container runtime must be named as well: a container on
/// the host's own kernel is too thin a wall for code tenants write.
fn containers(vars: &Env, environment: Environment) -> Read<Option<ContainerSettings>> {
    let Some(command) = vars.optional("SANDBOX_CONTAINER_COMMAND")? else {
        return Ok(None);
    };
    let runtime = vars.optional("SANDBOX_CONTAINER_RUNTIME")?;
    if runtime.is_none() && environment.is_production() {
        return Err(ConfigError::contradicts(
            "SANDBOX_CONTAINER_COMMAND",
            "is set in production with no SANDBOX_CONTAINER_RUNTIME, such as runsc, to keep tenants' code off the host's kernel",
        ));
    }
    let defaults = ContainerSettings::with_command(command);
    Ok(Some(ContainerSettings {
        runtime,
        start_grace: vars.seconds("SANDBOX_START_GRACE_SECONDS", defaults.start_grace)?,
        work_folder: vars
            .path("SANDBOX_WORK_DIR")?
            .unwrap_or_else(|| defaults.work_folder.clone()),
        proxy_network: vars.optional("SANDBOX_CONTAINER_PROXY_NETWORK")?,
        ..defaults
    }))
}

/// The registry at the address `name` holds, or at `public`. A plain `http`
/// address is refused in production: what it sends could be changed on
/// the way, before its fingerprint is checked against what it said.
fn registry(vars: &Env, environment: Environment, name: &str, public: &str) -> Read<String> {
    let Some(url) = vars.url(name)? else {
        return Ok(public.to_owned());
    };
    if url.scheme() != "https" && environment.is_production() {
        return Err(ConfigError::contradicts(
            name,
            "is not https in production, so a package and its fingerprint could be changed on the way",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::workflows::SandboxRuntimes as _;

    use super::*;

    /// Nothing set fetches from the public registries, the Python index's
    /// files from its own file host.
    #[test]
    fn nothing_set_fetches_from_the_public_registries() {
        let config = SandboxesConfig::read(&Env::of([]), Environment::Production).unwrap();

        assert_eq!(config.registries.npm, NPM_PUBLIC);
        assert_eq!(config.registries.pypi, PYPI_PUBLIC);
        assert_eq!(config.registries.pypi_file_hosts, [PYPI_PUBLIC_FILES]);
    }

    /// An HTTP package mirror is refused in production and retained as
    /// the configured registry in development.
    #[test]
    fn a_plain_http_registry_is_refused_in_production() {
        let vars = Env::of([("NPM_REGISTRY_URL", "http://mirror.internal")]);

        let production = SandboxesConfig::read(&vars, Environment::Production);
        let development = SandboxesConfig::read(&vars, Environment::Development).unwrap();

        assert!(production.is_err());
        assert_eq!(development.registries.npm, "http://mirror.internal");
    }

    /// Nothing set runs no code; a container command runs it in the slim
    /// images with no runtime named, in development.
    #[test]
    fn code_runs_only_through_a_named_container_command() {
        let unset = SandboxesConfig::read(&Env::of([]), Environment::Development).unwrap();
        let vars = Env::of([("SANDBOX_CONTAINER_COMMAND", "docker")]);

        let set = SandboxesConfig::read(&vars, Environment::Development).unwrap();

        assert!(matches!(unset.running, CodeRunning::Nowhere));
        let CodeRunning::Containers(containers) = set.running else {
            panic!("code does not run in containers");
        };
        assert_eq!(containers.command, "docker");
        assert_eq!(containers.runtime, None);
    }

    /// Two pods of each kind wait warm for fifteen minutes unless set; zero
    /// keeps none, and a pod never waits less than a minute.
    #[test]
    fn warm_pods_are_kept_as_set() {
        let cluster = [
            ("SANDBOX_CLUSTER_NAMESPACE", "ianua-code"),
            ("SANDBOX_CLUSTER_CONTEXT", "orbstack"),
        ];
        let unset = Env::of(cluster);
        let none = Env::of(cluster.into_iter().chain([("SANDBOX_CLUSTER_WARM", "0")]));
        let instant = Env::of(
            cluster
                .into_iter()
                .chain([("SANDBOX_CLUSTER_WARM_MINUTES", "0")]),
        );

        let unset = SandboxesConfig::read(&unset, Environment::Development).unwrap();
        let none = SandboxesConfig::read(&none, Environment::Development).unwrap();

        let (CodeRunning::Cluster(unset), CodeRunning::Cluster(none)) =
            (unset.running, none.running)
        else {
            panic!("code does not run on the cluster");
        };
        assert_eq!(unset.warm.per_kind, 2);
        assert_eq!(unset.warm.waiting_for, Duration::from_secs(900));
        assert_eq!(none.warm.per_kind, 0);
        assert!(SandboxesConfig::read(&instant, Environment::Development).is_err());
    }

    /// A namespace and a context run code on that cluster, under the
    /// runtime class named, eight runs at a time unless set.
    #[test]
    fn code_runs_on_the_cluster_and_context_named() {
        let vars = Env::of([
            ("SANDBOX_CLUSTER_NAMESPACE", "ianua-code"),
            ("SANDBOX_CLUSTER_CONTEXT", "orbstack"),
            ("SANDBOX_CLUSTER_RUNTIME_CLASS", "gvisor"),
        ]);

        let read = SandboxesConfig::read(&vars, Environment::Production).unwrap();

        let CodeRunning::Cluster(cluster) = read.running else {
            panic!("code does not run on the cluster");
        };
        assert_eq!(cluster.namespace, "ianua-code");
        assert_eq!(cluster.context.as_deref(), Some("orbstack"));
        assert_eq!(cluster.runtime_class.as_deref(), Some("gvisor"));
        assert_eq!(cluster.most_at_once, 8);
    }

    /// Sandbox configuration refuses an external cluster without a
    /// context, a production cluster without a runtime class and a cluster
    /// configured alongside a container command.
    #[test]
    fn a_cluster_is_reached_only_as_named_and_guarded() {
        let no_context = Env::of([("SANDBOX_CLUSTER_NAMESPACE", "ianua-code")]);
        let no_class = Env::of([
            ("SANDBOX_CLUSTER_NAMESPACE", "ianua-code"),
            ("SANDBOX_CLUSTER_CONTEXT", "orbstack"),
        ]);
        let both = Env::of([
            ("SANDBOX_CLUSTER_NAMESPACE", "ianua-code"),
            ("SANDBOX_CLUSTER_CONTEXT", "orbstack"),
            ("SANDBOX_CONTAINER_COMMAND", "docker"),
        ]);

        assert!(SandboxesConfig::read(&no_context, Environment::Development).is_err());
        assert!(SandboxesConfig::read(&no_class, Environment::Production).is_err());
        assert!(SandboxesConfig::read(&both, Environment::Development).is_err());
    }

    /// Nothing set offers every runtime in its pinned image. The operator
    /// moves Python 3.13 to another image and retires 3.11: 3.13 is offered
    /// in that image, 3.11 not at all.
    #[test]
    fn runtimes_are_offered_in_their_pinned_images_unless_set() {
        let moved = format!("registry.internal/python:3.13@sha256:{}", "e".repeat(64));
        let vars = Env::of([
            ("SANDBOX_IMAGE_PYTHON_3_13", moved.as_str()),
            ("SANDBOX_RETIRED_RUNTIMES", "python-3.11"),
        ]);

        let unset = SandboxesConfig::read(&Env::of([]), Environment::Production).unwrap();
        let set = SandboxesConfig::read(&vars, Environment::Production).unwrap();

        assert_eq!(unset.runtimes.offered().len(), Runtime::ALL.len());
        assert_eq!(
            set.runtimes
                .image_of(Runtime::Python313)
                .map(|image| image.as_str().to_owned()),
            Some(moved)
        );
        assert_eq!(set.runtimes.image_of(Runtime::Python311), None);
    }

    /// A sandbox image named only by its mutable tag is refused when
    /// reading configuration.
    #[test]
    fn an_image_named_by_its_tag_alone_is_refused() {
        let vars = Env::of([("SANDBOX_IMAGE_NODE_22", "node:22-slim")]);

        assert!(SandboxesConfig::read(&vars, Environment::Development).is_err());
    }

    /// Production refuses a container command without a runtime and
    /// accepts the same command with `runsc` retained as its runtime.
    #[test]
    fn production_runs_code_only_under_a_named_runtime() {
        let bare = Env::of([("SANDBOX_CONTAINER_COMMAND", "docker")]);
        let guarded = Env::of([
            ("SANDBOX_CONTAINER_COMMAND", "docker"),
            ("SANDBOX_CONTAINER_RUNTIME", "runsc"),
        ]);

        let refused = SandboxesConfig::read(&bare, Environment::Production);
        let taken = SandboxesConfig::read(&guarded, Environment::Production).unwrap();

        assert!(refused.is_err());
        let CodeRunning::Containers(containers) = taken.running else {
            panic!("code does not run in containers");
        };
        assert_eq!(containers.runtime.as_deref(), Some("runsc"));
    }
}
