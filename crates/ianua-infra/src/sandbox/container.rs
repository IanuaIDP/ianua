//! One run in a container started through a container command, such as
//! `docker`: the command that starts it locked down, its input written in,
//! and how it ended read as an outcome.
//!
//! The container reaches no network, has a read-only root, no capabilities
//! and no way to gain any, runs as nobody, and is held to the version's
//! memory with no swap, one CPU and a bounded number of processes. The
//! version's files are mounted read-only; only a small `/tmp` that runs
//! nothing is writable, and it goes with the container. The code is
//! stopped at its time limit inside the container, and the container is
//! killed from outside if it outlives that by the start-up grace.
//!
//! A company's image runs the same way, locked down alike, but holds no
//! folder and no `timeout`: it is pulled first, with its registry's login
//! in a configuration file of the run's own that goes with the run, within
//! the start-up grace, and then run as it is, its input on standard input,
//! killed from outside a moment after its time limit.

use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use base64::Engine as _;
use ianua_app::ports::workflows::PullLogin;
use ianua_domain::domains::workflows::data::MAX_SIZE;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use tokio::io::AsyncWriteExt as _;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use crate::sandbox::ContainerSettings;
use crate::sandbox::entry::{ENTRY_FOLDER, Entry, MOUNTED_AT};
use crate::sandbox::output::{
    ERRORS_HELD, Ended, Exit, KILLED, Memory, NOT_STARTED, bounded, code_outcome,
    ignore_closed_input, last_of, tail,
};

/// How long a company's image may outlive its time limit before it is
/// killed: it has no `timeout` of its own inside.
pub(super) const IMAGE_KILL_MARGIN: Duration = Duration::from_secs(5);

/// What a container runs.
pub(super) enum Runs<'a> {
    /// A version's code under its runtime, from the folder mounted as the
    /// sandbox.
    Code {
        /// The folder mounted as the sandbox.
        folder: &'a Path,
        /// How the runtime starts the code.
        entry: &'a Entry,
    },
    /// A company's image, as its own entry point starts it.
    Image,
}

/// What one container is started with.
pub(super) struct Launch<'a> {
    /// The container's name, unique to this try.
    pub(super) name: &'a str,
    /// The image it runs in.
    pub(super) image: &'a str,
    /// What it runs.
    pub(super) runs: Runs<'a>,
    /// The longest the code may run, in seconds.
    pub(super) seconds: u32,
    /// The memory it is given, in MiB.
    pub(super) memory_mib: u32,
    /// The network that reaches only the network filter, and the filter's
    /// address holding the run's ticket; `None` for no network at all.
    pub(super) proxied: Option<Proxied<'a>>,
}

/// How a run reaches the network filter.
pub(super) struct Proxied<'a> {
    /// The container command's network that reaches only the filter.
    pub(super) network: &'a str,
    /// The filter's address, the run's ticket in it.
    pub(super) proxy: &'a str,
}

/// The three pipes taken from a newly spawned container command.
struct Pipes {
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

/// Runs `launch` with `input` on its standard input, through `settings`'
/// container command, and reads how it ended. The container is removed
/// afterwards, however it ended.
pub(super) async fn run(settings: &ContainerSettings, launch: &Launch<'_>, input: &str) -> Ended {
    let ended = started(settings, launch, input).await;
    let ended = match ended {
        Ok(Some(exit)) => read_exit(settings, launch.name, exit).await,
        Ok(None) => {
            container_command(settings, &["kill", launch.name]).await;
            Ended::Ran(CodeOutcome::Failed(CodeFailure::TimedOut))
        }
        Err(error) => Ended::NotStarted(format!("the container command failed: {error}")),
    };
    container_command(settings, &["rm", "-f", launch.name]).await;
    ended
}

/// Starts the container and waits for it, within the version's time limit
/// and the start-up grace. `None` when it outlived both.
async fn started(
    settings: &ContainerSettings,
    launch: &Launch<'_>,
    input: &str,
) -> std::io::Result<Option<Exit>> {
    let mut child = Command::new(&settings.command)
        .args(arguments(settings, launch))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let pipes = Pipes {
        stdin: child.stdin.take().ok_or_else(missing_pipe)?,
        stdout: child.stdout.take().ok_or_else(missing_pipe)?,
        stderr: child.stderr.take().ok_or_else(missing_pipe)?,
    };
    let margin = match launch.runs {
        Runs::Code { .. } => settings.start_grace,
        Runs::Image => IMAGE_KILL_MARGIN,
    };
    let limit = Duration::from_secs(u64::from(launch.seconds)).saturating_add(margin);
    match tokio::time::timeout(limit, collect_exit(&mut child, pipes, input)).await {
        Ok(exit) => exit.map(Some),
        Err(_) => Ok(None),
    }
}

/// Writes input while draining both output pipes, then waits for the process status.
async fn collect_exit(child: &mut Child, pipes: Pipes, input: &str) -> std::io::Result<Exit> {
    let Pipes {
        mut stdin,
        stdout,
        stderr,
    } = pipes;
    let written = async move {
        stdin.write_all(input.as_bytes()).await?;
        stdin.flush().await
    };
    let (written, answer, errors) = tokio::join!(
        written,
        bounded(stdout, MAX_SIZE),
        last_of(stderr, ERRORS_HELD)
    );
    written.or_else(ignore_closed_input)?;
    let status = child.wait().await?;
    Ok(Exit {
        status: status.code(),
        answer: answer?,
        errors: errors?,
        memory: Memory::WithinItsLimit,
    })
}

/// Filesystem and privilege restrictions applied to every container invocation.
const ISOLATION: &[&str] = &[
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--user",
    "65534:65534",
];

/// Process and working-directory settings shared by every container invocation.
const PROCESS: &[&str] = &[
    "--cpus",
    "1",
    "--pids-limit",
    "128",
    "--workdir",
    "/tmp",
    "--env",
    "HOME=/tmp",
];

/// The arguments of the container command that runs `launch`.
fn arguments(settings: &ContainerSettings, launch: &Launch<'_>) -> Vec<String> {
    let mut arguments = resource_arguments(launch);
    if let Some(runtime) = &settings.runtime {
        arguments.extend(["--runtime".to_owned(), runtime.clone()]);
    }
    if let Some(proxied) = &launch.proxied {
        for name in ["HTTPS_PROXY", "https_proxy"] {
            arguments.extend(["--env".to_owned(), format!("{name}={}", proxied.proxy)]);
        }
        arguments.extend(["--env".to_owned(), "NODE_USE_ENV_PROXY=1".to_owned()]);
    }
    arguments.extend(run_arguments(launch));
    arguments
}

/// The arguments naming what `launch` runs: its folder, image and code
/// under `timeout`, or the company's image alone, already pulled.
fn run_arguments(launch: &Launch<'_>) -> Vec<String> {
    let Runs::Code { folder, entry } = launch.runs else {
        return vec![
            "--pull".to_owned(),
            "never".to_owned(),
            launch.image.to_owned(),
        ];
    };
    let mut arguments: Vec<String> = entry
        .environment
        .iter()
        .flat_map(|(name, value)| ["--env".to_owned(), format!("{name}={value}")])
        .collect();
    arguments.extend([
        "--volume".to_owned(),
        format!("{}:{MOUNTED_AT}:ro", folder.display()),
        launch.image.to_owned(),
        "timeout".to_owned(),
        "-k".to_owned(),
        "2".to_owned(),
        launch.seconds.to_string(),
        entry.interpreter.to_owned(),
        format!("{MOUNTED_AT}/{ENTRY_FOLDER}/{}", entry.entry_file),
    ]);
    arguments
}

/// Pulls `image` through `settings`' container command within the start-up
/// grace, with `login` in a configuration file under `config`, which only
/// this pull reads and which goes with the run.
///
/// # Errors
///
/// Why the image was not pulled.
pub(super) async fn pull(
    settings: &ContainerSettings,
    image: &str,
    login: &PullLogin,
    config: &Path,
) -> Result<(), String> {
    let registry = image.split('/').next().unwrap_or_default();
    write_login(config, registry, login)
        .map_err(|error| format!("the registry's login could not be laid out: {error}"))?;
    let auth_file = config.join("config.json");
    let pulled = Command::new(&settings.command)
        .args(["pull", image])
        .env("DOCKER_CONFIG", config)
        .env("REGISTRY_AUTH_FILE", &auth_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(settings.start_grace, pulled).await {
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => Err(format!(
            "the image was not pulled: {}",
            tail(&output.stderr)
        )),
        Ok(Err(error)) => Err(format!("the container command failed: {error}")),
        Err(_) => Err(format!(
            "the image was not pulled within {}s",
            settings.start_grace.as_secs()
        )),
    }
}

/// Writes the configuration a pull from `registry` reads `login` from:
/// readable by its owner alone, with no login at all when there is none.
fn write_login(config: &Path, registry: &str, login: &PullLogin) -> std::io::Result<()> {
    let mut auths = serde_json::Map::new();
    if let PullLogin::Password { username, password } = login {
        let pair = format!("{}:{}", username.as_str(), password.expose());
        let auth = base64::engine::general_purpose::STANDARD.encode(pair);
        auths.insert(registry.to_owned(), serde_json::json!({ "auth": auth }));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config.join("config.json"))?;
    std::io::Write::write_all(
        &mut file,
        serde_json::json!({ "auths": auths }).to_string().as_bytes(),
    )
}

/// Names the container and applies its network, isolation and resource limits.
fn resource_arguments(launch: &Launch<'_>) -> Vec<String> {
    let memory = format!("{}m", launch.memory_mib);
    let network = launch
        .proxied
        .as_ref()
        .map_or("none", |proxied| proxied.network);
    let mut arguments: Vec<String> = ["run", "-i", "--name", launch.name, "--network", network]
        .into_iter()
        .map(str::to_owned)
        .collect();
    arguments.extend(ISOLATION.iter().copied().map(str::to_owned));
    arguments.extend(
        ["--memory", &memory, "--memory-swap", &memory]
            .into_iter()
            .map(str::to_owned),
    );
    arguments.extend(PROCESS.iter().copied().map(str::to_owned));
    arguments
}

/// How `exit` reads as an outcome: a container that never started is no
/// outcome of the code.
async fn read_exit(settings: &ContainerSettings, name: &str, exit: Exit) -> Ended {
    if exit
        .status
        .is_some_and(|status| NOT_STARTED.contains(&status))
    {
        return Ended::NotStarted(tail(&exit.errors));
    }
    let killed_for_memory = exit.status == Some(KILLED) && out_of_memory(settings, name).await;
    let memory = match killed_for_memory {
        true => Memory::OverItsLimit,
        false => Memory::WithinItsLimit,
    };
    Ended::Ran(code_outcome(&Exit { memory, ..exit }))
}

/// Whether the kernel killed container `name` for using more memory than
/// it was given.
async fn out_of_memory(settings: &ContainerSettings, name: &str) -> bool {
    let inspected = Command::new(&settings.command)
        .args(["inspect", "--format", "{{.State.OOMKilled}}", name])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await;
    inspected.is_ok_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "true")
}

/// Runs the container command with `arguments`, for its effect alone.
async fn container_command(settings: &ContainerSettings, arguments: &[&str]) {
    let ran = Command::new(&settings.command)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if let Err(error) = tokio::time::timeout(settings.start_grace, ran).await {
        tracing::warn!(%error, "a sandbox container command did not finish");
    }
}

fn missing_pipe() -> std::io::Error {
    std::io::Error::other("a pipe to the container command was not opened")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A container is started with no network, a read-only root, no
    /// capabilities, as nobody, held to its memory, and its files mounted
    /// read-only.
    #[test]
    fn a_container_is_started_locked_down() {
        let settings = ContainerSettings::with_command("docker");
        let entry = crate::sandbox::entry::entry_of(
            ianua_domain::domains::workflows::sandbox::runtime::Runtime::Python312,
        );
        let launch = Launch {
            name: "ianua-code-1",
            image: "python:3.12-slim",
            runs: Runs::Code {
                folder: Path::new("/work/run"),
                entry: &entry,
            },
            seconds: 30,
            memory_mib: 256,
            proxied: None,
        };

        let arguments = arguments(&settings, &launch).join(" ");

        for locked in [
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--user 65534:65534",
            "--memory 256m --memory-swap 256m",
            "--volume /work/run:/sandbox:ro",
            "timeout -k 2 30 python3 /sandbox/.ianua/run.py",
        ] {
            assert!(arguments.contains(locked), "{locked} in {arguments}");
        }
        assert!(!arguments.contains("PROXY"));
    }

    /// A run reaching the filter joins only the network that reaches it,
    /// with the filter as its proxy, and is locked down as any other.
    #[test]
    fn a_networked_container_reaches_only_the_filter() {
        let settings = ContainerSettings::with_command("docker");
        let entry = crate::sandbox::entry::entry_of(
            ianua_domain::domains::workflows::sandbox::runtime::Runtime::Python312,
        );
        let launch = Launch {
            name: "ianua-code-2",
            image: "python:3.12-slim",
            runs: Runs::Code {
                folder: Path::new("/work/run"),
                entry: &entry,
            },
            seconds: 30,
            memory_mib: 256,
            proxied: Some(Proxied {
                network: "ianua-sandbox-egress",
                proxy: "http://run:t@172.31.0.2:3128",
            }),
        };

        let arguments = arguments(&settings, &launch).join(" ");

        for expected in [
            "--network ianua-sandbox-egress",
            "--env HTTPS_PROXY=http://run:t@172.31.0.2:3128",
            "--env NODE_USE_ENV_PROXY=1",
            "--cap-drop ALL",
        ] {
            assert!(arguments.contains(expected), "{expected} in {arguments}");
        }
        assert!(!arguments.contains("--network none"));
    }

    /// A company's image runs locked down as code does, already pulled, as
    /// its own entry point starts it, with no folder mounted and no
    /// `timeout` asked of it.
    #[test]
    fn an_image_is_started_locked_down_as_it_is() {
        let settings = ContainerSettings::with_command("docker");
        let image = format!("registry.acme.example/codegen@sha256:{}", "ab".repeat(32));
        let launch = Launch {
            name: "ianua-code-3",
            image: &image,
            runs: Runs::Image,
            seconds: 60,
            memory_mib: 512,
            proxied: None,
        };

        let arguments = arguments(&settings, &launch).join(" ");

        for locked in [
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--user 65534:65534",
            "--memory 512m --memory-swap 512m",
        ] {
            assert!(arguments.contains(locked), "{locked} in {arguments}");
        }
        assert!(arguments.ends_with(&format!("--pull never {image}")));
        assert!(!arguments.contains("--volume"));
    }

    /// The pull's configuration names the registry with the login, readable
    /// by its owner alone; with no login it names none.
    #[test]
    fn the_login_is_written_for_the_pull_alone() {
        let robot = tempfile::tempdir().unwrap();
        let anonymous = tempfile::tempdir().unwrap();
        let login = PullLogin::Password {
            username: ianua_domain::domains::workflows::sandbox::registry::RegistryUsername::new(
                "robot",
            )
            .unwrap(),
            password: ianua_domain::shared::security::secret::Secret::new("s3cret"),
        };

        write_login(robot.path(), "registry.acme.example", &login).unwrap();
        write_login(
            anonymous.path(),
            "registry.acme.example",
            &PullLogin::Anonymous,
        )
        .unwrap();

        let written = std::fs::read_to_string(robot.path().join("config.json")).unwrap();
        let mode = std::fs::metadata(robot.path().join("config.json"))
            .unwrap()
            .permissions();
        let none = std::fs::read_to_string(anonymous.path().join("config.json")).unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode("robot:s3cret");
        assert!(written.contains(&format!(r#""registry.acme.example":{{"auth":"{auth}"}}"#)));
        assert_eq!(mode.mode() & 0o777, 0o600);
        assert_eq!(none, r#"{"auths":{}}"#);
    }
}
