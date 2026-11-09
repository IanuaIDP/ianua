//! Nextest setup script: a small open model behind an OpenAI-compatible
//! server, for the agent scenarios run with `IANUA_SCENARIO_MODEL=local`.
//!
//! One Ollama container is started for the run, or the one a run before
//! left is used again while it answers. Its models are kept in a volume,
//! so the model is pulled once per machine. The server's `/v1` base and
//! the model's name are written to the file `$NEXTEST_ENV` names, with
//! `IANUA_SCENARIO_MODEL=local`, as the other setup scripts write theirs.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

use std::io::{self, Write as _};
use std::process::Command;
use std::time::Duration;

/// The server and the model it serves, named in one place.
const LOCAL_MODEL: LocalModel = LocalModel {
    image: "ollama/ollama:0.12.6",
    model: "qwen2.5:0.5b-instruct",
};

/// An image serving an OpenAI-compatible API, and the model pulled into it.
struct LocalModel {
    image: &'static str,
    model: &'static str,
}

/// The port the server listens on inside its container.
const PORT: u16 = 11434;

/// The volume the pulled models are kept in between runs.
const VOLUME: &str = "ianua-scenario-models";

/// The container's name, scoped to the CI runner when there is one, so two
/// jobs on one daemon never remove each other's model.
fn container_name() -> String {
    ianua_infra::test_support::container_names::on_this_runner("ianua-scenario-model")
}

/// The host port the container `name` publishes, if it runs.
fn mapped_port(name: &str) -> Option<u16> {
    let output = Command::new("docker")
        .args(["port", name, &format!("{PORT}/tcp")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .rsplit(':')
        .next()?
        .trim()
        .parse()
        .ok()
}

/// Starts the container `name` afresh and answers its host port.
fn start(name: &str) -> io::Result<u16> {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "ianua-test=1",
            "-v",
            &format!("{VOLUME}:/root/.ollama"),
            "-p",
            &format!("127.0.0.1::{PORT}"),
            LOCAL_MODEL.image,
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(
            "the local model server could not be started",
        ));
    }
    mapped_port(name).ok_or_else(|| io::Error::other("the local model server publishes no port"))
}

/// Whether the server on `port` answers.
async fn answers(port: u16) -> bool {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/api/tags"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .is_ok_and(|answer| answer.status().is_success())
}

/// Waits until the server on `port` answers.
async fn wait_until_ready(port: u16) {
    for _ in 0..120 {
        if answers(port).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the local model server did not answer on port {port}");
}

/// Pulls the model into the container `name`, at once when the volume
/// holds it already.
fn pull(name: &str) -> io::Result<()> {
    let status = Command::new("docker")
        .args(["exec", name, "ollama", "pull", LOCAL_MODEL.model])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "the model {} could not be pulled",
            LOCAL_MODEL.model
        )));
    }
    Ok(())
}

/// Starts or reuses the local model and exports its address to nextest.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = container_name();
    let running = match mapped_port(&name) {
        Some(port) if answers(port).await => Some(port),
        Some(_) | None => None,
    };
    let port = match running {
        Some(port) => port,
        None => {
            let port = start(&name)?;
            wait_until_ready(port).await;
            port
        }
    };
    pull(&name)?;
    write_environment(port)?;
    Ok(())
}

/// Writes the selected model and server address to nextest's setup environment file.
fn write_environment(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var("NEXTEST_ENV")?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "IANUA_SCENARIO_MODEL=local")?;
    writeln!(
        file,
        "IANUA_SCENARIO_LOCAL_MODEL_URL=http://127.0.0.1:{port}/v1"
    )?;
    writeln!(file, "IANUA_SCENARIO_LOCAL_MODEL={}", LOCAL_MODEL.model)?;
    Ok(())
}
