//! Nextest setup script: one S3-compatible object store for the whole test
//! run.
//!
//! The object file store is tested against a real store, since only a real
//! one proves a signature is taken, a multipart upload appears whole and
//! an aborted one leaves nothing. One VersityGW container (an
//! S3-compatible gateway over a plain folder, kept in memory) is started
//! for the run, or the one a run before left is used again while it
//! answers, and
//! its port is written as `IANUA_TEST_OBJECTS_PORT` to the file
//! `$NEXTEST_ENV` names, as the cache setup does. Each test makes a bucket
//! of its own in it.

// This nextest setup binary must fail the run if its object store or environment file is unavailable.
#![allow(clippy::expect_used)]

use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

use ianua_infra::http::client::fixed;
use ianua_infra::test_support::objects::{ACCESS_KEY_ID, SECRET};

/// The image the test object store runs, pinned so a run does not change
/// under the tests.
const IMAGE: &str = "versity/versitygw:v1.10.0";

/// The port the store listens on inside its container.
const PORT: u16 = 7070;

/// The path the store answers its health check on.
const HEALTH: &str = "/health";

/// The container's name, scoped to the CI runner when there is one, so two
/// jobs on one daemon never remove each other's store.
fn container_name() -> String {
    let base = "ianua-test-objects";
    match std::env::var("RUNNER_NAME") {
        Ok(runner) if !runner.trim().is_empty() => format!("{base}-{}", runner.trim()),
        _ => base.to_owned(),
    }
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
fn start(name: &str) -> u16 {
    let _ = Command::new("docker")
        .args(["rm", "-f", "-v", name])
        .output();
    let status = container_command(name).status().expect("docker can be run");
    assert!(
        status.success(),
        "the test object store could not be started"
    );
    mapped_port(name).expect("the test object store publishes its port")
}

/// Configures the isolated store with ephemeral data and its fixed test credentials.
fn container_command(name: &str) -> Command {
    let mut command = Command::new("docker");
    command.args([
        "run",
        "-d",
        "--name",
        name,
        "--label",
        "ianua-test=1",
        "-p",
        &format!("127.0.0.1::{PORT}"),
        "--tmpfs",
        "/data",
        "-e",
        &format!("ROOT_ACCESS_KEY={ACCESS_KEY_ID}"),
        "-e",
        &format!("ROOT_SECRET_KEY={SECRET}"),
        IMAGE,
        "--health",
        HEALTH,
        "posix",
        "/data",
    ]);
    command
}

/// Whether the store on `port` says it is ready to serve.
async fn answers(port: u16) -> bool {
    let Ok(client) = fixed(Duration::from_secs(2)) else {
        return false;
    };
    let ready = format!("http://127.0.0.1:{port}{HEALTH}");
    client
        .get(ready)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

/// Waits until the store on `port` is ready, not merely until it listens.
async fn wait_until_ready(port: u16) {
    for _ in 0..80 {
        if answers(port).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the test object store did not answer on port {port}");
}

#[tokio::main]
async fn main() {
    let name = container_name();
    let running = match mapped_port(&name) {
        Some(port) if answers(port).await => Some(port),
        Some(_) | None => None,
    };
    let port = match running {
        Some(port) => port,
        None => {
            let port = start(&name);
            wait_until_ready(port).await;
            port
        }
    };
    let path = std::env::var("NEXTEST_ENV").expect("this runs as a nextest setup script");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("the nextest env file opens");
    writeln!(file, "IANUA_TEST_OBJECTS_PORT={port}").expect("the port is written");
}
