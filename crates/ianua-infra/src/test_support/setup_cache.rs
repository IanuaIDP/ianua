//! Nextest setup script: one cache server for the whole test run.
//!
//! The cache adapters are tested against a real server, since only a real
//! one proves a script runs whole and a claim raced by two is won once. One
//! container is started for the run, or the one a run before left is used
//! again while it answers, and its port is written as
//! `IANUA_TEST_CACHE_PORT` to the file `$NEXTEST_ENV` names, as the
//! Postgres setup does. The image is Valkey; any server that speaks the
//! same protocol would do.

// This nextest setup binary must fail the run if its cache or environment file is unavailable.
#![allow(clippy::expect_used)]

use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

/// The image the test cache runs.
const IMAGE: &str = "valkey/valkey:8-alpine";

/// The port the server listens on inside its container.
const PORT: u16 = 6379;

/// The container's name, scoped to the CI runner when there is one, so two
/// jobs on one daemon never remove each other's cache.
fn container_name() -> String {
    let base = "ianua-test-cache";
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
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "ianua-test=1",
            "-p",
            &format!("127.0.0.1::{PORT}"),
            IMAGE,
        ])
        .status()
        .expect("docker can be run");
    assert!(status.success(), "the test cache could not be started");
    mapped_port(name).expect("the test cache publishes its port")
}

/// Whether the server on `port` answers `PING`.
async fn answers(port: u16) -> bool {
    let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}")) else {
        return false;
    };
    let Ok(mut connection) = client.get_multiplexed_async_connection().await else {
        return false;
    };
    redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await
        .is_ok()
}

/// Waits until the server on `port` answers, not merely until it listens.
async fn wait_until_ready(port: u16) {
    for _ in 0..80 {
        if answers(port).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the test cache did not answer on port {port}");
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
    writeln!(file, "IANUA_TEST_CACHE_PORT={port}").expect("the port is written");
}
