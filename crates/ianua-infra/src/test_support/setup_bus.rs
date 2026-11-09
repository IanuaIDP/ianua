//! Nextest setup script: one bus server for the whole test run.
//!
//! The bus adapters are tested against a real server, since only a real
//! one proves an id published twice is kept once. One container is started
//! for the run, with its persistent streams on, or the one a run before
//! left is used again while it answers and was started with today's store
//! limit, and its port is written as `IANUA_TEST_BUS_PORT` to the file
//! `$NEXTEST_ENV` names, as the Postgres setup does.
//!
//! Every scenario stack runs the platform under a namespace of its own, so
//! each makes its own event stream, and the server counts that stream's
//! full size, 8 GiB, against its store limit from the moment it is made,
//! before a byte is written. The container is therefore started with a
//! store limit of [`STORE_LIMIT`], room for every stack of a run, whatever
//! the disk under it holds: the streams of a test run stay small. Streams
//! the stacks and bus tests of earlier runs left are deleted before the
//! run starts, so their reservations never add up across runs; the
//! default `ianua-*` streams are kept. Two runs at once on one container
//! would delete each other's streams, which is why a CI runner gets a
//! container of its own.

// This nextest setup binary must fail the run if its bus or environment file is unavailable.
#![allow(clippy::expect_used)]

use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

use async_nats::jetstream;
use ianua_infra::test_support::bus::{clear_streams, left_by_a_test_namespace};

/// The image the test bus runs.
const IMAGE: &str = "nats:2.10-alpine";

/// The port the server listens on inside its container.
const PORT: u16 = 4222;

/// The most the server's persistent streams may reserve together: 2,048
/// streams of 8 GiB. Each stack makes an event stream and an agent message
/// stream, and a full run starts several hundred stacks besides the bus
/// tests' own streams; 512 was passed once the scenarios grew.
const STORE_LIMIT: &str = "16TB";

/// The label naming the store limit a container was started with, so a
/// container started with another one is replaced rather than used again.
const STORE_LABEL: &str = "ianua-test-bus-store";

/// The container's name, scoped to the CI runner when there is one, so two
/// jobs on one daemon never remove each other's bus.
fn container_name() -> String {
    let base = "ianua-test-bus";
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

/// Whether the container `name` was started with today's store limit.
fn has_store_limit(name: &str) -> bool {
    let format = format!("{{{{index .Config.Labels \"{STORE_LABEL}\"}}}}");
    Command::new("docker")
        .args(["inspect", "--format", &format, name])
        .output()
        .is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == STORE_LIMIT
        })
}

/// The server's command: its persistent streams on, under a store limit
/// set explicitly, which only a configuration file can set.
fn server_command() -> String {
    format!(
        "printf 'jetstream {{\\n  max_file_store: {STORE_LIMIT}\\n}}\\n' > /tmp/bus.conf \
         && exec nats-server --config /tmp/bus.conf"
    )
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
            "--label",
            &format!("{STORE_LABEL}={STORE_LIMIT}"),
            "-p",
            &format!("127.0.0.1::{PORT}"),
            IMAGE,
            "sh",
            "-c",
            &server_command(),
        ])
        .status()
        .expect("docker can be run");
    assert!(status.success(), "the test bus could not be started");
    mapped_port(name).expect("the test bus publishes its port")
}

/// Whether the server on `port` takes a connection and answers a flush.
async fn answers(port: u16) -> bool {
    let Ok(client) = async_nats::connect(format!("127.0.0.1:{port}")).await else {
        return false;
    };
    client.flush().await.is_ok()
}

/// Waits until the server on `port` answers, not merely until it listens.
async fn wait_until_ready(port: u16) {
    for _ in 0..80 {
        if answers(port).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the test bus did not answer on port {port}");
}

/// The port of the container `name` when it runs with today's store limit
/// and answers.
async fn reusable(name: &str) -> Option<u16> {
    let port = mapped_port(name)?;
    if !has_store_limit(name) || !answers(port).await {
        return None;
    }
    Some(port)
}

/// Deletes the streams earlier runs' scenario stacks and bus tests left on
/// the server at `port`.
async fn clear_left_streams(port: u16) {
    let client = async_nats::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("the test bus answers");
    clear_streams(&jetstream::new(client), left_by_a_test_namespace)
        .await
        .expect("the streams earlier runs left are deleted");
}

#[tokio::main]
async fn main() {
    let name = container_name();
    let port = match reusable(&name).await {
        Some(port) => {
            clear_left_streams(port).await;
            port
        }
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
    writeln!(file, "IANUA_TEST_BUS_PORT={port}").expect("the port is written");
}
