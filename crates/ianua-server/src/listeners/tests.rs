use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ianua_api::router::build_runtime;
use ianua_api::state::http::ListenerLimits;
use ianua_api::test_support::{adapters, internal_router, router};
use ianua_app::test_support::{FakeMetricsExporter, FakeReadinessProbe, METRICS_TEXT};
use ianua_assembly::deps::Adapters;
use ianua_infra::runtime::{LocalMetricsExporter, LocalServedRequestObserver};
use prometheus::Registry;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::*;

/// Any free port on the loopback address.
fn anywhere() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn limits() -> ListenerLimits {
    ListenerLimits {
        max_concurrency: 8,
        max_body_bytes: 1024,
        timeout: Duration::from_secs(5),
    }
}

/// The probes and the scrape of a node serving no API, the database
/// answering as `database` says.
fn runtime(database: FakeReadinessProbe) -> Router {
    build_runtime(
        RuntimePorts {
            database: Arc::new(database),
            message_bus: Arc::new(FakeReadinessProbe::ready()),
            cache: Arc::new(FakeReadinessProbe::ready()),
            exporter: Arc::new(FakeMetricsExporter::writing(METRICS_TEXT)),
        },
        limits(),
    )
}

/// The status and body `path` is answered with at `address`.
async fn get(address: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: ianua.test\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    let status = answer
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// An orchestrator probes a worker's internal listener: it lives, and its
/// dependencies answer, so it is ready.
#[tokio::test]
async fn internal_probes_answer_live_and_ready() {
    let shutdown = Shutdown::new(Duration::from_secs(1));
    let address = serve(
        Listener::Internal,
        runtime(FakeReadinessProbe::ready()),
        anywhere(),
        &shutdown,
    )
    .await
    .unwrap();

    assert_eq!(get(address, "/health/live").await.0, 200);
    assert_eq!(get(address, "/health/ready").await.0, 200);
    shutdown.stop();
    assert!(shutdown.join().await.is_ok());
}

/// A failed database probe makes readiness unavailable while liveness
/// still succeeds and the listener shuts down cleanly.
#[tokio::test]
async fn probe_failure_preserves_liveness_only() {
    let shutdown = Shutdown::new(Duration::from_secs(1));
    let address = serve(
        Listener::Internal,
        runtime(FakeReadinessProbe::not_ready("connection refused")),
        anywhere(),
        &shutdown,
    )
    .await
    .unwrap();

    assert_eq!(get(address, "/health/ready").await.0, 503);
    assert_eq!(get(address, "/health/live").await.0, 200);
    shutdown.stop();
    assert!(shutdown.join().await.is_ok());
}

/// One request to the public API is counted, and the internal listener's
/// scrape serves the count.
#[tokio::test]
async fn metrics_report_served_request_counts() {
    let registry = Registry::new();
    let observer = Arc::new(LocalServedRequestObserver::register(&registry).unwrap());
    let wired = || Adapters {
        served_request_observer: observer.clone(),
        metrics_exporter: Arc::new(LocalMetricsExporter::new(registry.clone())),
        ..adapters()
    };
    let shutdown = Shutdown::new(Duration::from_secs(1));
    let public = serve(Listener::Public, router(wired()), anywhere(), &shutdown)
        .await
        .unwrap();
    let internal = serve(
        Listener::Internal,
        internal_router(wired()),
        anywhere(),
        &shutdown,
    )
    .await
    .unwrap();

    assert_eq!(get(public, "/health").await.0, 200);
    let (status, scraped) = get(internal, "/metrics").await;

    assert_eq!(status, 200);
    assert!(scraped.contains("ianua_api_requests_total"), "{scraped}");
    shutdown.stop();
    assert!(shutdown.join().await.is_ok());
}

/// A listener that has joined after shutdown refuses new TCP connections.
#[tokio::test]
async fn a_stopped_listener_takes_no_connection() {
    let shutdown = Shutdown::new(Duration::from_secs(1));
    let address = serve(
        Listener::Internal,
        runtime(FakeReadinessProbe::ready()),
        anywhere(),
        &shutdown,
    )
    .await
    .unwrap();

    shutdown.stop();
    assert!(shutdown.join().await.is_ok());

    assert!(TcpStream::connect(address).await.is_err());
}

/// Binding an internal listener to an occupied public address fails with
/// an error identifying the internal listener.
#[tokio::test]
async fn a_taken_address_is_refused() {
    let shutdown = Shutdown::new(Duration::from_secs(1));
    let taken = serve(
        Listener::Public,
        runtime(FakeReadinessProbe::ready()),
        anywhere(),
        &shutdown,
    )
    .await
    .unwrap();

    let again = serve(
        Listener::Internal,
        runtime(FakeReadinessProbe::ready()),
        taken,
        &shutdown,
    )
    .await;

    assert!(matches!(
        again,
        Err(ServerError::Listen {
            listener: "internal",
            ..
        })
    ));
    shutdown.stop();
    assert!(shutdown.join().await.is_ok());
}
