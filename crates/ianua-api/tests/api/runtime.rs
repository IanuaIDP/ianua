//! The endpoints for running the service: a static `/health` on the public
//! listener, and the probes and the metrics scrape on the internal one
//! alone.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::router::build_runtime;
use ianua_api::state::http::ListenerLimits;
use ianua_api::test_support::{adapters, internal_router, router};
use ianua_app::test_support::{FakeMetricsExporter, FakeReadinessProbe, METRICS_TEXT};
use ianua_assembly::deps::Adapters;
use ianua_assembly::runtime::RuntimePorts;

/// The public listener over `adapters`.
fn public(adapters: Adapters) -> TestServer {
    TestServer::new(router(adapters)).unwrap()
}

/// The internal listener over `adapters`.
fn internal(adapters: Adapters) -> TestServer {
    TestServer::new(internal_router(adapters)).unwrap()
}

/// Someone outside asks the public listener whether the server is up. It
/// says so, with no credentials asked.
#[tokio::test]
async fn the_public_listener_says_the_server_is_up() {
    let response = public(adapters()).get("/health").await;

    response.assert_status_ok();
    assert_eq!(response.text(), "ok");
}

/// The public readiness path returns 404 while the public health route
/// remains successful with an unavailable database.
#[tokio::test]
async fn the_public_listener_serves_no_readiness_probe() {
    let server = public(Adapters {
        database_readiness: Arc::new(FakeReadinessProbe::not_ready("connection refused")),
        ..adapters()
    });

    server
        .get("/health/ready")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server.get("/health").await.assert_status_ok();
}

/// The public listener returns 404 for the liveness probe path.
#[tokio::test]
async fn the_public_listener_serves_no_liveness_probe() {
    let response = public(adapters()).get("/health/live").await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An orchestrator asks the internal listener whether the process runs.
/// It does, and says so, with no credentials asked.
#[tokio::test]
async fn a_running_process_is_live() {
    let response = internal(adapters()).get("/health/live").await;

    response.assert_status_ok();
    assert_eq!(response.text(), "ok");
}

/// Every dependency answers, so the process takes traffic.
#[tokio::test]
async fn a_process_whose_dependencies_answer_is_ready() {
    let response = internal(adapters()).get("/health/ready").await;

    response.assert_status_ok();
}

/// Database failure makes internal readiness return 503 with an empty body.
#[tokio::test]
async fn a_process_whose_database_is_down_is_not_ready_and_says_no_more() {
    let response = internal(Adapters {
        database_readiness: Arc::new(FakeReadinessProbe::not_ready(
            "connection refused by db.internal:5432",
        )),
        ..adapters()
    })
    .get("/health/ready")
    .await;

    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.text().is_empty());
}

/// The scraper asks the internal listener for the metrics and is handed
/// them in the Prometheus text format.
#[tokio::test]
async fn the_internal_listener_serves_the_metrics() {
    let response = internal(adapters()).get("/metrics").await;

    response.assert_status_ok();
    assert_eq!(response.text(), METRICS_TEXT);
    assert!(
        response
            .header("content-type")
            .to_str()
            .unwrap()
            .starts_with("text/plain; version=0.0.4")
    );
}

/// The orchestrator probes the internal listener, which the public ingress
/// never routes to. It answers there too.
#[tokio::test]
async fn the_internal_listener_answers_the_probes() {
    let server = internal(adapters());

    server.get("/health/live").await.assert_status_ok();
    server.get("/health/ready").await.assert_status_ok();
}

/// A worker serves no API, yet its orchestrator probes it and its metrics
/// are scraped. Its internal listener answers both from the probes and
/// the exporter alone.
#[tokio::test]
async fn a_node_serving_no_api_answers_its_probes_and_scrape() {
    let ports = RuntimePorts {
        database: Arc::new(FakeReadinessProbe::ready()),
        message_bus: Arc::new(FakeReadinessProbe::ready()),
        cache: Arc::new(FakeReadinessProbe::ready()),
        exporter: Arc::new(FakeMetricsExporter::writing(METRICS_TEXT)),
    };
    let server = TestServer::new(build_runtime(ports, limits())).unwrap();

    server.get("/health/live").await.assert_status_ok();
    server.get("/health/ready").await.assert_status_ok();
    assert_eq!(server.get("/metrics").await.text(), METRICS_TEXT);
}

/// A worker without a functioning bus returns 503 from internal readiness.
#[tokio::test]
async fn a_node_serving_no_api_whose_bus_is_down_is_not_ready() {
    let ports = RuntimePorts {
        database: Arc::new(FakeReadinessProbe::ready()),
        message_bus: Arc::new(FakeReadinessProbe::not_ready("no route to bus.internal")),
        cache: Arc::new(FakeReadinessProbe::ready()),
        exporter: Arc::new(FakeMetricsExporter::writing(METRICS_TEXT)),
    };
    let server = TestServer::new(build_runtime(ports, limits())).unwrap();

    let response = server.get("/health/ready").await;

    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

/// What the internal listener takes on in these tests.
fn limits() -> ListenerLimits {
    ListenerLimits {
        max_concurrency: 8,
        max_body_bytes: 1024,
        timeout: std::time::Duration::from_secs(5),
    }
}

/// The public listener returns 404 for the metrics path.
#[tokio::test]
async fn the_public_listener_does_not_serve_the_metrics() {
    let response = public(adapters()).get("/metrics").await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The registry cannot be written out. The scrape fails rather than
/// answering with empty metrics that read as a quiet process.
#[tokio::test]
async fn a_registry_that_cannot_be_written_out_fails_the_scrape() {
    let response = internal(Adapters {
        metrics_exporter: Arc::new(FakeMetricsExporter::failing()),
        ..adapters()
    })
    .get("/metrics")
    .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
}
