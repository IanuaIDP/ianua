//! Endpoints for running the service: a static `/health` on the public
//! listener, and the probes and the metrics scrape on the internal one.
//!
//! The readiness probe asks the database, the bus and the cache on every
//! call, and the metrics say how the process runs. Both stay off the public
//! listener: a stranger must not make the platform ask its dependencies as
//! often as they like, learn which of them is down, or read its traffic and
//! load. The internal listener answers the probes on every node: a worker
//! serves no public listener, and its orchestrator still asks whether it
//! lives and may work.

use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use ianua_assembly::runtime::RuntimeState;
use tower_http::timeout::TimeoutLayer;
use utoipa::OpenApi;

use crate::handlers::runtime as handlers;
use crate::method::get;
use crate::state::ApiState;

/// The longest the readiness check waits for its dependencies before it
/// answers not ready: a hung dependency must not hold the probe.
const READINESS_WAIT: Duration = Duration::from_secs(5);

/// The public listener's endpoint for running the service: `/health`, which
/// asks nothing of anyone.
pub(crate) fn routes() -> Router<ApiState> {
    Router::new().route("/health", get(handlers::health))
}

/// The internal listener's endpoints for running the service: the probes
/// and the metrics scrape.
pub(crate) fn internal_routes() -> Router<RuntimeState> {
    Router::new()
        .route("/health/live", get(handlers::live))
        .route(
            "/health/ready",
            get(handlers::ready).layer(TimeoutLayer::with_status_code(
                StatusCode::SERVICE_UNAVAILABLE,
                READINESS_WAIT,
            )),
        )
        .route("/metrics", get(handlers::metrics))
}

/// The public part of the OpenAPI document for running the service.
#[derive(OpenApi)]
#[openapi(paths(handlers::health))]
pub(crate) struct Document;

/// The internal listener's part of the OpenAPI document for running the
/// service: the probes and the scrape, which the public one leaves out.
#[derive(OpenApi)]
#[openapi(paths(handlers::live, handlers::ready, handlers::metrics))]
pub(crate) struct InternalDocument;
