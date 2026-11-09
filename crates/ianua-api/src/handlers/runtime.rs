//! Handlers for running the service: the public listener's static health
//! answer, and the internal listener's probes and metrics scrape.

use axum::extract::State;
use ianua_app::use_case::Query as _;
use ianua_assembly::runtime::RuntimeState;

use crate::error::{ApiError, ErrorBody};
use crate::response::runtime::{PrometheusMetrics, ReadinessAnswer};

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "The server is up", body = String, content_type = "text/plain")
    )
)]
/// Is the server up
///
/// Answers `200` with `ok` while the server is up. Public, and asks nothing
/// of anyone: no dependency is asked, so calling it costs the platform
/// nothing and says nothing of the deployment. The orchestrator's probes
/// are on the internal listener.
pub(crate) async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    responses(
        (status = 200, description = "The process is running", body = String, content_type = "text/plain")
    )
)]
/// Is the process running
///
/// Answers `200` with `ok` for as long as the process runs, whatever its
/// dependencies say: an orchestrator restarts a process that stops
/// answering here. Served on the internal listener only, and asks nothing
/// of anyone.
pub(crate) async fn live() -> &'static str {
    "ok"
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    responses(
        (status = 200, description = "Ready to take traffic"),
        (status = 503, description = "Not ready to take traffic")
    )
)]
/// May the process take traffic
///
/// Asks the database, the message bus and the cache, and answers `200`
/// when every one answers and `503` when one does not or the check runs
/// out of time. Neither answer has a body: which dependency failed, and
/// why, goes to the operator's logs, never to the caller. Served on the
/// internal listener only, with no credentials asked of the orchestrator's
/// probe: on the public one, anyone could make the platform ask all three
/// as often as they liked, and learn which of them is down.
pub(crate) async fn ready(State(runtime): State<RuntimeState>) -> ReadinessAnswer {
    ReadinessAnswer(runtime.readiness.execute(&(), ()).await)
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "Health",
    responses(
        (status = 200, description = "The process's metrics, in the Prometheus text format", body = String, content_type = "text/plain; version=0.0.4"),
        (status = 500, description = "The metrics could not be written out", body = ErrorBody)
    )
)]
/// Scrape the process's metrics
///
/// The process's own metrics in the Prometheus text format: how it runs,
/// never what any tenant holds. Served on the internal listener only, where
/// the scraper calls; the public listener has no such route.
pub(crate) async fn metrics(
    State(runtime): State<RuntimeState>,
) -> Result<PrometheusMetrics, ApiError> {
    let text = runtime.metrics.execute(&(), ()).await?;
    Ok(PrometheusMetrics(text))
}
