//! Answers for running the service: whether the process is ready, and its
//! metrics for a scrape.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ianua_app::ports::runtime::MetricsText;
use ianua_app::use_cases::runtime::ServiceReadiness;

/// The content type of the Prometheus text exposition format.
const PROMETHEUS_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Whether the process may take traffic: `200` when ready, `503` when not,
/// and no body either way, so nothing about its dependencies leaves the
/// process.
pub(crate) struct ReadinessAnswer(pub ServiceReadiness);

impl IntoResponse for ReadinessAnswer {
    fn into_response(self) -> Response {
        match self.0 {
            ServiceReadiness::Ready => StatusCode::OK.into_response(),
            ServiceReadiness::NotReady => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
}

/// The process's metrics, served as the registry wrote them, in the
/// Prometheus text format.
pub(crate) struct PrometheusMetrics(pub MetricsText);

impl IntoResponse for PrometheusMetrics {
    fn into_response(self) -> Response {
        (
            [(header::CONTENT_TYPE, PROMETHEUS_TEXT)],
            self.0.into_string(),
        )
            .into_response()
    }
}
