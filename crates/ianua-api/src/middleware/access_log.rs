//! Response access logging: records every failed request at the HTTP
//! boundary.
//!
//! Handler errors that map through `AppError::Internal` already log their
//! cause, but a 5xx can also come from an extractor rejection, a
//! middleware (timeout, body limit), or a panic: none of which reach that
//! path. This middleware sits outermost and observes the final status of
//! every response, so no server error goes unrecorded regardless of where
//! it originated.
//!
//! Only the request path is logged, never the query string, so tokens or
//! secrets passed as query parameters are not captured.

use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// The tracing span for a request, naming the path only.
///
/// `TraceLayer`'s default span records the whole URI, which puts the query
/// string, and any token passed in it, into every trace record. That undoes
/// the care taken below, so the layer is given this instead.
pub(crate) fn request_span(request: &Request) -> tracing::Span {
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        path = %request.uri().path(),
    )
}

/// Logs a structured record for failed responses: 5xx at `error`, 4xx at
/// `debug`. Successful responses are left to the span-level `TraceLayer`.
pub async fn access_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();

    let response = next.run(request).await;

    let status = response.status();
    let latency_ms = started.elapsed().as_millis();

    if status.is_server_error() {
        tracing::error!(
            method = %method,
            path = %path,
            status = status.as_u16(),
            latency_ms,
            "request failed"
        );
    } else if status.is_client_error() {
        tracing::debug!(
            method = %method,
            path = %path,
            status = status.as_u16(),
            latency_ms,
            "request rejected"
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tokens are passed in query strings on the WebSocket routes, so a span
    /// that records the whole URI writes them into every trace record.
    #[test]
    fn the_request_span_names_the_path_without_the_query() {
        let request = Request::builder()
            .uri("/api/v1/organizations/acme/ws/notifications?token=super-secret")
            .body(axum::body::Body::empty())
            .unwrap();

        let span = request_span(&request);
        let rendered = format!("{span:?}");

        assert!(
            !rendered.contains("super-secret"),
            "the span carried the query string: {rendered}"
        );
    }

    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower_http::catch_panic::CatchPanicLayer;

    /// A handler that panics.
    async fn boom() -> &'static str {
        panic!("kaboom")
    }

    /// A handler that answers `ok`.
    async fn ok() -> &'static str {
        "ok"
    }

    /// Both handlers behind the panic catcher and the access log, in the
    /// order the server stacks them.
    fn app() -> Router {
        Router::new()
            .route("/boom", get(boom))
            .route("/ok", get(ok))
            .layer(CatchPanicLayer::new())
            .layer(axum::middleware::from_fn(access_log))
    }

    /// A handler that panics answers `500`; the connection is not dropped.
    #[tokio::test]
    async fn panicking_handler_becomes_500_not_a_dropped_connection() {
        let server = axum_test::TestServer::new(app()).unwrap();

        let response = server.get("/boom").await;

        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// A handler that works answers as it would without the access log.
    #[tokio::test]
    async fn healthy_handler_passes_through() {
        let server = axum_test::TestServer::new(app()).unwrap();

        let response = server.get("/ok").await;

        response.assert_status_ok();
    }
}
