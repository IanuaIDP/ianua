//! What every answer of the public API tells the browser that receives
//! it, whatever the answer is: a success, a refusal, a page that never
//! existed or a panic caught on the way out.
//!
//! - Hold to HTTPS for two years, for the API's name and every name under
//!   it, so a browser is never talked down to plain HTTP on a later visit.
//!   A browser ignores this over plain HTTP, so it is sent always.
//! - Never guess what an answer is: a JSON body is never read as a page.
//! - Never show an answer inside another site's frame.
//! - Never pass the API's address on to wherever a link leads.
//!
//! Each is set only when the answer did not set it itself.

use axum::extract::Request;
use axum::http::header::{
    HeaderName, HeaderValue, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

/// Every security header, with the value set when an answer has none.
const SECURITY_HEADERS: [(HeaderName, HeaderValue); 4] = [
    (
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    ),
    (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
    (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
    (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
];

/// Runs the request, then sets every security header the answer did not
/// set itself.
pub(crate) async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.entry(name).or_insert(value);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;

    /// A route answering with `status`, with one security header of its
    /// own when `framing` is given.
    fn app(status: StatusCode, framing: Option<&'static str>) -> Router {
        Router::new()
            .route(
                "/",
                get(move || async move {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = status;
                    if let Some(framing) = framing {
                        response
                            .headers_mut()
                            .insert(X_FRAME_OPTIONS, HeaderValue::from_static(framing));
                    }
                    response
                }),
            )
            .layer(axum::middleware::from_fn(security_headers))
    }

    /// What `app` answers to `GET /`.
    async fn answer(app: Router) -> Response {
        let request = Request::builder().uri("/").body(Body::empty()).unwrap();
        app.oneshot(request).await.unwrap()
    }

    /// A success and a refusal alike carry every security header.
    #[tokio::test]
    async fn every_answer_carries_every_security_header() {
        for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
            let response = answer(app(status, None)).await;
            for (name, value) in SECURITY_HEADERS {
                assert_eq!(
                    response.headers().get(&name),
                    Some(&value),
                    "{status} {name}"
                );
            }
        }
    }

    /// A header the answer set itself is kept as it set it.
    #[tokio::test]
    async fn a_header_the_answer_set_is_kept() {
        let response = answer(app(StatusCode::OK, Some("SAMEORIGIN"))).await;

        assert_eq!(
            response.headers().get(X_FRAME_OPTIONS),
            Some(&HeaderValue::from_static("SAMEORIGIN"))
        );
    }
}
