//! A floor under how fast a request that names an address is answered.
//!
//! Asking for a reset link or a sign-in link answers the same whether or
//! not an account has the address. The work does not: a known address is
//! looked up, its old links spent, a new one saved and a mail queued, while
//! an unknown one is only looked up. Answering no sooner than the floor
//! hides that difference, so the time an answer takes says nothing about
//! which addresses have accounts.

use std::time::Duration;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// The soonest a request for a link by address is answered. Well above
/// what the work for a known address takes.
const LINK_REQUEST_FLOOR: Duration = Duration::from_millis(400);

/// Runs the request, then waits until [`LINK_REQUEST_FLOOR`] has passed
/// since it arrived before answering.
pub(crate) async fn link_request_floor(request: Request, next: Next) -> Response {
    let due = tokio::time::Instant::now() + LINK_REQUEST_FLOOR;
    let response = next.run(request).await;
    tokio::time::sleep_until(due).await;
    response
}

/// Marks a response as one that must not tell whether an address has an
/// account, such as a relayed app sign-in's answer to a reset request. An
/// endpoint that answers many kinds of request sets it on those alone.
#[derive(Clone, Copy)]
pub(crate) struct HeldToLinkFloor;

/// Runs the request, then, when the response carries [`HeldToLinkFloor`],
/// waits until [`LINK_REQUEST_FLOOR`] has passed since it arrived. Other
/// answers go out at once.
pub(crate) async fn marked_link_request_floor(request: Request, next: Next) -> Response {
    let due = tokio::time::Instant::now() + LINK_REQUEST_FLOOR;
    let response = next.run(request).await;
    if response.extensions().get::<HeldToLinkFloor>().is_some() {
        tokio::time::sleep_until(due).await;
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::post;
    use tower::ServiceExt as _;

    use super::*;

    /// Even an empty handler waits for the configured minimum response time.
    #[tokio::test]
    async fn an_answer_comes_no_sooner_than_the_floor() {
        let app = Router::new().route(
            "/",
            post(|| async {}).layer(axum::middleware::from_fn(link_request_floor)),
        );
        let started = tokio::time::Instant::now();

        app.oneshot(Request::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(started.elapsed() >= LINK_REQUEST_FLOOR);
    }

    /// A marked response is delayed until the configured time floor has passed.
    #[tokio::test]
    async fn a_marked_answer_comes_no_sooner_than_the_floor() {
        let app = Router::new().route(
            "/",
            post(|| async {
                let mut response = Response::<Body>::default();
                response.extensions_mut().insert(HeldToLinkFloor);
                response
            })
            .layer(axum::middleware::from_fn(marked_link_request_floor)),
        );
        let started = tokio::time::Instant::now();

        app.oneshot(Request::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(started.elapsed() >= LINK_REQUEST_FLOOR);
    }

    /// Ann signs in at an app's host; an answer with nothing to hide is not
    /// held back.
    #[tokio::test]
    async fn an_unmarked_answer_is_not_held() {
        let app = Router::new().route(
            "/",
            post(|| async {}).layer(axum::middleware::from_fn(marked_link_request_floor)),
        );
        let started = tokio::time::Instant::now();

        app.oneshot(Request::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(started.elapsed() < LINK_REQUEST_FLOOR);
    }
}
