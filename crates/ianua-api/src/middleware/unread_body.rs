//! A request answered before its body was read still has the rest of that
//! body read and thrown away before the answer goes out.
//!
//! Mallory, signed in nowhere, posts a megabyte. The API turns her away at
//! once, never reading the body, and closes the connection while the bytes
//! are still arriving. Her side, or the proxy in front, meets a reset
//! instead of the refusal, and a proxy answers that as a bad gateway. So a
//! refusal by the sign-in check, a rate limit or anything else that answers
//! early is followed by reading what is left of the body, at most the
//! listener's body limit and for at most [`BodyDraining::within`], and
//! only then is the answer sent. A body past the limit or slower than that
//! is left as it is: no sender holds an answer back for long.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use http_body_util::{BodyExt as _, Limited};

/// How much of a body left unread is read and thrown away, and for how
/// long.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BodyDraining {
    /// The most bytes read: the listener's body limit.
    pub(crate) most: usize,
    /// The longest the answer waits for them.
    pub(crate) within: Duration,
}

/// Runs the request with its body shared, then reads and throws away
/// whatever of it nothing read, as [`BodyDraining`] allows, before the
/// answer goes out.
pub(crate) async fn drain_unread_body(
    State(draining): State<BodyDraining>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let shared = SharedBody::holding(body);
    let response = next
        .run(Request::from_parts(parts, Body::new(shared.clone())))
        .await;
    if let Some(left) = shared.taken() {
        let _ = tokio::time::timeout(draining.within, Limited::new(left, draining.most).collect())
            .await;
    }
    response
}

/// A request body the request reads through while this middleware keeps
/// hold of it, so what is left can be taken back once the answer is made.
#[derive(Clone)]
struct SharedBody(Arc<Mutex<Option<Body>>>);

impl SharedBody {
    /// A shared hold on `body`.
    fn holding(body: Body) -> Self {
        Self(Arc::new(Mutex::new(Some(body))))
    }

    /// The body, taken back so the request reads nothing more; none when a
    /// read panicked while holding it.
    fn taken(&self) -> Option<Body> {
        self.0.lock().ok()?.take()
    }
}

impl http_body::Body for SharedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let Ok(mut held) = self.0.lock() else {
            return Poll::Ready(Some(Err(axum::Error::new(
                "the request body was lost to a panic",
            ))));
        };
        let Some(body) = held.as_mut() else {
            return Poll::Ready(None);
        };
        Pin::new(body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .map_or(true, |held| held.as_ref().is_none_or(Body::is_end_stream))
    }

    fn size_hint(&self) -> SizeHint {
        self.0
            .lock()
            .ok()
            .and_then(|held| held.as_ref().map(Body::size_hint))
            .unwrap_or_else(|| SizeHint::with_exact(0))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::post;
    use tower::ServiceExt as _;

    use super::*;

    /// The drain as the public API sets it up in these tests.
    const DRAINING: BodyDraining = BodyDraining {
        most: 1024,
        within: Duration::from_secs(1),
    };

    /// A route that turns every request away unread, behind the drain.
    fn refusing() -> Router {
        Router::new()
            .route("/", post(|| async { StatusCode::UNAUTHORIZED }))
            .layer(axum::middleware::from_fn_with_state(
                DRAINING,
                drain_unread_body,
            ))
    }

    /// A body of `left` pieces of `size` bytes, counting into `read` each
    /// piece read.
    struct Counted {
        left: usize,
        size: usize,
        read: Arc<AtomicUsize>,
    }

    impl http_body::Body for Counted {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            if self.left == 0 {
                return Poll::Ready(None);
            }
            self.left -= 1;
            self.read.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'a'; self.size])))))
        }
    }

    /// A body of `chunks` pieces of `size` bytes, and how many were read.
    fn counted(chunks: usize, size: usize) -> (Body, Arc<AtomicUsize>) {
        let read = Arc::new(AtomicUsize::new(0));
        let body = Counted {
            left: chunks,
            size,
            read: read.clone(),
        };
        (Body::new(body), read)
    }

    /// Mallory's body is turned away unread: the answer is still the
    /// refusal, and every piece of her body was read before it went out.
    #[tokio::test]
    async fn a_body_turned_away_unread_is_read_before_the_answer() {
        let (body, read) = counted(4, 100);
        let request = Request::post("/").body(body).unwrap();

        let response = refusing().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(read.load(Ordering::Relaxed), 4, "the whole body was read");
    }

    /// A body past the limit is read only up to it, and the refusal still
    /// goes out.
    #[tokio::test]
    async fn a_body_past_the_limit_is_read_no_further_than_it() {
        let (body, read) = counted(100, 100);
        let request = Request::post("/").body(body).unwrap();

        let response = refusing().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            read.load(Ordering::Relaxed) < 100,
            "reading stopped at the limit"
        );
    }

    /// A route that reads the body gets every byte of it through the
    /// drain, as it would without it.
    #[tokio::test]
    async fn a_route_reading_the_body_gets_all_of_it() {
        let app = Router::new()
            .route(
                "/",
                post(|body: String| async move { body.len().to_string() }),
            )
            .layer(axum::middleware::from_fn_with_state(
                DRAINING,
                drain_unread_body,
            ));
        let request = Request::post("/").body(Body::from("Ann's note")).unwrap();

        let response = app.oneshot(request).await.unwrap();
        let read = axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap();

        assert_eq!(read.as_ref(), b"10");
    }
}
