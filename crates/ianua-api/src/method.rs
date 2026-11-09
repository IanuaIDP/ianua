//! HTTP method constructors. Development builds share the surrounding
//! routing implementation across handlers; optimized builds use Axum's
//! constructors directly.

#[cfg(not(debug_assertions))]
pub(crate) use axum::routing::{any, delete, get, patch, post, put};
#[cfg(debug_assertions)]
pub(crate) use development::{any, delete, get, patch, post, put, shared};

/// Keeps release registration on the original typed handler, including when
/// another method is added to an existing method router.
#[cfg(not(debug_assertions))]
pub(crate) fn shared<H>(handler: H) -> H {
    handler
}

#[cfg(debug_assertions)]
mod development {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use axum::extract::Request;
    use axum::handler::Handler;
    use axum::response::Response;
    use axum::routing::{MethodFilter, MethodRouter};

    /// The response future Axum already allocates for an async handler.
    type HandlerFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

    /// Calls the original typed handler without exposing its type to the router.
    type HandlerCall<S> = dyn Fn(Request, S) -> HandlerFuture + Send + Sync;

    /// A common routing type that preserves the original handler's extraction,
    /// response conversion and response future without another future allocation.
    #[derive(Clone)]
    pub(crate) struct SharedHandler<S> {
        call: Arc<HandlerCall<S>>,
    }

    impl<S: Clone + Send + Sync + 'static> Handler<(), S> for SharedHandler<S> {
        type Future = HandlerFuture;

        fn call(self, request: Request, state: S) -> Self::Future {
            (self.call)(request, state)
        }
    }

    /// Shares routing wrappers for a handler added to an existing method
    /// router, retaining its original future and extraction order.
    pub(crate) fn shared<H, T, S>(handler: H) -> SharedHandler<S>
    where
        H: Handler<T, S, Future = HandlerFuture>,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        SharedHandler {
            call: Arc::new(move |request, state| handler.clone().call(request, state)),
        }
    }

    /// Shares Axum's service wrappers while leaving argument extraction and
    /// authentication inside the original typed handler.
    fn route<H, T, S>(filter: MethodFilter, handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S, Future = HandlerFuture>,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        axum::routing::on(filter, shared(handler))
    }

    /// Keeps Axum's fallback-based handling of every HTTP method while sharing
    /// the service wrappers around the original handler.
    pub(crate) fn any<H, T, S>(handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S, Future = HandlerFuture>,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        axum::routing::any(shared(handler))
    }

    macro_rules! methods {
        ($($name:ident => $filter:ident),+ $(,)?) => {
            $(
                #[doc = concat!("Routes ", stringify!($filter), " requests through the original typed handler and shared service wrappers.")]
                pub(crate) fn $name<H, T, S>(handler: H) -> MethodRouter<S>
                where
                    H: Handler<T, S, Future = HandlerFuture>,
                    T: 'static,
                    S: Clone + Send + Sync + 'static,
                {
                    route(MethodFilter::$filter, handler)
                }
            )+
        };
    }

    methods!(delete => DELETE, get => GET, patch => PATCH, post => POST, put => PUT);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::State;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt as _;

    use super::*;

    /// Counts handler calls only after every argument has been extracted.
    #[derive(Clone)]
    struct Calls {
        count: Arc<AtomicUsize>,
    }

    /// Returns a recognizable body for method selection and automatic HEAD.
    async fn answer() -> &'static str {
        "available"
    }

    /// Records successful extraction and returns the original request body.
    async fn echo(State(calls): State<Calls>, body: String) -> String {
        calls.count.fetch_add(1, Ordering::SeqCst);
        body
    }

    /// Each constructor serves its method, GET still serves HEAD without a
    /// body, and a method not registered on a path remains refused.
    #[tokio::test]
    async fn method_selection_and_automatic_head_are_preserved() {
        let router = method_router();
        assert_registered_methods(&router).await;
        let head = Request::builder()
            .uri("/get")
            .method(Method::HEAD)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(head).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(to_bytes(response.into_body(), 64).await.unwrap().is_empty());
        let refused = Request::builder()
            .uri("/get")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(refused).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    /// Registers every method constructor, a chained pair, and the any-method fallback.
    fn method_router() -> Router {
        Router::new()
            .route("/get", get(answer))
            .route("/post", post(answer))
            .route("/put", put(answer))
            .route("/patch", patch(answer))
            .route("/delete", delete(answer))
            .route("/chained", get(answer).post(shared(answer)))
            .route("/any", any(answer))
    }

    /// Every registered method reaches the original handler and returns its body.
    async fn assert_registered_methods(router: &Router) {
        for (path, method) in [
            ("/get", Method::GET),
            ("/post", Method::POST),
            ("/put", Method::PUT),
            ("/patch", Method::PATCH),
            ("/delete", Method::DELETE),
            ("/chained", Method::GET),
            ("/chained", Method::POST),
            ("/any", Method::OPTIONS),
        ] {
            let request = Request::builder()
                .uri(path)
                .method(method)
                .body(Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(response.into_body(), 64).await.unwrap(),
                "available"
            );
        }
    }

    /// Invalid UTF-8 returns 400 without calling the handler; a subsequent
    /// valid body reaches the handler and increments its call count.
    #[tokio::test]
    async fn extraction_refusals_stop_the_handler_and_leave_it_usable() {
        let calls = Calls {
            count: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route("/", get(answer).post(shared(echo)))
            .with_state(calls.clone());
        let invalid = Request::builder()
            .method(Method::POST)
            .body(Body::from(vec![0xff]))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(invalid).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(calls.count.load(Ordering::SeqCst), 0);
        let valid = Request::builder()
            .method(Method::POST)
            .body(Body::from("accepted"))
            .unwrap();
        let response = router.oneshot(valid).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 64).await.unwrap(),
            "accepted"
        );
        assert_eq!(calls.count.load(Ordering::SeqCst), 1);
    }
}
