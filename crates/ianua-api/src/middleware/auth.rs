//! Bearer token authentication middleware.
//!
//! Reads `Authorization: Bearer <token>`, resolves it through the
//! `TokenResolver` port, and puts the app's `ResolvedCaller` into the
//! request's extensions. It refuses nothing: a request without a token, or
//! with one that resolves to no one, goes on with no caller, and the caller
//! extractors answer `401` where one is needed. What the caller may do is
//! the app's question.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_app::ports::shared::{ResolvedCaller, TokenResolver};
use ianua_domain::shared::security::secret::Secret;
use tower::{Layer, Service};

/// Tower layer that injects bearer-token authentication.
#[derive(Clone)]
pub(crate) struct AuthLayer {
    resolver: Arc<dyn TokenResolver>,
}

impl AuthLayer {
    /// Creates a new auth layer backed by the given token resolver.
    pub(crate) fn new(resolver: Arc<dyn TokenResolver>) -> Self {
        Self { resolver }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            resolver: self.resolver.clone(),
        }
    }
}

/// Tower service that resolves bearer tokens before forwarding.
#[derive(Clone)]
pub(crate) struct AuthService<S> {
    inner: S,
    resolver: Arc<dyn TokenResolver>,
}

impl<S> Service<Request> for AuthService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let token = extract_bearer_token(&request);
        let resolver = self.resolver.clone();
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            let Some(token) = token else {
                return inner.call(request).await;
            };

            match resolve_caller(&*resolver, token).await {
                Ok(Some(caller)) => {
                    request.extensions_mut().insert(caller);
                }
                Ok(None) => {}
                Err(()) => return Ok(auth_unavailable()),
            }

            inner.call(request).await
        })
    }
}

/// Response returned when the token resolver itself fails (e.g. the
/// auth datastore is down). Distinct from "no/invalid token" so an
/// outage surfaces as 503 instead of silently downgrading the caller
/// to anonymous.
fn auth_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication temporarily unavailable",
    )
        .into_response()
}

/// Extracts the bearer token from the `Authorization` header, or, only on a
/// WebSocket route being upgraded, the URL-decoded `token` query parameter.
/// Browsers cannot set `Authorization` on a WS handshake, so the query param
/// is restricted to that case to keep session tokens out of ordinary access
/// logs and `Referer` headers.
///
/// The route is what decides. Keying on the `Upgrade` header alone let any
/// endpoint in the API be authenticated by `?token=`: the header is the
/// caller's to write, so it proved nothing about where the request was going.
fn extract_bearer_token(request: &Request) -> Option<String> {
    if let Some(token) = header_bearer_token(request) {
        return Some(token.to_owned());
    }

    if !is_websocket_route(request.uri().path()) || !is_websocket_upgrade(request) {
        return None;
    }

    query_token(request.uri().query()?)
}

/// Whether `path` is one of the API's WebSocket endpoints.
///
/// The two shapes the router exposes: everything under a `/ws/` segment, and
/// the per-run step stream.
fn is_websocket_route(path: &str) -> bool {
    path.contains("/ws/") || path.ends_with("/stream")
}

/// Reads the bearer token from the `Authorization` header, if present.
fn header_bearer_token(request: &Request) -> Option<&str> {
    let header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())?;

    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?;

    (!token.is_empty()).then_some(token)
}

/// Whether the request is a WebSocket upgrade handshake.
fn is_websocket_upgrade(request: &Request) -> bool {
    request
        .headers()
        .get("upgrade")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Extracts and URL-decodes the `token` query parameter.
fn query_token(query: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
        .filter(|token| !token.is_empty())
}

/// Resolves a bearer token into the caller behind it.
///
/// `Ok(Some)` is a valid token, `Ok(None)` is an invalid/expired token,
/// and `Err(())` signals an infrastructure failure in the resolver that
/// the caller must surface as 5xx rather than treat as anonymous.
async fn resolve_caller(
    resolver: &dyn TokenResolver,
    token: String,
) -> Result<Option<ResolvedCaller>, ()> {
    resolver.resolve(&Secret::new(token)).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request as it arrives: a path, and whatever headers the caller chose
    /// to send.
    fn request(uri: &str, headers: &[(&str, &str)]) -> Request {
        let mut builder = axum::http::Request::builder().uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    /// The header a browser sends to open a WebSocket.
    fn upgrade() -> (&'static str, &'static str) {
        ("upgrade", "websocket")
    }

    /// A browser cannot set headers on a WebSocket handshake, so the token
    /// rides in the query string: and a query string is written into links,
    /// logged by proxies, and kept in history. It is therefore accepted on a
    /// WebSocket handshake and nowhere else.
    ///
    /// Keying on the `Upgrade` header alone is the regression: the header is
    /// the caller's to write, so it proves nothing about where the request is
    /// going, and every endpoint in the API becomes authenticatable by
    /// `?token=`.
    #[test]
    fn a_query_token_is_refused_on_a_route_that_is_not_a_websocket() {
        let ordinary = request("/api/v1/organizations?token=stolen", &[upgrade()]);

        assert_eq!(
            extract_bearer_token(&ordinary),
            None,
            "an upgrade header on an ordinary route must not admit a query token"
        );
    }

    /// The other half of the same rule: the route being a WebSocket route is
    /// not enough either, or an ordinary GET of the stream endpoint would
    /// authenticate from the URL.
    #[test]
    fn a_query_token_is_refused_without_an_upgrade_handshake() {
        let no_upgrade = request("/api/v1/agents/runs/abc/stream?token=stolen", &[]);

        assert_eq!(extract_bearer_token(&no_upgrade), None);
    }

    /// Both together are what a real handshake looks like, on both the route
    /// shapes the router exposes.
    #[test]
    fn a_query_token_is_read_from_a_genuine_handshake() {
        let nested = request("/api/v1/ws/notifications?token=good", &[upgrade()]);
        let stream = request("/api/v1/agents/runs/abc/stream?token=good", &[upgrade()]);

        assert_eq!(extract_bearer_token(&nested), Some("good".to_owned()));
        assert_eq!(extract_bearer_token(&stream), Some("good".to_owned()));
    }

    /// The header is the ordinary way in, and it is read whatever the route.
    #[test]
    fn a_bearer_header_is_read_on_any_route() {
        let req = request(
            "/api/v1/organizations",
            &[("authorization", "Bearer header-token")],
        );

        assert_eq!(extract_bearer_token(&req), Some("header-token".to_owned()));
    }

    /// `Bearer` is a scheme name, and schemes are case-insensitive. What is
    /// not accepted is a scheme that is not bearer at all, or a bearer with
    /// nothing after it: an empty token would otherwise be handed to the
    /// resolver as if somebody had presented something.
    #[test]
    fn the_authorization_header_is_read_only_as_a_non_empty_bearer() {
        let lower = request("/x", &[("authorization", "bearer token")]);
        assert_eq!(header_bearer_token(&lower), Some("token"));

        let empty = request("/x", &[("authorization", "Bearer ")]);
        assert_eq!(header_bearer_token(&empty), None);

        let basic = request("/x", &[("authorization", "Basic dXNlcjpwYXNz")]);
        assert_eq!(header_bearer_token(&basic), None);

        let absent = request("/x", &[]);
        assert_eq!(header_bearer_token(&absent), None);
    }

    /// The query parameter is named, not positional: another parameter that
    /// happens to carry a value is not a credential.
    #[test]
    fn only_the_token_parameter_is_read_as_a_token() {
        assert_eq!(query_token("token=good"), Some("good".to_owned()));
        assert_eq!(query_token("access_token=good"), None);
        assert_eq!(query_token("tenant=acme"), None);
        assert_eq!(
            query_token("tenant=acme&token=good&other=1"),
            Some("good".to_owned())
        );
    }

    /// An empty `?token=` is not a token, and a percent-encoded one is the
    /// value it decodes to rather than the text as written.
    #[test]
    fn a_query_token_is_decoded_and_must_not_be_empty() {
        assert_eq!(query_token("token="), None);
        assert_eq!(query_token("token=a%20b"), Some("a b".to_owned()));
    }

    /// The handshake is identified by the header's value, not its presence,
    /// and the value is compared without regard to case because that is how
    /// browsers send it.
    #[test]
    fn an_upgrade_is_recognised_only_for_websocket() {
        assert!(is_websocket_upgrade(&request("/x", &[upgrade()])));
        assert!(is_websocket_upgrade(&request(
            "/x",
            &[("upgrade", "WebSocket")]
        )));
        assert!(!is_websocket_upgrade(&request("/x", &[("upgrade", "h2c")])));
        assert!(!is_websocket_upgrade(&request("/x", &[])));
    }

    /// The two shapes the router exposes, and nothing else. A path that
    /// merely mentions them elsewhere is not one of them.
    #[test]
    fn a_websocket_route_is_one_of_the_two_shapes_the_router_exposes() {
        assert!(is_websocket_route("/api/v1/ws/notifications"));
        assert!(is_websocket_route("/api/v1/agents/runs/abc/stream"));

        assert!(!is_websocket_route("/api/v1/organizations"));
        assert!(!is_websocket_route("/api/v1/streams"));
    }
}
