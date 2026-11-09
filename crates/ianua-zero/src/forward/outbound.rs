//! The request a backend is sent, built from the one the client sent.
//!
//! It keeps the method, the headers the caller left and the body, which
//! streams on unread but held to the pipeline's body limit: a body that
//! declares more is refused before any backend is contacted, and one that
//! streams past it is cut off before the backend receives the excess. The
//! address becomes the backend's, with the route's path and the request's
//! own query; the connection headers go, the `Host` is the one the service
//! asks for, and nothing the inbound connection attached to the request
//! travels on with it.

use http::{Extensions, HeaderMap, Request, Uri, Version, header};
use http_body_util::{BodyExt, Limited};
use ianua_domain::domains::proxy::request::body::ByteCap;
use ianua_domain::types::HttpUrl;

use super::client::RequestBody;
use super::error::ForwardError;
use super::headers::{self, Hop};
use super::target::ForwardTarget;

/// Refuses a request whose declared body is longer than `limit`.
///
/// # Errors
///
/// - [`ForwardError::RequestTooLarge`] when `Content-Length` is past it.
pub(super) fn ensure_within(headers: &HeaderMap, limit: ByteCap) -> Result<(), ForwardError> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit.get()) {
        return Err(ForwardError::RequestTooLarge);
    }
    Ok(())
}

/// `request` addressed to `backend` as `target` says.
///
/// # Errors
///
/// - [`ForwardError::InvalidAddress`] when the backend, path and query
///   make no valid address.
pub(super) fn request(
    request: Request<RequestBody>,
    target: &ForwardTarget,
    backend: &HttpUrl,
    hop: Hop,
) -> Result<Request<RequestBody>, ForwardError> {
    let path = path_and_query(&target.path, request.uri().query());
    let uri = uri_of(backend, &path).map_err(ForwardError::InvalidAddress)?;
    let (mut parts, body) = request.into_parts();
    headers::prepare_request(&mut parts.headers, hop);
    let client_host = target.client_host.as_ref();
    headers::set_host(
        &mut parts.headers,
        target.pool.host_header(),
        client_host,
        &uri,
    );
    parts.uri = uri;
    parts.version = Version::HTTP_11;
    parts.extensions = Extensions::new();
    Ok(Request::from_parts(parts, limited(body, target.body_limit)))
}

/// `body`, failing once it streams past `limit` and before the frame that
/// crosses it is passed on.
fn limited(body: RequestBody, limit: ByteCap) -> RequestBody {
    let most = usize::try_from(limit.get()).unwrap_or(usize::MAX);
    Limited::new(body, most).boxed()
}

/// The route's `path` with the request's `query`, when it has one.
fn path_and_query(path: &str, query: Option<&str>) -> String {
    let Some(query) = query else {
        return path.to_owned();
    };
    format!("{path}?{query}")
}

/// The address of `path` on `base`, which may carry a path of its own.
///
/// # Errors
///
/// - [`http::Error`] when the two make no valid address.
pub(super) fn uri_of(base: &HttpUrl, path: &str) -> Result<Uri, http::Error> {
    let joined = format!("{}{}", base.as_str().trim_end_matches('/'), path);
    joined.parse::<Uri>().map_err(http::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> HttpUrl {
        HttpUrl::new(text).unwrap()
    }

    fn cap(bytes: u64) -> ByteCap {
        ByteCap::new(bytes).unwrap()
    }

    #[test]
    fn the_path_is_joined_to_the_backend() {
        let uri = uri_of(&url("http://10.0.0.5:8080/"), "/orders?page=2").unwrap();

        assert_eq!(uri.to_string(), "http://10.0.0.5:8080/orders?page=2");
    }

    #[test]
    fn a_backend_with_a_base_path_keeps_it() {
        let uri = uri_of(&url("https://api.internal/v2"), "/orders").unwrap();

        assert_eq!(uri.to_string(), "https://api.internal/v2/orders");
    }

    /// The route's rewrite carries no query; the request's own is kept.
    #[test]
    fn the_request_query_follows_the_rewritten_path() {
        assert_eq!(
            path_and_query("/v1/orders", Some("page=2")),
            "/v1/orders?page=2"
        );
        assert_eq!(path_and_query("/v1/orders", None), "/v1/orders");
    }

    #[test]
    fn a_declared_body_past_the_limit_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "2048".parse().unwrap());

        assert!(matches!(
            ensure_within(&headers, cap(1_024)),
            Err(ForwardError::RequestTooLarge)
        ));
        assert!(ensure_within(&headers, cap(2_048)).is_ok());
        assert!(ensure_within(&HeaderMap::new(), cap(1)).is_ok());
    }
}
