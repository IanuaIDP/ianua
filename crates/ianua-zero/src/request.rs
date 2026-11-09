//! What the gateway reads off an inbound request before it asks anyone
//! anything: the headers it owns stripped, the host, method and path, the
//! credential presented, and as much of the body as the pipeline needs.
//!
//! [`admit`] is the first thing the handler calls. It strips every header
//! the proxy owns before anything else reads the request, so a value a
//! client typed into `X-Forwarded-User` or `X-Ianua-Assertion` never reaches
//! a stage, a route condition or an upstream, and every header the client
//! names in its `Connection` header, which describes its own hop. What it
//! cannot read cleanly it refuses: a request whose host, method or path
//! has two readings is never guessed at.
//!
//! [`strip_credentials`] runs on what is forwarded. No route setting asks
//! for the caller's credential to be passed on, so it never is: the
//! upstream learns who the caller is from the signed assertion alone.

mod body;
mod cookies;
mod credentials;
mod headers;
mod host;
mod method;
mod origin;
mod path;
mod values;

pub(crate) use body::{BodyRead, PeekError, PrefixThenBody, peek};
pub(crate) use cookies::{
    APP_CHALLENGE_COOKIE, APP_CSRF_COOKIE, APP_DEVICE_COOKIE, APP_HOP_COOKIE, APP_SESSION_COOKIE,
    APP_SINGLE_SIGN_ON_COOKIE, CookieRead, read as read_cookie,
};
pub(crate) use credentials::{
    CredentialRefusal, ListenerRole, Scheme, SessionCookies, dpop, presented, run_pass, target,
};
pub(crate) use headers::{strip_connection_named, strip_credentials, strip_proxy_owned};
pub(crate) use host::{HostRefusal, RequestHost};
use http::request::Parts;
use ianua_domain::types::{CanonicalPath, HttpMethod};
pub(crate) use values::RequestHeaders;

/// A request the gateway can read: one host, a method it knows, and a path
/// in its one canonical spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admitted {
    host: RequestHost,
    method: HttpMethod,
    path: CanonicalPath,
}

impl Admitted {
    /// The host the request was sent to, without a port.
    #[must_use]
    pub(crate) fn host(&self) -> &RequestHost {
        &self.host
    }

    /// The method it was sent with.
    #[must_use]
    pub(crate) fn method(&self) -> HttpMethod {
        self.method
    }

    /// Its path, decoded once and canonical, the spelling routes and policy
    /// compare.
    #[must_use]
    pub(crate) fn path(&self) -> &CanonicalPath {
        &self.path
    }
}

/// Why a request could not be read. Each is a bad request, answered
/// without saying more than this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RequestRefusal {
    /// The host is missing, repeated, contradicted or not a domain name.
    #[error(transparent)]
    Host(#[from] HostRefusal),
    /// The method is not one the gateway knows.
    #[error("the request's method is not one the gateway serves")]
    Method,
    /// The path has no canonical spelling: a dot segment, an encoded slash,
    /// a double encoding or anything else an upstream could read otherwise.
    #[error("the request's path has no canonical spelling")]
    Path,
}

/// Strips the headers the proxy owns and the ones the client names in its
/// `Connection` header, then reads the request's host, method and path.
///
/// The stripping comes first and happens whatever follows, so a request
/// refused here has already lost the headers a client must not set.
///
/// # Errors
///
/// - [`RequestRefusal::Host`] when the host is missing, sent twice, differs
///   between `:authority` and `Host`, or is not a domain name.
/// - [`RequestRefusal::Method`] for a method the gateway does not know.
/// - [`RequestRefusal::Path`] when the path has no canonical spelling.
pub(crate) fn admit(parts: &mut Parts) -> Result<Admitted, RequestRefusal> {
    strip_proxy_owned(&mut parts.headers);
    strip_connection_named(&mut parts.headers);
    let host = host::request_host(parts)?;
    let method = method::request_method(&parts.method).ok_or(RequestRefusal::Method)?;
    let path = path::request_path(&parts.uri).ok_or(RequestRefusal::Path)?;
    Ok(Admitted { host, method, path })
}

#[cfg(test)]
mod tests {
    use http::Request;

    use super::*;

    fn parts(build: http::request::Builder) -> Parts {
        build.body(()).unwrap().into_parts().0
    }

    /// Admission removes client-supplied identity, assertion and forwarded
    /// address headers while retaining an unrelated request ID.
    #[test]
    fn a_proxy_owned_header_a_client_sent_is_gone_once_admitted() {
        let mut inbound = parts(
            Request::get("/orders")
                .header("host", "shop.acme.com")
                .header("x-forwarded-user", "ann")
                .header("X-Ianua-Assertion", "forged")
                .header("x_forwarded_for", "10.0.0.1")
                .header("x-request-id", "kept"),
        );

        admit(&mut inbound).unwrap();

        assert!(inbound.headers.get("x-forwarded-user").is_none());
        assert!(inbound.headers.get("x-ianua-assertion").is_none());
        assert!(inbound.headers.get("x_forwarded_for").is_none());
        assert_eq!(inbound.headers["x-request-id"], "kept");
    }

    /// Admission removes a request ID named in Connection while retaining
    /// the Connection field for the forwarder.
    #[test]
    fn a_header_the_client_names_in_connection_is_gone_once_admitted() {
        let mut inbound = parts(
            Request::get("/orders")
                .header("host", "shop.acme.com")
                .header("connection", "x-request-id")
                .header("x-request-id", "abc"),
        );

        admit(&mut inbound).unwrap();

        assert!(inbound.headers.get("x-request-id").is_none());
        assert_eq!(inbound.headers["connection"], "x-request-id");
    }

    /// A request refused for its path has still lost the owned headers, so
    /// whatever answers the refusal never sees them.
    #[test]
    fn a_refused_request_is_stripped_too() {
        let mut inbound = parts(
            Request::get("/a/%2e%2e/admin")
                .header("host", "shop.acme.com")
                .header("x-forwarded-user", "ann"),
        );

        assert_eq!(admit(&mut inbound), Err(RequestRefusal::Path));
        assert!(inbound.headers.get("x-forwarded-user").is_none());
    }

    #[test]
    fn a_readable_request_is_admitted_with_its_canonical_path() {
        let mut inbound = parts(Request::post("/api//orders/").header("host", "Shop.Acme.com:443"));

        let admitted = admit(&mut inbound).unwrap();

        assert_eq!(admitted.host().as_str(), "shop.acme.com");
        assert_eq!(admitted.method(), HttpMethod::Post);
        assert_eq!(admitted.path().as_str(), "/api/orders");
    }

    /// `*` is how a route says "every method". As a request's own method it
    /// would match routes no real method does, so it is refused.
    #[test]
    fn a_method_the_gateway_does_not_know_is_refused() {
        for method in ["*", "PROPFIND", "TRACE"] {
            let mut inbound = parts(
                Request::builder()
                    .method(method)
                    .uri("/")
                    .header("host", "shop.acme.com"),
            );

            assert_eq!(admit(&mut inbound), Err(RequestRefusal::Method), "{method}");
        }
    }

    #[test]
    fn a_request_without_a_host_is_refused() {
        let mut inbound = parts(Request::get("/"));

        assert_eq!(
            admit(&mut inbound),
            Err(RequestRefusal::Host(HostRefusal::Missing))
        );
    }
}
