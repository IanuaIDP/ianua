//! The host a request was sent to, read from the one place it names it.
//!
//! HTTP/2 names the host in `:authority`, which hyper puts on the URI;
//! HTTP/1.1 in `Host`, or in an absolute URI. A request naming it in both
//! must name the same host in both, and `Host` sent twice is refused: two
//! readings of the host are two readings of the tenant.

use std::str::FromStr;

use http::header::HOST;
use http::request::Parts;
use http::uri::Authority;
use ianua_domain::types::DomainName;

/// The host a request was sent to: a domain name, lower case, without a
/// port or a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RequestHost(DomainName);

impl RequestHost {
    /// A host named by `name`, which the TLS handshake or a test already
    /// read as a domain name.
    ///
    /// # Errors
    ///
    /// - [`HostRefusal::Malformed`] when `name` is a wildcard: a request is
    ///   sent to one host, never to a pattern.
    pub(crate) fn new(name: DomainName) -> Result<Self, HostRefusal> {
        if name.is_wildcard() {
            return Err(HostRefusal::Malformed);
        }
        Ok(Self(name))
    }

    /// The host as a domain name.
    #[must_use]
    pub(crate) fn name(&self) -> &DomainName {
        &self.0
    }

    /// The host as text.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Why a request's host could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HostRefusal {
    /// The request names no host at all.
    #[error("the request names no host")]
    Missing,
    /// `Host` is sent more than once.
    #[error("the request names its host more than once")]
    Repeated,
    /// `:authority` or the absolute URI names one host and `Host` another.
    #[error("the request names two different hosts")]
    Conflicting,
    /// The host is an address, a wildcard, carries user information, or is
    /// not a domain name at all.
    #[error("the request's host is not a domain name")]
    Malformed,
}

/// The host `parts` was sent to.
///
/// # Errors
///
/// - [`HostRefusal::Missing`] when neither the URI nor `Host` names one.
/// - [`HostRefusal::Repeated`] when `Host` is sent twice.
/// - [`HostRefusal::Conflicting`] when the URI and `Host` disagree.
/// - [`HostRefusal::Malformed`] when either is not a domain name.
pub(crate) fn request_host(parts: &Parts) -> Result<RequestHost, HostRefusal> {
    let from_uri = parts.uri.authority().map(host_of).transpose()?;
    let from_header = header_host(parts)?;
    match (from_uri, from_header) {
        (None, None) => Err(HostRefusal::Missing),
        (Some(host), None) | (None, Some(host)) => Ok(host),
        (Some(uri), Some(header)) if uri == header => Ok(uri),
        (Some(_), Some(_)) => Err(HostRefusal::Conflicting),
    }
}

/// The host the `Host` header names, if it is sent.
fn header_host(parts: &Parts) -> Result<Option<RequestHost>, HostRefusal> {
    let mut sent = parts.headers.get_all(HOST).iter();
    let Some(first) = sent.next() else {
        return Ok(None);
    };
    if sent.next().is_some() {
        return Err(HostRefusal::Repeated);
    }
    let text = first.to_str().map_err(|_| HostRefusal::Malformed)?;
    parse_host(text).map(Some)
}

/// The host a `Host` value names.
fn parse_host(text: &str) -> Result<RequestHost, HostRefusal> {
    let authority = Authority::from_str(text).map_err(|_| HostRefusal::Malformed)?;
    host_of(&authority)
}

/// The domain name an authority names, without its port.
fn host_of(authority: &Authority) -> Result<RequestHost, HostRefusal> {
    if authority.as_str().contains('@') {
        return Err(HostRefusal::Malformed);
    }
    let host = authority.host();
    let host = host.strip_suffix('.').unwrap_or(host);
    let name = DomainName::new(host).map_err(|_| HostRefusal::Malformed)?;
    RequestHost::new(name)
}

#[cfg(test)]
mod tests {
    use http::Request;
    use proptest::prelude::*;

    use super::*;

    fn parts(build: http::request::Builder) -> Parts {
        build.body(()).unwrap().into_parts().0
    }

    fn host(text: &str) -> Result<String, HostRefusal> {
        parse_host(text).map(|host| host.as_str().to_owned())
    }

    #[test]
    fn a_host_is_read_lower_case_without_its_port_or_trailing_dot() {
        assert_eq!(host("Shop.Acme.COM").unwrap(), "shop.acme.com");
        assert_eq!(host("shop.acme.com:8443").unwrap(), "shop.acme.com");
        assert_eq!(host("shop.acme.com.").unwrap(), "shop.acme.com");
    }

    /// A single label, an IPv6 address, a wildcard or user information
    /// names no tenant's domain, so it is refused rather than looked up.
    #[test]
    fn what_is_not_a_domain_name_is_refused() {
        for text in [
            "localhost",
            "[::1]:443",
            "*.acme.com",
            "ann@shop.acme.com",
            "",
            "a b",
        ] {
            assert_eq!(host(text), Err(HostRefusal::Malformed), "{text:?}");
        }
    }

    /// HTTP/2 names the host in `:authority`, which reaches the URI.
    #[test]
    fn the_authority_names_the_host_without_a_host_header() {
        let request = parts(Request::get("https://shop.acme.com/orders"));

        assert_eq!(request_host(&request).unwrap().as_str(), "shop.acme.com");
    }

    #[test]
    fn the_authority_and_host_may_name_the_same_host() {
        let request =
            parts(Request::get("https://shop.acme.com/").header("host", "SHOP.acme.com:443"));

        assert_eq!(request_host(&request).unwrap().as_str(), "shop.acme.com");
    }

    /// A URI naming Ann's host with a Host header naming Eve's is rejected
    /// as conflicting rather than selecting either tenant.
    #[test]
    fn two_different_hosts_are_refused() {
        let request = parts(Request::get("https://ann.acme.com/").header("host", "eve.acme.com"));

        assert_eq!(request_host(&request), Err(HostRefusal::Conflicting));
    }

    #[test]
    fn a_host_header_sent_twice_is_refused() {
        let request = parts(
            Request::get("/")
                .header("host", "ann.acme.com")
                .header("host", "ann.acme.com"),
        );

        assert_eq!(request_host(&request), Err(HostRefusal::Repeated));
    }

    proptest! {
        /// Any `Host` value either fails or reads as a lower-case domain
        /// name with no port, never panicking.
        #[test]
        fn a_read_host_is_always_a_bare_lower_case_name(text in "[ -~]{0,40}") {
            if let Ok(read) = parse_host(&text) {
                prop_assert!(!read.as_str().contains([':', '@', '*', '[']));
                prop_assert_eq!(read.as_str(), read.as_str().to_ascii_lowercase());
            }
        }
    }
}
