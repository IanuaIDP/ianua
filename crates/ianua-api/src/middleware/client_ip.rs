//! Who the request actually came from.
//!
//! The rule lives in the domain: see
//! [`ianua_domain::domains::proxy::request::forwarded`]: because the proxy has to
//! answer the same question about the same deployment, and two copies of a
//! trust boundary are one edit away from disagreeing. This is the adapter
//! over it: pulls the header off an axum request and hands it, with the
//! deployment's trusted proxies, to the rule.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
pub use ianua_domain::domains::proxy::request::forwarded::TrustedProxies;

/// Resolves the client address from the peer and the forwarding header.
#[must_use]
pub(crate) fn resolve(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted: &TrustedProxies,
) -> Option<IpAddr> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());

    Some(
        ianua_domain::domains::proxy::request::forwarded::client_address(
            peer?.ip(),
            forwarded,
            trusted,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Headers carrying this `X-Forwarded-For` value.
    fn headers_with(forwarded: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", forwarded.parse().unwrap());
        headers
    }

    /// The connecting peer at this address.
    fn peer(addr: &str) -> SocketAddr {
        format!("{addr}:443").parse().unwrap()
    }

    /// The trusted proxies this specification names.
    fn trusting(spec: &str) -> TrustedProxies {
        TrustedProxies::parse(spec)
    }

    /// An untrusted peer's forwarded header cannot replace its own address.
    #[test]
    fn an_untrusted_peer_cannot_name_someone_else() {
        let resolved = resolve(
            &headers_with("203.0.113.9"),
            Some(peer("198.51.100.7")),
            &TrustedProxies::default(),
        );

        assert_eq!(resolved, Some("198.51.100.7".parse().unwrap()));
    }

    /// A trusted proxy names the client in the header, and that client is
    /// the answer.
    #[test]
    fn a_trusted_proxy_is_believed() {
        let resolved = resolve(
            &headers_with("203.0.113.9"),
            Some(peer("10.0.0.1")),
            &trusting("10.0.0.1"),
        );

        assert_eq!(resolved, Some("203.0.113.9".parse().unwrap()));
    }

    /// A client can prepend entries to the header before it reaches our proxy,
    /// so the leftmost is theirs to choose. The rightmost non-proxy entry is
    /// the one our own proxy wrote.
    #[test]
    fn a_forged_prefix_does_not_win() {
        let resolved = resolve(
            &headers_with("1.2.3.4, 203.0.113.9"),
            Some(peer("10.0.0.1")),
            &trusting("10.0.0.1"),
        );

        assert_eq!(resolved, Some("203.0.113.9".parse().unwrap()));
    }

    /// A trusted proxy that sends no header is itself the client.
    #[test]
    fn a_trusted_proxy_with_no_header_is_itself_the_client() {
        let resolved = resolve(
            &HeaderMap::new(),
            Some(peer("10.0.0.1")),
            &trusting("10.0.0.1"),
        );

        assert_eq!(resolved, Some("10.0.0.1".parse().unwrap()));
    }

    /// The reason ranges exist. An in-cluster ingress is the peer, and its
    /// address changes on every rollout: pinning one would stop matching
    /// silently, and every client would be recorded as the ingress.
    #[test]
    fn a_proxy_inside_a_trusted_range_is_believed() {
        let resolved = resolve(
            &headers_with("203.0.113.9"),
            Some(peer("10.2.0.20")),
            &trusting("10.2.0.0/16"),
        );

        assert_eq!(resolved, Some("203.0.113.9".parse().unwrap()));
    }

    /// The range has to end somewhere, or it is not a boundary.
    #[test]
    fn an_address_outside_the_range_is_still_the_client() {
        let resolved = resolve(
            &headers_with("203.0.113.9"),
            Some(peer("10.3.0.20")),
            &trusting("10.2.0.0/16"),
        );

        assert_eq!(resolved, Some("10.3.0.20".parse().unwrap()));
    }

    /// A forwarded entry inside our own range is one of our hops, not the
    /// client: otherwise a second proxy in the chain becomes the answer.
    #[test]
    fn a_forwarded_entry_inside_the_range_is_skipped() {
        let resolved = resolve(
            &headers_with("203.0.113.9, 10.2.0.19"),
            Some(peer("10.2.0.20")),
            &trusting("10.2.0.0/16"),
        );

        assert_eq!(resolved, Some("203.0.113.9".parse().unwrap()));
    }

    /// One list can hold single addresses and ranges, with stray spaces and
    /// commas; addresses in neither are not trusted.
    #[test]
    fn addresses_and_ranges_mix() {
        let trusted = trusting("172.233.36.241, 10.2.0.0/16 , ");

        assert!(trusted.contains("172.233.36.241".parse().unwrap()));
        assert!(trusted.contains("10.2.0.20".parse().unwrap()));
        assert!(!trusted.contains("8.8.8.8".parse().unwrap()));
    }

    /// Trusting less than intended is recoverable; trusting more is not, so a
    /// malformed entry is dropped rather than widened or fatal.
    #[test]
    fn an_unparseable_entry_is_dropped() {
        let trusted = trusting("not-an-address, 10.2.0.0/16");

        assert!(trusted.contains("10.2.0.20".parse().unwrap()));
        assert!(!trusted.contains("8.8.8.8".parse().unwrap()));
    }

    /// An empty list, or one of only spaces and commas, trusts nobody.
    #[test]
    fn an_empty_specification_trusts_nothing() {
        assert!(trusting("").is_empty());
        assert!(trusting("  ,  ").is_empty());
    }
}
