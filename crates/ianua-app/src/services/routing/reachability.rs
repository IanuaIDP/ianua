//! SSRF guard for tenant-configured route upstreams.

use std::net::IpAddr;

use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::stream::StreamBackend;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

/// Rejects an upstream whose primary URL or any weighted backend targets an
/// internal address outside the networks the operator allows.
///
/// Only the operator sets `networks`; tenants cannot open the deployment's
/// private network to their routes. IP literals and internal-only names are
/// screened here. Resolved addresses are screened again at connection time.
///
/// # Errors
///
/// Returns `DomainError::Validation` if any target URL is a refused IP literal
/// or internal name.
pub(crate) fn reject_private_upstream(
    upstream: &Upstream,
    networks: &UpstreamNetworks,
) -> Result<(), DomainError> {
    for target in upstream.all_target_urls() {
        networks.check_url(target, "upstream.url")?;
    }
    Ok(())
}

/// Rejects a stream backend on an internal address outside the networks the
/// operator allows.
///
/// Like [`reject_private_upstream`], this protects the deployment's network
/// from tenant-selected destinations. Hosts are parsed as bare IP addresses:
/// parsing `::1` as a URL authority would mistake its final segment for a port.
///
/// # Errors
///
/// Returns `DomainError::Validation` if any backend host is a refused IP
/// literal.
pub(crate) fn reject_private_stream_backends(
    backends: &[StreamBackend],
    networks: &UpstreamNetworks,
) -> Result<(), DomainError> {
    for ip in backends.iter().filter_map(address_of) {
        networks.check_ip(ip, "backend.host")?;
    }
    Ok(())
}

/// The address `backend` dials, when its host is written as one rather than
/// as a name to resolve.
fn address_of(backend: &StreamBackend) -> Option<IpAddr> {
    backend.host().as_str().parse().ok()
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::routing::backend::upstream::{
        HostHeader, UpstreamTimeout, WeightedBackend,
    };
    use ianua_domain::types::HttpUrl;

    use super::*;

    fn backend(host: &str) -> StreamBackend {
        StreamBackend::new(host, 5432, 1).unwrap()
    }

    fn public_only() -> UpstreamNetworks {
        UpstreamNetworks::public_only()
    }

    fn allowing(list: &str) -> UpstreamNetworks {
        UpstreamNetworks::parse_list(list).unwrap()
    }

    fn url(s: &str) -> HttpUrl {
        HttpUrl::new(s).unwrap()
    }

    fn upstream(target: &str) -> Upstream {
        Upstream::new(url(target), thirty_seconds(), HostHeader::Rewrite)
    }

    fn thirty_seconds() -> UpstreamTimeout {
        UpstreamTimeout::seconds(30).unwrap()
    }

    fn weighted(target: &str, weight: u32) -> WeightedBackend {
        WeightedBackend::new(url(target), NonZeroU32::new(weight).unwrap())
    }

    /// Ann points a stream route at a database by its public name, and it is
    /// accepted.
    #[test]
    fn allows_a_public_stream_backend() {
        assert!(
            reject_private_stream_backends(&[backend("db.example.com")], &public_only()).is_ok()
        );
    }

    /// A loopback stream backend is rejected when only public networks
    /// are allowed.
    #[test]
    fn rejects_a_loopback_stream_backend() {
        assert!(reject_private_stream_backends(&[backend("127.0.0.1")], &public_only()).is_err());
    }

    /// The metadata address cannot be used as a stream backend under the
    /// public-only policy.
    #[test]
    fn rejects_the_metadata_service_as_a_stream_backend() {
        assert!(
            reject_private_stream_backends(&[backend("169.254.169.254")], &public_only()).is_err()
        );
    }

    /// Bare IPv6 loopback, unique-local and link-local addresses are all
    /// rejected as stream backends under the public-only policy.
    #[test]
    fn rejects_a_private_ipv6_stream_backend() {
        for host in ["::1", "fc00::1", "fe80::1"] {
            assert!(
                reject_private_stream_backends(&[backend(host)], &public_only()).is_err(),
                "{host}"
            );
        }
    }

    /// Bracketed IPv6 is rejected by the backend constructor before the
    /// reachability guard is called.
    #[test]
    fn a_bracketed_host_is_refused_before_the_guard_sees_it() {
        assert!(StreamBackend::new("[::1]", 5432, 1).is_err());
    }

    /// Ann points a stream route at a public IPv6 address, and it is
    /// accepted.
    #[test]
    fn allows_a_public_ipv6_stream_backend() {
        assert!(reject_private_stream_backends(&[backend("2001:db8::1")], &public_only()).is_ok());
    }

    /// One private address makes the stream backend set fail validation,
    /// even when another backend has a public hostname.
    #[test]
    fn rejects_when_only_one_backend_is_private() {
        let backends = [backend("db.example.com"), backend("10.0.0.5")];

        assert!(reject_private_stream_backends(&backends, &public_only()).is_err());
    }

    /// Ann's operator allows `10.0.0.0/8`, so her stream route may reach a
    /// database there.
    #[test]
    fn an_allowed_network_admits_a_private_stream_backend() {
        assert!(
            reject_private_stream_backends(&[backend("10.0.0.5")], &allowing("10.0.0.0/8")).is_ok()
        );
    }

    /// Allowing every IPv4 network still leaves the metadata address
    /// forbidden as a stream backend.
    #[test]
    fn an_allowed_network_still_refuses_the_metadata_service_as_a_stream_backend() {
        assert!(
            reject_private_stream_backends(&[backend("169.254.169.254")], &allowing("0.0.0.0/0"))
                .is_err()
        );
    }

    /// Ann points a route at a host by name; names are screened once they
    /// resolve, so it is accepted here.
    #[test]
    fn allows_a_public_hostname() {
        assert!(
            reject_private_upstream(&upstream("https://api.example.com:8080"), &public_only())
                .is_ok()
        );
    }

    /// An HTTP upstream using a loopback literal fails the public-only
    /// reachability check.
    #[test]
    fn rejects_a_loopback_literal() {
        assert!(
            reject_private_upstream(&upstream("http://127.0.0.1:8080"), &public_only()).is_err()
        );
    }

    /// HTTP access to the metadata address is rejected by the upstream
    /// reachability guard.
    #[test]
    fn rejects_the_metadata_service() {
        let target = upstream("http://169.254.169.254/latest/meta-data/");

        assert!(reject_private_upstream(&target, &public_only()).is_err());
    }

    /// A private backend with only a tenth of the weight still causes
    /// rejection, despite the public primary URL and other backend.
    #[test]
    fn rejects_a_blocked_canary_backend_even_when_the_primary_is_public() {
        let target = Upstream::with_backends(
            url("https://api.example.com"),
            thirty_seconds(),
            HostHeader::Rewrite,
            vec![
                weighted("https://api.example.com", 90),
                weighted("http://10.0.0.5:8080", 10),
            ],
        );

        assert!(reject_private_upstream(&target, &public_only()).is_err());
    }

    /// Ann's operator allows `10.0.0.0/8`, so her route may reach an app
    /// there.
    #[test]
    fn an_allowed_network_admits_a_private_literal() {
        let target = upstream("http://10.0.0.5:8080");

        assert!(reject_private_upstream(&target, &allowing("10.0.0.0/8")).is_ok());
    }

    /// Allowing `10.0.0.0/8` does not permit an upstream in
    /// `192.168.0.0/16`; that target remains rejected.
    #[test]
    fn an_allowed_network_leaves_other_private_literals_refused() {
        let target = upstream("http://192.168.1.10:8080");

        assert!(reject_private_upstream(&target, &allowing("10.0.0.0/8")).is_err());
    }

    /// The metadata URL remains forbidden even with every IPv4 network
    /// listed as allowed.
    #[test]
    fn an_allowed_network_still_refuses_the_metadata_service() {
        let target = upstream("http://169.254.169.254/latest/meta-data/");

        assert!(reject_private_upstream(&target, &allowing("0.0.0.0/0")).is_err());
    }
}
