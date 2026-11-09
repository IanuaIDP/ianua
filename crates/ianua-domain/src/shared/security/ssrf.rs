//! Address classification for URLs the platform will fetch on a tenant's
//! behalf.
//!
//! Such a URL can be a webhook target, a model provider's endpoint or an
//! identity provider's token endpoint. Each one makes the platform send a
//! request from inside the deployment's network. The metadata service and
//! every internal service live there. This module refuses URLs that name an
//! internal address outright.
//!
//! It only catches IP literals. A hostname that *resolves* to an internal
//! address is caught where DNS is available. The resolved address is checked
//! again before the connection is made. This module does no I/O and no DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::message;
use crate::shared::validation::{UrlHost, ValidationError};
use crate::types::{CidrRange, HttpUrl};

/// The internal networks an operator has put route upstreams in.
///
/// A route upstream makes the proxy connect somewhere on a tenant's behalf.
/// So by default it may only name a public address. That suits a deployment
/// serving tenants it does not control. A self-hosted deployment keeps its
/// apps on private networks, so the operator lists those networks here.
/// Nothing a tenant configures can add to the list.
///
/// Some addresses stay refused whatever is listed, because no real upstream
/// lives there:
/// - link-local, where every cloud keeps its instance credentials
/// - the known metadata and Azure WireServer addresses
/// - unspecified, multicast, broadcast and reserved addresses
/// - IPv6 forms that tunnel to an IPv4 address
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamNetworks(Vec<CidrRange>);

impl UpstreamNetworks {
    /// Upstreams may name only public addresses.
    #[must_use]
    pub fn public_only() -> Self {
        Self::default()
    }

    /// Upstreams may also name addresses inside `networks`.
    #[must_use]
    pub fn new(networks: Vec<CidrRange>) -> Self {
        Self(networks)
    }

    /// Reads a comma-separated list such as `10.0.0.0/8, 172.16.0.0/12`.
    ///
    /// Blank entries are skipped, so an empty string is [`Self::public_only`].
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] for the first entry that is not a CIDR range.
    pub fn parse_list(list: &str) -> Result<Self, ValidationError> {
        list.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(CidrRange::new)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Whether an upstream may connect to `ip`.
    #[must_use]
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if is_never_reachable(ip) {
            return false;
        }
        !is_blocked_ip(ip) || self.0.iter().any(|network| network.contains_addr(ip))
    }

    /// Refuses a URL whose host is an IP address this policy does not
    /// permit, or, where it permits no internal network, a name that can
    /// only be internal.
    ///
    /// Any other hostname passes here and is screened again once resolved.
    /// Refusing an internal name up front tells the person setting the
    /// upstream at once: `metadata.google.internal` would otherwise be
    /// accepted and only ever fail when a request is sent.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Custom`] when the host is a refused address or
    ///   internal name.
    pub fn check_url(&self, url: &HttpUrl, field: &'static str) -> Result<(), ValidationError> {
        match url.host() {
            UrlHost::Address(ip) => self.check_ip(ip, field),
            UrlHost::Name(name) if self.0.is_empty() && is_never_public(name) => {
                Err(internal_refused(field))
            }
            UrlHost::Name(_) => Ok(()),
        }
    }

    /// Refuses an address this policy does not permit.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Custom`] when `ip` is refused.
    pub fn check_ip(&self, ip: IpAddr, field: &'static str) -> Result<(), ValidationError> {
        if self.permits(ip) {
            return Ok(());
        }
        Err(internal_refused(field))
    }
}

/// The refusal of an upstream that targets an internal address.
fn internal_refused(field: &'static str) -> ValidationError {
    ValidationError::Custom {
        field,
        code: "ssrf_blocked".to_owned(),
        message: message!(
            "values-upstreams-may-not-target-an-internal",
            "upstreams may not target an internal address outside the networks this \
                  deployment allows."
        ),
    }
}

/// An IPv4-mapped IPv6 address as the IPv4 address it carries, so a listed
/// IPv4 network matches it and an IPv4 rule cannot be dodged by spelling.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Instance-metadata services that sit outside link-local: Alibaba Cloud's in
/// the carrier-grade NAT range, and AWS's IPv6 endpoint in unique-local space.
/// Listing either surrounding network must not open them.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// Azure's WireServer: the host agent every Azure machine reaches for its
/// configuration, extensions and certificates. It is a public address, so no
/// private-range check catches it.
const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);

/// Addresses no listed network can open.
fn is_never_reachable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, ..] = v4.octets();
            v4 == METADATA_V4
                || v4 == AZURE_WIRESERVER
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                || a >= 240
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let first = segments[0];
            v6 == METADATA_V6
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xffc0) == 0xfe80
                || (first == 0x0064 && segments[1] == 0xff9b)
                || first == 0x2002
                || (first == 0x2001 && segments[1] == 0)
                || (segments[..6].iter().all(|s| *s == 0) && !v6.is_loopback())
        }
    }
}

/// Whether an IP address points at infrastructure a tenant must not reach.
///
/// That covers private, loopback, link-local, unspecified, multicast and
/// reserved addresses. The full ranges are listed on `is_blocked_v4` and
/// `is_blocked_v6`.
#[must_use]
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| is_blocked_v6(v6), is_blocked_v4),
    }
}

/// Refuses a host that is an IP address in a blocked range.
///
/// `field` names the offending input so the caller sees which URL was
/// refused. A hostname passes here and is screened again after resolution.
///
/// # Errors
///
/// - [`ValidationError::Custom`] when the host is a blocked address.
pub(crate) fn reject_internal_host(
    host: UrlHost<'_>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let UrlHost::Address(ip) = host else {
        return Ok(());
    };
    if !is_blocked_ip(ip) {
        return Ok(());
    }

    Err(ValidationError::Custom {
        field,
        code: "ssrf_blocked".to_owned(),
        message: message!(
            "values-urls-may-not-target-private-loopback",
            "URLs may not target private, loopback, or link-local addresses."
        ),
    })
}

/// Blocked IPv4 ranges: RFC1918 private, loopback, link-local, broadcast,
/// unspecified, `0.0.0.0/8`, carrier-grade NAT (`100.64.0.0/10`, which holds
/// Alibaba Cloud's metadata address), benchmarking (`198.18.0.0/15`), IETF
/// protocol assignments (`192.0.0.0/24`), multicast, reserved
/// (`240.0.0.0/4`), and Azure's WireServer.
fn is_blocked_v4(addr: Ipv4Addr) -> bool {
    let [a, b, c, _] = addr.octets();
    addr == AZURE_WIRESERVER
        || addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_unspecified()
        || addr.is_multicast()
        || a == 0
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 198 && (b & 0xfe) == 18)
        || (a == 192 && b == 0 && c == 0)
        || a >= 240
}

/// Blocked IPv6 ranges: loopback, unspecified, multicast, unique-local
/// (`fc00::/7`), link-local (`fe80::/10`), and every form that carries an
/// IPv4 address a translator or tunnel would deliver to. Those are NAT64
/// (`64:ff9b::/96`), 6to4 (`2002::/16`), Teredo (`2001::/32`) and
/// IPv4-compatible (`::a.b.c.d`). They can name an internal IPv4 address in
/// a form the IPv4 check never sees, so they are all refused.
fn is_blocked_v6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    let first = segments[0];
    let ipv4_compatible = segments[..6].iter().all(|s| *s == 0);
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first == 0x0064 && segments[1] == 0xff9b)
        || first == 0x2002
        || (first == 0x2001 && segments[1] == 0)
        || ipv4_compatible
}

/// Suffixes no public DNS name ends in.
///
/// `.lan` is not reserved, but home and office routers hand it out and no
/// public registry sells it. `.home.arpa` is the one RFC 8375 sets aside for
/// home networks.
const INTERNAL_SUFFIXES: [&str; 7] = [
    ".internal",
    ".local",
    ".localhost",
    ".lan",
    ".home.arpa",
    ".svc",
    ".cluster.local",
];

/// Whether `name` can only ever name something inside a network: a single
/// label such as `localhost`, or one under a suffix kept for internal use,
/// such as `metadata.google.internal`, `nas.lan` or `db.svc.cluster.local`.
pub(crate) fn is_never_public(name: &str) -> bool {
    let lowered = name.trim_end_matches('.').to_ascii_lowercase();
    !lowered.contains('.')
        || INTERNAL_SUFFIXES
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback, private, link-local and unspecified address examples are
    /// classified as blocked outbound destinations in IPv4 and IPv6.
    #[test]
    fn blocks_private_loopback_linklocal() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
    }

    /// Shared, reserved and multicast addresses remain blocked, as do IPv6
    /// translation and tunnel forms that could conceal an internal IPv4 target.
    #[test]
    fn blocks_shared_reserved_and_embedded_addresses() {
        for ip in [
            "100.100.100.200",
            "100.64.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "0.1.2.3",
            "192.0.0.8",
            "224.0.0.1",
            "240.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "2001:0:4136:e378::1",
            "::169.254.169.254",
            "ff02::1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
    }

    /// Two public IPv4 addresses and a public IPv6 address are not blocked,
    /// so a real webhook target still works.
    #[test]
    fn public_addresses_are_not_blocked() {
        for ip in ["93.184.216.34", "8.8.8.8", "2606:2800:220:1::1"] {
            assert!(
                !is_blocked_ip(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    /// Mapped IPv6 notation does not let an IPv4 loopback address evade the
    /// blocked-address classification.
    #[test]
    fn blocks_ipv4_mapped_loopback() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    fn screened(url: &str) -> Result<(), ValidationError> {
        let url = HttpUrl::new(url).unwrap();
        reject_internal_host(url.host(), "endpoint")
    }

    /// Azure's WireServer is blocked in plain and mapped notation while its
    /// adjacent public address remains allowed.
    #[test]
    fn azure_wireserver_is_blocked() {
        assert!(is_blocked_ip("168.63.129.16".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:168.63.129.16".parse().unwrap()));
        assert!(!is_blocked_ip("168.63.129.17".parse().unwrap()));
    }

    /// Metadata-service URLs fail host screening over either HTTP or HTTPS.
    #[test]
    fn rejects_the_metadata_service_over_either_scheme() {
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/",
        ] {
            assert!(screened(url).is_err(), "{url}");
        }
    }

    /// An explicit port on a bracketed IPv6 loopback URL does not bypass host
    /// screening.
    #[test]
    fn rejects_a_bracketed_ipv6_loopback_with_a_port() {
        assert!(screened("http://[::1]:8080/v1").is_err());
    }

    /// `http://user@127.0.0.1/v1` never becomes an [`HttpUrl`], since a user
    /// name before the host is refused. It never reaches the address screen.
    #[test]
    fn a_url_with_credentials_is_not_a_url_at_all() {
        assert!(HttpUrl::new("http://user@127.0.0.1/v1").is_err());
    }

    fn networks(list: &str) -> UpstreamNetworks {
        UpstreamNetworks::parse_list(list).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// With no networks listed, a route upstream may still name a public
    /// address.
    #[test]
    fn public_only_permits_a_public_address() {
        assert!(UpstreamNetworks::public_only().permits(ip("93.184.216.34")));
    }

    /// A private IPv4 target is denied when the deployment has not allowed
    /// any internal upstream networks.
    #[test]
    fn public_only_refuses_a_private_address() {
        assert!(!UpstreamNetworks::public_only().permits(ip("10.0.0.5")));
    }

    /// An operator lists `10.0.0.0/8` and `172.16.0.0/12`. Routes may then
    /// name 10.42.0.7 and 172.30.0.130.
    #[test]
    fn a_listed_network_permits_the_addresses_inside_it() {
        let allowed = networks("10.0.0.0/8, 172.16.0.0/12");

        assert!(allowed.permits(ip("10.42.0.7")));
        assert!(allowed.permits(ip("172.30.0.130")));
    }

    /// An operator lists only `10.0.0.0/8`. An address in 192.168.0.0/16
    /// stays refused.
    #[test]
    fn a_listed_network_leaves_other_private_networks_refused() {
        assert!(!networks("10.0.0.0/8").permits(ip("192.168.1.10")));
    }

    /// With `10.0.0.0/8` listed, `::ffff:10.0.0.5` is permitted too. It is
    /// the same address in IPv6 spelling.
    #[test]
    fn a_listed_ipv4_network_matches_its_ipv4_mapped_spelling() {
        assert!(networks("10.0.0.0/8").permits(ip("::ffff:10.0.0.5")));
    }

    /// Allowing all IPv4 and IPv6 networks still excludes metadata services,
    /// link-local targets and alternate encodings of those protected addresses.
    #[test]
    fn no_listed_network_opens_a_metadata_service() {
        let everything = networks("0.0.0.0/0, ::/0");

        for target in [
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "::ffff:168.63.129.16",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "::169.254.169.254",
        ] {
            assert!(
                !everything.permits(ip(target)),
                "{target} must stay refused"
            );
        }
    }

    /// With every network listed, the unspecified, multicast, broadcast and
    /// reserved addresses stay refused. No real upstream lives at them.
    #[test]
    fn no_listed_network_opens_unspecified_multicast_or_broadcast() {
        let everything = networks("0.0.0.0/0, ::/0");

        for target in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::",
            "ff02::1",
        ] {
            assert!(
                !everything.permits(ip(target)),
                "{target} must stay refused"
            );
        }
    }

    /// A self-hosted operator lists `127.0.0.0/8` and `::1/128` for apps on
    /// the same machine. Both loopback addresses are then permitted.
    #[test]
    fn listing_loopback_permits_it() {
        let allowed = networks("127.0.0.0/8, ::1/128");

        assert!(allowed.permits(ip("127.0.0.1")));
        assert!(allowed.permits(ip("::1")));
    }

    /// A list of only a space and a comma has no entries, so it is the same
    /// as public only.
    #[test]
    fn an_empty_list_is_public_only() {
        assert_eq!(networks(" , "), UpstreamNetworks::public_only());
    }

    /// A list with `not-a-network` after a valid range is refused whole. The
    /// good entry is not kept on its own.
    #[test]
    fn a_malformed_entry_is_refused() {
        assert!(UpstreamNetworks::parse_list("10.0.0.0/8, not-a-network").is_err());
    }

    /// With `10.0.0.0/8` listed, an upstream URL at 192.168.1.10 is refused.
    #[test]
    fn check_url_refuses_a_private_literal_outside_the_list() {
        assert!(
            networks("10.0.0.0/8")
                .check_url(
                    &HttpUrl::new("http://192.168.1.10:8080/").unwrap(),
                    "upstream.url"
                )
                .is_err()
        );
    }

    /// With `10.0.0.0/8` listed, an upstream URL at 10.0.0.5 with a port
    /// passes.
    #[test]
    fn check_url_admits_a_literal_inside_the_list() {
        assert!(
            networks("10.0.0.0/8")
                .check_url(
                    &HttpUrl::new("http://10.0.0.5:8080/").unwrap(),
                    "upstream.url"
                )
                .is_ok()
        );
    }

    /// Without an allowed internal network, URL screening rejects metadata,
    /// localhost and cluster-service names before DNS resolution.
    #[test]
    fn check_url_refuses_an_internal_name_when_no_network_is_allowed() {
        for url in [
            "http://metadata.google.internal/",
            "http://localhost:8080/",
            "http://db.svc.cluster.local/",
        ] {
            let url = HttpUrl::new(url).unwrap();

            assert!(
                UpstreamNetworks::public_only()
                    .check_url(&url, "upstream")
                    .is_err()
            );
        }
    }

    /// A deployment that allows an internal network reaches its services by
    /// their internal names; the address they resolve to is screened then.
    #[test]
    fn check_url_admits_an_internal_name_when_a_network_is_allowed() {
        let url = HttpUrl::new("http://api.svc.cluster.local/").unwrap();

        assert!(networks("10.0.0.0/8").check_url(&url, "upstream").is_ok());
    }

    proptest::proptest! {
        /// An operator lists `169.254.0.0` at any prefix plus every IPv4
        /// address. Every 169.254 address stays refused.
        #[test]
        fn link_local_is_never_permitted(c in 0u8..=255, d in 0u8..=255, prefix in 0u8..=16) {
            let listed = networks(&format!("169.254.0.0/{prefix}, 0.0.0.0/0"));
            proptest::prop_assert!(!listed.permits(IpAddr::V4(Ipv4Addr::new(169, 254, c, d))));
        }

        /// For any IPv4 address, a policy with nothing listed permits it
        /// exactly when [`is_blocked_ip`] does not block it.
        #[test]
        fn public_only_matches_the_public_check(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let addr = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            proptest::prop_assert_eq!(UpstreamNetworks::public_only().permits(addr), !is_blocked_ip(addr));
        }
    }

    /// A model provider hostname, an identity provider hostname and a public
    /// address pass. Hostnames are screened again once they resolve.
    #[test]
    fn admits_hostnames_and_public_literals() {
        for url in [
            "https://api.openai.com/v1",
            "http://93.184.216.34/v1",
            "https://idp.example.com/token",
        ] {
            assert!(screened(url).is_ok(), "{url}");
        }
    }
}
