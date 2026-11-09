//! Who the request came from, and what the upstream is told about it.
//!
//! Two halves of one question. Inbound, `X-Forwarded-For` is written by
//! whoever is speaking to us. Believing it blindly lets an attacker pick the
//! address in the audit record and the bucket in the rate limiter. Outbound,
//! the upstream needs the client's address and scheme and cannot see them
//! itself. So the proxy tells it. That is only worth anything because the
//! inbound copy was stripped first.
//!
//! The rule is: **the peer decides.** If the peer is not a proxy we put there,
//! the peer *is* the client and the header is ignored. If it is, the client is
//! the rightmost forwarded entry that is not itself one of ours. That is the
//! address our own proxy saw, and the last one an outsider could not have
//! added.

use std::net::{IpAddr, SocketAddr};

use crate::domains::proxy::stages::decision::HeaderEntry;
use crate::shared::validation::ValidationError;
use crate::types::network::in_block;
use crate::types::{HeaderName, HeaderValue};

/// The scheme the client used to reach the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientScheme {
    /// Plain HTTP.
    Http,
    /// TLS, terminated here.
    Https,
}

impl ClientScheme {
    /// The value `X-Forwarded-Proto` carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// One trusted range: a network address and how many of its bits are fixed.
#[derive(Debug, Clone, Copy)]
struct Block {
    network: IpAddr,
    prefix: u8,
}

impl Block {
    /// Whether `ip` falls inside this block. A v4 block never contains a
    /// v6 address, nor the reverse.
    fn contains(self, ip: IpAddr) -> bool {
        in_block(self.network, self.prefix, ip)
    }
}

/// The proxies whose `X-Forwarded-For` we believe.
///
/// An entry is one address or a CIDR block. A deployment behind an in-cluster
/// ingress needs the block form. There the peer is a pod, and a pod takes a
/// new address every time it restarts. Naming the proxy by address would stop
/// matching on the next rollout, and every client would be recorded as the
/// proxy.
///
/// Parsed once, at construction. Both the proxy and the control plane ask it
/// on every request, so parsing the text each time would cost on every
/// request.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Block>);

impl TrustedProxies {
    /// Reads a comma-separated list of addresses and CIDR blocks.
    ///
    /// Unparseable entries are dropped instead of failing. Trusting less than
    /// intended is the safe way to be wrong, never trusting more. Unset or
    /// empty trusts nobody, so the peer is always the client.
    #[must_use]
    pub fn parse(spec: &str) -> Self {
        Self(
            spec.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .filter_map(as_range)
                .collect(),
        )
    }

    /// Trusts nobody.
    #[must_use]
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// Whether `ip` is one of our proxies.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|block| block.contains(ip))
    }

    /// Whether no proxy is trusted at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One entry, as a block. A bare address becomes a single-host block.
fn as_range(entry: &str) -> Option<Block> {
    let Some((network, prefix)) = entry.split_once('/') else {
        let network: IpAddr = entry.parse().ok()?;
        let prefix = if network.is_ipv4() { 32 } else { 128 };
        return Some(Block { network, prefix });
    };

    let network: IpAddr = network.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let widest = if network.is_ipv4() { 32 } else { 128 };

    (prefix <= widest).then_some(Block { network, prefix })
}

/// The address the request actually came from.
///
/// `forwarded_for` is the raw header, if any. Returns `peer` whenever the
/// header must not be believed, which is every case except a trusted peer
/// naming an address that is not itself one of ours.
#[must_use]
pub fn client_address(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &TrustedProxies,
) -> IpAddr {
    if !trusted.contains(peer) {
        return peer;
    }

    forwarded_client(forwarded_for, trusted).unwrap_or(peer)
}

/// The rightmost forwarded entry that is not one of our own proxies.
///
/// Walks right to left, through our own proxies, and stops at the first
/// entry it cannot read. Skipping it would mean believing whatever sits
/// further left, which the client wrote. Stopping falls back to the peer.
fn forwarded_client(forwarded_for: Option<&str>, trusted: &TrustedProxies) -> Option<IpAddr> {
    for entry in forwarded_for?.split(',').rev() {
        let ip = forwarded_entry(entry.trim())?;
        if !trusted.contains(ip) {
            return Some(ip);
        }
    }
    None
}

/// The address one forwarded entry names: a bare address, `ip:port`, `[v6]`
/// or `[v6]:port`, with any `%zone` dropped.
fn forwarded_entry(entry: &str) -> Option<IpAddr> {
    let unbracketed = entry
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(entry);
    let unzoned = unbracketed.split('%').next().unwrap_or(unbracketed);
    unzoned
        .parse::<IpAddr>()
        .ok()
        .or_else(|| entry.parse::<SocketAddr>().ok().map(|socket| socket.ip()))
}

/// What the proxy tells the upstream about the client.
///
/// Each of these headers is one [`is_proxy_owned`] refuses to a tenant
/// transform, and the proxy strips it from every inbound request. That is
/// why the upstream can trust them. They say what the proxy saw, not what a
/// client typed.
///
/// [`is_proxy_owned`]: crate::shared::web::proxy_headers::is_proxy_owned
///
/// # Errors
///
/// - [`ValidationError`] when `host`, which the client sent, is not a value
///   a header may carry.
pub fn forwarded_headers(
    client: IpAddr,
    scheme: ClientScheme,
    host: &str,
) -> Result<Vec<HeaderEntry>, ValidationError> {
    Ok(vec![
        header("x-forwarded-for", client.to_string())?,
        header("x-forwarded-proto", scheme.as_str())?,
        header("x-forwarded-host", host)?,
        header("forwarded", forwarded_value(client, scheme, host))?,
    ])
}

/// The RFC 7239 `Forwarded` value for what the proxy observed: the client
/// address, bracketed and quoted when it is IPv6, the scheme, and the host as
/// a quoted string.
fn forwarded_value(client: IpAddr, scheme: ClientScheme, host: &str) -> String {
    let node = match client {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{v6}]\""),
    };
    let quoted_host: String = host
        .chars()
        .flat_map(|c| match c {
            '"' | '\\' => vec!['\\', c],
            _ => vec![c],
        })
        .collect();
    format!(
        "for={node};proto={};host=\"{quoted_host}\"",
        scheme.as_str()
    )
}

fn header(name: &str, value: impl Into<String>) -> Result<HeaderEntry, ValidationError> {
    Ok(HeaderEntry::new(
        HeaderName::new(name)?,
        HeaderValue::new(value)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn value(entries: &[HeaderEntry], name: &str) -> String {
        entries
            .iter()
            .find(|entry| entry.name().as_str() == name)
            .map(|entry| entry.value().as_str().to_owned())
            .unwrap_or_default()
    }

    /// With no trusted proxies, a forwarded address is ignored and the
    /// peer's address is returned as the client.
    #[test]
    fn an_untrusted_peer_cannot_name_someone_else() {
        let resolved = client_address(
            ip("198.51.100.7"),
            Some("203.0.113.9"),
            &TrustedProxies::none(),
        );

        assert_eq!(resolved, ip("198.51.100.7"));
    }

    /// The ingress at 10.0.0.1 is trusted and forwards for 203.0.113.9. That
    /// address is taken as the client.
    #[test]
    fn a_trusted_peer_is_believed() {
        let resolved = client_address(
            ip("10.0.0.1"),
            Some("203.0.113.9"),
            &TrustedProxies::parse("10.0.0.1"),
        );

        assert_eq!(resolved, ip("203.0.113.9"));
    }

    /// A trusted peer's forwarded chain resolves to the rightmost address
    /// outside the trusted block, ignoring the address farther left.
    #[test]
    fn the_rightmost_entry_that_is_not_ours_wins() {
        let trusted = TrustedProxies::parse("10.0.0.0/8");

        let resolved = client_address(
            ip("10.0.0.1"),
            Some("1.2.3.4, 203.0.113.9, 10.0.0.7"),
            &trusted,
        );

        assert_eq!(resolved, ip("203.0.113.9"));
    }

    /// A trusted peer that sends no `X-Forwarded-For` is itself the client.
    #[test]
    fn a_trusted_peer_with_no_header_is_the_client() {
        let resolved = client_address(ip("10.0.0.1"), None, &TrustedProxies::parse("10.0.0.1"));

        assert_eq!(resolved, ip("10.0.0.1"));
    }

    /// A header that lists only addresses inside our trusted block names no
    /// outside client, so the peer is used.
    #[test]
    fn a_header_naming_only_our_own_proxies_falls_back_to_the_peer() {
        let trusted = TrustedProxies::parse("10.0.0.0/8");

        let resolved = client_address(ip("10.0.0.1"), Some("10.0.0.5, 10.0.0.6"), &trusted);

        assert_eq!(resolved, ip("10.0.0.1"));
    }

    /// With `not-an-ip, 203.0.113.9`, the walk reads 203.0.113.9 first and
    /// stops there. The garbage to its left is never reached.
    #[test]
    fn a_readable_entry_right_of_garbage_is_the_client() {
        let trusted = TrustedProxies::parse("10.0.0.1");

        let resolved = client_address(ip("10.0.0.1"), Some("not-an-ip, 203.0.113.9"), &trusted);

        assert_eq!(resolved, ip("203.0.113.9"));
    }

    /// IPv4 and bracketed IPv6 forwarded entries with ports resolve to their
    /// addresses, without using the earlier address in either chain.
    #[test]
    fn an_entry_with_a_port_names_its_address() {
        let trusted = TrustedProxies::parse("10.0.0.1");

        let v4 = client_address(
            ip("10.0.0.1"),
            Some("203.0.113.77, 198.51.100.9:51234"),
            &trusted,
        );
        let v6 = client_address(
            ip("10.0.0.1"),
            Some("203.0.113.77, [2001:db8::9]:443"),
            &trusted,
        );

        assert_eq!(v4, ip("198.51.100.9"));
        assert_eq!(v6, ip("2001:db8::9"));
    }

    /// An unreadable rightmost forwarded entry makes resolution fall back
    /// to the trusted peer instead of using the address farther left.
    #[test]
    fn an_unreadable_entry_stops_the_walk_at_the_peer() {
        let trusted = TrustedProxies::parse("10.0.0.1");

        let resolved = client_address(ip("10.0.0.1"), Some("203.0.113.77, garbage"), &trusted);

        assert_eq!(resolved, ip("10.0.0.1"));
    }

    /// Listing `10.0.0.1` trusts that one address and not its neighbour.
    #[test]
    fn a_bare_address_is_a_single_host_block() {
        let trusted = TrustedProxies::parse("10.0.0.1");

        assert!(trusted.contains(ip("10.0.0.1")));
        assert!(!trusted.contains(ip("10.0.0.2")));
    }

    /// Listing `10.0.0.0/8` trusts 10.99.0.4 and not 11.0.0.1.
    #[test]
    fn a_cidr_block_covers_its_range() {
        let trusted = TrustedProxies::parse("10.0.0.0/8");

        assert!(trusted.contains(ip("10.99.0.4")));
        assert!(!trusted.contains(ip("11.0.0.1")));
    }

    /// Listing one IPv6 address trusts only that address, not the next one.
    #[test]
    fn an_ipv6_address_becomes_a_128_bit_block() {
        let trusted = TrustedProxies::parse("2001:db8::1");

        assert!(trusted.contains(ip("2001:db8::1")));
        assert!(!trusted.contains(ip("2001:db8::2")));
    }

    /// A list with `nonsense` between two addresses keeps those two and drops
    /// the bad entry. Nothing else, such as 10.0.0.3, becomes trusted.
    #[test]
    fn an_unparseable_entry_is_dropped_rather_than_widening_trust() {
        let trusted = TrustedProxies::parse("10.0.0.1, nonsense, 10.0.0.2");

        assert!(trusted.contains(ip("10.0.0.1")));
        assert!(trusted.contains(ip("10.0.0.2")));
        assert!(!trusted.contains(ip("10.0.0.3")));
    }

    /// An empty setting, or one of only spaces and commas, trusts no proxy.
    #[test]
    fn an_empty_specification_trusts_nobody() {
        assert!(TrustedProxies::parse("").is_empty());
        assert!(TrustedProxies::parse("  ,  ").is_empty());
    }

    /// A client at 203.0.113.9 reaching `app.acme.com` over HTTPS gives the
    /// upstream those three values in the `x-forwarded-` headers.
    #[test]
    fn the_upstream_is_told_the_client_the_scheme_and_the_host() {
        let entries =
            forwarded_headers(ip("203.0.113.9"), ClientScheme::Https, "app.acme.com").unwrap();

        assert_eq!(value(&entries, "x-forwarded-for"), "203.0.113.9");
        assert_eq!(value(&entries, "x-forwarded-proto"), "https");
        assert_eq!(value(&entries, "x-forwarded-host"), "app.acme.com");
    }

    /// Every header the proxy sets upstream is one it strips from inbound
    /// requests. So the copy the upstream sees is always the proxy's own.
    #[test]
    fn every_forwarded_header_is_one_the_proxy_owns() {
        let entries =
            forwarded_headers(ip("203.0.113.9"), ClientScheme::Http, "acme.test").unwrap();

        assert!(
            entries
                .iter()
                .all(|entry| crate::shared::web::proxy_headers::is_proxy_owned(
                    entry.name().as_str()
                )),
            "{entries:?}"
        );
    }

    /// No list, and an empty one, report that they trust nobody. A list with
    /// one address reports that it trusts someone. Callers use this to decide
    /// whether to read a forwarded header at all.
    #[test]
    fn a_list_knows_whether_it_trusts_anybody() {
        assert!(TrustedProxies::none().is_empty());
        assert!(TrustedProxies::parse("").is_empty());
        assert!(!TrustedProxies::parse("10.0.0.1").is_empty());
    }

    /// An IPv6 trust block contains addresses sharing its /64 prefix and
    /// excludes the tested addresses with different prefixes.
    #[test]
    fn an_ipv6_block_covers_its_prefix_and_nothing_outside_it() {
        let trusted = TrustedProxies::parse("2001:db8:1::/64");

        assert!(trusted.contains(ip("2001:db8:1::1")));
        assert!(trusted.contains(ip("2001:db8:1::ffff:ffff")));
        assert!(
            !trusted.contains(ip("2001:db8:2::1")),
            "a different /64 is outside the block"
        );
        assert!(!trusted.contains(ip("2001:db9:1::1")));
    }

    /// A /32 trusts `2001:db8:ffff::1`, and a /126 does not. The /126 trusts
    /// only `2001:db8::` to `2001:db8::3`, so the prefix written is the one
    /// applied.
    #[test]
    fn a_narrower_ipv6_prefix_trusts_fewer_addresses() {
        let wide = TrustedProxies::parse("2001:db8::/32");
        let narrow = TrustedProxies::parse("2001:db8::/126");

        assert!(wide.contains(ip("2001:db8:ffff::1")));
        assert!(!narrow.contains(ip("2001:db8:ffff::1")));
        assert!(narrow.contains(ip("2001:db8::3")));
        assert!(!narrow.contains(ip("2001:db8::4")));
    }

    /// Forwarded-header construction rejects a host containing a line break
    /// followed by an injected `X-User` header.
    #[test]
    fn a_host_that_would_split_the_header_is_refused() {
        assert!(
            forwarded_headers(
                ip("203.0.113.9"),
                ClientScheme::Https,
                "a.test\r\nX-User: admin"
            )
            .is_err()
        );
    }

    /// The `Forwarded` header carries the client, scheme and quoted host. An
    /// IPv6 client is bracketed and quoted, as RFC 7239 writes it.
    #[test]
    fn the_forwarded_header_is_written_by_the_proxy() {
        let v4 = forwarded_headers(ip("203.0.113.7"), ClientScheme::Https, "app.acme.com").unwrap();
        let v6 = forwarded_headers(ip("2001:db8::1"), ClientScheme::Http, "app.acme.com").unwrap();

        assert_eq!(
            value(&v4, "forwarded"),
            "for=203.0.113.7;proto=https;host=\"app.acme.com\""
        );
        assert_eq!(
            value(&v6, "forwarded"),
            "for=\"[2001:db8::1]\";proto=http;host=\"app.acme.com\""
        );
    }
}
