use std::fmt;
use std::net::IpAddr;

use crate::message;
use crate::shared::validation::{ValidationError, Validator};

/// An IPv4 or IPv6 address, such as `192.168.1.1` or `2001:db8::1`.
///
/// It is checked to parse as a `std::net::IpAddr` when built, and kept as
/// written. Every stored IP address uses it, in sessions, audit records,
/// access contexts, consent records and flow traces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct IpAddress(String);

impl TryFrom<String> for IpAddress {
    type Error = ValidationError;

    /// Goes through [`IpAddress::new`], so a value that arrives as JSON is
    /// held to the same rules as one built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl IpAddress {
    /// Checks and wraps an IPv4 or IPv6 address.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the string is empty.
    /// - [`ValidationError`] if it is not a valid IPv4 or IPv6 address.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();

        Validator::new("ip_address", &value)
            .not_empty()
            .validate_first()?;

        value
            .parse::<IpAddr>()
            .map_err(|_| ValidationError::Custom {
                field: "ip_address",
                code: "invalid_ip".to_owned(),
                message: message!(
                    "values-ip-address-is-not-a-valid",
                    format!("ip_address '{value}' is not a valid IPv4 or IPv6 address.")
                ),
            })?;

        Ok(Self(value))
    }

    /// The address as it was written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is an IPv6 address.
    ///
    /// Other code depends on the family, such as which DNS record type
    /// answers for the address. Reading it from the address itself means the
    /// two can never disagree. `new` is the only constructor and parses
    /// before storing, so the parse here does not fail.
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.0.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6())
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A CIDR range: an IPv4 or IPv6 network and a prefix length.
///
/// Examples: `10.0.0.0/8`, `192.168.1.0/24`, `2001:db8::/32`. The address
/// must be valid. The prefix must be 0 to 32 for IPv4, or 0 to 128 for
/// IPv6.
///
/// The tenant and organization sign-in settings use it for their IP
/// allowlists, and the proxy stages use it too.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct CidrRange(String);

impl TryFrom<String> for CidrRange {
    type Error = ValidationError;

    /// Goes through [`CidrRange::new`], so a value that arrives as JSON is
    /// held to the same rules as one built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// The address and prefix length of an `ip/prefix` string.
fn parse_cidr(value: &str) -> Result<(IpAddr, u8), ValidationError> {
    let invalid = |message: String| ValidationError::Custom {
        field: "cidr_range",
        code: "invalid_cidr".to_owned(),
        message: message.into(),
    };
    let (ip_str, prefix_str) = value.split_once('/').ok_or_else(|| {
        invalid(format!(
            "cidr_range '{value}' must be in 'ip/prefix' format (e.g. 10.0.0.0/8)."
        ))
    })?;
    let ip: IpAddr = ip_str.parse().map_err(|_| {
        invalid(format!(
            "cidr_range '{ip_str}' is not a valid IPv4 or IPv6 address."
        ))
    })?;
    let prefix: u8 = prefix_str.parse().map_err(|_| {
        invalid(format!(
            "cidr_range prefix '{prefix_str}' is not a valid number."
        ))
    })?;
    Ok((ip, prefix))
}

/// Refuses a prefix longer than the address has bits.
fn ensure_prefix_fits(ip: IpAddr, prefix: u8) -> Result<(), ValidationError> {
    let (max_prefix, family) = match ip {
        IpAddr::V4(_) => (32, "IPv4"),
        IpAddr::V6(_) => (128, "IPv6"),
    };
    if prefix <= max_prefix {
        return Ok(());
    }
    Err(ValidationError::Custom {
        field: "cidr_range",
        code: "invalid_cidr".to_owned(),
        message: message!(
            "values-cidr-range-prefix-exceeds-maximum-for",
            format!("cidr_range prefix /{prefix} exceeds maximum /{max_prefix} for {family}.")
        ),
    })
}

impl CidrRange {
    /// Checks and wraps a CIDR range.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the string is empty.
    /// - [`ValidationError`] if it is not in the form `ip/prefix`.
    /// - [`ValidationError`] if the address is not valid IPv4 or IPv6.
    /// - [`ValidationError`] if the prefix is longer than the address.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        Validator::new("cidr_range", &value)
            .not_empty()
            .validate_first()?;
        let (ip, prefix) = parse_cidr(&value)?;
        ensure_prefix_fits(ip, prefix)?;
        Ok(Self(value))
    }

    /// The range as it was written, such as `10.0.0.0/8`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The network address part.
    #[must_use]
    pub fn network(&self) -> &str {
        self.0.split('/').next().unwrap_or(&self.0)
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.0
            .split('/')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Whether an IP address falls within this range.
    ///
    /// It compares the address's leading bits with the network's, up to the
    /// prefix length. See [`contains_addr`](Self::contains_addr) for how
    /// IPv4 and IPv6 mix.
    #[must_use]
    pub fn contains(&self, ip: &IpAddress) -> bool {
        ip.as_str()
            .parse::<IpAddr>()
            .is_ok_and(|addr| self.contains_addr(addr))
    }

    /// Whether a parsed address falls within this range.
    ///
    /// An IPv4 address written as `::ffff:1.2.3.4` counts as the IPv4
    /// address, so an IPv4 range holds it. An IPv6 range holds an IPv4
    /// address only when the range lies inside `::ffff:0:0/96`. Otherwise an
    /// IPv4 range never holds an IPv6 address, nor the reverse.
    #[must_use]
    pub fn contains_addr(&self, addr: IpAddr) -> bool {
        let Ok(network) = self.network().parse::<IpAddr>() else {
            return false;
        };
        in_block(network, self.prefix_len(), addr)
    }
}

/// Whether `addr` shares the leading `prefix` bits of `network`.
///
/// An IPv4 address written in its IPv6-mapped form, `::ffff:1.2.3.4`, is
/// the IPv4 address it maps. A dual-stack listener reports clients that
/// way, and the spelling must not let a client slip past an IPv4 rule.
///
/// An IPv4 address falls in an IPv6 network only when that network lies
/// inside the mapped space, `::ffff:0:0/96`. A wider one such as `::/0`
/// means IPv6 clients and holds no IPv4 address. Otherwise an IPv4 network
/// never holds an IPv6 address, nor the reverse. A prefix longer than the
/// address counts as the whole address.
pub(crate) fn in_block(network: IpAddr, prefix: u8, addr: IpAddr) -> bool {
    let free_bits = |width: u32| width.saturating_sub(u32::from(prefix));
    let maps_v4 =
        matches!(network, IpAddr::V6(net) if prefix >= 96 && net.to_ipv4_mapped().is_some());
    let addr = match (network, addr.to_canonical()) {
        (IpAddr::V6(_), IpAddr::V4(v4)) if maps_v4 => IpAddr::V6(v4.to_ipv6_mapped()),
        (_, canonical) => canonical,
    };
    match (network, addr) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(free_bits(32)).unwrap_or(0);
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(free_bits(128)).unwrap_or(0);
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

impl fmt::Display for CidrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `192.168.1.1` is accepted and kept as written.
    #[test]
    fn ipv4_addresses_are_kept_as_written() {
        let ip = IpAddress::new("192.168.1.1").unwrap();
        assert_eq!(ip.as_str(), "192.168.1.1");
    }

    /// The loopback address `127.0.0.1` is a valid address to record.
    #[test]
    fn accepts_ipv4_loopback() {
        assert!(IpAddress::new("127.0.0.1").is_ok());
    }

    /// `0.0.0.0` is accepted.
    #[test]
    fn accepts_ipv4_zeros() {
        assert!(IpAddress::new("0.0.0.0").is_ok());
    }

    /// The broadcast address `255.255.255.255` is accepted.
    #[test]
    fn accepts_ipv4_broadcast() {
        assert!(IpAddress::new("255.255.255.255").is_ok());
    }

    /// An IPv6 address written out in full, with every zero group, is
    /// accepted.
    #[test]
    fn accepts_ipv6_full() {
        assert!(IpAddress::new("2001:0db8:85a3:0000:0000:8a2e:0370:7334").is_ok());
    }

    /// The short form `2001:db8::1` is accepted.
    #[test]
    fn accepts_ipv6_shorthand() {
        assert!(IpAddress::new("2001:db8::1").is_ok());
    }

    /// The IPv6 loopback `::1` is accepted.
    #[test]
    fn accepts_ipv6_loopback() {
        assert!(IpAddress::new("::1").is_ok());
    }

    /// The unspecified IPv6 address `::` is accepted.
    #[test]
    fn accepts_ipv6_unspecified() {
        assert!(IpAddress::new("::").is_ok());
    }

    /// Empty text is refused before it can identify a client's network address.
    #[test]
    fn an_empty_ip_address_is_refused() {
        assert!(IpAddress::new("").is_err());
    }

    /// `not-an-ip` is refused.
    #[test]
    fn text_without_an_address_is_refused() {
        assert!(IpAddress::new("not-an-ip").is_err());
    }

    /// `999.999.999.999` has octets above 255 and is refused.
    #[test]
    fn rejects_octet_overflow() {
        assert!(IpAddress::new("999.999.999.999").is_err());
    }

    /// `192.168.1` has only three octets and is refused.
    #[test]
    fn rejects_partial_ipv4() {
        assert!(IpAddress::new("192.168.1").is_err());
    }

    /// `192.168.1.1:8080` carries a port, so it is not an address. It is
    /// refused.
    #[test]
    fn rejects_ipv4_with_port() {
        assert!(IpAddress::new("192.168.1.1:8080").is_err());
    }

    /// A range, `10.0.0.0/8`, is refused where one address is expected.
    #[test]
    fn rejects_cidr_notation() {
        assert!(IpAddress::new("10.0.0.0/8").is_err());
    }

    /// An address with a NUL byte inside it is refused.
    #[test]
    fn rejects_control_chars() {
        assert!(IpAddress::new("10.0\x00.0.1").is_err());
    }

    /// `10.0.0.1 ` with a trailing space is refused, not trimmed.
    #[test]
    fn addresses_with_trailing_spaces_are_refused() {
        assert!(IpAddress::new("10.0.0.1 ").is_err());
    }

    /// The address `10.0.0.1` prints as `10.0.0.1`.
    #[test]
    fn display_returns_value() {
        let ip = IpAddress::new("10.0.0.1").unwrap();
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    /// The all-IPv6 range excludes both plain and mapped IPv4 addresses,
    /// while still containing a native IPv6 address.
    #[test]
    fn a_wide_ipv6_range_holds_no_ipv4_address() {
        let any_v6 = CidrRange::new("::/0").unwrap();

        assert!(!any_v6.contains(&IpAddress::new("203.0.113.9").unwrap()));
        assert!(!any_v6.contains(&IpAddress::new("::ffff:203.0.113.9").unwrap()));
        assert!(any_v6.contains(&IpAddress::new("2001:db8::1").unwrap()));
    }

    /// An IPv4 subnet contains its addresses in mapped IPv6 notation,
    /// while a mapped address in the next subnet remains outside it.
    #[test]
    fn an_ipv4_range_holds_the_mapped_spelling_of_its_addresses() {
        let denied = CidrRange::new("1.2.3.0/24").unwrap();
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        let outside: IpAddr = "::ffff:1.2.4.4".parse().unwrap();

        assert!(denied.contains_addr(mapped));
        assert!(!denied.contains_addr(outside));
    }

    /// A range written in mapped form, `::ffff:1.2.3.0/120`, holds the plain
    /// IPv4 address `1.2.3.4`.
    #[test]
    fn a_mapped_range_holds_the_plain_spelling_of_its_addresses() {
        let range = CidrRange::new("::ffff:1.2.3.0/120").unwrap();

        assert!(range.contains_addr("1.2.3.4".parse().unwrap()));
    }

    /// `10.0.0.0/8` is accepted and splits into network `10.0.0.0` and
    /// prefix 8.
    #[test]
    fn accepts_ipv4_cidr() {
        let cidr = CidrRange::new("10.0.0.0/8").unwrap();
        assert_eq!(cidr.as_str(), "10.0.0.0/8");
        assert_eq!(cidr.network(), "10.0.0.0");
        assert_eq!(cidr.prefix_len(), 8);
    }

    /// A single-host range, `192.168.1.1/32`, is accepted.
    #[test]
    fn accepts_ipv4_host_route() {
        assert!(CidrRange::new("192.168.1.1/32").is_ok());
    }

    /// The all-addresses range `0.0.0.0/0` is accepted.
    #[test]
    fn accepts_ipv4_default_route() {
        assert!(CidrRange::new("0.0.0.0/0").is_ok());
    }

    /// `192.168.1.0/24` reports a prefix of 24.
    #[test]
    fn accepts_ipv4_slash_24() {
        let cidr = CidrRange::new("192.168.1.0/24").unwrap();
        assert_eq!(cidr.prefix_len(), 24);
    }

    /// `2001:db8::/32` splits into network `2001:db8::` and prefix 32.
    #[test]
    fn accepts_ipv6_cidr() {
        let cidr = CidrRange::new("2001:db8::/32").unwrap();
        assert_eq!(cidr.network(), "2001:db8::");
        assert_eq!(cidr.prefix_len(), 32);
    }

    /// A single-host IPv6 range, `::1/128`, is accepted.
    #[test]
    fn accepts_ipv6_slash_128() {
        assert!(CidrRange::new("::1/128").is_ok());
    }

    /// The all-IPv6 range `::/0` is accepted.
    #[test]
    fn accepts_ipv6_slash_0() {
        assert!(CidrRange::new("::/0").is_ok());
    }

    /// An empty range is refused.
    #[test]
    fn rejects_empty_cidr() {
        assert!(CidrRange::new("").is_err());
    }

    /// A bare address, `10.0.0.0`, with no `/prefix` is refused as a range.
    #[test]
    fn rejects_no_slash() {
        assert!(CidrRange::new("10.0.0.0").is_err());
    }

    /// `999.999.999.999/8` has an invalid address and is refused.
    #[test]
    fn rejects_invalid_ip_in_cidr() {
        assert!(CidrRange::new("999.999.999.999/8").is_err());
    }

    /// `10.0.0.0/abc` has a prefix that is not a number and is refused.
    #[test]
    fn rejects_invalid_prefix() {
        assert!(CidrRange::new("10.0.0.0/abc").is_err());
    }

    /// `10.0.0.0/33` asks for more bits than IPv4 has. It is refused.
    #[test]
    fn rejects_ipv4_prefix_over_32() {
        assert!(CidrRange::new("10.0.0.0/33").is_err());
    }

    /// `2001:db8::/129` asks for more bits than IPv6 has. It is refused.
    #[test]
    fn rejects_ipv6_prefix_over_128() {
        assert!(CidrRange::new("2001:db8::/129").is_err());
    }

    /// `not-a-cidr/8` has a valid prefix but no address. It is refused.
    #[test]
    fn rejects_garbage_cidr() {
        assert!(CidrRange::new("not-a-cidr/8").is_err());
    }

    /// `10.0.0.0//8` with two slashes is refused.
    #[test]
    fn rejects_double_slash() {
        assert!(CidrRange::new("10.0.0.0//8").is_err());
    }

    /// The range `10.0.0.0/8` prints as `10.0.0.0/8`.
    #[test]
    fn cidr_display_returns_value() {
        let cidr = CidrRange::new("10.0.0.0/8").unwrap();
        assert_eq!(cidr.to_string(), "10.0.0.0/8");
    }

    /// `10.0.0.0/8` holds both its first host, `10.0.0.1`, and its last
    /// address, `10.255.255.255`.
    #[test]
    fn cidr_contains_ip_in_range() {
        let cidr = CidrRange::new("10.0.0.0/8").unwrap();
        assert!(cidr.contains(&IpAddress::new("10.0.0.1").unwrap()));
        assert!(cidr.contains(&IpAddress::new("10.255.255.255").unwrap()));
    }

    /// `10.0.0.0/8` does not hold `11.0.0.1` or `192.168.1.1`.
    #[test]
    fn cidr_excludes_ip_outside_range() {
        let cidr = CidrRange::new("10.0.0.0/8").unwrap();
        assert!(!cidr.contains(&IpAddress::new("11.0.0.1").unwrap()));
        assert!(!cidr.contains(&IpAddress::new("192.168.1.1").unwrap()));
    }

    /// `192.168.1.0/24` holds `.1` and `.254` of its subnet but not
    /// `192.168.2.1`.
    #[test]
    fn cidr_24_contains() {
        let cidr = CidrRange::new("192.168.1.0/24").unwrap();
        assert!(cidr.contains(&IpAddress::new("192.168.1.1").unwrap()));
        assert!(cidr.contains(&IpAddress::new("192.168.1.254").unwrap()));
        assert!(!cidr.contains(&IpAddress::new("192.168.2.1").unwrap()));
    }

    /// `192.168.1.1/32` holds that one address and not its neighbour
    /// `192.168.1.2`.
    #[test]
    fn cidr_32_exact_match() {
        let cidr = CidrRange::new("192.168.1.1/32").unwrap();
        assert!(cidr.contains(&IpAddress::new("192.168.1.1").unwrap()));
        assert!(!cidr.contains(&IpAddress::new("192.168.1.2").unwrap()));
    }

    /// `0.0.0.0/0` holds every IPv4 address, from `1.2.3.4` to
    /// `255.255.255.255`.
    #[test]
    fn cidr_0_matches_everything() {
        let cidr = CidrRange::new("0.0.0.0/0").unwrap();
        assert!(cidr.contains(&IpAddress::new("1.2.3.4").unwrap()));
        assert!(cidr.contains(&IpAddress::new("255.255.255.255").unwrap()));
    }

    /// `2001:db8::/32` holds `2001:db8::1` but not `2001:db9::1`.
    #[test]
    fn cidr_ipv6_contains() {
        let cidr = CidrRange::new("2001:db8::/32").unwrap();
        assert!(cidr.contains(&IpAddress::new("2001:db8::1").unwrap()));
        assert!(!cidr.contains(&IpAddress::new("2001:db9::1").unwrap()));
    }

    /// `2001:db8:0:1::/64` holds every address in its subnet, up to the
    /// all-`ffff` one, but not `2001:db8:0:2::5` next door.
    #[test]
    fn cidr_ipv6_64_matches_the_network_half_only() {
        let cidr = CidrRange::new("2001:db8:0:1::/64").unwrap();

        assert!(cidr.contains(&IpAddress::new("2001:db8:0:1::5").unwrap()));
        assert!(cidr.contains(&IpAddress::new("2001:db8:0:1:ffff:ffff:ffff:ffff").unwrap()));
        assert!(!cidr.contains(&IpAddress::new("2001:db8:0:2::5").unwrap()));
    }

    /// An IPv4 range, `10.0.0.0/8`, never holds an IPv6 address such as
    /// `::1`.
    #[test]
    fn cidr_v4_does_not_match_v6() {
        let cidr = CidrRange::new("10.0.0.0/8").unwrap();
        assert!(!cidr.contains(&IpAddress::new("::1").unwrap()));
    }
}
