//! Where a sign-in attempt came from, as its failures are counted.
//!
//! An IPv4 address is one origin. An IPv6 address is counted by its `/64`
//! network: one home or one cloud machine is handed a whole `/64`, so
//! counting each address would let one guesser step to a fresh address
//! after every lockout. An IPv4 address written in IPv6 form counts as the
//! IPv4 address. An attempt whose address nobody observed counts under one
//! origin of its own.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::types::{Fact, IpAddress};

/// The bits of an IPv6 address that name its network.
const NETWORK_BITS: u32 = 64;

/// Where a sign-in attempt came from, as its failures are counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptOrigin(Origin);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Origin {
    V4(Ipv4Addr),
    V6Network(Ipv6Addr),
    Unobserved,
}

impl AttemptOrigin {
    /// The origin of an attempt from `ip`.
    #[must_use]
    pub fn of(ip: Fact<&IpAddress>) -> Self {
        let Fact::Known(ip) = ip else {
            return Self(Origin::Unobserved);
        };
        let Ok(parsed) = ip.as_str().parse::<IpAddr>() else {
            return Self(Origin::Unobserved);
        };
        Self(origin_of(parsed))
    }

    /// Whether the attempt's address was observed.
    #[must_use]
    pub fn is_observed(&self) -> bool {
        !matches!(self.0, Origin::Unobserved)
    }
}

/// The origin `ip` counts under.
fn origin_of(ip: IpAddr) -> Origin {
    match ip {
        IpAddr::V4(v4) => Origin::V4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| Origin::V6Network(network_of(v6)), Origin::V4),
    }
}

/// The `/64` network `ip` is in.
fn network_of(ip: Ipv6Addr) -> Ipv6Addr {
    let mask = u128::MAX
        .checked_shl(u128::BITS.saturating_sub(NETWORK_BITS))
        .unwrap_or_default();
    Ipv6Addr::from(u128::from(ip) & mask)
}

impl fmt::Display for AttemptOrigin {
    /// The origin as a record or a key names it: `203.0.113.7`,
    /// `2001:db8:1:2::/64`, or `unobserved`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Origin::V4(ip) => write!(f, "{ip}"),
            Origin::V6Network(network) => write!(f, "{network}/{NETWORK_BITS}"),
            Origin::Unobserved => f.write_str("unobserved"),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn from(ip: &str) -> AttemptOrigin {
        AttemptOrigin::of(Fact::Known(&IpAddress::new(ip).unwrap()))
    }

    /// Distinct IPv4 hosts remain separate, so attempts are not pooled across neighbors.
    #[test]
    fn an_ipv4_address_is_its_own_origin() {
        assert_eq!(from("203.0.113.7").to_string(), "203.0.113.7");
        assert_ne!(from("203.0.113.7"), from("203.0.113.8"));
    }

    /// IPv6 addresses within one `/64` share an origin; an adjacent `/64` differs.
    #[test]
    fn ipv6_addresses_in_one_network_are_one_origin() {
        let first = from("2001:db8:1:2::1");
        let next = from("2001:db8:1:2:ffff:ffff:ffff:fffe");

        assert_eq!(first, next);
        assert_eq!(first.to_string(), "2001:db8:1:2::/64");
        assert_ne!(first, from("2001:db8:1:3::1"));
    }

    /// IPv4 and its IPv4-mapped IPv6 spelling produce the same origin.
    #[test]
    fn an_ipv4_address_in_ipv6_form_is_the_ipv4_origin() {
        assert_eq!(from("::ffff:203.0.113.7"), from("203.0.113.7"));
    }

    /// An attempt whose address nobody saw counts under one origin of its
    /// own, apart from every address.
    #[test]
    fn an_unobserved_address_is_one_origin_of_its_own() {
        let unobserved = AttemptOrigin::of(Fact::Unknown);

        assert!(!unobserved.is_observed());
        assert_eq!(unobserved.to_string(), "unobserved");
        assert_ne!(unobserved, from("203.0.113.7"));
    }

    proptest! {
        /// Whatever two IPv6 addresses are, they are one origin exactly
        /// when they share their first 64 bits.
        #[test]
        fn ipv6_origins_follow_the_network(a: u128, b: u128) {
            let mapped = |n: u128| Ipv6Addr::from(n).to_ipv4_mapped().is_some();
            prop_assume!(!mapped(a) && !mapped(b));
            let left = from(&Ipv6Addr::from(a).to_string());
            let right = from(&Ipv6Addr::from(b).to_string());

            prop_assert_eq!(left == right, a.checked_shr(64) == b.checked_shr(64));
        }
    }
}
