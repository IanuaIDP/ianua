//! The addresses scenario clients stand for: one of their own each, in the
//! ranges set aside for documentation (TEST-NET-1, -2 and -3), so no
//! client shares a per-address limit or a sign-in record with another and
//! none is anyone's real address.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use rand::Rng as _;

/// The three documentation networks, each a `/24`.
const NETWORKS: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];

/// The hosts of one `/24` a client may stand for: `.1` to `.254`.
const HOSTS: usize = 254;

/// Every address a client may stand for.
const ADDRESSES: usize = NETWORKS.len() * HOSTS;

/// Where this process starts handing addresses out, chosen at random once.
static FIRST: OnceLock<usize> = OnceLock::new();

/// How many addresses this process has handed out.
static HANDED_OUT: AtomicUsize = AtomicUsize::new(0);

/// An address no other client of this process stands for, until all 762
/// were handed out.
pub(crate) fn fresh() -> IpAddr {
    let first = *FIRST.get_or_init(|| rand::thread_rng().gen_range(0..ADDRESSES));
    let index = (first + HANDED_OUT.fetch_add(1, Ordering::Relaxed)) % ADDRESSES;
    nth(index)
}

/// The `index`th address of the documentation networks, from 0.
fn nth(index: usize) -> IpAddr {
    let [a, b, c] = NETWORKS[index / HOSTS % NETWORKS.len()];
    let host = u8::try_from(index % HOSTS + 1).unwrap_or(1);
    IpAddr::V4(Ipv4Addr::new(a, b, c, host))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Every address handed out lies in a documentation network, never on
    /// the network's own address or its broadcast.
    #[test]
    fn every_address_is_a_documentation_address() {
        for index in 0..ADDRESSES {
            let IpAddr::V4(address) = nth(index) else {
                panic!("an IPv6 address was handed out");
            };
            let [a, b, c, host] = address.octets();
            assert!(NETWORKS.contains(&[a, b, c]), "{address}");
            assert!((1..=254).contains(&host), "{address}");
        }
    }

    /// Two clients never stand for one address.
    #[test]
    fn two_clients_stand_for_two_addresses() {
        let handed: HashSet<IpAddr> = (0..100).map(|_| fresh()).collect();

        assert_eq!(handed.len(), 100);
    }
}
