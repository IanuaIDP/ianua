//! Proof that a workspace or organization admitted a sign-in attempt.
//!
//! A workspace or organization decides first whether it takes a way of
//! signing in at all, and from which addresses. It decides this before any
//! account is looked up. The operations that check a credential take this
//! proof. So none of them can run on an attempt that was never admitted, and
//! none keeps its own copy of the admission rules.

use crate::domains::authentication::methods::AuthMethod;
use crate::types::{CidrRange, Fact, IpAddress};

/// A sign-in attempt that its workspace or organization admitted, with the
/// method and the address it was admitted for.
///
/// Only `Tenant::admits_sign_in` and `OrganizationAuthConfig::admits` make
/// one.
#[derive(Debug, PartialEq, Eq)]
pub struct SignInAdmitted {
    method: AuthMethod,
    client_ip: Fact<IpAddress>,
}

impl SignInAdmitted {
    pub(crate) fn new(method: AuthMethod, client_ip: Fact<&IpAddress>) -> Self {
        Self {
            method,
            client_ip: client_ip.cloned(),
        }
    }

    /// The sign-in method that was admitted.
    #[must_use]
    pub fn method(&self) -> AuthMethod {
        self.method
    }

    /// The address the attempt came from, as seen when it was admitted.
    #[must_use]
    pub fn client_ip(&self) -> Fact<&IpAddress> {
        self.client_ip.as_ref()
    }

    /// The address the attempt came from, handed to the operation that
    /// checks its credential.
    pub(crate) fn into_client_ip(self) -> Fact<IpAddress> {
        self.client_ip
    }
}

/// Whether `client_ip` may sign in under `allowlist`.
///
/// An empty list admits everyone. A list admits only the addresses on it.
/// While a list is set, a caller whose address is unknown is refused.
/// Otherwise anyone could hide their address and get past the list.
#[must_use]
pub(crate) fn allowlist_admits(allowlist: &[CidrRange], client_ip: Fact<&IpAddress>) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    client_ip
        .known()
        .is_some_and(|ip| allowlist.iter().any(|range| range.contains(ip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(cidr: &str) -> CidrRange {
        CidrRange::new(cidr).unwrap()
    }

    fn ip(address: &str) -> IpAddress {
        IpAddress::new(address).unwrap()
    }

    /// A workspace sets no address list. A caller from a public address and
    /// a caller with no known address are both admitted.
    #[test]
    fn no_list_admits_every_caller() {
        assert!(allowlist_admits(&[], Fact::Unknown));
        assert!(allowlist_admits(&[], Fact::Known(&ip("203.0.113.9"))));
    }

    /// A workspace allows only `10.0.0.0/8`. A caller from `10.1.2.3` is
    /// admitted and a caller from `192.168.1.1` is refused.
    #[test]
    fn a_list_admits_only_its_addresses() {
        let list = [range("10.0.0.0/8")];

        assert!(allowlist_admits(&list, Fact::Known(&ip("10.1.2.3"))));
        assert!(!allowlist_admits(&list, Fact::Known(&ip("192.168.1.1"))));
    }

    /// A nonempty IP allowlist refuses a caller whose address is unknown.
    #[test]
    fn a_list_refuses_a_caller_whose_address_is_unknown() {
        assert!(!allowlist_admits(&[range("10.0.0.0/8")], Fact::Unknown));
    }
}
