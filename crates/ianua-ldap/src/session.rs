//! One connection's state: where it came from, the certificate its
//! handshake presented, and who it is bound as.

use std::net::IpAddr;

use ianua_app::use_cases::directory::principal::DirectoryPrincipal;
use ianua_app::use_cases::directory::service_accounts::service_principal::ServiceAccountPrincipal;
use ianua_domain::types::{CertificateFingerprint, Fact, IpAddress};

/// Who a connection is bound as.
pub(crate) enum Bound {
    /// Nobody: before any bind, after an anonymous one, or after one the
    /// server stopped counting.
    Nobody,
    /// A person, by their password over their client certificate. Boxed,
    /// as what they hold is large beside nobody.
    Person(Box<PersonBind>),
    /// An application, as its service account.
    Service(Box<ServiceBind>),
}

/// A person a connection is bound as.
pub(crate) struct PersonBind {
    /// What the bind use case made of the person.
    pub(crate) principal: DirectoryPrincipal,
    /// The DN they bound as.
    pub(crate) dn: String,
}

/// A service account a connection is bound as.
pub(crate) struct ServiceBind {
    /// What the bind use case made of the account.
    pub(crate) principal: ServiceAccountPrincipal,
    /// The DN it bound as.
    pub(crate) dn: String,
}

/// One connection's state.
pub(crate) struct Session {
    /// Who it is bound as.
    pub(crate) bound: Bound,
    /// The address it came from, as the throttle counts it.
    pub(crate) peer: IpAddr,
    /// The address it came from, as records carry it.
    pub(crate) ip: Fact<IpAddress>,
    /// The fingerprint of the client certificate its TLS handshake
    /// presented and the client authority checked, if any.
    pub(crate) presented: Option<CertificateFingerprint>,
}

impl Session {
    /// A connection from `peer`, bound as nobody yet.
    pub(crate) fn new(peer: IpAddr, presented: Option<CertificateFingerprint>) -> Self {
        Self {
            bound: Bound::Nobody,
            peer,
            ip: Fact::from_option(IpAddress::new(peer.to_string()).ok()),
            presented,
        }
    }

    /// Stops counting the bind: the next request is as nobody's.
    pub(crate) fn sign_out(&mut self) {
        self.bound = Bound::Nobody;
    }

    /// The DN the connection is bound as, if any.
    pub(crate) fn bound_dn(&self) -> Option<&str> {
        match &self.bound {
            Bound::Nobody => None,
            Bound::Person(person) => Some(&person.dn),
            Bound::Service(service) => Some(&service.dn),
        }
    }
}
