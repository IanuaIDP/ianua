//! How a Protected data step's connection to the system behind a stream
//! route is protected: TLS from the worker to the system itself, checked
//! against the system's own certificate, or none when the company says so.

use crate::domains::routing::stream::StreamRoute;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CertificatePem, HostName};

/// How a Protected data step's connection to the system behind a stream
/// route is protected, from the worker to the system itself, through the
/// gateway, so neither the network nor the gateway reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginTls {
    /// TLS, the system's certificate checked as this says.
    Required(TlsCheck),
    /// None: for a system that serves no TLS, on a network the company
    /// trusts. Chosen by name, never implied.
    Off,
}

impl LoginTls {
    /// The stored form, `required` or `off`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required(_) => "required",
            Self::Off => "off",
        }
    }
}

/// The authority a system's certificate must chain to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsAuthority {
    /// The public roots, for a system with a publicly trusted certificate.
    PublicRoots,
    /// The company's own authority, and nothing else, as the worker checks
    /// it.
    Own(CertificatePem),
}

/// The name a system's certificate is checked for, as the caller gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateName {
    /// The one host every backend of the route shares.
    SharedBackendHost,
    /// This name, such as the system's own when the backends are reached
    /// by address.
    Given(HostName),
}

/// How the system's certificate is checked: chaining to `authority` and
/// naming `server_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCheck {
    authority: TlsAuthority,
    server_name: HostName,
}

impl TlsCheck {
    /// The check of a certificate naming `server_name`, chaining to
    /// `authority`.
    #[must_use]
    pub fn new(authority: TlsAuthority, server_name: HostName) -> Self {
        Self {
            authority,
            server_name,
        }
    }

    /// The authority the certificate must chain to.
    #[must_use]
    pub fn authority(&self) -> &TlsAuthority {
        &self.authority
    }

    /// The name the certificate must be for.
    #[must_use]
    pub fn server_name(&self) -> &HostName {
        &self.server_name
    }
}

impl<T: TenantScope> StreamRoute<T> {
    /// The check of the system's certificate for a login on this route:
    /// chaining to `authority` and naming `name`, the given one or the one
    /// host every backend shares.
    ///
    /// # Errors
    ///
    /// [`DomainError::Validation`] when the backends' shared host is asked
    /// for and they are on different hosts: a certificate names the system
    /// it serves, so the check needs one name to hold it to.
    pub fn tls_check(
        &self,
        authority: TlsAuthority,
        name: CertificateName,
    ) -> Result<TlsCheck, DomainError> {
        let server_name = match name {
            CertificateName::Given(name) => Some(name),
            CertificateName::SharedBackendHost => self.shared_backend_host().cloned(),
        };
        let Some(server_name) = server_name else {
            return Err(DomainError::invalid(message!(
                "routing-tls-to-the-system-needs-its-name",
                "the backends are on different hosts, so name the host the system's certificate is for"
            )));
        };
        Ok(TlsCheck::new(authority, server_name))
    }

    /// The host every backend is on, when they share one.
    fn shared_backend_host(&self) -> Option<&HostName> {
        let (first, rest) = self.backends().split_first()?;
        rest.iter()
            .all(|backend| backend.host() == first.host())
            .then(|| first.host())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::matching::host::RouteHosts;
    use crate::domains::routing::policy::RoutePolicy;
    use crate::domains::routing::stream::access::StreamAccess;
    use crate::domains::routing::stream::{
        CreateStreamRouteParams, ListenPort, StreamBackend, StreamPolicy, StreamProtocol,
        StreamTimeouts,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::Label;

    fn database_on(hosts: &[&str]) -> StreamRoute<ResolvedTenant> {
        StreamRoute::create(
            CreateStreamRouteParams {
                name: Label::new("name", "orders-db").unwrap(),
                protocol: StreamProtocol::Tcp,
                listen_port: ListenPort::new(15432).unwrap(),
                sni: RouteHosts::Any,
                policy: StreamPolicy::Tunnel,
                access: StreamAccess::People(RoutePolicy::Authenticated),
                backends: hosts
                    .iter()
                    .map(|host| StreamBackend::new(*host, 5432, 100).unwrap())
                    .collect(),
                timeouts: StreamTimeouts::default(),
            },
            &crate::domains::routing::fixtures::routing_admin(),
        )
        .unwrap()
    }

    fn host(name: &str) -> HostName {
        HostName::new(name).unwrap()
    }

    /// Ann's orders database has two replicas on the same host. Opening it
    /// with TLS and no name holds the certificate to that host.
    #[test]
    fn the_shared_backend_host_is_the_name_checked() {
        let route = database_on(&["db.internal", "db.internal"]);

        let check = route
            .tls_check(
                TlsAuthority::PublicRoots,
                CertificateName::SharedBackendHost,
            )
            .unwrap();

        assert_eq!(check.server_name(), &host("db.internal"));
        assert_eq!(check.authority(), &TlsAuthority::PublicRoots);
    }

    /// A name Ann gives is the one checked, even where the backends share
    /// another, so a database reached by address can be held to its name.
    #[test]
    fn a_given_name_is_the_one_checked() {
        let route = database_on(&["10.0.0.5"]);

        let check = route
            .tls_check(
                TlsAuthority::PublicRoots,
                CertificateName::Given(host("orders.db.internal")),
            )
            .unwrap();

        assert_eq!(check.server_name(), &host("orders.db.internal"));
    }

    /// Inferring a shared certificate name fails when the route's backends
    /// have different hostnames.
    #[test]
    fn backends_on_different_hosts_need_a_name() {
        let route = database_on(&["db-a.internal", "db-b.internal"]);

        let check = route.tls_check(
            TlsAuthority::PublicRoots,
            CertificateName::SharedBackendHost,
        );

        assert!(
            matches!(check, Err(DomainError::Validation(_))),
            "{check:?}"
        );
    }
}
