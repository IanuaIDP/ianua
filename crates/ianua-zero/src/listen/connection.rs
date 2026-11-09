//! What the gateway learned about a connection while opening it, handed to
//! the request layer with every request on it.
//!
//! These are facts about the transport, not decisions: the client's
//! address, the name it asked for in TLS, the client certificate the
//! handshake verified and the fingerprint of its ClientHello. What they
//! mean for a request is decided by the stages and use cases that read
//! them.

use std::net::SocketAddr;

use ianua_domain::domains::proxy::request::forwarded::ClientScheme;
use ianua_domain::types::{CertificateFingerprint, DomainName, Fact};

use super::ja4::Ja4;

/// What the handshake made of the client's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientCertificate {
    /// None was asked for: the tenant does not use mutual TLS, or the
    /// connection is plain HTTP.
    NotAsked,
    /// One was asked for and none presented.
    NotPresented,
    /// One was presented and chains to an authority the tenant trusts.
    /// The fingerprint is of the leaf certificate.
    Verified(CertificateFingerprint),
    /// The tenant asks for certificates but its authorities cannot be
    /// used, so none could be verified: a route that needs a client
    /// certificate refuses.
    Unverifiable,
}

/// Whether a request's host is one this connection may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostCheck {
    /// The host is the name the client asked for in TLS, or the connection
    /// is plain HTTP and asked for none.
    Matches,
    /// The host is another name than the one the handshake was for, as
    /// when a client reuses an HTTP/2 connection across names one
    /// certificate covers. Answered `421 Misdirected Request`.
    Misdirected,
}

/// Carries verified transport observations into every request on the connection.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionFacts {
    client: SocketAddr,
    peer: SocketAddr,
    scheme: ClientScheme,
    server_name: Fact<DomainName>,
    client_certificate: ClientCertificate,
    ja4: Fact<Ja4>,
    certified: Certified,
}

/// Whose certificate a TLS connection was opened with, which decides what
/// hosts it may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Certified {
    /// A tenant's, chosen for the name the client asked for: only that
    /// name may be carried.
    ForTheName,
    /// The platform's own, on a listener inside the deployment's network:
    /// it stands for no tenant's name, so it holds no host to one.
    ForThePlatform,
}

/// Everything [`ConnectionFacts`] holds, to build one.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionParts {
    /// The client: named by a trusted ingress, or the socket peer.
    pub client: SocketAddr,
    /// The socket peer.
    pub peer: SocketAddr,
    /// Whether TLS was ended here.
    pub scheme: ClientScheme,
    /// The name the client asked for in TLS.
    pub server_name: Fact<DomainName>,
    /// What the handshake made of the client's certificate.
    pub client_certificate: ClientCertificate,
    /// The fingerprint of the ClientHello.
    pub ja4: Fact<Ja4>,
}

impl ConnectionFacts {
    /// The facts `parts` describe.
    #[must_use]
    pub(crate) fn new(parts: ConnectionParts) -> Self {
        Self {
            client: parts.client,
            peer: parts.peer,
            scheme: parts.scheme,
            server_name: parts.server_name,
            client_certificate: parts.client_certificate,
            ja4: parts.ja4,
            certified: Certified::ForTheName,
        }
    }

    /// The facts of a connection from `client` through `peer` to a
    /// listener inside the deployment's network, over TLS with the
    /// platform's own certificate. Any client certificate is the
    /// platform's, so it is not offered as any tenant's client certificate.
    pub(crate) fn internal(client: SocketAddr, peer: SocketAddr) -> Self {
        Self {
            certified: Certified::ForThePlatform,
            ..Self::new(ConnectionParts {
                client,
                peer,
                scheme: ClientScheme::Https,
                server_name: Fact::Unknown,
                client_certificate: ClientCertificate::NotAsked,
                ja4: Fact::Unknown,
            })
        }
    }

    /// The facts of a plain HTTP connection from `client` through `peer`.
    pub(crate) fn plain(client: SocketAddr, peer: SocketAddr) -> Self {
        Self::new(ConnectionParts {
            client,
            peer,
            scheme: ClientScheme::Http,
            server_name: Fact::Unknown,
            client_certificate: ClientCertificate::NotAsked,
            ja4: Fact::Unknown,
        })
    }

    /// The client: named by a trusted ingress in a PROXY protocol header,
    /// or the socket peer when it connected directly. Forwarding headers
    /// are read by the request layer on top of this.
    #[must_use]
    pub(crate) fn client(&self) -> SocketAddr {
        self.client
    }

    /// The socket peer: the ingress when one relayed the connection.
    #[must_use]
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Whether TLS was ended here.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn scheme(&self) -> ClientScheme {
        self.scheme
    }

    /// What the handshake made of the client's certificate.
    #[must_use]
    pub(crate) fn client_certificate(&self) -> &ClientCertificate {
        &self.client_certificate
    }

    /// The JA4 fingerprint of the ClientHello; unknown on plain HTTP.
    #[must_use]
    pub(crate) fn ja4(&self) -> Fact<&Ja4> {
        self.ja4.as_ref()
    }

    /// Whether a request for `host`, as its `Host` header or authority
    /// names it, may be carried on this connection.
    ///
    /// On TLS it must be the name the handshake was for, compared without
    /// port, case or a trailing dot: the certificate and the client
    /// certificate checks were chosen for that name, and must not stand
    /// for another tenant's. A TLS connection without a known name matches
    /// nothing, but one opened with the platform's own certificate on an
    /// internal listener stands for no name and matches every host.
    #[must_use]
    pub(crate) fn host_check(&self, host: &str) -> HostCheck {
        if self.certified == Certified::ForThePlatform {
            return HostCheck::Matches;
        }
        let server_name = match (self.scheme, &self.server_name) {
            (ClientScheme::Http, _) => return HostCheck::Matches,
            (ClientScheme::Https, Fact::Unknown) => return HostCheck::Misdirected,
            (ClientScheme::Https, Fact::Known(name)) => name,
        };
        let name = host
            .rsplit_once(':')
            .map_or(host, |(name, _port)| name)
            .trim_end_matches('.');
        if name.eq_ignore_ascii_case(server_name.as_str()) {
            return HostCheck::Matches;
        }
        HostCheck::Misdirected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SocketAddr {
        "203.0.113.9:443".parse().unwrap()
    }

    fn tls_with(server_name: Fact<DomainName>) -> ConnectionFacts {
        ConnectionFacts::new(ConnectionParts {
            client: address(),
            peer: address(),
            scheme: ClientScheme::Https,
            server_name,
            client_certificate: ClientCertificate::NotAsked,
            ja4: Fact::Unknown,
        })
    }

    fn tls_for(name: &str) -> ConnectionFacts {
        tls_with(Fact::Known(DomainName::new(name).unwrap()))
    }

    /// The name the handshake was for matches, whatever its port, case or
    /// trailing dot.
    #[test]
    fn the_handshake_name_matches_its_host() {
        let facts = tls_for("app.acme.com");

        assert_eq!(facts.host_check("app.acme.com"), HostCheck::Matches);
        assert_eq!(facts.host_check("App.Acme.com:443"), HostCheck::Matches);
        assert_eq!(facts.host_check("app.acme.com."), HostCheck::Matches);
    }

    /// Another name on the same connection is misdirected, even one the
    /// same wildcard certificate covers.
    #[test]
    fn another_host_is_misdirected() {
        let facts = tls_for("app.acme.com");

        assert_eq!(facts.host_check("api.acme.com"), HostCheck::Misdirected);
        assert_eq!(
            facts.host_check("app.acme.com.evil.test"),
            HostCheck::Misdirected
        );
    }

    /// A TLS connection with no known name carries no host.
    #[test]
    fn tls_without_a_name_matches_nothing() {
        let facts = tls_with(Fact::Unknown);

        assert_eq!(facts.host_check("app.acme.com"), HostCheck::Misdirected);
    }

    /// Plain HTTP named nothing to compare with.
    #[test]
    fn plain_http_matches_any_host() {
        let facts = ConnectionFacts::plain(address(), address());

        assert_eq!(facts.host_check("anything.test"), HostCheck::Matches);
    }

    /// A connection to an internal listener, over the platform's own
    /// certificates, carries any host, offers no client certificate as a
    /// tenant's, and still reads as TLS.
    #[test]
    fn an_internal_connection_matches_any_host_and_offers_no_tenant_certificate() {
        let facts = ConnectionFacts::internal(address(), address());

        assert_eq!(facts.host_check("orders.acme.com"), HostCheck::Matches);
        assert_eq!(facts.client_certificate(), &ClientCertificate::NotAsked);
        assert_eq!(facts.scheme(), ClientScheme::Https);
    }
}
