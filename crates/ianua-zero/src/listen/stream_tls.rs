//! Ending TLS on a stream route's port: the certificate for the name the
//! client asked for and, on a mutual-TLS route, the client certificate
//! verified against the authorities of the tenant whose port it is.
//!
//! The HTTPS listener learns the tenant from the name. Here the port names
//! it already, so a name is served only when it is that tenant's: a client
//! asking one tenant's port for another tenant's name is refused, never
//! answered with the other's certificate and spliced into this tenant's
//! backend. Client certificates are verified against this tenant's
//! authorities alone, from the same [`ClientAuthTable`] the HTTPS side
//! reads. A mutual-TLS route of a tenant that names no authorities, or
//! whose authorities cannot be used, refuses every handshake rather than
//! taking connections it cannot check.
//!
//! What runs inside is the route's, not the gateway's, so no application
//! protocol is offered, except on the signed-in tunnel, whose `CONNECT` is
//! HTTP/1.1.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::types::{DomainName, TenantId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::server::{Acceptor, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, StartHandshake};

use super::certificates::CertificateTable;
use super::client_auth::{ClientAuth, ClientAuthTable};
use super::connection::ClientCertificate;
use super::tls::{Chosen, ServedNames, leaf_fingerprint};

/// What a stream route's handshake asks of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamHandshake {
    /// TLS ended at the gateway, and nothing more asked.
    Terminate,
    /// A client certificate, verified against the tenant's authorities.
    MutualTls,
    /// The signed-in tunnel: HTTP/1.1 inside, for its `CONNECT`.
    Tunnel,
}

impl StreamHandshake {
    /// The application protocols offered.
    fn protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Terminate | Self::MutualTls => Vec::new(),
            Self::Tunnel => vec![b"http/1.1".to_vec()],
        }
    }
}

/// Where a stream handshake's choices come from.
pub(crate) struct StreamTlsSources {
    /// The certificate for each name.
    pub certificates: Arc<CertificateTable>,
    /// Each tenant's client-certificate verification.
    pub client_auth: Arc<ClientAuthTable>,
    /// The tenant answering on each name.
    pub names: Arc<dyn ServedNames>,
}

/// Ends TLS on the connections a stream route's port accepts.
pub(crate) struct StreamTls {
    provider: Arc<CryptoProvider>,
    sources: StreamTlsSources,
    handshake: Duration,
}

/// Why a stream handshake was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StreamHandshakeError {
    /// It did not finish within its timeout.
    #[error("the TLS handshake did not finish in time")]
    TimedOut,
    /// The client named no server, or not as a domain name.
    #[error("the client named no server")]
    NoServerName,
    /// The name is not one the port's tenant answers on.
    #[error("{0} is not a name of the tenant whose port this is")]
    NotTheTenants(DomainName),
    /// No certificate is served for the name.
    #[error("no certificate is served for {0}")]
    NoCertificate(DomainName),
    /// The route asks for client certificates and the tenant has no
    /// authorities that can verify one.
    #[error("the tenant has no usable client certificate authorities")]
    NoClientAuthorities,
    /// The configuration for the handshake could not be built.
    #[error("the TLS configuration could not be built")]
    Config(#[source] tokio_rustls::rustls::Error),
    /// rustls refused the handshake, a client certificate the tenant's
    /// authorities did not sign included, or the connection failed.
    #[error("the TLS handshake failed")]
    Tls(#[source] std::io::Error),
}

impl StreamHandshakeError {
    /// A short, stable reason for the record.
    #[must_use]
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::TimedOut => "handshake_timed_out",
            Self::NoServerName => "no_server_name",
            Self::NotTheTenants(_) => "server_name_of_another_tenant",
            Self::NoCertificate(_) => "no_certificate",
            Self::NoClientAuthorities => "no_client_authorities",
            Self::Config(_) => "tls_config",
            Self::Tls(_) => "handshake_refused",
        }
    }
}

/// A stream whose handshake finished, and what it showed.
pub(crate) struct TerminatedStream<S> {
    /// The decrypted stream.
    pub stream: TlsStream<S>,
    /// The name the client asked for.
    pub server_name: DomainName,
    /// What the handshake made of the client's certificate.
    pub client_certificate: ClientCertificate,
}

impl StreamTls {
    /// Ends TLS with what `sources` hold, refusing a handshake that takes
    /// longer than `handshake`.
    #[must_use]
    pub(crate) fn new(
        provider: Arc<CryptoProvider>,
        sources: StreamTlsSources,
        handshake: Duration,
    ) -> Self {
        Self {
            provider,
            sources,
            handshake,
        }
    }

    /// Ends TLS on `stream`, which arrived on a port of `tenant`, asking
    /// what `asked` says, within the handshake timeout.
    ///
    /// # Errors
    ///
    /// [`StreamHandshakeError`] when the handshake is refused or takes too
    /// long.
    pub(crate) async fn terminate<S>(
        &self,
        stream: S,
        tenant: TenantId,
        asked: StreamHandshake,
    ) -> Result<TerminatedStream<S>, StreamHandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(self.handshake, self.handshake_on(stream, tenant, asked))
            .await
            .map_err(|_| StreamHandshakeError::TimedOut)?
    }

    async fn handshake_on<S>(
        &self,
        stream: S,
        tenant: TenantId,
        asked: StreamHandshake,
    ) -> Result<TerminatedStream<S>, StreamHandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let start = LazyConfigAcceptor::new(Acceptor::default(), stream)
            .await
            .map_err(StreamHandshakeError::Tls)?;
        let server_name = server_name_of(&start)?;
        let config = self.config_for(&server_name, tenant, asked)?;
        let stream = start
            .into_stream(config)
            .await
            .map_err(StreamHandshakeError::Tls)?;
        let client_certificate = certificate_of(&stream, asked);
        Ok(TerminatedStream {
            stream,
            server_name,
            client_certificate,
        })
    }

    /// The configuration of a handshake for `server_name` on `tenant`'s
    /// port.
    fn config_for(
        &self,
        server_name: &DomainName,
        tenant: TenantId,
        asked: StreamHandshake,
    ) -> Result<Arc<ServerConfig>, StreamHandshakeError> {
        if self.sources.names.tenant_of(server_name) != Some(tenant) {
            return Err(StreamHandshakeError::NotTheTenants(server_name.clone()));
        }
        let key = self
            .sources
            .certificates
            .find(server_name)
            .ok_or_else(|| StreamHandshakeError::NoCertificate(server_name.clone()))?;
        let builder = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(StreamHandshakeError::Config)?;
        let builder = match asked {
            StreamHandshake::Terminate | StreamHandshake::Tunnel => builder.with_no_client_auth(),
            StreamHandshake::MutualTls => match self.sources.client_auth.of(Some(&tenant)) {
                ClientAuth::Verify(verifier) => builder.with_client_cert_verifier(verifier),
                ClientAuth::Off | ClientAuth::Unbuildable(_) => {
                    return Err(StreamHandshakeError::NoClientAuthorities);
                }
            },
        };
        let mut config = builder.with_cert_resolver(Arc::new(Chosen(key)));
        config.alpn_protocols = asked.protocols();
        Ok(Arc::new(config))
    }
}

/// The name the client asked for, as a domain name.
fn server_name_of<S>(start: &StartHandshake<S>) -> Result<DomainName, StreamHandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    start
        .client_hello()
        .server_name()
        .and_then(|name| DomainName::new(name).ok())
        .ok_or(StreamHandshakeError::NoServerName)
}

/// What a finished handshake made of the client's certificate.
fn certificate_of<S>(stream: &TlsStream<S>, asked: StreamHandshake) -> ClientCertificate {
    match asked {
        StreamHandshake::Terminate | StreamHandshake::Tunnel => ClientCertificate::NotAsked,
        StreamHandshake::MutualTls => leaf_fingerprint(stream)
            .map_or(ClientCertificate::NotPresented, ClientCertificate::Verified),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use ianua_domain::domains::tenant::access::network_security::{MtlsConfig, MtlsMode};
    use ianua_domain::types::{CertificatePem, TenantId};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    use super::{StreamTls, StreamTlsSources};
    use crate::listen::certificates::CertificateTable;
    use crate::listen::certificates::fixtures::{self_signed, served};
    use crate::listen::client_auth::{ClientAuthTable, TenantMtls};
    use crate::listen::tls::fixtures::{Names, provider};

    /// An authority and a client certificate it signed, as PEM.
    pub(crate) struct Authority {
        pub(crate) pem: String,
        pub(crate) client_chain: String,
        pub(crate) client_key: String,
    }

    /// A fresh authority named `name`, with one client certificate.
    pub(crate) fn authority(name: &str) -> Authority {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let certificate = params.self_signed(&key).unwrap();
        let issuer = rcgen::Issuer::from_params(&params, &key);
        let client_key = rcgen::KeyPair::generate().unwrap();
        let mut client_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "a client");
        let client = client_params.signed_by(&client_key, &issuer).unwrap();
        Authority {
            pem: certificate.pem(),
            client_chain: client.pem(),
            client_key: client_key.serialize_pem(),
        }
    }

    pub(crate) fn chain(pem: &str) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn key(pem: &str) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut pem.as_bytes())
            .unwrap()
            .unwrap()
    }

    /// The ports of one tenant serving `name`, and the certificate a
    /// client must trust to reach them.
    pub(crate) struct Ports {
        pub(crate) tenant: TenantId,
        pub(crate) server_chain: String,
        pub(crate) client_auth: Arc<ClientAuthTable>,
        pub(crate) tls: Arc<StreamTls>,
    }

    /// `tenant`'s ports, serving `name` for it, and `other_name` for
    /// another tenant.
    pub(crate) fn ports(tenant: TenantId, name: &str, other_name: &str) -> Ports {
        let names = Names(HashMap::from([
            (name.to_owned(), tenant),
            (other_name.to_owned(), TenantId::new()),
        ]));
        let certificates = Arc::new(CertificateTable::new(provider(), &[]).unwrap());
        let (server_chain, server_key) = self_signed(&[name, other_name]);
        certificates.replace(&[
            served(tenant, name, &server_chain, &server_key),
            served(TenantId::new(), other_name, &server_chain, &server_key),
        ]);
        let client_auth = Arc::new(ClientAuthTable::new(provider()));
        let sources = StreamTlsSources {
            certificates,
            client_auth: Arc::clone(&client_auth),
            names: Arc::new(names),
        };
        Ports {
            tenant,
            server_chain,
            client_auth,
            tls: Arc::new(StreamTls::new(provider(), sources, Duration::from_secs(5))),
        }
    }

    impl Ports {
        /// Has the tenant trust `authority` for client certificates.
        pub(crate) fn trust(&self, authority: &Authority) {
            let authorities = vec![CertificatePem::new(authority.pem.clone()).unwrap()];
            self.client_auth
                .set(&TenantMtls {
                    tenant_id: self.tenant,
                    config: MtlsConfig::new(MtlsMode::Required, authorities).unwrap(),
                })
                .unwrap();
        }

        /// A client trusting the ports' certificate, presenting
        /// `presenting`'s client certificate when given, and offering
        /// `protocols`.
        pub(crate) fn client(
            &self,
            presenting: Option<&Authority>,
            protocols: &[&[u8]],
        ) -> tokio_rustls::TlsConnector {
            let mut roots = RootCertStore::empty();
            for certificate in chain(&self.server_chain) {
                roots.add(certificate).unwrap();
            }
            let builder = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots);
            let mut config = match presenting {
                Some(authority) => builder
                    .with_client_auth_cert(
                        chain(&authority.client_chain),
                        key(&authority.client_key),
                    )
                    .unwrap(),
                None => builder.with_no_client_auth(),
            };
            config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
            tokio_rustls::TlsConnector::from(Arc::new(config))
        }
    }

    /// `name` as a server name a client asks for.
    pub(crate) fn server_name(name: &str) -> ServerName<'static> {
        ServerName::try_from(name.to_owned()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::CertificateFingerprint;
    use sha2::{Digest, Sha256};

    use super::fixtures::{Authority, Ports, authority, chain, ports, server_name};
    use super::*;

    const NAME: &str = "db.acme.test";
    const OTHER: &str = "db.globex.test";

    /// Runs one handshake asking for `sni`, and what the port made of it.
    async fn handshake(
        ports: &Ports,
        sni: &str,
        asked: StreamHandshake,
        presenting: Option<&Authority>,
    ) -> Result<ClientCertificate, StreamHandshakeError> {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let connector = ports.client(presenting, &[]);
        let name = server_name(sni);
        let client = async move {
            let connected = connector.connect(name, client_end).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            connected
        };
        let serving = ports.tls.terminate(server_end, ports.tenant, asked);
        let (served, _) = tokio::join!(serving, client);
        served.map(|terminated| terminated.client_certificate)
    }

    /// The billing device presents a certificate from Acme's authority on
    /// Acme's mutual-TLS port. It is verified, by its leaf's fingerprint.
    #[tokio::test]
    async fn a_certificate_from_the_tenants_authority_is_verified() {
        let ports = ports(TenantId::new(), NAME, OTHER);
        let acme = authority("acme CA");
        ports.trust(&acme);

        let seen = handshake(&ports, NAME, StreamHandshake::MutualTls, Some(&acme))
            .await
            .unwrap();

        let leaf = chain(&acme.client_chain).remove(0);
        let expected = CertificateFingerprint::from_digest(Sha256::digest(leaf.as_ref()).into());
        assert_eq!(seen, ClientCertificate::Verified(expected));
    }

    /// Acme's mutual-TLS handshake fails when the client presents a
    /// certificate from an authority Acme does not trust.
    #[tokio::test]
    async fn a_certificate_from_another_authority_is_refused() {
        let ports = ports(TenantId::new(), NAME, OTHER);
        ports.trust(&authority("acme CA"));

        let refused = handshake(
            &ports,
            NAME,
            StreamHandshake::MutualTls,
            Some(&authority("mallory CA")),
        )
        .await;

        assert!(matches!(refused, Err(StreamHandshakeError::Tls(_))));
    }

    /// A mutual-TLS handshake for a tenant with no configured authorities
    /// fails with the missing-authorities reason.
    #[tokio::test]
    async fn a_tenant_with_no_authorities_refuses_a_mutual_tls_handshake() {
        let ports = ports(TenantId::new(), NAME, OTHER);

        let refused = handshake(&ports, NAME, StreamHandshake::MutualTls, None).await;

        assert!(matches!(
            refused,
            Err(StreamHandshakeError::NoClientAuthorities)
        ));
    }

    /// A TLS handshake asking Acme's port for Globex's name is refused
    /// because the name belongs to another tenant.
    #[tokio::test]
    async fn another_tenants_name_is_refused_on_this_tenants_port() {
        let ports = ports(TenantId::new(), NAME, OTHER);

        let refused = handshake(&ports, OTHER, StreamHandshake::Terminate, None).await;

        assert!(matches!(
            refused,
            Err(StreamHandshakeError::NotTheTenants(_))
        ));
    }

    /// A port that only ends TLS asks for no certificate.
    #[tokio::test]
    async fn a_terminating_port_asks_for_no_certificate() {
        let ports = ports(TenantId::new(), NAME, OTHER);

        let seen = handshake(&ports, NAME, StreamHandshake::Terminate, None)
            .await
            .unwrap();

        assert_eq!(seen, ClientCertificate::NotAsked);
    }
}
