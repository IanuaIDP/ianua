//! The TLS handshake: a certificate for the name the client asked for, and
//! the client-certificate verification of the tenant behind that name.
//!
//! Each handshake reads the ClientHello first, takes its JA4 fingerprint,
//! then lets rustls read it again and choose: the name the client asked
//! for picks the certificate, and the tenant answering on that name picks
//! how client certificates are verified. A configuration is built for
//! that one handshake, so no tenant's authorities ever verify a handshake
//! for another tenant's name.
//!
//! Refused, and closed: a connection that does not open with a ClientHello,
//! one naming no server or a name no certificate is served for, one whose
//! tenant requires client certificates it cannot verify, and one that has
//! not finished its handshake within the timeout.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::types::{CertificateFingerprint, DomainName, TenantId};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::server::{Acceptor, ResolvesServerCert, ServerConfig};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, StartHandshake};

use super::certificates::CertificateTable;
use super::client_auth::{ClientAuth, ClientAuthTable, Demand};
use super::connection::ClientCertificate;
use super::hello::{HelloError, read_client_hello};
use super::ja4::Ja4;
use super::rewind::Rewind;

/// The application protocols offered, HTTP/2 first.
const PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Which tenant answers on a name, as the gateway's host table knows it.
pub(crate) trait ServedNames: Send + Sync {
    /// The tenant answering on `name`, or `None` when none does.
    fn tenant_of(&self, name: &DomainName) -> Option<TenantId>;
}

/// Where a handshake's choices come from.
pub(crate) struct TlsSources {
    /// The certificate for each name.
    pub certificates: Arc<CertificateTable>,
    /// Each tenant's client-certificate verification.
    pub client_auth: Arc<ClientAuthTable>,
    /// The tenant answering on each name.
    pub names: Arc<dyn ServedNames>,
}

/// Ends TLS on accepted connections.
pub(crate) struct TlsTerminator {
    provider: Arc<CryptoProvider>,
    sources: TlsSources,
    handshake: Duration,
}

/// Why a handshake was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HandshakeError {
    /// It did not finish within its timeout.
    #[error("the TLS handshake did not finish in time")]
    TimedOut,
    /// The connection did not open with a readable ClientHello.
    #[error(transparent)]
    Hello(#[from] HelloError),
    /// The client named no server, or not as a domain name.
    #[error("the client named no server")]
    NoServerName,
    /// No certificate is served for the name the client asked for.
    #[error("no certificate is served for {0}")]
    NoCertificate(DomainName),
    /// The tenant requires client certificates and cannot verify any.
    #[error("the tenant requires client certificates and its authorities cannot be used")]
    ClientAuthUnavailable,
    /// The configuration for the handshake could not be built.
    #[error("the TLS configuration could not be built")]
    Config(#[source] tokio_rustls::rustls::Error),
    /// rustls refused the handshake, or the connection failed during it.
    #[error("the TLS handshake failed")]
    Tls(#[source] std::io::Error),
}

/// A connection whose handshake finished, and what it showed.
pub(crate) struct Terminated<S> {
    pub(crate) stream: TlsStream<Rewind<S>>,
    pub(crate) server_name: DomainName,
    pub(crate) client_certificate: ClientCertificate,
    pub(crate) ja4: Ja4,
}

/// What one handshake's configuration asks of the client.
enum Asked {
    Nothing,
    Certificate,
    Unverifiable,
}

impl TlsTerminator {
    /// Ends TLS with what `sources` hold, refusing a handshake that takes
    /// longer than `handshake`.
    #[must_use]
    pub(crate) fn new(
        provider: Arc<CryptoProvider>,
        sources: TlsSources,
        handshake: Duration,
    ) -> Self {
        Self {
            provider,
            sources,
            handshake,
        }
    }

    /// Ends TLS on `stream` within the handshake timeout.
    ///
    /// # Errors
    ///
    /// [`HandshakeError`] when the handshake is refused or takes too long.
    pub(crate) async fn terminate<S>(&self, stream: S) -> Result<Terminated<S>, HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(self.handshake, self.handshake_on(stream))
            .await
            .map_err(|_| HandshakeError::TimedOut)?
    }

    async fn handshake_on<S>(&self, mut stream: S) -> Result<Terminated<S>, HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let recorded = read_client_hello(&mut stream).await?;
        let ja4 = Ja4::of(recorded.hello());
        let rewound = Rewind::new(recorded.into_records(), stream);
        let start = LazyConfigAcceptor::new(Acceptor::default(), rewound)
            .await
            .map_err(HandshakeError::Tls)?;
        let server_name = server_name_of(&start)?;
        let (config, asked) = self.config_for(&server_name)?;
        let stream = start
            .into_stream(config)
            .await
            .map_err(HandshakeError::Tls)?;
        let client_certificate = asked.outcome(&stream);
        Ok(Terminated {
            stream,
            server_name,
            client_certificate,
            ja4,
        })
    }

    /// The configuration for a handshake for `server_name`.
    fn config_for(
        &self,
        server_name: &DomainName,
    ) -> Result<(Arc<ServerConfig>, Asked), HandshakeError> {
        let key = self
            .sources
            .certificates
            .find(server_name)
            .ok_or_else(|| HandshakeError::NoCertificate(server_name.clone()))?;
        let tenant = self.sources.names.tenant_of(server_name);
        let builder = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(HandshakeError::Config)?;
        let (builder, asked) = match self.sources.client_auth.of(tenant.as_ref()) {
            ClientAuth::Off => (builder.with_no_client_auth(), Asked::Nothing),
            ClientAuth::Verify(verifier) => (
                builder.with_client_cert_verifier(verifier),
                Asked::Certificate,
            ),
            ClientAuth::Unbuildable(Demand::Optional) => {
                (builder.with_no_client_auth(), Asked::Unverifiable)
            }
            ClientAuth::Unbuildable(Demand::Required) => {
                return Err(HandshakeError::ClientAuthUnavailable);
            }
        };
        let mut config = builder.with_cert_resolver(Arc::new(Chosen(key)));
        config.alpn_protocols = PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
        Ok((Arc::new(config), asked))
    }
}

/// The name the client asked for, as a domain name.
fn server_name_of<S>(start: &StartHandshake<S>) -> Result<DomainName, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    start
        .client_hello()
        .server_name()
        .and_then(|name| DomainName::new(name).ok())
        .ok_or(HandshakeError::NoServerName)
}

impl Asked {
    fn outcome<S>(&self, stream: &TlsStream<S>) -> ClientCertificate {
        match self {
            Self::Nothing => ClientCertificate::NotAsked,
            Self::Unverifiable => ClientCertificate::Unverifiable,
            Self::Certificate => leaf_fingerprint(stream)
                .map_or(ClientCertificate::NotPresented, ClientCertificate::Verified),
        }
    }
}

/// The SHA-256 fingerprint of the certificate the client presented, which
/// the handshake verified.
pub(super) fn leaf_fingerprint<S>(stream: &TlsStream<S>) -> Option<CertificateFingerprint> {
    let (_, connection) = stream.get_ref();
    let leaf = connection.peer_certificates()?.first()?;
    Some(CertificateFingerprint::from_digest(
        Sha256::digest(leaf.as_ref()).into(),
    ))
}

/// The certificate already chosen for this handshake.
#[derive(Debug)]
pub(super) struct Chosen(pub(super) Arc<CertifiedKey>);

impl ResolvesServerCert for Chosen {
    fn resolve(
        &self,
        _client_hello: tokio_rustls::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use ianua_domain::types::{DomainName, TenantId};
    use tokio_rustls::rustls::crypto::{CryptoProvider, ring};

    use super::{ServedNames, TlsSources, TlsTerminator};
    use crate::listen::certificates::CertificateTable;
    use crate::listen::client_auth::ClientAuthTable;

    /// Names answered by the tenants a test registered.
    #[derive(Default)]
    pub(crate) struct Names(pub(crate) HashMap<String, TenantId>);

    impl ServedNames for Names {
        fn tenant_of(&self, name: &DomainName) -> Option<TenantId> {
            self.0.get(name.as_str()).copied()
        }
    }

    pub(crate) fn provider() -> Arc<CryptoProvider> {
        Arc::new(ring::default_provider())
    }

    /// Empty tables, and a terminator over them.
    pub(crate) fn terminator(
        names: Names,
        handshake: Duration,
    ) -> (Arc<CertificateTable>, Arc<ClientAuthTable>, TlsTerminator) {
        let certificates = Arc::new(CertificateTable::new(provider(), &[]).unwrap());
        let client_auth = Arc::new(ClientAuthTable::new(provider()));
        let sources = TlsSources {
            certificates: Arc::clone(&certificates),
            client_auth: Arc::clone(&client_auth),
            names: Arc::new(names),
        };
        let terminator = TlsTerminator::new(provider(), sources, handshake);
        (certificates, client_auth, terminator)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::tenant::access::network_security::{MtlsConfig, MtlsMode};
    use ianua_domain::types::CertificatePem;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    use super::fixtures::{Names, provider, terminator};
    use super::*;
    use crate::listen::certificates::fixtures::served;
    use crate::listen::client_auth::TenantMtls;

    const HANDSHAKE: Duration = Duration::from_secs(5);
    const TENANT_NAME: &str = "app.acme.test";

    /// A certificate authority and a client certificate it signed.
    struct Authority {
        pem: String,
        client_chain: String,
        client_key: String,
    }

    fn authority(name: &str) -> Authority {
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

    fn mtls(tenant: TenantId, mode: MtlsMode, authority: &Authority) -> TenantMtls {
        let authorities = vec![CertificatePem::new(authority.pem.clone()).unwrap()];
        TenantMtls {
            tenant_id: tenant,
            config: MtlsConfig::new(mode, authorities).unwrap(),
        }
    }

    fn chain(pem: &str) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn key(pem: &str) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut pem.as_bytes())
            .unwrap()
            .unwrap()
    }

    /// A gateway serving `TENANT_NAME` for one tenant, and the certificate
    /// a client must trust to reach it.
    struct Gateway {
        tenant: TenantId,
        server_chain: String,
        client_auth: Arc<ClientAuthTable>,
        terminator: TlsTerminator,
    }

    fn gateway() -> Gateway {
        let tenant = TenantId::new();
        let names = Names(HashMap::from([(TENANT_NAME.to_owned(), tenant)]));
        let (certificates, client_auth, terminator) = terminator(names, HANDSHAKE);
        let (server_chain, server_key) =
            crate::listen::certificates::fixtures::self_signed(&[TENANT_NAME]);
        certificates.replace(&[served(tenant, TENANT_NAME, &server_chain, &server_key)]);
        Gateway {
            tenant,
            server_chain,
            client_auth,
            terminator,
        }
    }

    fn client_config(trusted: &str, presenting: Option<&Authority>) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        for certificate in chain(trusted) {
            roots.add(certificate).unwrap();
        }
        let builder = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let mut config = match presenting {
            Some(authority) => builder
                .with_client_auth_cert(chain(&authority.client_chain), key(&authority.client_key))
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        config
    }

    /// Runs one handshake for `sni` and returns what the gateway made of it.
    async fn handshake(
        gateway: &Gateway,
        sni: &str,
        presenting: Option<&Authority>,
    ) -> Result<Terminated<tokio::io::DuplexStream>, HandshakeError> {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let connector =
            TlsConnector::from(Arc::new(client_config(&gateway.server_chain, presenting)));
        let name = ServerName::try_from(sni.to_owned()).unwrap();
        let client = async move {
            let connected = connector.connect(name, client_end).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            connected
        };
        let (served, _) = tokio::join!(gateway.terminator.terminate(server_end), client);
        served
    }

    /// A name with a certificate is served, and the connection says which
    /// name it was, that no client certificate was asked for, and the
    /// ClientHello's fingerprint.
    #[tokio::test]
    async fn a_served_name_completes_the_handshake() {
        let gateway = gateway();

        let terminated = handshake(&gateway, TENANT_NAME, None).await.unwrap();

        assert_eq!(terminated.server_name.as_str(), TENANT_NAME);
        assert_eq!(terminated.client_certificate, ClientCertificate::NotAsked);
        assert!(terminated.ja4.as_str().starts_with("t13d"));
        assert!(terminated.ja4.as_str()[..10].ends_with("h2"));
    }

    /// A name no certificate is served for is refused, never answered with
    /// another name's certificate.
    #[tokio::test]
    async fn a_name_without_a_certificate_is_refused() {
        let gateway = gateway();

        let refused = handshake(&gateway, "other.acme.test", None).await;

        assert!(matches!(refused, Err(HandshakeError::NoCertificate(_))));
    }

    /// A connection that never sends its ClientHello is given up at the
    /// handshake timeout.
    #[tokio::test]
    async fn a_silent_client_times_out() {
        let (_, _, terminator) = terminator(Names::default(), Duration::from_millis(50));
        let (_client_end, server_end) = tokio::io::duplex(1024);

        let refused = terminator.terminate(server_end).await;

        assert!(matches!(refused, Err(HandshakeError::TimedOut)));
    }

    /// A tenant's own authority's client certificate is verified, and the
    /// connection carries its leaf's fingerprint.
    #[tokio::test]
    async fn a_client_certificate_from_the_tenants_authority_is_verified() {
        let gateway = gateway();
        let tenants_authority = authority("acme CA");
        gateway
            .client_auth
            .set(&mtls(
                gateway.tenant,
                MtlsMode::Required,
                &tenants_authority,
            ))
            .unwrap();

        let terminated = handshake(&gateway, TENANT_NAME, Some(&tenants_authority))
            .await
            .unwrap();

        let leaf = chain(&tenants_authority.client_chain).remove(0);
        let expected = CertificateFingerprint::from_digest(Sha256::digest(leaf.as_ref()).into());
        assert_eq!(
            terminated.client_certificate,
            ClientCertificate::Verified(expected)
        );
    }

    /// A certificate from an authority the tenant does not trust is refused.
    #[tokio::test]
    async fn a_client_certificate_from_another_authority_is_refused() {
        let gateway = gateway();
        gateway
            .client_auth
            .set(&mtls(
                gateway.tenant,
                MtlsMode::Required,
                &authority("acme CA"),
            ))
            .unwrap();

        let refused = handshake(&gateway, TENANT_NAME, Some(&authority("someone else's CA"))).await;

        assert!(matches!(refused, Err(HandshakeError::Tls(_))));
    }

    /// An authority the tenant removed stops verifying at the next
    /// handshake.
    #[tokio::test]
    async fn a_removed_authority_stops_verifying_on_the_next_handshake() {
        let gateway = gateway();
        let old = authority("old CA");
        gateway
            .client_auth
            .set(&mtls(gateway.tenant, MtlsMode::Optional, &old))
            .unwrap();
        let before = handshake(&gateway, TENANT_NAME, Some(&old)).await;

        gateway
            .client_auth
            .set(&mtls(
                gateway.tenant,
                MtlsMode::Optional,
                &authority("new CA"),
            ))
            .unwrap();
        let after = handshake(&gateway, TENANT_NAME, Some(&old)).await;

        assert!(matches!(
            before.map(|terminated| terminated.client_certificate),
            Ok(ClientCertificate::Verified(_))
        ));
        assert!(matches!(after, Err(HandshakeError::Tls(_))));
    }

    /// Optional client certificates: a client presenting none connects,
    /// and the connection says none was presented.
    #[tokio::test]
    async fn an_optional_certificate_may_be_left_out() {
        let gateway = gateway();
        gateway
            .client_auth
            .set(&mtls(
                gateway.tenant,
                MtlsMode::Optional,
                &authority("acme CA"),
            ))
            .unwrap();

        let terminated = handshake(&gateway, TENANT_NAME, None).await.unwrap();

        assert_eq!(
            terminated.client_certificate,
            ClientCertificate::NotPresented
        );
    }

    /// A tenant requiring certificates it cannot verify refuses every
    /// handshake rather than asking for none.
    #[tokio::test]
    async fn an_unbuildable_verifier_refuses_when_required() {
        let gateway = gateway();
        let refused = gateway
            .client_auth
            .set(&unreadable(gateway.tenant, MtlsMode::Required));
        assert!(refused.is_err());

        let refused = handshake(&gateway, TENANT_NAME, None).await;

        assert!(matches!(
            refused,
            Err(HandshakeError::ClientAuthUnavailable)
        ));
    }

    /// A tenant with optional certificates it cannot verify connects, and
    /// the connection says no certificate could be verified.
    #[tokio::test]
    async fn an_unbuildable_verifier_marks_optional_connections_unverifiable() {
        let gateway = gateway();
        let refused = gateway
            .client_auth
            .set(&unreadable(gateway.tenant, MtlsMode::Optional));
        assert!(refused.is_err());

        let terminated = handshake(&gateway, TENANT_NAME, None).await.unwrap();

        assert_eq!(
            terminated.client_certificate,
            ClientCertificate::Unverifiable
        );
    }

    fn unreadable(tenant: TenantId, mode: MtlsMode) -> TenantMtls {
        let pem =
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----";
        TenantMtls {
            tenant_id: tenant,
            config: MtlsConfig::new(mode, vec![CertificatePem::new(pem).unwrap()]).unwrap(),
        }
    }
}
