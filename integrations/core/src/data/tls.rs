//! TLS from the worker to the system behind a stream route, checked against
//! the system's own certificate: chaining to the authority the route's
//! login names, or to the public roots, and naming the system.

use std::fmt;
use std::sync::Arc;

use ianua_domain::shared::errors::DomainError;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::data::DataStream;

/// How the connection to the system is protected, as the route's login
/// says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataTls {
    /// TLS, the system's certificate checked as this says.
    Required(TlsCheck),
    /// None: the company chose a system serving no TLS.
    Off,
}

/// How the system's certificate is checked.
#[derive(Clone, PartialEq, Eq)]
pub struct TlsCheck {
    authority: Option<String>,
    server_name: String,
}

impl TlsCheck {
    /// A certificate naming `server_name`, chaining to `authority`, a PEM
    /// of one or more certificates, or to the public roots when none is
    /// given.
    #[must_use]
    pub fn new(authority: Option<String>, server_name: String) -> Self {
        Self {
            authority,
            server_name,
        }
    }

    /// The authority's PEM, when not the public roots.
    #[must_use]
    pub fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }

    /// The name the certificate must be for.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

impl fmt::Debug for TlsCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCheck")
            .field("authority", &self.authority.as_ref().map(|_| "<given>"))
            .field("server_name", &self.server_name)
            .finish()
    }
}

/// The TLS a connection to the system speaks.
#[derive(Clone)]
pub struct TlsClient {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl TlsClient {
    /// The client checking the system's certificate as `check` says.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the authority holds no certificate that
    /// reads, or the server name is neither a host name nor an address.
    pub fn checking(check: &TlsCheck) -> Result<Self, DomainError> {
        let server_name = ServerName::try_from(check.server_name.clone())
            .map_err(|_| DomainError::infra_msg("the system's name is not a host name"))?;
        let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(DomainError::infra)?
            .with_root_certificates(roots(check.authority())?)
            .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }

    /// The settings a TLS library is built from.
    #[must_use]
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
    }

    /// The name the certificate is checked for.
    #[must_use]
    pub fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }

    /// `stream` inside TLS from its first byte, once the system's
    /// certificate is checked.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the handshake fails, as it does for a
    /// certificate not the one asked for or a system speaking no TLS.
    pub async fn wrapped<S>(&self, stream: S) -> Result<Box<dyn DataStream>, DomainError>
    where
        S: DataStream + 'static,
    {
        let tls = TlsConnector::from(Arc::clone(&self.config))
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(DomainError::infra)?;
        Ok(Box::new(tls))
    }
}

impl fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsClient")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// The certificates the system's must chain to: those in `authority`, or
/// the public roots when none is given.
fn roots(authority: Option<&str>) -> Result<RootCertStore, DomainError> {
    let Some(authority) = authority else {
        return Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    };
    let mut roots = RootCertStore::empty();
    for anchor in CertificateDer::pem_slice_iter(authority.as_bytes()) {
        roots
            .add(anchor.map_err(DomainError::infra)?)
            .map_err(DomainError::infra)?;
    }
    if roots.is_empty() {
        return Err(DomainError::infra_msg(
            "the system's authority holds no certificate",
        ));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    use super::*;

    /// A database's private authority, and what it signs.
    struct Authority {
        pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn authority() -> Authority {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let pem = params.self_signed(&key).unwrap().pem();
        Authority {
            pem,
            issuer: Issuer::new(params, key),
        }
    }

    /// A database serving TLS for `name` under `authority`, answering `ok`
    /// to the first byte it reads.
    fn database(authority: &Authority, name: &str) -> TlsAcceptor {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        let certificate = params.signed_by(&key, &authority.issuer).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    /// What the worker reads back over TLS checked as `check` says from a
    /// database `acceptor` serves, or why the handshake failed.
    async fn exchanged(acceptor: TlsAcceptor, check: &TlsCheck) -> Result<Vec<u8>, DomainError> {
        let (near, far) = duplex(16 * 1024);
        tokio::spawn(async move {
            let Ok(mut served) = acceptor.accept(far).await else {
                return;
            };
            let mut asked = [0; 1];
            drop(served.read_exact(&mut asked).await);
            drop(served.write_all(b"ok").await);
            drop(served.flush().await);
        });
        let mut stream = TlsClient::checking(check)?.wrapped(near).await?;
        stream.write_all(b"?").await.map_err(DomainError::infra)?;
        let mut answer = vec![0; 2];
        stream
            .read_exact(&mut answer)
            .await
            .map_err(DomainError::infra)?;
        Ok(answer)
    }

    /// Ann's orders database serves a certificate from her own authority
    /// for `db.internal`. A login naming both reaches it.
    #[tokio::test]
    async fn the_database_named_under_its_authority_is_reached() {
        let ca = authority();

        let answer = exchanged(
            database(&ca, "db.internal"),
            &TlsCheck::new(Some(ca.pem.clone()), "db.internal".to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(answer, b"ok");
    }

    /// A server certificate from another authority makes the checked TLS
    /// exchange fail.
    #[tokio::test]
    async fn a_certificate_from_another_authority_is_refused() {
        let ca = authority();

        let answer = exchanged(
            database(&authority(), "db.internal"),
            &TlsCheck::new(Some(ca.pem.clone()), "db.internal".to_owned()),
        )
        .await;

        assert!(answer.is_err());
    }

    /// A trusted authority's certificate for a different host still makes
    /// the TLS exchange fail.
    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let ca = authority();

        let answer = exchanged(
            database(&ca, "billing.internal"),
            &TlsCheck::new(Some(ca.pem.clone()), "db.internal".to_owned()),
        )
        .await;

        assert!(answer.is_err());
    }

    /// Without a configured private authority, a private certificate fails
    /// verification against the public roots.
    #[tokio::test]
    async fn a_private_certificate_fails_the_public_roots() {
        let ca = authority();

        let answer = exchanged(
            database(&ca, "db.internal"),
            &TlsCheck::new(None, "db.internal".to_owned()),
        )
        .await;

        assert!(answer.is_err());
    }

    /// A plaintext database reply fails the required TLS handshake.
    #[tokio::test]
    async fn a_database_without_tls_is_refused() {
        let ca = authority();
        let (near, mut far) = duplex(1024);
        tokio::spawn(async move {
            let mut asked = vec![0; 512];
            drop(far.read(&mut asked).await);
            drop(far.write_all(b"-ERR plain\r\n").await);
        });
        let check = TlsCheck::new(Some(ca.pem.clone()), "db.internal".to_owned());

        let stream = TlsClient::checking(&check).unwrap().wrapped(near).await;

        assert!(stream.is_err());
    }

    /// An authority holding no certificate is refused, rather than trusting
    /// nothing in silence.
    #[test]
    fn an_empty_authority_is_refused() {
        let check = TlsCheck::new(
            Some("not a certificate".to_owned()),
            "db.internal".to_owned(),
        );

        assert!(TlsClient::checking(&check).is_err());
    }
}
