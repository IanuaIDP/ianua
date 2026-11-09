//! TLS on the gateway's listeners inside the deployment's network: one
//! fixed certificate of the platform's served. Mutual TLS also requires a
//! client certificate of every connection, checked against one authority
//! alone: the connector listener speaks it, and so does the workflow
//! listener. The runner listener asks none, since every request on it
//! carries a proof made with the agent's own key.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ianua_boot::network::PemFiles;
use ianua_domain::shared::security::secret::Secret;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use tokio_rustls::rustls::{self, RootCertStore, ServerConfig};
use tokio_rustls::server::TlsStream;

/// Why a listener's mutual TLS could not be set up.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MutualTlsError {
    /// A file could not be read or holds no PEM that reads.
    #[error("a listener's certificate file cannot be read")]
    Unreadable(#[source] std::io::Error),
    /// The authority's file holds no certificate.
    #[error("the authority's file holds no certificate")]
    NoAuthority,
    /// The listener's certificate file holds no certificate.
    #[error("the listener's certificate file holds no certificate")]
    NoCertificate,
    /// The listener's key file holds no private key.
    #[error("the listener's key file holds no private key")]
    NoPrivateKey,
    /// The client certificate check could not be built.
    #[error("the client certificate check could not be built")]
    Verifier(#[source] VerifierBuilderError),
    /// rustls refused a certificate or the key.
    #[error("the listener's TLS settings were refused")]
    Tls(#[source] rustls::Error),
}

/// What a listener's mutual TLS is made of, as PEM text. The key never
/// prints.
pub(crate) struct ListenerPem {
    /// The authority's certificate, the only one a client's certificate may
    /// chain to.
    pub authority: String,
    /// The listener's certificate chain.
    pub chain: String,
    /// The listener's private key.
    pub key: Secret,
}

impl fmt::Debug for ListenerPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ListenerPem(..)")
    }
}

impl ListenerPem {
    /// The `authority` file and the `certificate` files, read.
    ///
    /// # Errors
    ///
    /// [`MutualTlsError::Unreadable`] when one cannot be read.
    pub(crate) fn read(authority: &Path, certificate: &PemFiles) -> Result<Self, MutualTlsError> {
        let read = |path: &Path| std::fs::read_to_string(path).map_err(MutualTlsError::Unreadable);
        Ok(Self {
            authority: read(authority)?,
            chain: read(&certificate.certificate)?,
            key: Secret::new(read(&certificate.key)?),
        })
    }
}

/// The mutual TLS `pem` describes on `provider`, offering `protocols`.
///
/// # Errors
///
/// Any [`MutualTlsError`].
pub(crate) fn server_config(
    provider: &Arc<CryptoProvider>,
    pem: &ListenerPem,
    protocols: &[&[u8]],
) -> Result<Arc<ServerConfig>, MutualTlsError> {
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(&pem.authority)?),
        Arc::clone(provider),
    )
    .build()
    .map_err(MutualTlsError::Verifier)?;
    let chain = served_chain(&pem.chain)?;
    let mut config = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()
        .map_err(MutualTlsError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, private_key(&pem.key)?)
        .map_err(MutualTlsError::Tls)?;
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// What a listener asking no client certificate serves, as PEM text. The
/// key never prints.
pub(crate) struct ServedPem {
    /// The listener's certificate chain.
    pub chain: String,
    /// The listener's private key.
    pub key: Secret,
}

impl fmt::Debug for ServedPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServedPem(..)")
    }
}

impl ServedPem {
    /// The `certificate` files, read.
    ///
    /// # Errors
    ///
    /// [`MutualTlsError::Unreadable`] when one cannot be read.
    pub(crate) fn read(certificate: &PemFiles) -> Result<Self, MutualTlsError> {
        let read = |path: &Path| std::fs::read_to_string(path).map_err(MutualTlsError::Unreadable);
        Ok(Self {
            chain: read(&certificate.certificate)?,
            key: Secret::new(read(&certificate.key)?),
        })
    }
}

/// TLS serving `pem` on `provider`, offering `protocols`, asking no
/// client certificate.
///
/// # Errors
///
/// [`MutualTlsError::NoCertificate`], [`MutualTlsError::NoPrivateKey`],
/// [`MutualTlsError::Unreadable`] or [`MutualTlsError::Tls`].
pub(crate) fn server_only_config(
    provider: &Arc<CryptoProvider>,
    pem: &ServedPem,
    protocols: &[&[u8]],
) -> Result<Arc<ServerConfig>, MutualTlsError> {
    let mut config = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()
        .map_err(MutualTlsError::Tls)?
        .with_no_client_auth()
        .with_single_cert(served_chain(&pem.chain)?, private_key(&pem.key)?)
        .map_err(MutualTlsError::Tls)?;
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// The certificate chain in `pem`, refused when it holds none.
fn served_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, MutualTlsError> {
    let chain = certificates(pem)?;
    if chain.is_empty() {
        return Err(MutualTlsError::NoCertificate);
    }
    Ok(chain)
}

/// Ends TLS on an internal listener's connections, refusing a handshake
/// that takes longer than its timeout.
pub(crate) struct InternalTls {
    acceptor: TlsAcceptor,
    handshake: Duration,
}

/// Why an internal listener's handshake was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InternalHandshakeError {
    /// It did not finish within its timeout.
    #[error("the TLS handshake did not finish in time")]
    TimedOut,
    /// rustls refused it, a client certificate missing or not the
    /// authority's included, or the connection failed during it.
    #[error("the TLS handshake failed")]
    Tls(#[source] std::io::Error),
}

impl InternalTls {
    /// Ends TLS as `config` says, within `handshake`.
    #[must_use]
    pub(crate) fn new(config: Arc<ServerConfig>, handshake: Duration) -> Self {
        Self {
            acceptor: TlsAcceptor::from(config),
            handshake,
        }
    }

    /// Ends TLS on `stream`.
    ///
    /// # Errors
    ///
    /// [`InternalHandshakeError`] when the handshake is refused or takes too
    /// long.
    pub(crate) async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, InternalHandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(self.handshake, self.acceptor.accept(stream))
            .await
            .map_err(|_| InternalHandshakeError::TimedOut)?
            .map_err(InternalHandshakeError::Tls)
    }
}

/// The certificates of `authority` as the only trust anchors.
fn roots(authority: &str) -> Result<RootCertStore, MutualTlsError> {
    let anchors = certificates(authority)?;
    if anchors.is_empty() {
        return Err(MutualTlsError::NoAuthority);
    }
    let mut store = RootCertStore::empty();
    for anchor in anchors {
        store.add(anchor).map_err(MutualTlsError::Tls)?;
    }
    Ok(store)
}

/// Every certificate in `pem`.
fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, MutualTlsError> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(MutualTlsError::Unreadable)
}

/// The first private key in `key`.
fn private_key(key: &Secret) -> Result<PrivateKeyDer<'static>, MutualTlsError> {
    rustls_pemfile::private_key(&mut key.expose().as_bytes())
        .map_err(MutualTlsError::Unreadable)?
        .ok_or(MutualTlsError::NoPrivateKey)
}
