//! TLS on every connection from its first byte (LDAPS), and the client
//! certificates a person's bind needs.
//!
//! A simple bind carries its password in the clear at the LDAP level, so
//! without TLS every bind, and what a search returns, crosses the wire
//! unencrypted. StartTLS is not offered: implicit TLS protects the same
//! without a plaintext phase a client could be talked out of upgrading.
//!
//! With a client authority, the handshake asks for a client certificate
//! signed by it, but never requires one: an application binding as its
//! service account presents none. A person's bind needs the certificate
//! the handshake checked, and the bind use case decides whether it is one
//! the tenant issued to them.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::ClientCertVerifier;

use crate::config::LdapTls;
use crate::error::LdapError;

/// A TLS acceptor that can be loaded again from its files while the server
/// runs; connections in flight keep the one they started with.
pub struct ReloadableAcceptor {
    current: ArcSwap<TlsAcceptor>,
    files: LdapTls,
}

impl ReloadableAcceptor {
    /// The acceptor `files` describe.
    ///
    /// # Errors
    ///
    /// [`LdapError`] when the certificate, the key or the client authority
    /// cannot be read or make no TLS configuration.
    pub fn new(files: LdapTls) -> Result<Self, LdapError> {
        let acceptor = acceptor(&files)?;
        Ok(Self {
            current: ArcSwap::from_pointee(acceptor),
            files,
        })
    }

    /// The acceptor a newly accepted connection is wrapped by.
    #[must_use]
    pub fn load(&self) -> Arc<TlsAcceptor> {
        self.current.load_full()
    }

    /// Reads the files again. New connections use what was read; when the
    /// files do not read, the acceptor in use is kept and the failure
    /// logged, so a bad renewal does not take the directory offline.
    pub fn reload(&self) {
        match acceptor(&self.files) {
            Ok(acceptor) => {
                self.current.store(Arc::new(acceptor));
                tracing::info!("ldap: TLS certificate reloaded");
            }
            Err(error) => {
                tracing::error!(%error, "ldap: TLS certificate not reloaded, keeping the one in use");
            }
        }
    }
}

/// Reloads `acceptor` on every `SIGHUP` until `stop` is done.
#[cfg(unix)]
pub async fn reload_on_hangup(
    acceptor: Arc<ReloadableAcceptor>,
    stop: impl Future<Output = ()> + Send,
) {
    use tokio::signal::unix::{SignalKind, signal};

    let Ok(mut hangups) = signal(SignalKind::hangup()) else {
        tracing::error!("ldap: SIGHUP cannot be listened for; the certificate is not reloaded");
        return;
    };
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => return,
            _ = hangups.recv() => acceptor.reload(),
        }
    }
}

/// Never reloads: there is no `SIGHUP` off Unix.
#[cfg(not(unix))]
pub async fn reload_on_hangup(
    _acceptor: Arc<ReloadableAcceptor>,
    stop: impl Future<Output = ()> + Send,
) {
    stop.await;
}

/// The acceptor `files` describe.
fn acceptor(files: &LdapTls) -> Result<TlsAcceptor, LdapError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let chain = certificates(&files.certificate, "certificate")?;
    let key = private_key(&files.key)?;
    let builder = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|cause| LdapError::Tls(Box::new(cause)))?;
    let builder = match &files.client_ca {
        Some(authority) => builder.with_client_cert_verifier(client_verifier(authority, provider)?),
        None => builder.with_no_client_auth(),
    };
    let config = builder
        .with_single_cert(chain, key)
        .map_err(|cause| LdapError::Tls(Box::new(cause)))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// A verifier asking for, never requiring, a client certificate signed by
/// the authority in `path`.
fn client_verifier(
    path: &Path,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ClientCertVerifier>, LdapError> {
    let mut roots = RootCertStore::empty();
    for authority in certificates(path, "client authority")? {
        roots.add(authority).map_err(|cause| LdapError::Unusable {
            what: "client authority",
            path: path.to_owned(),
            cause: Box::new(cause),
        })?;
    }
    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .allow_unauthenticated()
        .build()
        .map_err(|cause| LdapError::Tls(Box::new(cause)))
}

/// The certificates in the PEM file at `path`, the server's `what`.
fn certificates(
    path: &Path,
    what: &'static str,
) -> Result<Vec<CertificateDer<'static>>, LdapError> {
    let pem = read(path, what)?;
    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|cause| LdapError::Unusable {
            what,
            path: path.to_owned(),
            cause: Box::new(cause),
        })
}

/// The private key in the PEM file at `path`.
fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>, LdapError> {
    let pem = read(path, "key")?;
    let unusable = |cause: Box<dyn std::error::Error + Send + Sync>| LdapError::Unusable {
        what: "key",
        path: path.to_owned(),
        cause,
    };
    rustls_pemfile::private_key(&mut pem.as_slice())
        .map_err(|cause| unusable(Box::new(cause)))?
        .ok_or_else(|| unusable("the file holds no private key".into()))
}

/// The bytes of the file at `path`, the server's `what`.
fn read(path: &Path, what: &'static str) -> Result<Vec<u8>, LdapError> {
    std::fs::read(path).map_err(|cause| LdapError::Read {
        what,
        path: path.to_owned(),
        cause,
    })
}
