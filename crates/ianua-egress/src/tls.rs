//! The TLS the egress gateway serves: its own certificate, and a client
//! certificate required of every service, chaining to the authorities it
//! is told to trust. A service is named by the certificate it proved.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use ianua_boot::network::PemFiles;
use ianua_domain::domains::routing::egress::ServiceIdentity;
use ianua_infra::proofs::service_named_by;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig, ServerConnection};

use crate::error::EgressError;

/// An acceptor serving `certificate`, which refuses any service whose
/// client certificate does not chain to an authority in `client_ca`.
///
/// # Errors
///
/// [`EgressError::Tls`] naming what does not read: the certificate, its
/// key, or the authorities.
pub fn acceptor(certificate: &PemFiles, client_ca: &Path) -> Result<TlsAcceptor, EgressError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for authority in certificates_in(client_ca, "the client authorities do not read")? {
        roots.add(authority).map_err(|_| {
            EgressError::Tls("a client authority is not a certificate it can trust")
        })?;
    }
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(|_| EgressError::Tls("no client authority to require certificates against"))?;
    let chain = certificates_in(&certificate.certificate, "the certificate does not read")?;
    let key = key_in(&certificate.key)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| EgressError::Tls("TLS cannot be set up"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| EgressError::Tls("the certificate and its key do not fit"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The service the client certificate of `connection` names, when it
/// presented one that reads.
#[must_use]
pub fn service_of(connection: &ServerConnection) -> Option<ServiceIdentity> {
    let leaf = connection.peer_certificates()?.first()?;
    service_named_by(leaf.as_ref())
}

/// Every certificate in the PEM file at `path`, refused as `unreadable`
/// when it cannot be read or holds none.
fn certificates_in(
    path: &Path,
    unreadable: &'static str,
) -> Result<Vec<CertificateDer<'static>>, EgressError> {
    let file = File::open(path).map_err(|_| EgressError::Tls(unreadable))?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| EgressError::Tls(unreadable))?;
    if certificates.is_empty() {
        return Err(EgressError::Tls(unreadable));
    }
    Ok(certificates)
}

/// The private key in the PEM file at `path`.
fn key_in(path: &Path) -> Result<PrivateKeyDer<'static>, EgressError> {
    let unreadable = || EgressError::Tls("the certificate's key does not read");
    let file = File::open(path).map_err(|_| unreadable())?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|_| unreadable())?
        .ok_or_else(unreadable)
}
