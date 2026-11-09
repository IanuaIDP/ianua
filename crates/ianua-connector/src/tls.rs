//! The TLS a link is opened with: the connector's certificate and key as
//! its client certificate, and the gateway's listener checked against the
//! connector authority alone, never the public roots. A certificate any
//! public authority signed is no gateway of ianua's.

use std::io::BufReader;
use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use time::OffsetDateTime;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::state::Issued;

/// The protocol the link speaks, asked for by ALPN.
pub(crate) const HTTP2: &[u8] = b"h2";

/// Why the link's TLS could not be set up. None of it names the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TlsError(&'static str);

/// What links are opened with now: the TLS settings, and when the
/// certificate in them ends.
#[derive(Clone)]
pub struct Credentials {
    /// The TLS settings.
    pub config: Arc<ClientConfig>,
    /// When the certificate ends; no link is opened with it after.
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// The settings `issued` and `key` make.
    ///
    /// # Errors
    ///
    /// [`TlsError`] naming what does not read: the certificate, the
    /// authority or the key, or a key that does not fit the certificate.
    pub fn of(issued: &Issued, key: &Secret) -> Result<Self, TlsError> {
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for authority in certificates_in(&issued.authority_pem, "the authority does not read")? {
            roots
                .add(authority)
                .map_err(|_| TlsError("the authority is not a certificate it can trust"))?;
        }
        let chain = certificates_in(&issued.certificate_pem, "the certificate does not read")?;
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsError("TLS cannot be set up"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key_in(key)?)
            .map_err(|_| TlsError("the certificate and the key do not fit"))?;
        config.alpn_protocols = vec![HTTP2.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            expires_at: issued.expires_at,
        })
    }

    /// Whether a link may be opened with them at `now`.
    #[must_use]
    pub fn hold_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }
}

/// Every certificate in `pem`, refused as `unreadable` when it holds none.
fn certificates_in(
    pem: &str,
    unreadable: &'static str,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError(unreadable))?;
    if certificates.is_empty() {
        return Err(TlsError(unreadable));
    }
    Ok(certificates)
}

/// The private key `key` holds.
fn key_in(key: &Secret) -> Result<PrivateKeyDer<'static>, TlsError> {
    let unreadable = || TlsError("the key does not read");
    rustls_pemfile::private_key(&mut BufReader::new(key.expose().as_bytes()))
        .map_err(|_| unreadable())?
        .ok_or_else(unreadable)
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use uuid::Uuid;

    use super::*;

    fn issued(certificate_pem: String, authority_pem: String) -> Issued {
        Issued {
            id: Uuid::now_v7(),
            certificate_pem,
            authority_pem,
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            renew_after: OffsetDateTime::now_utc(),
        }
    }

    /// Authority text containing no certificate refuses credential
    /// construction with an unreadable-authority error.
    #[test]
    fn an_authority_that_is_no_certificate_is_refused() {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["c".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();

        let made = Credentials::of(
            &issued(certificate, "not a certificate".to_owned()),
            &Secret::new(key.serialize_pem()),
        );

        assert_eq!(made.unwrap_err(), TlsError("the authority does not read"));
    }

    /// A certificate past its end opens no link.
    #[test]
    fn credentials_hold_until_the_certificate_ends() {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["c".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let made = Credentials::of(
            &issued(certificate.clone(), certificate),
            &Secret::new(key.serialize_pem()),
        )
        .unwrap();

        assert!(made.hold_at(OffsetDateTime::now_utc()));
        assert!(!made.hold_at(made.expires_at));
    }
}
