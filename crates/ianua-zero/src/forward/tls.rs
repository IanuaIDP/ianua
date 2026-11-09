//! How TLS to a backend is set up: which authorities its certificate must
//! chain to, which name it is checked against, and which certificate the
//! gateway presents when the backend asks for one.
//!
//! Verification is never switched off. A backend on a private PKI names
//! the CA that signed it, and then only that CA is trusted for it.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use hyper_rustls::ConfigBuilderExt;
use ianua_domain::domains::routing::backend::tls::{UpstreamTls, UpstreamTrust};
use ianua_domain::types::{CertificatePem, ServiceId};
use tokio_rustls::rustls::client::WantsClientCert;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ConfigBuilder, RootCertStore, WantsVerifier};

use super::error::PoolError;

/// The private key of the certificate a service presents to its backends,
/// opened from its seal by the caller. It never prints.
pub(crate) struct ClientKey(PrivateKeyDer<'static>);

impl ClientKey {
    /// The first private key in `pem`.
    ///
    /// # Errors
    ///
    /// - [`PoolError::NoPrivateKey`] when `pem` holds none.
    /// - [`PoolError::UnreadablePem`] when it cannot be read.
    pub(crate) fn from_pem(pem: &[u8]) -> Result<Self, PoolError> {
        let mut text = pem;
        match rustls_pemfile::private_key(&mut text) {
            Ok(Some(key)) => Ok(Self(key)),
            Ok(None) => Err(PoolError::NoPrivateKey),
            Err(error) => Err(PoolError::UnreadablePem(error)),
        }
    }
}

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientKey(..)")
    }
}

/// The opened client keys of a tenant's services, by service.
#[derive(Debug, Default)]
pub(crate) struct ClientKeys(HashMap<ServiceId, ClientKey>);

impl ClientKeys {
    /// No keys: every service presenting a client certificate is refused.
    #[must_use]
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// Hands in the key `service_id` presents with its certificate.
    pub(crate) fn insert(&mut self, service_id: ServiceId, key: ClientKey) {
        self.0.insert(service_id, key);
    }

    /// The key `service_id` presents, when one was handed in.
    pub(super) fn get(&self, service_id: &ServiceId) -> Option<&ClientKey> {
        self.0.get(service_id)
    }
}

/// TLS for a backend that asks for nothing special: the public roots, no
/// client certificate.
pub(super) fn public_roots() -> Result<ClientConfig, PoolError> {
    Ok(verifying()?.with_webpki_roots().with_no_client_auth())
}

/// TLS as `tls` asks, presenting `key` with its certificate.
///
/// # Errors
///
/// - [`PoolError::ClientKeyMissing`] when a certificate is to be presented
///   and `key` is `None`.
/// - [`PoolError::NoCertificate`] or [`PoolError::UnreadablePem`] when a
///   bundle cannot be read.
/// - [`PoolError::Tls`] when rustls refuses a certificate or the key.
pub(super) fn client_config(
    tls: &UpstreamTls,
    key: Option<&ClientKey>,
) -> Result<ClientConfig, PoolError> {
    let trusting = trusting(tls.trust())?;
    let Some(identity) = tls.client_certificate() else {
        return Ok(trusting.with_no_client_auth());
    };
    let Some(key) = key else {
        return Err(PoolError::ClientKeyMissing);
    };
    let chain = certificates(identity.certificate())?;
    trusting
        .with_client_auth_cert(chain, key.0.clone_key())
        .map_err(PoolError::Tls)
}

/// The name the backend's certificate is checked against, when it is not
/// the host in its address.
///
/// # Errors
///
/// - [`PoolError::ServerName`] when the name cannot be sent.
pub(super) fn server_name(tls: &UpstreamTls) -> Result<Option<ServerName<'static>>, PoolError> {
    let Some(name) = tls.server_name() else {
        return Ok(None);
    };
    ServerName::try_from(name.as_str().to_owned())
        .map(Some)
        .map_err(PoolError::ServerName)
}

/// A configuration on the ring provider and its safe protocol versions.
fn verifying() -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, PoolError> {
    ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(PoolError::Tls)
}

/// A configuration trusting the authorities `trust` names, and only them.
fn trusting(
    trust: &UpstreamTrust,
) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>, PoolError> {
    let builder = verifying()?;
    match trust {
        UpstreamTrust::PublicRoots => Ok(builder.with_webpki_roots()),
        UpstreamTrust::PrivateCa(bundle) => Ok(builder.with_root_certificates(roots(bundle)?)),
    }
}

/// The certificates of `bundle` as trust anchors.
fn roots(bundle: &CertificatePem) -> Result<RootCertStore, PoolError> {
    let mut store = RootCertStore::empty();
    for certificate in certificates(bundle)? {
        store.add(certificate).map_err(PoolError::Tls)?;
    }
    Ok(store)
}

/// Every certificate in `pem`, at least one.
fn certificates(pem: &CertificatePem) -> Result<Vec<CertificateDer<'static>>, PoolError> {
    let mut text = pem.as_str().as_bytes();
    let found = rustls_pemfile::certs(&mut text)
        .collect::<Result<Vec<_>, _>>()
        .map_err(PoolError::UnreadablePem)?;
    if found.is_empty() {
        return Err(PoolError::NoCertificate);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::backend::tls::UpstreamTlsParams;
    use ianua_domain::types::{DomainName, Setting};

    use super::*;

    fn private_ca() -> CertificatePem {
        let names = vec!["orders.internal".to_owned()];
        let issued = rcgen::generate_simple_self_signed(names).unwrap();
        CertificatePem::new(issued.cert.pem()).unwrap()
    }

    fn tls(trust: UpstreamTrust, server_name: Setting<DomainName>) -> UpstreamTls {
        UpstreamTls::new(UpstreamTlsParams {
            trust,
            client_certificate: Setting::Unset,
            server_name,
        })
        .unwrap()
    }

    #[test]
    fn a_backend_on_a_private_ca_is_trusted_through_it() {
        let settings = tls(UpstreamTrust::PrivateCa(private_ca()), Setting::Unset);

        assert!(client_config(&settings, None).is_ok());
    }

    #[test]
    fn the_public_roots_need_nothing_handed_in() {
        assert!(public_roots().is_ok());
    }

    #[test]
    fn a_server_name_is_sent_in_place_of_the_host() {
        let name = DomainName::new("orders.internal").unwrap();
        let settings = tls(UpstreamTrust::PublicRoots, Setting::Set(name));

        let sent = server_name(&settings).unwrap().unwrap();

        assert_eq!(sent.to_str(), "orders.internal");
    }

    #[test]
    fn a_key_is_read_from_its_pem() {
        let issued = rcgen::generate_simple_self_signed(vec!["gateway".to_owned()]).unwrap();

        let key = ClientKey::from_pem(issued.signing_key.serialize_pem().as_bytes());

        assert!(key.is_ok());
        assert_eq!(format!("{:?}", key.unwrap()), "ClientKey(..)");
    }

    #[test]
    fn text_without_a_key_is_refused() {
        let refused = ClientKey::from_pem(b"not a key");

        assert!(matches!(refused, Err(PoolError::NoPrivateKey)));
    }
}
