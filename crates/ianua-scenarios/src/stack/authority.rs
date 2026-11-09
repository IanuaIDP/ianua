//! The stack's own certificate authority, made fresh for each stack, the
//! certificate the ingress serves for the stack's domain and every name
//! under it, and the certificates it issues for the gateway: the platform's
//! own for the domain tenants' apps sit under, and one for each domain a
//! tenant brings, which the tenant uploads as a customer would.
//!
//! Clients trust this authority and nothing else, so an answer that did
//! not come through the stack's ingress or its gateway cannot pass for one
//! that did.

use std::fmt;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::StackError;

/// The protocols the ingress offers, HTTP/2 first.
const PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// A certificate the authority issued and its key, both as PEM. `Debug`
/// shows no key.
#[derive(Clone)]
pub struct Issued {
    chain: String,
    key: String,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued").finish_non_exhaustive()
    }
}

impl Issued {
    /// The certificate followed by the authority's, as PEM.
    #[must_use]
    pub fn chain_pem(&self) -> &str {
        &self.chain
    }

    /// The certificate's private key, as PKCS #8 PEM.
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key
    }
}

/// The authority and what the ingress serves under it.
pub(crate) struct Authority {
    root: CertifiedIssuer<'static, KeyPair>,
    server: Arc<ServerConfig>,
}

impl Authority {
    /// Signs a verified CSR only for the names the ACME order authorized.
    /// The returned chain uses the request's key, never a replacement key.
    pub(crate) fn sign_request(&self, der: &[u8], names: &[String]) -> Result<String, StackError> {
        let request = CertificateSigningRequestParams::from_der(&der.into())?;
        let mut requested: Vec<_> = request
            .params
            .subject_alt_names
            .iter()
            .map(|name| match name {
                SanType::DnsName(name) => name.to_string(),
                _ => String::new(),
            })
            .collect();
        requested.sort();
        let mut expected = names.to_vec();
        expected.sort();
        if requested != expected {
            return Err(StackError::Certificate(
                rcgen::Error::CouldNotParseCertificationRequest,
            ));
        }
        let issued = request.signed_by(&self.root)?;
        Ok(format!("{}{}", issued.pem(), self.root.pem()))
    }

    /// A new authority and a certificate it signed for `base_domain` and
    /// `*.base_domain`, which the ingress serves.
    ///
    /// # Errors
    ///
    /// [`StackError::Certificate`] when a certificate cannot be made, and
    /// [`StackError::Tls`] when TLS will not take it.
    pub(crate) fn for_domain(base_domain: &str) -> Result<Self, StackError> {
        let root = root()?;
        let leaf_key = KeyPair::generate()?;
        let served = leaf(&[base_domain.to_owned(), format!("*.{base_domain}")])?
            .signed_by(&leaf_key, &*root)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let chain = vec![served.der().clone(), root.der().clone()];
        let mut server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        server.alpn_protocols = PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
        Ok(Self {
            root,
            server: Arc::new(server),
        })
    }

    /// A certificate for `domain` and every name one label under it, for
    /// serving.
    ///
    /// # Errors
    ///
    /// [`StackError::Certificate`] when it cannot be made.
    pub(crate) fn issue_wildcard(&self, domain: &str) -> Result<Issued, StackError> {
        self.issue(&[domain.to_owned(), format!("*.{domain}")])
    }

    /// A certificate for exactly `names`, for serving.
    ///
    /// # Errors
    ///
    /// [`StackError::Certificate`] when it cannot be made.
    pub(crate) fn issue(&self, names: &[String]) -> Result<Issued, StackError> {
        let key = KeyPair::generate()?;
        let issued = leaf(names)?.signed_by(&key, &*self.root)?;
        Ok(Issued {
            chain: format!("{}{}", issued.pem(), self.root.pem()),
            key: key.serialize_pem(),
        })
    }

    /// The authority's certificate, for clients to trust.
    pub(crate) fn root_pem(&self) -> String {
        self.root.pem()
    }

    /// The TLS the ingress serves.
    pub(crate) fn server(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.server)
    }
}

/// The authority's own certificate, signed by itself.
fn root() -> Result<CertifiedIssuer<'static, KeyPair>, StackError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "ianua scenarios authority");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
}

/// What a certificate for `names` says, for serving: the first name as its
/// common name.
fn leaf(names: &[String]) -> Result<CertificateParams, StackError> {
    let mut params = CertificateParams::new(names.to_vec())?;
    if let Some(first) = names.first() {
        params
            .distinguished_name
            .push(DnType::CommonName, first.as_str());
    }
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    Ok(params)
}
