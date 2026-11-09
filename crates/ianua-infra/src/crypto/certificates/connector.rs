//! The platform's connector authority: the private authority the
//! connectors inside tenants' networks and the gateway's connector
//! listener authenticate each other with.
//!
//! Private on purpose, as the nameserver link's is: a public root would let
//! any certificate on the internet open a link. The authority signs two
//! kinds of leaf. The gateway's listener gets a server certificate, issued
//! once by `ianua connector-pki`. Each connector gets a client certificate
//! for a day, signed from its own signing request: only the request's key
//! is taken from it, whatever else it asks for is dropped, and the
//! certificate names its tenant and connector in one URI,
//! `urn:ianua:connector:<tenant>:<connector>`. The gateway reads that name
//! back with [`connector_identity`] and lets the link in only when the
//! tenant's connector holds the same key.

use std::fmt;

use async_trait::async_trait;
use der::Decode as _;
use der::asn1::ObjectIdentifier;
use ianua_app::ports::routing::{ConnectorAuthority, ConnectorIssue, IssuedConnectorCertificate};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, CertificateRequestPem, ConnectorId, PublicKeyPin, TenantId,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData as _,
    SanType,
};
use sha2::{Digest as _, Sha256};
use time::Duration;
use uuid::Uuid;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use crate::crypto::certificates::ldap::fresh_serial;
use crate::crypto::certificates::link::KeyedCertificate;

/// What every connector's name begins with.
const CONNECTOR_URN: &str = "urn:ianua:connector:";

/// The subject alternative name extension.
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// How far before its issue a connector's certificate starts, so a gateway
/// whose clock runs a little behind the API's still takes it.
const CLOCK_SKEW: Duration = Duration::minutes(5);

/// Why the authority could not be set up. None of it names the key.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorCaError {
    /// The authority's key is not one this build reads.
    #[error("the connector authority's key is not a key this build reads; convert it to PKCS#8")]
    BadKey,
    /// The authority's certificate cannot be read.
    #[error("the connector authority's certificate cannot be read")]
    BadCertificate,
}

/// The authority, loaded from its certificate and key.
pub struct RcgenConnectorAuthority {
    issuer: Issuer<'static, KeyPair>,
    authority_pem: String,
}

impl fmt::Debug for RcgenConnectorAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RcgenConnectorAuthority(<key redacted>)")
    }
}

impl RcgenConnectorAuthority {
    /// The authority whose certificate is `certificate` and key `key`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorCaError`] when either cannot be read.
    pub fn new(certificate: &CertificatePem, key: &Secret) -> Result<Self, ConnectorCaError> {
        let key = KeyPair::from_pem(key.expose()).map_err(|_| ConnectorCaError::BadKey)?;
        let issuer = Issuer::from_ca_cert_pem(certificate.as_str(), key)
            .map_err(|_| ConnectorCaError::BadCertificate)?;
        Ok(Self {
            issuer,
            authority_pem: certificate.as_str().to_owned(),
        })
    }
}

#[async_trait]
impl ConnectorAuthority for RcgenConnectorAuthority {
    fn key_of(&self, request: &CertificateRequestPem) -> Result<PublicKeyPin, DomainError> {
        read_request(request).map(|read| pin_of(&read))
    }

    async fn issue(
        &self,
        issue: ConnectorIssue<'_>,
    ) -> Result<IssuedConnectorCertificate, DomainError> {
        let read = read_request(issue.request)?;
        if pin_of(&read) != *issue.certificate.key() {
            return Err(DomainError::invalid(message!(
                "infra-the-signing-request-names-another-key",
                "the signing request names another key than the connector enrolled with"
            )));
        }
        let signing = CertificateSigningRequestParams {
            params: connector_params(&issue)?,
            public_key: read.public_key,
        };
        let certificate = signing
            .signed_by(&self.issuer)
            .map_err(DomainError::infra)?;
        Ok(IssuedConnectorCertificate {
            certificate_pem: certificate.pem(),
            authority_pem: self.authority_pem.clone(),
        })
    }
}

/// A connector certificate asked for where no authority is set up.
#[derive(Debug, thiserror::Error)]
#[error("no connector authority is set up, so no connector can enroll or renew")]
struct NoAuthority;

/// The authority of a deployment that set none up: every request is
/// refused, so no connector enrolls and the services behind connectors
/// stay unreachable.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnectorAuthority;

#[async_trait]
impl ConnectorAuthority for NoConnectorAuthority {
    fn key_of(&self, _request: &CertificateRequestPem) -> Result<PublicKeyPin, DomainError> {
        Err(DomainError::infra(NoAuthority))
    }

    async fn issue(
        &self,
        _issue: ConnectorIssue<'_>,
    ) -> Result<IssuedConnectorCertificate, DomainError> {
        Err(DomainError::infra(NoAuthority))
    }
}

/// Who a connector certificate says it is: the tenant and connector it
/// names, and the key it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorIdentity {
    /// The tenant the connector belongs to.
    pub tenant: TenantId,
    /// Enrolled identity claimed by the certificate's URI.
    pub connector: ConnectorId,
    /// The pin of the key the certificate carries.
    pub key: PublicKeyPin,
}

/// Who the connector certificate `leaf_der` names.
///
/// Read only after the TLS layer checked the certificate chains to the
/// connector authority and is good now: the name is believed because the
/// authority wrote it.
///
/// # Errors
///
/// Returns `DomainError::Forbidden` when the certificate does not read, or
/// names no connector or more than one.
pub fn connector_identity(leaf_der: &[u8]) -> Result<ConnectorIdentity, DomainError> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|_| DomainError::forbidden("the certificate does not read"))?;
    let (tenant, connector) = named_connector(&leaf)?;
    let key = leaf
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| DomainError::forbidden("the certificate's key does not read"))?;
    Ok(ConnectorIdentity {
        tenant,
        connector,
        key: PublicKeyPin::from_digest(Sha256::digest(key).into()),
    })
}

/// How long the connector authority and the listener's certificate are
/// good for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorPkiValidity {
    /// The authority's lifetime. Long, as replacing it means every
    /// connector enrolling again.
    pub authority: Duration,
    /// The gateway listener's certificate's lifetime.
    pub listener: Duration,
}

impl Default for ConnectorPkiValidity {
    /// Ten years for the authority, one for the listener.
    fn default() -> Self {
        Self {
            authority: Duration::days(3_650),
            listener: Duration::days(365),
        }
    }
}

/// The connector authority and the gateway listener's certificate.
#[derive(Debug)]
pub struct ConnectorPki {
    /// The authority. Its key signs every connector's certificate and is
    /// held by the API alone; its certificate goes to the gateway.
    pub authority: KeyedCertificate,
    /// The gateway's connector listener.
    pub listener: KeyedCertificate,
}

/// Issues a fresh connector authority and the gateway listener's
/// certificate for `listener_names`, each a hostname or an address the
/// connectors dial.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a key cannot be made or
/// signed, no name is given, or a name is neither a hostname nor an
/// address.
pub fn issue_connector_pki(
    listener_names: &[String],
    validity: ConnectorPkiValidity,
) -> Result<ConnectorPki, DomainError> {
    if listener_names.is_empty() {
        return Err(DomainError::infra_msg(
            "the connector listener needs at least one name",
        ));
    }
    let (params, key, authority_pem) = authority(validity.authority)?;
    let authority_key = Secret::new(key.serialize_pem());
    let issuer = Issuer::new(params, key);
    let listener = listener_certificate(&issuer, listener_names, validity.listener)?;
    Ok(ConnectorPki {
        authority: KeyedCertificate {
            certificate_pem: authority_pem,
            private_key_pem: authority_key,
        },
        listener,
    })
}

/// The request `request` holds, its signature checked.
fn read_request(
    request: &CertificateRequestPem,
) -> Result<CertificateSigningRequestParams, DomainError> {
    CertificateSigningRequestParams::from_pem(request.as_str()).map_err(|_| {
        DomainError::invalid(
            message!("infra-the-signing-request-does-not-read", "the signing request does not read, asks for an extension, or its signature does not hold"),
        )
    })
}

/// The pin of the key `request` names.
fn pin_of(request: &CertificateSigningRequestParams) -> PublicKeyPin {
    PublicKeyPin::from_digest(Sha256::digest(request.public_key.der_bytes()).into())
}

/// What a connector's certificate is made of: its name, its dates, and a
/// use for client authentication alone.
fn connector_params(issue: &ConnectorIssue<'_>) -> Result<CertificateParams, DomainError> {
    let name = connector_name(&issue.tenant, &issue.connector);
    let mut params = CertificateParams::default();
    params.distinguished_name = common_name(&issue.connector.to_string());
    params.subject_alt_names = vec![SanType::URI(name.try_into().map_err(DomainError::infra)?)];
    params.not_before = clock::now().saturating_sub(CLOCK_SKEW);
    params.not_after = issue.certificate.expires_at();
    params.serial_number = Some(fresh_serial()?);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    Ok(params)
}

/// The URI a connector's certificate names it by.
fn connector_name(tenant: &TenantId, connector: &ConnectorId) -> String {
    format!(
        "{CONNECTOR_URN}{}:{}",
        tenant.as_uuid().simple(),
        connector.as_uuid().simple()
    )
}

/// The tenant and connector the one URI of `leaf` names.
fn named_connector(leaf: &Certificate) -> Result<(TenantId, ConnectorId), DomainError> {
    let Some(extension) = leaf
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == SUBJECT_ALT_NAME)
    else {
        return Err(DomainError::forbidden("the certificate names no connector"));
    };
    let names = SubjectAltName::from_der(extension.extn_value.as_bytes())
        .map_err(|_| DomainError::forbidden("the certificate's names do not read"))?;
    let mut uris = names.0.iter().filter_map(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
        GeneralName::OtherName(_)
        | GeneralName::Rfc822Name(_)
        | GeneralName::DnsName(_)
        | GeneralName::DirectoryName(_)
        | GeneralName::EdiPartyName(_)
        | GeneralName::IpAddress(_)
        | GeneralName::RegisteredId(_) => None,
    });
    let (Some(uri), None) = (uris.next(), uris.next()) else {
        return Err(DomainError::forbidden(
            "a connector certificate names exactly one URI",
        ));
    };
    parsed_name(uri)
        .ok_or_else(|| DomainError::forbidden("the certificate's URI names no connector"))
}

/// The tenant and connector `uri` names, when it is a connector's name.
fn parsed_name(uri: &str) -> Option<(TenantId, ConnectorId)> {
    let (tenant, connector) = uri.strip_prefix(CONNECTOR_URN)?.split_once(':')?;
    Some((
        TenantId::from_uuid(Uuid::try_parse(tenant).ok()?),
        ConnectorId::from_uuid(Uuid::try_parse(connector).ok()?),
    ))
}

/// The authority, able to sign leaves and no further authority.
fn authority(lifetime: Duration) -> Result<(CertificateParams, KeyPair, String), DomainError> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(fresh_serial()?);
    let now = clock::now();
    params.not_before = now;
    params.not_after = now.saturating_add(lifetime);
    params.distinguished_name = common_name("Ianua connector authority");
    let key = KeyPair::generate().map_err(DomainError::infra)?;
    let pem = params.self_signed(&key).map_err(DomainError::infra)?.pem();
    Ok((params, key, pem))
}

/// The gateway listener's certificate for `names`, for serving alone.
fn listener_certificate(
    issuer: &Issuer<'_, KeyPair>,
    names: &[String],
    lifetime: Duration,
) -> Result<KeyedCertificate, DomainError> {
    let mut params = CertificateParams::default();
    params.serial_number = Some(fresh_serial()?);
    let now = clock::now();
    params.not_before = now;
    params.not_after = now.saturating_add(lifetime);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = common_name("Ianua connector listener");
    params.subject_alt_names = names
        .iter()
        .map(|name| subject_name(name))
        .collect::<Result<_, _>>()?;
    let key = KeyPair::generate().map_err(DomainError::infra)?;
    let certificate_pem = params
        .signed_by(&key, issuer)
        .map_err(DomainError::infra)?
        .pem();
    Ok(KeyedCertificate {
        certificate_pem,
        private_key_pem: Secret::new(key.serialize_pem()),
    })
}

/// A subject naming `name` alone.
fn common_name(name: &str) -> DistinguishedName {
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    subject
}

/// The name a listener certificate is checked against: an address entry
/// when `name` reads as one, a hostname entry otherwise. An address written
/// as a hostname entry is checked against nothing, and the failure says
/// only "invalid peer certificate".
pub(super) fn subject_name(name: &str) -> Result<SanType, DomainError> {
    if let Ok(address) = name.parse() {
        return Ok(SanType::IpAddress(address));
    }
    let host = name.try_into().map_err(DomainError::infra)?;
    Ok(SanType::DnsName(host))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::connector::certificate::ConnectorCertificate;

    use super::*;
    use crate::crypto::certificates::pem::certificate_in;

    /// A fresh authority and its loaded signer.
    fn authority() -> (ConnectorPki, RcgenConnectorAuthority) {
        let pki = issue_connector_pki(
            &["connect.ianua.test".to_owned()],
            ConnectorPkiValidity::default(),
        )
        .unwrap();
        let signer = RcgenConnectorAuthority::new(
            &CertificatePem::new(pki.authority.certificate_pem.clone()).unwrap(),
            &pki.authority.private_key_pem,
        )
        .unwrap();
        (pki, signer)
    }

    /// A signing request from `key`, asking for more than it gets.
    fn request(key: &KeyPair) -> CertificateRequestPem {
        let mut params = CertificateParams::new(vec!["admin.acme.example".to_owned()]).unwrap();
        params.distinguished_name = common_name("admin");
        CertificateRequestPem::new(params.serialize_request(key).unwrap().pem().unwrap()).unwrap()
    }

    /// `pem` with one letter of its last body line changed: the signature
    /// sits at the end, so the request still reads but no longer checks.
    fn with_signature_changed(pem: &str) -> String {
        let mut lines: Vec<String> = pem.lines().map(str::to_owned).collect();
        let last_body = lines.len() - 2;
        let changed: String = lines[last_body]
            .chars()
            .enumerate()
            .map(|(at, letter)| match (at, letter) {
                (2, 'A') => 'B',
                (2, _) => 'A',
                (_, other) => other,
            })
            .collect();
        lines[last_body] = changed;
        lines.join("\n")
    }

    /// The certificate the domain allows for `pin`, issued now.
    fn allowed(pin: PublicKeyPin) -> ConnectorCertificate {
        let mut connector = ianua_app::test_support::routing::awaiting_connector(
            "wiki",
            "c-1",
            &["wiki.corp.internal"],
        );
        connector
            .enroll(
                &ianua_app::test_support::routing::connector_code_hash("c-1"),
                pin,
            )
            .unwrap()
    }

    /// Acme's agent sends a request. The certificate signed for it names
    /// Acme's tenant and connector and carries the agent's key, and the
    /// gateway reads both back.
    #[tokio::test]
    async fn a_signed_certificate_names_its_tenant_connector_and_key() {
        let (_, signer) = authority();
        let key = KeyPair::generate().unwrap();
        let request = request(&key);
        let pin = signer.key_of(&request).unwrap();
        let (tenant, connector) = (TenantId::new(), ConnectorId::new());

        let issued = signer
            .issue(ConnectorIssue {
                tenant,
                connector,
                request: &request,
                certificate: &allowed(pin),
            })
            .await
            .unwrap();

        let leaf = certificate_in(&issued.certificate_pem).unwrap();
        let der = der::Encode::to_der(&leaf).unwrap();
        let identity = connector_identity(&der).unwrap();
        assert_eq!(identity.tenant, tenant);
        assert_eq!(identity.connector, connector);
        assert_eq!(identity.key, pin);
        assert!(!issued.certificate_pem.contains("admin"));
    }

    /// A request whose public key differs from the enrolled key receives no signed certificate.
    #[tokio::test]
    async fn a_request_for_another_key_is_not_signed() {
        let (_, signer) = authority();
        let theirs = KeyPair::generate().unwrap();
        let hers = KeyPair::generate().unwrap();
        let enrolled = signer.key_of(&request(&theirs)).unwrap();

        let issued = signer
            .issue(ConnectorIssue {
                tenant: TenantId::new(),
                connector: ConnectorId::new(),
                request: &request(&hers),
                certificate: &allowed(enrolled),
            })
            .await;

        assert!(matches!(issued, Err(DomainError::Validation(_))));
    }

    /// Tampering with the request's signature makes the signing request invalid.
    #[test]
    fn a_tampered_request_is_refused() {
        let (_, signer) = authority();
        let pem = request(&KeyPair::generate().unwrap());
        let tampered = with_signature_changed(pem.as_str());

        let read = signer.key_of(&CertificateRequestPem::new(tampered).unwrap());

        assert!(read.is_err());
    }

    /// The listener certificate cannot be read as a connector identity.
    #[test]
    fn a_certificate_naming_no_connector_is_refused() {
        let (pki, _) = authority();
        let listener = certificate_in(&pki.listener.certificate_pem).unwrap();

        let read = connector_identity(&der::Encode::to_der(&listener).unwrap());

        assert!(matches!(read, Err(DomainError::Forbidden(_))));
    }

    /// Where none is set up, no connector is enrolled.
    #[test]
    fn no_authority_refuses_every_request() {
        let read = NoConnectorAuthority.key_of(&request(&KeyPair::generate().unwrap()));

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Debug representations of the connector PKI and signer omit private-key PEM text.
    #[test]
    fn a_key_never_prints() {
        let (pki, signer) = authority();

        assert!(!format!("{pki:?}").contains("PRIVATE KEY"));
        assert!(!format!("{signer:?}").contains("PRIVATE KEY"));
    }
}
