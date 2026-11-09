//! The authority that signs the client certificates LDAP binds with: the
//! second factor a simple bind cannot carry.
//!
//! It never sees a private key. The caller makes the key on its device and
//! sends a signing request; only the public key travels here. Whatever
//! subject, names and key usages the request asks for are dropped: the
//! certificate signs for client authentication alone, names the user for
//! readability alone, and is only ever found by its fingerprint.

use std::fmt;

use ianua_app::ports::directory::{LdapCertificateAuthority, SignedLdapCertificate};
use ianua_domain::domains::authentication::ldap_certificate::CertificateValidity;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateFingerprint, CertificatePem, UserId};
use sha2::{Digest as _, Sha256};

use crate::crypto::issued::made;
use crate::crypto::random::random_bytes;

/// The bytes in a certificate's serial number.
const SERIAL_BYTES: usize = 20;

/// Why the authority could not be set up. None of it names the key.
#[derive(Debug, thiserror::Error)]
pub enum LdapCaError {
    /// The authority's key is not one this build reads: P-256 or another
    /// key in PKCS#8.
    #[error("the LDAP CA key is not a key this build reads; convert it to PKCS#8")]
    BadKey,
    /// The authority's certificate cannot be read.
    #[error("the LDAP CA certificate cannot be read")]
    BadCertificate,
}

/// The authority, loaded from its certificate and key.
pub struct RcgenLdapCertificateAuthority {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl fmt::Debug for RcgenLdapCertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RcgenLdapCertificateAuthority(<key redacted>)")
    }
}

impl RcgenLdapCertificateAuthority {
    /// The authority whose certificate is `certificate` and key `key`.
    ///
    /// # Errors
    ///
    /// Returns [`LdapCaError`] when either cannot be read.
    pub fn new(certificate: &CertificatePem, key: &Secret) -> Result<Self, LdapCaError> {
        let key = rcgen::KeyPair::from_pem(key.expose()).map_err(|_| LdapCaError::BadKey)?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(certificate.as_str(), key)
            .map_err(|_| LdapCaError::BadCertificate)?;
        Ok(Self { issuer })
    }
}

/// A fresh serial number of 20 random bytes, the most RFC 5280 allows,
/// its top bit clear so it reads as a positive number. Left to itself the
/// library derives the serial from the public key, so a key signed twice
/// would carry one serial on two certificates.
pub(super) fn fresh_serial() -> Result<rcgen::SerialNumber, DomainError> {
    let mut bytes = random_bytes::<SERIAL_BYTES>()?;
    if let Some(first) = bytes.first_mut() {
        *first &= 0x7f;
    }
    Ok(rcgen::SerialNumber::from_slice(&bytes))
}

/// A subject naming only `user_id`.
fn subject(user_id: &UserId) -> rcgen::DistinguishedName {
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, user_id.to_string());
    name
}

impl LdapCertificateAuthority for RcgenLdapCertificateAuthority {
    fn sign(
        &self,
        csr_pem: &str,
        user_id: &UserId,
        validity: CertificateValidity,
    ) -> Result<SignedLdapCertificate, DomainError> {
        let mut request =
            rcgen::CertificateSigningRequestParams::from_pem(csr_pem).map_err(|_| {
                DomainError::invalid(message!(
                    "infra-the-certificate-request-cannot-be-read",
                    "the certificate request cannot be read"
                ))
            })?;
        let now = clock::now();
        request.params.distinguished_name = subject(user_id);
        request.params.subject_alt_names = Vec::new();
        request.params.not_before = now;
        request.params.not_after = now.saturating_add(validity.as_duration());
        request.params.serial_number = Some(fresh_serial()?);
        request.params.is_ca = rcgen::IsCa::ExplicitNoCa;
        request.params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = request
            .signed_by(&self.issuer)
            .map_err(DomainError::infra)?;
        Ok(SignedLdapCertificate {
            fingerprint: CertificateFingerprint::from_digest(
                Sha256::digest(certificate.der()).into(),
            ),
            certificate_pem: made(CertificatePem::new(certificate.pem()))?,
        })
    }
}

/// A certificate asked for where no authority is set up.
#[derive(Debug, thiserror::Error)]
#[error("no LDAP client certificate authority is set up, so no client certificate is issued")]
struct NoAuthority;

/// The authority of a deployment that set none up: every request is
/// refused, so no client certificate is issued and no directory write can
/// be made with one.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLdapCertificateAuthority;

impl LdapCertificateAuthority for NoLdapCertificateAuthority {
    fn sign(
        &self,
        _csr_pem: &str,
        _user_id: &UserId,
        _validity: CertificateValidity,
    ) -> Result<SignedLdapCertificate, DomainError> {
        Err(DomainError::infra(NoAuthority))
    }
}

#[cfg(test)]
mod tests {
    use der::Decode as _;

    use super::*;
    use crate::crypto::certificates::pem::certificate_in;

    fn authority() -> RcgenLdapCertificateAuthority {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let certificate = params.self_signed(&key).unwrap();
        RcgenLdapCertificateAuthority::new(
            &CertificatePem::new(certificate.pem()).unwrap(),
            &Secret::new(key.serialize_pem()),
        )
        .unwrap()
    }

    fn request(claimed: &str) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![claimed.to_owned()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, claimed);
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    /// A request is signed into a client certificate naming only the user,
    /// whatever names the request asked for, found by its fingerprint.
    #[test]
    fn a_request_is_signed_for_the_user_alone() {
        let user = UserId::new();

        let signed = authority()
            .sign(
                &request("admin.acme.example"),
                &user,
                CertificateValidity::days(30).unwrap(),
            )
            .unwrap();

        let certificate = certificate_in(signed.certificate_pem.as_str()).unwrap();
        let subject = certificate.tbs_certificate.subject.to_string();
        assert!(subject.contains(&user.to_string()));
        assert!(!subject.contains("admin"));
        assert!(
            !signed
                .certificate_pem
                .as_str()
                .contains("admin.acme.example")
        );
    }

    /// A request from `key` asking to sign other certificates.
    fn request_to_sign_certificates(key: &rcgen::KeyPair) -> String {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.serialize_request(key).unwrap().pem().unwrap()
    }

    /// The key usages a signed certificate carries.
    fn key_usage_of(pem: &str) -> x509_cert::ext::pkix::KeyUsage {
        let certificate = certificate_in(pem).unwrap();
        let extension = certificate
            .tbs_certificate
            .extensions
            .unwrap()
            .into_iter()
            .find(|extension| extension.extn_id.to_string() == "2.5.29.15")
            .unwrap();
        x509_cert::ext::pkix::KeyUsage::from_der(extension.extn_value.as_bytes()).unwrap()
    }

    /// Requested CA usages are discarded: the issued certificate permits digital signatures
    /// but neither certificate nor revocation-list signing.
    #[test]
    fn a_request_for_signing_usages_gets_a_signature_key_only() {
        let key = rcgen::KeyPair::generate().unwrap();

        let signed = authority()
            .sign(
                &request_to_sign_certificates(&key),
                &UserId::new(),
                CertificateValidity::days(30).unwrap(),
            )
            .unwrap();

        let usage = key_usage_of(signed.certificate_pem.as_str());
        assert!(usage.digital_signature());
        assert!(!usage.key_cert_sign());
        assert!(!usage.crl_sign());
    }

    /// Signing the same key twice produces certificates with different serial numbers.
    #[test]
    fn one_key_signed_twice_gets_two_serials() {
        let authority = authority();
        let key = rcgen::KeyPair::generate().unwrap();
        let sign = || {
            authority
                .sign(
                    &request_to_sign_certificates(&key),
                    &UserId::new(),
                    CertificateValidity::days(30).unwrap(),
                )
                .unwrap()
        };

        let (first, second) = (sign(), sign());

        let serial = |signed: &SignedLdapCertificate| {
            certificate_in(signed.certificate_pem.as_str())
                .unwrap()
                .tbs_certificate
                .serial_number
        };
        assert_ne!(serial(&first), serial(&second));
    }

    /// Malformed signing-request text returns a validation error.
    #[test]
    fn a_malformed_request_is_refused() {
        let signed = authority().sign(
            "not a request",
            &UserId::new(),
            CertificateValidity::days(30).unwrap(),
        );

        assert!(matches!(signed, Err(DomainError::Validation(_))));
    }

    /// Without a configured authority, signing returns an infrastructure error and no certificate.
    #[test]
    fn a_deployment_with_no_authority_issues_no_certificate() {
        let signed = NoLdapCertificateAuthority.sign(
            &request("ann"),
            &UserId::new(),
            CertificateValidity::days(30).unwrap(),
        );

        assert!(matches!(signed, Err(DomainError::Infrastructure(_))));
    }
}
