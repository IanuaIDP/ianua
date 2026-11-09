//! The certificates SAML names keys by: the one a tenant's identity
//! provider metadata publishes for its signing key, and the key pairs a
//! connection's provider seals assertions to.
//!
//! A signing certificate is self-signed by the tenant's key, under a
//! serial number taken from the key itself and a fixed validity, so the
//! same key always gives a certificate for the same key and metadata
//! fetched twice names one. An encryption pair is a fresh RSA key, made
//! off the request threads since that takes a moment, its certificate
//! valid for ten years.

use async_trait::async_trait;
use aws_lc_rs::rsa::OAEP_SHA1_MGF1SHA1;
use ianua_app::ports::crypto::XmlSigningKey;
use ianua_app::ports::federation::{GeneratedSpKey, SamlEncryptionKeys, SigningCertificateIssuer};
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, SamlEntityId};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, SerialNumber};
use sha2::{Digest as _, Sha256};
use time::Duration;

use crate::crypto::certificates::rsa_keys::{RsaSealingKey, RsaSigningKey};
use crate::saml::encryption::DecryptionKey;
use crate::saml::xml::keys::{random_bytes, rsa_key_of};

/// How long a certificate for sealed assertions is valid.
const ENCRYPTION_VALIDITY: Duration = Duration::days(3650);

/// The year a signing certificate is valid from, the same for every one.
const SIGNING_VALID_FROM: i32 = 2025;

/// The year a signing certificate is valid until. Service providers check
/// a metadata key, not its dates, and the key rotates long before.
const SIGNING_VALID_UNTIL: i32 = 2125;

/// Issues the certificate a tenant's identity provider metadata publishes,
/// self-signed by the signing key it names.
#[derive(Debug, Clone, Copy, Default)]
pub struct X509SigningCertificateIssuer;

#[async_trait]
impl SigningCertificateIssuer for X509SigningCertificateIssuer {
    async fn certificate_for(
        &self,
        key: &XmlSigningKey<'_>,
        issuer: &SamlEntityId,
    ) -> Result<CertificatePem, DomainError> {
        let pair = KeyPair::from_pkcs8_pem_and_sign_algo(
            key.private_key.expose(),
            signed_with(key.algorithm),
        )
        .map_err(DomainError::infra)?;
        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(DomainError::infra)?;
        params.distinguished_name = named(issuer.as_str());
        params.serial_number = Some(serial_of(pair.public_key_raw()));
        params.not_before = rcgen::date_time_ymd(SIGNING_VALID_FROM, 1, 1);
        params.not_after = rcgen::date_time_ymd(SIGNING_VALID_UNTIL, 1, 1);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = params.self_signed(&pair).map_err(DomainError::infra)?;
        CertificatePem::new(certificate.pem()).map_err(DomainError::infra)
    }
}

/// Makes and checks the RSA key pairs a provider seals assertions to.
#[derive(Debug, Clone, Copy, Default)]
pub struct RsaSamlEncryptionKeys;

#[async_trait]
impl SamlEncryptionKeys for RsaSamlEncryptionKeys {
    async fn generate(&self, subject: &SamlEntityId) -> Result<GeneratedSpKey, DomainError> {
        let subject = subject.as_str().to_owned();
        let starts = clock::now();
        tokio::task::spawn_blocking(move || generated_pair(&subject, starts))
            .await
            .map_err(DomainError::infra)?
    }

    fn ensure_pair(
        &self,
        certificate: &CertificatePem,
        private_key: &Secret,
    ) -> Result<(), DomainError> {
        let public = rsa_key_of(certificate)?;
        let private = DecryptionKey::from_pkcs8_pem(private_key.expose()).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-private-key-is-not-an",
                "the private key is not an RSA key in PKCS#8"
            ))
        })?;
        ensure_opens(&public, &private)
    }
}

/// A fresh RSA key and its certificate in the name of `subject`, valid
/// from `starts`.
fn generated_pair(
    subject: &str,
    starts: time::OffsetDateTime,
) -> Result<GeneratedSpKey, DomainError> {
    let (_, pem) = RsaSigningKey::generated().map_err(DomainError::infra)?;
    let pair = KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256)
        .map_err(DomainError::infra)?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(DomainError::infra)?;
    params.distinguished_name = named(subject);
    params.not_before = starts;
    params.not_after = starts.saturating_add(ENCRYPTION_VALIDITY);
    params.key_usages = vec![
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment,
    ];
    let certificate = params.self_signed(&pair).map_err(DomainError::infra)?;
    Ok(GeneratedSpKey {
        certificate: CertificatePem::new(certificate.pem()).map_err(DomainError::infra)?,
        private_key: Secret::new(pem.as_str()),
    })
}

/// Refuses a pair that does not open what is sealed to it, checked with a
/// random key sealed and opened again. A private key of another pair opens
/// nothing sealed to this certificate, so this also refuses a key that
/// does not match it.
fn ensure_opens(public: &RsaSealingKey, private: &DecryptionKey) -> Result<(), DomainError> {
    let probe = random_bytes::<32>()?;
    let sealed = public.sealed(&probe).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-certificate-s-key-cannot-be",
            "the certificate's key cannot be sealed to"
        ))
    })?;
    let mismatched = || {
        DomainError::invalid(message!(
            "infra-the-private-key-does-not-match",
            "the private key does not match the certificate"
        ))
    };
    let opened = private
        .unsealed(&OAEP_SHA1_MGF1SHA1, &sealed)
        .map_err(|_| mismatched())?;
    if opened.as_slice() != probe.as_slice() {
        return Err(mismatched());
    }
    Ok(())
}

/// The algorithm a tenant's key of `algorithm` signs a certificate with.
fn signed_with(algorithm: SigningAlgorithm) -> &'static rcgen::SignatureAlgorithm {
    match algorithm {
        SigningAlgorithm::Rs256 => &rcgen::PKCS_RSA_SHA256,
        SigningAlgorithm::Es256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        SigningAlgorithm::EdDsa => &rcgen::PKCS_ED25519,
    }
}

/// A subject naming `entity` alone.
fn named(entity: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, entity);
    name
}

/// A positive serial number of 128 bits, taken from `public_key`, so one
/// key always gives one serial.
fn serial_of(public_key: &[u8]) -> SerialNumber {
    let digest = Sha256::digest(public_key);
    let mut serial = [0_u8; 16];
    for (slot, byte) in serial.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x7f) | 0x40;
    }
    SerialNumber::from_slice(&serial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::certificates::pem::certificate_in;
    use crate::saml::xml::keys::TrustedKey;
    use crate::saml::xml::keys::tests::TestKey;

    fn issuer() -> SamlEntityId {
        SamlEntityId::new("https://auth.acme.com/saml").unwrap()
    }

    /// The certificate names the tenant's provider and carries the key that
    /// signs its assertions, for every kind of tenant key.
    #[tokio::test]
    async fn the_signing_certificate_carries_the_tenants_key() {
        for algorithm in [
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Es256,
            SigningAlgorithm::EdDsa,
        ] {
            let key = TestKey::new(algorithm);

            let certificate = X509SigningCertificateIssuer
                .certificate_for(&key.signing(), &issuer())
                .await
                .unwrap();

            assert_certificate_identity(&certificate, &key);
            assert!(
                TrustedKey::from_certificate(&certificate).is_ok(),
                "{algorithm:?}"
            );
        }
    }

    /// Checks that metadata retains the signing key and names its tenant issuer.
    fn assert_certificate_identity(certificate: &CertificatePem, key: &TestKey) {
        let parsed = certificate_in(certificate.as_str()).unwrap();
        let public = parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;
        let theirs = certificate_in(key.certificate.as_str()).unwrap();
        assert_eq!(
            public,
            theirs
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
        );
        assert!(
            parsed
                .tbs_certificate
                .subject
                .to_string()
                .contains("auth.acme.com")
        );
    }

    /// Metadata fetched twice names one key: the same key gives a
    /// certificate of the same serial and dates every time.
    #[tokio::test]
    async fn the_same_key_gives_the_same_certificate() {
        let key = TestKey::new(SigningAlgorithm::Rs256);
        let certificates = X509SigningCertificateIssuer;

        let first = certificates
            .certificate_for(&key.signing(), &issuer())
            .await
            .unwrap();
        let second = certificates
            .certificate_for(&key.signing(), &issuer())
            .await
            .unwrap();

        assert_eq!(first, second);
    }

    /// A made pair's certificate names this platform, and its private key
    /// opens what is sealed to the certificate.
    #[tokio::test]
    async fn a_made_pair_holds_together() {
        let keys = RsaSamlEncryptionKeys;

        let pair = keys.generate(&issuer()).await.unwrap();

        assert!(
            keys.ensure_pair(&pair.certificate, &pair.private_key)
                .is_ok()
        );
    }

    /// A private key that does not match the certificate fails validation before use.
    #[tokio::test]
    async fn a_private_key_of_another_pair_is_refused() {
        let keys = RsaSamlEncryptionKeys;
        let ours = keys.generate(&issuer()).await.unwrap();
        let theirs = keys.generate(&issuer()).await.unwrap();

        let result = keys.ensure_pair(&ours.certificate, &theirs.private_key);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An ECDSA key pair is rejected because assertion encryption requires RSA.
    #[test]
    fn a_pair_that_cannot_seal_is_refused() {
        let ecdsa = TestKey::new(SigningAlgorithm::Es256);

        let result = RsaSamlEncryptionKeys.ensure_pair(&ecdsa.certificate, &ecdsa.private_key);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
