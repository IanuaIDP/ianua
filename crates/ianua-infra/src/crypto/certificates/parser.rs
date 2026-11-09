//! Reading the certificate chain a tenant uploads for its domain.
//!
//! The leaf is the first certificate of the chain. The private key is read
//! only to check that its public half is the leaf's, by comparing the two
//! public keys as DER; it is kept nowhere and named in no error. RSA keys
//! in PKCS#1 or PKCS#8, P-256 keys in SEC1 or PKCS#8, and Ed25519 keys are
//! read.

use der::{Decode as _, Encode as _};
use ianua_app::ports::domain::CertificateParser;
use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::{
    CertificateIssuer, ParsedCertificate,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName};
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::time::Time;

use crate::crypto::certificates::pem::certificates_in;
use crate::crypto::certificates::rsa_keys::RsaSigningKey;

/// The OID of the subject alternative name extension.
const SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

/// The public key `pem` holds the private half of, as SPKI DER.
fn public_key_of(pem: &str) -> Option<Vec<u8>> {
    let rsa = RsaSigningKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaSigningKey::from_pkcs1_pem(pem))
        .ok()
        .and_then(|key| key.public_key().spki_der().ok());
    let p256 = || {
        p256::SecretKey::from_pkcs8_pem(pem)
            .or_else(|_| p256::SecretKey::from_sec1_pem(pem))
            .ok()
            .and_then(|key| key.public_key().to_public_key_der().ok())
            .map(|document| document.as_bytes().to_vec())
    };
    let ed25519 = || {
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .ok()
            .and_then(|key| key.verifying_key().to_public_key_der().ok())
            .map(|document| document.as_bytes().to_vec())
    };
    rsa.or_else(p256).or_else(ed25519)
}

/// When `time` is.
fn instant(time: Time) -> Result<OffsetDateTime, DomainError> {
    let seconds = i64::try_from(time.to_unix_duration().as_secs())
        .map_err(|_| DomainError::invalid("the certificate's validity is no time"))?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| DomainError::invalid("the certificate's validity is no time"))
}

/// Every DNS name the leaf's subject alternative names list.
fn dns_names(leaf: &Certificate) -> Result<Vec<DomainName>, DomainError> {
    let Some(extension) = leaf
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == SUBJECT_ALT_NAME)
    else {
        return Ok(Vec::new());
    };
    let names = SubjectAltName::from_der(extension.extn_value.as_bytes())
        .map_err(|_| DomainError::invalid("the certificate's names cannot be read"))?;
    names
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::DnsName(dns) => Some(dns.as_str()),
            GeneralName::OtherName(_)
            | GeneralName::Rfc822Name(_)
            | GeneralName::DirectoryName(_)
            | GeneralName::EdiPartyName(_)
            | GeneralName::UniformResourceIdentifier(_)
            | GeneralName::IpAddress(_)
            | GeneralName::RegisteredId(_) => None,
        })
        .map(|name| {
            DomainName::new(name)
                .map_err(|_| DomainError::invalid("the certificate names a host that is not one"))
        })
        .collect()
}

/// The reader of uploaded certificate chains.
#[derive(Debug, Clone, Copy, Default)]
pub struct X509CertificateParser;

impl CertificateParser for X509CertificateParser {
    fn parse(
        &self,
        chain: &CertificatePem,
        private_key_pem: &Secret,
    ) -> Result<ParsedCertificate, DomainError> {
        let chain = certificates_in(chain.as_str())
            .map_err(|_| DomainError::invalid("the chain cannot be read"))?;
        let leaf = chain
            .first()
            .ok_or_else(|| DomainError::invalid("the chain holds no certificate"))?;
        let leaf_key = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| DomainError::invalid("the certificate's key cannot be read"))?;
        let key = public_key_of(private_key_pem.expose())
            .ok_or_else(|| DomainError::invalid("the key cannot be read"))?;
        if key != leaf_key {
            return Err(DomainError::invalid("the key is not the certificate's"));
        }
        let validity = &leaf.tbs_certificate.validity;
        Ok(ParsedCertificate {
            issuer: CertificateIssuer::new(leaf.tbs_certificate.issuer.to_string())
                .map_err(|_| DomainError::invalid("the certificate names no issuer"))?,
            subject_names: dns_names(leaf)?,
            not_before: instant(validity.not_before)?,
            not_after: instant(validity.not_after)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::certificates::tests::self_signed;

    /// A chain and its own key read back as the names, issuer and validity
    /// of the leaf.
    #[test]
    fn a_chain_with_its_key_reads_back() {
        let (certificate, key) = self_signed("shop.acme.example");

        let parsed = X509CertificateParser
            .parse(
                &CertificatePem::new(certificate).unwrap(),
                &Secret::new(key),
            )
            .unwrap();

        assert_eq!(
            parsed.subject_names,
            [DomainName::new("shop.acme.example").unwrap()]
        );
        assert!(parsed.not_before < parsed.not_after);
    }

    /// A certificate chain paired with a different private key fails validation.
    #[test]
    fn a_chain_with_another_key_is_refused() {
        let (certificate, _) = self_signed("shop.acme.example");
        let (_, other) = self_signed("shop.acme.example");

        let parsed = X509CertificateParser.parse(
            &CertificatePem::new(certificate).unwrap(),
            &Secret::new(other),
        );

        assert!(matches!(parsed, Err(DomainError::Validation(_))));
    }
}
