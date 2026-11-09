//! A certificate a tenant brings itself, in place of one the platform asks
//! an ACME authority for.
//!
//! The domain never parses a certificate. The certificate adapter reads the
//! uploaded chain and hands over what it says as a [`ParsedCertificate`].
//! The domain then decides whether that certificate may serve the name: it
//! must name the domain, exactly or through a matching wildcard, and be
//! valid now. Nobody renews an uploaded certificate for the tenant, so its
//! expiry is reported instead.

use std::fmt;

use time::OffsetDateTime;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::security::secret::Secret;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{CertificatePem, DomainName};

/// The most names one uploaded certificate may carry.
pub(crate) const MAX_SUBJECT_NAMES: usize = 100;

text_value! {
    /// Who issued a certificate, as its issuer field reads, such as
    /// `CN=R3, O=Let's Encrypt, C=US`.
    pub struct CertificateIssuer;
}

impl TextValue for CertificateIssuer {
    const FIELD: &'static str = "certificate_issuer";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_blank().char_length(1..=1024).no_control_chars()
    }
}

/// What the certificate adapter read from an uploaded chain's leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate {
    /// Who issued it.
    pub issuer: CertificateIssuer,
    /// Every DNS name it is for, wildcards included.
    pub subject_names: Vec<DomainName>,
    /// When it starts being valid.
    pub not_before: OffsetDateTime,
    /// When it stops being valid.
    pub not_after: OffsetDateTime,
}

/// What a tenant uploads: the chain, its private key, and what the adapter
/// read from the chain.
///
/// The key is held as a [`Secret`] and is sealed by the adapter before it
/// is stored. `Debug` shows neither the key nor the chain.
pub struct CertificateUpload {
    /// The certificate chain, leaf first, PEM-encoded.
    pub certificate_pem: CertificatePem,
    /// The leaf's private key, PEM-encoded.
    pub private_key_pem: Secret,
    /// What the adapter read from the leaf.
    pub parsed: ParsedCertificate,
}

impl fmt::Debug for CertificateUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateUpload")
            .field("certificate_pem", &"<chain>")
            .field("private_key_pem", &"<redacted>")
            .field("parsed", &self.parsed)
            .finish()
    }
}

/// What a certificate a tenant uploaded says about itself, as recorded once
/// it was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedDetails {
    issuer: CertificateIssuer,
    subject_names: Vec<DomainName>,
    not_after: OffsetDateTime,
}

impl UploadedDetails {
    /// The details of `parsed`, once it may serve `domain` at `now`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names no host, or more than
    ///   `MAX_SUBJECT_NAMES`.
    /// - [`DomainError::Validation`] when it is valid for no time at all.
    /// - [`DomainError::Conflict`] when it is not valid yet, or has expired.
    /// - [`DomainError::Conflict`] when none of its names covers `domain`.
    pub(crate) fn accepted(
        parsed: ParsedCertificate,
        domain: &DomainName,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        validate_count(
            "subject_names",
            parsed.subject_names.len(),
            1..=MAX_SUBJECT_NAMES,
        )?;
        if parsed.not_before >= parsed.not_after {
            return Err(DomainError::invalid(message!(
                "tenant-the-certificate-is-valid-for-no",
                "the certificate is valid for no time at all"
            )));
        }
        if now < parsed.not_before || now >= parsed.not_after {
            return Err(DomainError::conflict(message!(
                "tenant-the-certificate-is-not-valid-now",
                "the certificate is not valid now: it has expired or has not started"
            )));
        }
        if !parsed.subject_names.iter().any(|name| covers(name, domain)) {
            return Err(DomainError::conflict(message!(
                "tenant-the-certificate-does-not-name",
                format!("the certificate does not name {domain}")
            )));
        }
        Ok(Self {
            issuer: parsed.issuer,
            subject_names: parsed.subject_names,
            not_after: parsed.not_after,
        })
    }

    /// Rebuilds the details as stored, for a certificate already accepted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row names no host.
    pub fn stored(
        issuer: CertificateIssuer,
        subject_names: Vec<DomainName>,
        not_after: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        if validate_count("subject_names", subject_names.len(), 1..=MAX_SUBJECT_NAMES).is_err() {
            return Err(DomainError::corrupt_row(
                "uploaded certificate",
                "a certificate that names no host",
            ));
        }
        Ok(Self {
            issuer,
            subject_names,
            not_after,
        })
    }

    /// Who issued it.
    #[must_use]
    pub fn issuer(&self) -> &CertificateIssuer {
        &self.issuer
    }

    /// Every DNS name it is for.
    #[must_use]
    pub fn subject_names(&self) -> &[DomainName] {
        &self.subject_names
    }

    /// When it stops being valid.
    #[must_use]
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }
}

/// Whether the certificate name `name` covers `domain`: the same name, or a
/// wildcard one label above it. `*.acme.com` covers `auth.acme.com`, but
/// neither `acme.com` nor `a.b.acme.com`.
fn covers(name: &DomainName, domain: &DomainName) -> bool {
    let (name, domain) = (name.as_str(), domain.as_str());
    if name.eq_ignore_ascii_case(domain) {
        return true;
    }
    let Some(parent) = name.strip_prefix("*.") else {
        return false;
    };
    domain
        .split_once('.')
        .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(parent))
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::test_support::builders::domain_name;

    /// A certificate from Let's Encrypt for `names`, valid from a day ago
    /// for ninety days.
    fn parsed(names: &[&str]) -> ParsedCertificate {
        let now = crate::shared::clock::now();
        ParsedCertificate {
            issuer: CertificateIssuer::new("CN=R3, O=Let's Encrypt").unwrap(),
            subject_names: names.iter().map(|name| domain_name(name)).collect(),
            not_before: now.saturating_sub(Duration::days(1)),
            not_after: now.saturating_add(Duration::days(89)),
        }
    }

    /// Acme uploads a certificate for `auth.acme.com`. It is accepted, with
    /// its issuer and expiry recorded.
    #[test]
    fn a_certificate_naming_the_domain_is_accepted() {
        let now = crate::shared::clock::now();
        let details = UploadedDetails::accepted(
            parsed(&["auth.acme.com"]),
            &domain_name("auth.acme.com"),
            now,
        )
        .unwrap();

        assert_eq!(details.issuer().as_str(), "CN=R3, O=Let's Encrypt");
        assert_eq!(details.subject_names().len(), 1);
    }

    /// A wildcard `*.acme.com` covers `auth.acme.com`.
    #[test]
    fn a_matching_wildcard_covers_the_domain() {
        let now = crate::shared::clock::now();

        let result =
            UploadedDetails::accepted(parsed(&["*.acme.com"]), &domain_name("auth.acme.com"), now);

        assert!(result.is_ok());
    }

    /// Certificate details are rejected for a different domain and for a name
    /// two labels below the wildcard's parent.
    #[test]
    fn a_certificate_for_another_name_is_refused() {
        let now = crate::shared::clock::now();

        let other =
            UploadedDetails::accepted(parsed(&["bank.com"]), &domain_name("auth.acme.com"), now);
        let too_deep =
            UploadedDetails::accepted(parsed(&["*.acme.com"]), &domain_name("a.b.acme.com"), now);

        assert!(matches!(other, Err(DomainError::Conflict(_))));
        assert!(matches!(too_deep, Err(DomainError::Conflict(_))));
    }

    /// An expired certificate, and one not valid until next week, are
    /// refused: neither would serve the name now.
    #[test]
    fn a_certificate_not_valid_now_is_refused() {
        let now = crate::shared::clock::now();
        let expired = ParsedCertificate {
            not_before: now.saturating_sub(Duration::days(100)),
            not_after: now.saturating_sub(Duration::days(10)),
            ..parsed(&["auth.acme.com"])
        };
        let early = ParsedCertificate {
            not_before: now.saturating_add(Duration::days(7)),
            not_after: now.saturating_add(Duration::days(97)),
            ..parsed(&["auth.acme.com"])
        };
        let domain = domain_name("auth.acme.com");

        assert!(matches!(
            UploadedDetails::accepted(expired, &domain, now),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            UploadedDetails::accepted(early, &domain, now),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A certificate that names no host at all is refused.
    #[test]
    fn a_certificate_without_names_is_refused() {
        let now = crate::shared::clock::now();

        let result = UploadedDetails::accepted(parsed(&[]), &domain_name("auth.acme.com"), now);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The upload prints neither its private key nor its chain.
    #[test]
    fn an_upload_never_prints_its_key() {
        let upload = CertificateUpload {
            certificate_pem: CertificatePem::new(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )
            .unwrap(),
            private_key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\nTOPSECRET\n-----END PRIVATE KEY-----",
            ),
            parsed: parsed(&["auth.acme.com"]),
        };

        let printed = format!("{upload:?}");

        assert!(!printed.contains("TOPSECRET"));
        assert!(!printed.contains("BEGIN"));
    }
}
