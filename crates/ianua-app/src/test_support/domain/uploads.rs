//! Uploaded certificates in tests: a parser that reads back what it was
//! told to, and the uploaded certificates tests start from.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundle, CertificateBundleRow, CertificateSource,
};
use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::{
    CertificateIssuer, ParsedCertificate, UploadedDetails,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainId, DomainName};
use time::{Duration, OffsetDateTime};

use crate::ports::domain::CertificateParser;
use crate::test_support::Fake;
use crate::test_support::domain::{TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM};

/// The issuer of every certificate [`parsed_for`] reads.
pub const TEST_UPLOAD_ISSUER: &str = "CN=Acme Internal CA";

/// A certificate parser that reads every chain as the certificate it was
/// given, or refuses every chain when given none.
pub struct FakeCertificateParser {
    reads: Option<ParsedCertificate>,
}

impl FakeCertificateParser {
    /// A parser that reads every chain as `parsed`.
    #[must_use]
    pub fn reading(parsed: ParsedCertificate) -> Self {
        Self {
            reads: Some(parsed),
        }
    }

    /// A parser that refuses every chain as unreadable.
    #[must_use]
    pub fn refusing() -> Self {
        Self { reads: None }
    }
}

impl CertificateParser for FakeCertificateParser {
    fn parse(
        &self,
        _chain: &CertificatePem,
        _private_key_pem: &Secret,
    ) -> Result<ParsedCertificate, DomainError> {
        self.reads
            .clone()
            .ok_or_else(|| DomainError::invalid("the certificate chain cannot be read"))
    }
}

impl Fake for Arc<dyn CertificateParser> {
    fn fake() -> Self {
        Arc::new(FakeCertificateParser::refusing())
    }
}

/// What a certificate for `name`, valid from a day ago for `days` more,
/// says about itself.
///
/// # Panics
///
/// If `name` is not a hostname. Tests pass one that is.
#[must_use]
pub fn parsed_for(name: &str, days: i64) -> ParsedCertificate {
    let now = clock::now();
    ParsedCertificate {
        issuer: CertificateIssuer::new(TEST_UPLOAD_ISSUER).expect("the test issuer is valid"),
        subject_names: vec![DomainName::new(name).expect("a test hostname")],
        not_before: now.saturating_sub(Duration::days(1)),
        not_after: now.saturating_add(Duration::days(days)),
    }
}

/// The test chain, as uploaded.
///
/// # Panics
///
/// If [`TEST_CERTIFICATE_PEM`] stops being PEM.
#[must_use]
pub fn test_chain() -> CertificatePem {
    CertificatePem::new(TEST_CERTIFICATE_PEM).expect("the test chain is PEM")
}

/// The test private key, as uploaded.
#[must_use]
pub fn test_private_key() -> Secret {
    Secret::new(TEST_PRIVATE_KEY_PEM)
}

/// A certificate the tenant uploaded for `domain_id`, named `name`, issued
/// a day ago and running out at `expires_at`, as read back from storage.
///
/// # Panics
///
/// If `expires_at` is not after the issue time, or `name` is not a
/// hostname. Tests pass ones that are.
#[must_use]
pub fn test_uploaded_certificate(
    domain_id: DomainId,
    name: &str,
    expires_at: OffsetDateTime,
) -> CertificateBundle {
    let details = UploadedDetails::stored(
        CertificateIssuer::new(TEST_UPLOAD_ISSUER).expect("the test issuer is valid"),
        vec![DomainName::new(name).expect("a test hostname")],
        expires_at,
    )
    .expect("the test certificate names a host");
    CertificateBundle::reconstitute(CertificateBundleRow {
        id: CertificateId::new(),
        domain_id,
        certificate_pem: test_chain(),
        private_key_pem: test_private_key(),
        issued_at: expires_at.saturating_sub(Duration::days(91)),
        expires_at,
        source: CertificateSource::Uploaded(details),
    })
    .expect("issued before it expires")
}
