//! Issuing certificates in tests: a queue for certificate requests, an
//! issuance use case wired to fakes, an authority that refuses, and the
//! certificates tests start from.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundle, IssuedCertificate,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainId, DomainName};
use time::{Duration, OffsetDateTime};

use crate::ports::domain::TlsProvisioner;
use crate::test_support::Fake;
use crate::test_support::domain::{TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM};
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::domain::certificates::ProvisionTlsUseCase;
use crate::use_cases::domain::verification::verified::CertificateQueue;

/// How many times a test's certificate requests are tried.
const ATTEMPTS: NonZeroU32 = NonZeroU32::new(5).expect("five is not zero");

/// Certificate requests queued on `queue`, tried five times each.
#[must_use]
pub fn certificates(queue: Arc<FakeJobQueue>) -> CertificateQueue {
    CertificateQueue {
        queue,
        attempts: ATTEMPTS,
    }
}

impl Fake for CertificateQueue {
    fn fake() -> Self {
        certificates(Arc::new(FakeJobQueue::new()))
    }
}

impl Fake for Arc<ProvisionTlsUseCase> {
    fn fake() -> Self {
        Arc::new(ProvisionTlsUseCase::new(Fake::fake()))
    }
}

/// A certificate for `domain_id`, issued eighty days ago and running out at
/// `expires_at`.
///
/// # Panics
///
/// If `expires_at` is not after the issue time. Tests pass one that is.
#[must_use]
pub fn test_certificate(domain_id: DomainId, expires_at: OffsetDateTime) -> CertificateBundle {
    CertificateBundle::new(IssuedCertificate {
        domain_id,
        certificate_pem: CertificatePem::new(TEST_CERTIFICATE_PEM).expect("the test chain is PEM"),
        private_key_pem: Secret::new(TEST_PRIVATE_KEY_PEM),
        issued_at: clock::now() - Duration::days(80),
        expires_at,
    })
    .expect("issued before it expires")
}

/// A certificate authority that refuses every hostname.
pub struct RefusingTlsProvisioner;

#[async_trait]
impl TlsProvisioner for RefusingTlsProvisioner {
    async fn provision(
        &self,
        _domain: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        Err(DomainError::infra_msg("the authority refused the order"))
    }
}
