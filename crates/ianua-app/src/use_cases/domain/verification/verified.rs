//! What a domain is owed the moment it becomes verified, wherever that
//! happened.
//!
//! Two paths verify a registered domain: the request a tenant makes by
//! pressing the button, and the periodic sweep. Both owe the tenant the same
//! two things. An event, so the change reaches their notifications and their
//! browser, and a certificate, so the hostname they just handed over answers
//! over TLS. A domain that arrives already proved at registration is owed the
//! certificate too.
//!
//! The sweep is where most domains are verified, because nobody is watching
//! at the moment DNS finally propagates. Keeping both here means it cannot
//! quietly owe less than the button does.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{DomainId, TenantId};

use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::JobQueue;
use crate::use_cases::scheduling::key_of;

/// The job type that asks for a certificate.
pub const PROVISION_TLS_JOB: &str = "domain.provision_tls";

/// Where certificate requests are queued, and how many times each is tried
/// before it is given up on.
#[derive(Clone)]
pub struct CertificateQueue {
    /// The queue the requests wait in.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a request gets.
    pub attempts: NonZeroU32,
}

/// What a certificate job carries: which domain of which tenant.
///
/// The one definition of the payload, so the side that queues the job and
/// the worker that runs it cannot disagree on a field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvisionTlsJob {
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The domain registration the certificate is for.
    pub domain_id: DomainId,
}

impl ProvisionTlsJob {
    /// The job that issues this certificate, due now and tried up to
    /// `attempts` times.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the job cannot be built.
    pub fn scheduled(&self, attempts: NonZeroU32) -> Result<ScheduledJob, AppError> {
        let job_type = JobType::new(PROVISION_TLS_JOB).or_internal()?;
        let payload = serde_json::to_string(self).map_err(AppError::internal)?;
        Ok(ScheduledJob::new(job_type, payload, clock::now(), attempts))
    }

    /// The payload `job` carries.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the payload is not a certificate job's.
    pub fn read(job: &ScheduledJob) -> Result<Self, AppError> {
        serde_json::from_str(job.payload()).map_err(AppError::internal)
    }
}

/// Queues the certificate request for a domain that has just been verified.
///
/// Queued rather than done inline because issuance talks to a certificate
/// authority and waits for a proof to become visible, which takes longer than
/// a request should. The queue also gives it retries: an authority that
/// cannot see the proof yet must be asked again later, not abandoned. A
/// request that cannot be queued is logged, and the periodic TLS sweep picks
/// the domain up instead.
pub async fn request_certificate(
    certificates: &CertificateQueue,
    tenant_id: &TenantId,
    domain: &RegisteredDomain<ResolvedTenant>,
) {
    let Err(error) = queue_certificate(certificates, tenant_id, domain).await else {
        return;
    };
    tracing::warn!(
        domain = domain.domain().as_str(),
        %error,
        "could not queue the certificate request; the periodic TLS sweep will pick it up instead"
    );
}

/// Queues the job that issues `domain`'s certificate, once: while one waits
/// or runs, asking again adds nothing.
///
/// # Errors
///
/// Returns `AppError::Internal` if the job cannot be built or queued.
pub(in crate::use_cases::domain) async fn queue_certificate(
    certificates: &CertificateQueue,
    tenant_id: &TenantId,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    let job = ProvisionTlsJob {
        tenant_id: *tenant_id,
        domain_id: *domain.id(),
    }
    .scheduled(certificates.attempts)?
    .for_tenant(*tenant_id)
    .keyed(key_of(domain.id(), "certificate")?);
    certificates.queue.enqueue(&job).await.or_internal()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::domain::{DomainSeed, certificates};
    use crate::test_support::scheduling::FakeJobQueue;

    fn job() -> ProvisionTlsJob {
        ProvisionTlsJob {
            tenant_id: TenantId::new(),
            domain_id: DomainId::new(),
        }
    }

    /// A certificate job for Acme's domain reads back as the same tenant and
    /// domain it was queued for.
    #[test]
    fn a_scheduled_job_reads_back_as_the_same_payload() {
        let sent = job();

        let scheduled = sent.scheduled(NonZeroU32::new(5).unwrap()).unwrap();

        assert_eq!(scheduled.job_type().as_str(), PROVISION_TLS_JOB);
        assert_eq!(ProvisionTlsJob::read(&scheduled).unwrap(), sent);
    }

    /// The deployment tries certificate jobs nine times. The job is
    /// scheduled with nine attempts.
    #[test]
    fn a_scheduled_job_is_tried_as_often_as_configured() {
        let scheduled = job().scheduled(NonZeroU32::new(9).unwrap()).unwrap();

        assert_eq!(scheduled.max_attempts().get(), 9);
    }

    /// A job whose payload names no domain is refused instead of issuing a
    /// certificate for something unknown.
    #[test]
    fn a_payload_without_a_domain_is_refused() {
        let scheduled = ScheduledJob::new(
            JobType::new(PROVISION_TLS_JOB).unwrap(),
            format!(r#"{{"tenant_id":"{}"}}"#, uuid::Uuid::now_v7()),
            clock::now(),
            NonZeroU32::new(5).unwrap(),
        );

        assert!(matches!(
            ProvisionTlsJob::read(&scheduled),
            Err(AppError::Internal(_))
        ));
    }

    /// Acme's domain was just verified. Its certificate request is queued.
    #[test]
    fn a_verified_domain_has_its_certificate_queued() {
        let queue = Arc::new(FakeJobQueue::new());
        let domain = DomainSeed::verified("auth.acme.test").build();

        block_on(request_certificate(
            &certificates(queue.clone()),
            &TenantId::new(),
            &domain,
        ));

        assert!(queue.holds(PROVISION_TLS_JOB));
    }
}
