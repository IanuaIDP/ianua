//! The job that issues a verified domain's certificate, as the worker runs
//! it: queued when the domain became verified, and tried again on the
//! queue's backoff while the authority cannot issue it.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::errors::DomainError;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command as _;
use crate::use_cases::domain::certificates::provision_tls::ProvisionTlsUseCase;
use crate::use_cases::domain::verification::verified::{PROVISION_TLS_JOB, ProvisionTlsJob};
use crate::use_cases::scheduling::{Handled, JobHandler};

/// Runs certificate jobs through [`ProvisionTlsUseCase`].
pub struct ProvisionTlsHandler {
    job_type: JobType,
    provision: Arc<ProvisionTlsUseCase>,
}

impl ProvisionTlsHandler {
    /// A handler issuing certificates through `provision`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(provision: Arc<ProvisionTlsUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(PROVISION_TLS_JOB)?;
        Ok(Self {
            job_type,
            provision,
        })
    }
}

#[async_trait]
impl JobHandler for ProvisionTlsHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Issues the certificate the job names. An authority that cannot
    /// issue it yet is asked again on the queue's backoff; a domain that is
    /// gone, no longer verified or already served is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload = ProvisionTlsJob::read(job)?;
        after_provisioning(self.provision.execute(&(), auditor, payload).await)
    }
}

/// What an order that came to `provisioned` leaves to do: nothing once the
/// certificate is issued, or once the domain is gone or no longer waits
/// for one; another try when the authority or a store failed.
///
/// # Errors
///
/// Every error but `AppError::NotFound` and `AppError::Conflict`.
fn after_provisioning(provisioned: Result<(), AppError>) -> Result<Handled, AppError> {
    match provisioned {
        Ok(()) | Err(AppError::NotFound(_) | AppError::Conflict(_)) => Ok(Handled::Done),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::domain::certificates::provision_tls::ProvisionTlsPorts;

    fn handler() -> ProvisionTlsHandler {
        ProvisionTlsHandler::new(Arc::new(ProvisionTlsUseCase::new(
            ProvisionTlsPorts::fakes(),
        )))
        .unwrap()
    }

    /// The handler runs the jobs the certificate queue holds.
    #[test]
    fn the_handler_runs_certificate_jobs() {
        assert_eq!(handler().job_type().as_str(), PROVISION_TLS_JOB);
    }

    /// An authority that failed is asked again; a certificate issued is
    /// done.
    #[test]
    fn only_a_failed_order_is_tried_again() {
        assert_eq!(after_provisioning(Ok(())).unwrap(), Handled::Done);
        assert!(after_provisioning(Err(AppError::internal_msg("authority down"))).is_err());
    }

    /// Missing or already-served domains finish their certificate jobs
    /// instead of requesting another attempt.
    #[test]
    fn a_domain_gone_or_already_served_is_done() {
        let gone = Err(AppError::NotFound("domain".to_owned().into()));
        let served = Err(AppError::Conflict("already active".to_owned().into()));

        assert_eq!(after_provisioning(gone).unwrap(), Handled::Done);
        assert_eq!(after_provisioning(served).unwrap(), Handled::Done);
    }

    /// A job whose payload names no domain fails, rather than asking for a
    /// certificate of nothing.
    #[test]
    fn a_job_without_a_domain_fails() {
        let job = ScheduledJob::new(
            JobType::new(PROVISION_TLS_JOB).unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::new(5).unwrap(),
        );

        let handled =
            block_on(handler().handle(&job, &test_auditor(Arc::new(FakeEventDispatcher::new()))));

        assert!(matches!(handled, Err(AppError::Internal(_))));
    }
}
