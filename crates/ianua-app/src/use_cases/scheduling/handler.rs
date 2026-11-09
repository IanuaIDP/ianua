//! What runs a job of one type, and what it says should happen next.
//!
//! A handler reads its job's payload and runs the work the job stands for.
//! Almost every one is the app's own code, running a use case. The one
//! outside it is the mail outbox's: the outbox adapter seals its mail into
//! the job and alone can open, render and deliver it. The worker registers
//! the handlers it is given; none of them is a port a use case calls.

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;

use crate::auditor::RequestAuditor;
use crate::error::AppError;

/// How a job a handler ran came out, short of an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    /// The work is done, or there is nothing left to do: its target is
    /// gone or no longer takes it.
    Done,
    /// The work was tried and must be tried again.
    Retry {
        /// Why, in words safe to show whoever follows the job.
        reason: &'static str,
        /// The timing policy for the next attempt.
        when: RetryWhen,
    },
}

/// When a job a handler asked to retry runs again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryWhen {
    /// Once this has passed, as the work's own policy says, such as a
    /// webhook's retry delay.
    After(time::Duration),
    /// On the queue's backoff for the job's attempt.
    OnBackoff,
}

/// Dyn-safe trait for the code that runs jobs of one type.
///
/// Each handler runs one job type and is registered with the job processor
/// at startup.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// The job type this handler runs (e.g. `"domain.provision_tls"`).
    fn job_type(&self) -> &JobType;

    /// Runs `job`, recording what it changes through `auditor`.
    ///
    /// # Errors
    ///
    /// Returns the [`AppError`] that stopped the job. The processor retries
    /// it on its backoff, and keeps a reason safe to show on the job.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError>;
}

/// `result`, or `None` when what it worked on is gone: a job whose target
/// was deleted since is done, not failed.
///
/// # Errors
///
/// Every error but `AppError::NotFound`.
pub(crate) fn unless_gone<T>(result: Result<T, AppError>) -> Result<Option<T>, AppError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(AppError::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Done once `result` came back, or once what it worked on is gone or no
/// longer takes the work, as a workflow unpublished or moved to another
/// trigger since its start was queued: the domain's refusal ends the job
/// rather than failing it again and again.
///
/// # Errors
///
/// Every error but `AppError::NotFound` and `AppError::Domain`.
pub(crate) fn done_unless_failed<T>(result: Result<T, AppError>) -> Result<Handled, AppError> {
    match unless_gone(result) {
        Ok(_) | Err(AppError::Domain(_)) => Ok(Handled::Done),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::errors::DomainError;

    use super::*;

    /// A workflow republished on another trigger refuses its start; the
    /// job is done, not retried. A store that fails is still an error.
    #[test]
    fn a_refusal_ends_the_job_and_a_failure_does_not() {
        let refused: Result<(), AppError> = Err(AppError::from_domain(DomainError::invalid(
            "the version does not start on this event",
        )));
        let failed: Result<(), AppError> = Err(AppError::internal_msg("store down"));

        assert!(matches!(done_unless_failed(refused), Ok(Handled::Done)));
        assert!(done_unless_failed(failed).is_err());
    }

    /// A webhook deleted while its delivery waited answers not found; the
    /// delivery is over, not failed.
    #[test]
    fn a_target_that_is_gone_is_none() {
        let gone: Result<(), AppError> = Err(AppError::NotFound("subscription".to_owned().into()));

        assert!(matches!(unless_gone(gone), Ok(None)));
    }

    /// A store that fails is still an error, so the job is tried again.
    #[test]
    fn any_other_error_stays_an_error() {
        let failed: Result<(), AppError> = Err(AppError::internal_msg("store down"));

        assert!(matches!(unless_gone(failed), Err(AppError::Internal(_))));
    }
}
