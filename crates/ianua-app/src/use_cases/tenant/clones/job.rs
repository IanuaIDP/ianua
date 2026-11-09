//! The job that copies a clone on a worker: queued with the clone when it
//! starts, and again for a clone left copying with nobody copying it.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantCloneId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::use_case::Command as _;
use crate::use_cases::scheduling::{Handled, JobHandler, NewJob, key_of, payload_of, unless_gone};
use crate::use_cases::tenant::clones::RunUseCase;

/// The job type that copies a clone.
pub const RUN_CLONE_JOB: &str = "tenant.run_clone";

/// What a clone job carries: which clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CloneJob {
    clone_id: TenantCloneId,
}

/// Where clone jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct CloneRuns {
    /// Persists work for a worker to copy the remaining tenant data.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a clone job gets. Each try starts at the first part not yet
    /// copied.
    pub attempts: NonZeroU32,
}

impl CloneRuns {
    /// Queues the job copying `clone_id` into `target`, once: while one
    /// waits or runs, asking again adds nothing.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub async fn queue(
        &self,
        clone_id: TenantCloneId,
        target: TenantId,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: RUN_CLONE_JOB,
            payload: &CloneJob { clone_id },
            tenant_id: target,
            key: key_of(clone_id, "copy")?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs clone jobs through [`RunUseCase`].
pub struct RunCloneHandler {
    job_type: JobType,
    run: Arc<RunUseCase>,
}

impl RunCloneHandler {
    /// A handler copying clones through `run`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(run: Arc<RunUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(RUN_CLONE_JOB)?;
        Ok(Self { job_type, run })
    }
}

#[async_trait]
impl JobHandler for RunCloneHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Copies what the clone still has to copy. A clone that is gone is
    /// done with, and one that ended is left as it is.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: CloneJob = payload_of(job)?;
        unless_gone(self.run.execute(&(), auditor, payload.clone_id).await)?;
        Ok(Handled::Done)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::scheduling::job_status::JobStatus;

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::clone_runs;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::tenant::clones::RunPorts;

    /// Acme's clone is asked to be copied twice before a worker takes it.
    /// One job is queued, for the tenant it fills.
    #[test]
    fn a_clone_is_queued_to_be_copied_once() {
        let queue = Arc::new(FakeJobQueue::new());
        let runs = clone_runs(queue.clone());
        let clone_id = TenantCloneId::new();
        let target = TenantId::new();

        block_on(runs.queue(clone_id, target)).unwrap();
        block_on(runs.queue(clone_id, target)).unwrap();

        let jobs = queue.jobs_of(RUN_CLONE_JOB);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].tenant_id(), Some(&target));
        assert_eq!(jobs[0].status(), JobStatus::Pending);
    }

    /// A clone deleted while its job waited is done with, not failed again
    /// and again.
    #[test]
    fn a_job_for_a_clone_that_is_gone_is_done() {
        let queue = Arc::new(FakeJobQueue::new());
        block_on(clone_runs(queue.clone()).queue(TenantCloneId::new(), TenantId::new())).unwrap();
        let job = queue.jobs_of(RUN_CLONE_JOB).remove(0);
        let handler = RunCloneHandler::new(Arc::new(RunUseCase::new(RunPorts::fakes()))).unwrap();

        let handled =
            block_on(handler.handle(&job, &test_auditor(Arc::new(FakeEventDispatcher::new()))))
                .unwrap();

        assert_eq!(handled, Handled::Done);
    }
}
