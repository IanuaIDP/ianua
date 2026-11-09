//! The job that drives an agent run on a worker: queued when a run is
//! started, and again for a run left started with nobody driving it.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentRunId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command as _;
use crate::use_cases::agents::runs::driving::DriveUseCase;
use crate::use_cases::scheduling::{Handled, JobHandler, NewJob, key_of, payload_of, unless_gone};

/// The job type that drives an agent run.
pub const DRIVE_RUN_JOB: &str = "agents.drive_run";

/// What a drive job carries: which run of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DriveRunJob {
    tenant_id: TenantId,
    run_id: AgentRunId,
}

/// Where drive jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct RunDrives {
    /// Persists work for a worker to resume driving a run.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a drive job gets.
    pub attempts: NonZeroU32,
}

impl RunDrives {
    /// Queues the job driving `run_id` of `tenant_id`, once: while one waits
    /// or runs, asking again adds nothing.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub async fn queue(
        &self,
        tenant_id: TenantId,
        run_id: AgentRunId,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: DRIVE_RUN_JOB,
            payload: &DriveRunJob { tenant_id, run_id },
            tenant_id,
            key: key_of(run_id, "drive")?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }

    /// Hands `run` of `tenant` to a worker by queueing its drive job, in
    /// the unit of work that saved it, so a run is never kept started with
    /// no job to drive it.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub async fn hand_over(
        &self,
        tenant: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.queue(**tenant, *run.id()).await.map(|_| ())
    }
}

/// Runs drive jobs through [`DriveUseCase`].
pub struct DriveRunHandler {
    job_type: JobType,
    drive: Arc<DriveUseCase>,
}

impl DriveRunHandler {
    /// A handler driving runs through `drive`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(drive: Arc<DriveUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(DRIVE_RUN_JOB)?;
        Ok(Self { job_type, drive })
    }
}

#[async_trait]
impl JobHandler for DriveRunHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Drives the run the job names. A run that is gone is done with; one
    /// another worker holds is left to it.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: DriveRunJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        unless_gone(self.drive.execute(&tenant, &auditor, payload.run_id).await)?;
        Ok(Handled::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::scheduling::FakeJobQueue;

    /// Acme's run is asked to be driven twice before a worker takes it. One
    /// drive job is queued, for Acme, naming the run.
    #[test]
    fn a_run_is_queued_to_be_driven_once() {
        let queue = Arc::new(FakeJobQueue::new());
        let drives = RunDrives {
            queue: queue.clone(),
            attempts: NonZeroU32::new(3).unwrap(),
        };
        let tenant_id = TenantId::new();
        let run_id = AgentRunId::new();

        let first = block_on(drives.queue(tenant_id, run_id)).unwrap();
        let second = block_on(drives.queue(tenant_id, run_id)).unwrap();

        let jobs = queue.jobs_of(DRIVE_RUN_JOB);
        assert_eq!((first, second), (Enqueued::Queued, Enqueued::AlreadyQueued));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].tenant_id(), Some(&tenant_id));
        let payload: DriveRunJob = payload_of(&jobs[0]).unwrap();
        assert_eq!(payload.run_id, run_id);
    }
}
