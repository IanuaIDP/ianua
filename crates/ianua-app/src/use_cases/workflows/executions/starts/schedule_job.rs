//! The job that starts one version when its schedule comes round: queued
//! by the scheduler sweep, once per version and minute, and run through
//! [`StartOnTriggerUseCase`].

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantId, WorkflowId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command as _;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, done_unless_failed, key_of, payload_of,
};
use crate::use_cases::workflows::executions::{StartOnTriggerRequest, StartOnTriggerUseCase};

/// The job type that starts a version on its schedule.
pub const START_SCHEDULED_JOB: &str = "workflow.start_scheduled";

/// What a schedule job carries: which version of which tenant fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ScheduleJob {
    tenant_id: TenantId,
    workflow_id: WorkflowId,
}

/// Where schedule jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct ScheduledStarts {
    /// Persists starts caused by due workflow schedules.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a schedule job gets before it is given up.
    pub attempts: NonZeroU32,
}

impl ScheduledStarts {
    /// Queues the job starting `workflow_id` of `tenant_id` for the firing
    /// in minute `minute`, counted from the Unix epoch, once for that
    /// version and minute.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        tenant_id: TenantId,
        workflow_id: WorkflowId,
        minute: i64,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: START_SCHEDULED_JOB,
            payload: &ScheduleJob {
                tenant_id,
                workflow_id,
            },
            tenant_id,
            key: key_of(workflow_id, minute)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs schedule jobs through [`StartOnTriggerUseCase`].
pub struct StartScheduledHandler {
    job_type: JobType,
    start: Arc<StartOnTriggerUseCase>,
}

impl StartScheduledHandler {
    /// A handler starting versions through `start`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(start: Arc<StartOnTriggerUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(START_SCHEDULED_JOB)?;
        Ok(Self { job_type, start })
    }
}

#[async_trait]
impl JobHandler for StartScheduledHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Starts the version. A firing carries no data. A start the publisher
    /// may not have is refused and recorded by the start itself; a version
    /// unpublished or moved off its schedule since is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: ScheduleJob = payload_of(job)?;
        let request = StartOnTriggerRequest {
            workflow_id: payload.workflow_id,
            input: FlowData::null(),
            exposure: DataClassLevel::Public,
        };
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        done_unless_failed(self.start.execute(&tenant, &auditor, request).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::scheduling::FakeJobQueue;

    /// Two workers' sweeps both find the payroll workflow due at nine. One
    /// job is queued for that minute; the next minute's firing is another.
    #[test]
    fn a_version_is_started_once_a_minute() {
        let queue = Arc::new(FakeJobQueue::new());
        let starts = ScheduledStarts {
            queue: queue.clone(),
            attempts: NonZeroU32::MIN,
        };
        let (tenant, workflow) = (TenantId::new(), WorkflowId::new());

        block_on(starts.queue(tenant, workflow, 100)).unwrap();
        block_on(starts.queue(tenant, workflow, 100)).unwrap();
        block_on(starts.queue(tenant, workflow, 101)).unwrap();

        assert_eq!(queue.jobs_of(START_SCHEDULED_JOB).len(), 2);
    }
}
