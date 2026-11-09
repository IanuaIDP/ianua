//! The job that starts one version on one event: queued by the planning of
//! the event, and run through [`StartOnEventUseCase`].

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin};
use ianua_domain::types::{AuditRecordId, TenantId, WorkflowId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command as _;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, done_unless_failed, key_of, payload_of,
};
use crate::use_cases::workflows::executions::starts::on_event::{
    StartOnEventRequest, StartOnEventUseCase,
};

/// The job type that starts a version on an event.
pub const START_ON_EVENT_JOB: &str = "workflow.start_on_event";

/// What an event job carries: which version of which tenant, which event,
/// and how deep in a chain of executions the event was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EventJob {
    tenant_id: TenantId,
    workflow_id: WorkflowId,
    record_id: AuditRecordId,
    chain_depth: Option<u8>,
}

impl EventJob {
    /// Where the event came from, read back.
    fn origin(self) -> Result<EventOrigin, DomainError> {
        let Some(depth) = self.chain_depth else {
            return Ok(EventOrigin::Outside);
        };
        ChainDepth::from_stored(depth).map(EventOrigin::Execution)
    }
}

/// The depth `origin` names, as a job keeps it.
fn depth_of(origin: EventOrigin) -> Option<u8> {
    match origin {
        EventOrigin::Outside => None,
        EventOrigin::Execution(depth) => Some(depth.get()),
    }
}

/// Where event jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct EventStarts {
    /// Persists starts caused by incoming service events.
    pub queue: Arc<dyn JobQueue>,
    /// Tries an event job gets before it is given up.
    pub attempts: NonZeroU32,
}

impl EventStarts {
    /// Queues the job starting `workflow_id` of `tenant_id` on the event
    /// `record_id`, raised from `origin`, once for that event and version.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        tenant_id: TenantId,
        workflow_id: WorkflowId,
        record_id: AuditRecordId,
        origin: EventOrigin,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: START_ON_EVENT_JOB,
            payload: &EventJob {
                tenant_id,
                workflow_id,
                record_id,
                chain_depth: depth_of(origin),
            },
            tenant_id,
            key: key_of(record_id, workflow_id)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// Runs event jobs through [`StartOnEventUseCase`].
pub struct StartOnEventHandler {
    job_type: JobType,
    start: Arc<StartOnEventUseCase>,
}

impl StartOnEventHandler {
    /// A handler starting versions through `start`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(start: Arc<StartOnEventUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(START_ON_EVENT_JOB)?;
        Ok(Self { job_type, start })
    }
}

#[async_trait]
impl JobHandler for StartOnEventHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Starts the version on the event. A start the publisher may not have
    /// is refused and recorded by the start itself; a version unpublished
    /// or moved to another trigger since, or an event whose record is gone,
    /// is done with.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: EventJob = payload_of(job)?;
        let request = StartOnEventRequest {
            workflow_id: payload.workflow_id,
            record_id: payload.record_id,
            origin: payload.origin().map_err(AppError::internal)?,
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

    /// An event raised by a run two deep in a chain reads back two deep,
    /// so the start it plans continues the chain rather than resetting it.
    #[test]
    fn an_event_job_keeps_its_chain_depth() {
        let queue = Arc::new(FakeJobQueue::new());
        let starts = EventStarts {
            queue: queue.clone(),
            attempts: NonZeroU32::MIN,
        };
        let depth = ChainDepth::from_stored(2).unwrap();

        block_on(starts.queue(
            TenantId::new(),
            WorkflowId::new(),
            AuditRecordId::new(),
            EventOrigin::Execution(depth),
        ))
        .unwrap();

        let job = queue.jobs_of(START_ON_EVENT_JOB).remove(0);
        let payload: EventJob = payload_of(&job).unwrap();
        assert_eq!(payload.origin().unwrap(), EventOrigin::Execution(depth));
    }
}
