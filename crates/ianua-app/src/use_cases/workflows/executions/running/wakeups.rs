//! Wake-ups: an execution asks to be driven again at a time, a wait that
//! ends, a decision window that closes, a call due again or its run limit,
//! as a `workflow.drive` job due then, and the handler that drives it.
//!
//! A loop's passes wake their loop and are woken by it the same way: a
//! pass that ended asks its loop to take it in, as a `workflow.settle_pass`
//! job, and a loop that failed, or whose execution ended, asks each pass
//! still running to stop, as a `workflow.stop_pass` job. A code step that
//! starts asks for its code to be run, as a `workflow.run_code` job.
//!
//! Every job is queued in the unit of work that kept the change, so an
//! execution is never kept waiting with no wake-up to end the wait.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CodeRunId, TenantId, WorkflowExecutionId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::JobQueue;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command as _;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};
use crate::use_cases::workflows::executions::approvals::ask_in_slack::{
    ASK_IN_SLACK_JOB, AskInSlackJob,
};
use crate::use_cases::workflows::executions::running::DriveUseCase;
use crate::use_cases::workflows::executions::running::run_code::{
    CODE_TRIES, CodeJob, RUN_CODE_JOB,
};

/// The job type that drives an execution.
pub const DRIVE_WORKFLOW_JOB: &str = "workflow.drive";

/// The job type that has a loop take in one of its passes that ended.
pub const SETTLE_PASS_JOB: &str = "workflow.settle_pass";

/// The job type that stops a pass whose loop failed or ended.
pub const STOP_PASS_JOB: &str = "workflow.stop_pass";

/// Tries an ask-in-Slack job gets. A failing store is tried again; Slack
/// refusing is logged and left, the approval open in the inbox either way.
const SLACK_TRIES: NonZeroU32 = match NonZeroU32::new(3) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// Tries a drive job gets. Driving is safe to repeat, and a failure that
/// lasts is the execution's own to end, at its run limit.
const DRIVE_TRIES: NonZeroU32 = match NonZeroU32::new(5) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// Tries a job about one pass gets. Up to ten passes of a loop end at once
/// and each must take the loop's lease in turn, so a turn missed is no
/// failure; the tries leave room for every pass to wait its turn.
const PASS_TRIES: NonZeroU32 = match NonZeroU32::new(30) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// What a job about pass `id` does with `result`: done, or, when the run
/// it needs was busy, tried again within a second. The wait is spread by
/// the pass's id, so passes that met at the lease do not meet again.
///
/// # Errors
///
/// Every error but a busy run, a missing one and `AppError::NotFound`.
pub(crate) fn taken_in_turn(
    result: Result<(), AppError>,
    id: &WorkflowExecutionId,
) -> Result<Handled, AppError> {
    match unless_gone(result) {
        Ok(_) => Ok(Handled::Done),
        Err(AppError::Conflict(_)) => Ok(Handled::Retry {
            reason: "the run the pass needs is busy",
            when: RetryWhen::After(turn_wait(id)),
        }),
        Err(error) => Err(error),
    }
}

/// Between a fifth of a second and a second, picked by `id`.
fn turn_wait(id: &WorkflowExecutionId) -> time::Duration {
    let spread = i64::try_from(id.as_uuid().as_u128() % 800).unwrap_or(0);
    time::Duration::milliseconds(200 + spread)
}

/// What a drive job, or a job about one pass of a loop, carries: which
/// execution of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DriveJob {
    /// The scope in which this worker resumes the run.
    pub(crate) tenant_id: TenantId,
    /// The stored run that should be driven again.
    pub(crate) execution_id: WorkflowExecutionId,
}

/// Where executions ask to be driven again.
#[derive(Clone)]
pub struct Wakeups {
    queue: Arc<dyn JobQueue>,
}

impl Wakeups {
    /// Wake-ups queued on `queue`.
    #[must_use]
    pub fn new(queue: Arc<dyn JobQueue>) -> Self {
        Self { queue }
    }

    /// Drives `id` of `tenant` again at `at`, or at once when `at` has
    /// passed. Asking twice for the same second queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn wake_at(
        &self,
        tenant: &ScopedTenant,
        id: &WorkflowExecutionId,
        at: OffsetDateTime,
    ) -> Result<(), AppError> {
        NewJob {
            job_type: DRIVE_WORKFLOW_JOB,
            payload: &DriveJob {
                tenant_id: **tenant,
                execution_id: *id,
            },
            tenant_id: **tenant,
            key: key_of(id, at.unix_timestamp())?,
            hold: KeyHold::WhileLive,
            run_at: at,
            attempts: DRIVE_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }

    /// Has the loop that started pass `id` of `tenant` take it in, now
    /// that it ended. Asking twice queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn pass_ended(
        &self,
        tenant: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<(), AppError> {
        self.about_pass(tenant, id, SETTLE_PASS_JOB).await
    }

    /// Stops pass `id` of `tenant`, whose loop failed or ended. Asking
    /// twice queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn stop_pass(
        &self,
        tenant: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<(), AppError> {
        self.about_pass(tenant, id, STOP_PASS_JOB).await
    }

    /// Runs the code of step `step` of execution `id` of `tenant`, the run
    /// `run_id`, as soon as a worker is free. Asking twice queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn run_code(
        &self,
        tenant: &ScopedTenant,
        id: &WorkflowExecutionId,
        step: &NodeKey,
        run_id: CodeRunId,
    ) -> Result<(), AppError> {
        NewJob {
            job_type: RUN_CODE_JOB,
            payload: &CodeJob {
                tenant_id: **tenant,
                execution_id: *id,
                step: step.as_str().to_owned(),
                run_id,
            },
            tenant_id: **tenant,
            key: key_of(run_id, RUN_CODE_JOB)?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: CODE_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }

    /// Asks the approval step `step` of execution `id` of `tenant` in the
    /// Slack channel it names, as soon as a worker is free. Asking twice
    /// queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn ask_in_slack(
        &self,
        tenant: &ScopedTenant,
        id: &WorkflowExecutionId,
        step: &NodeKey,
    ) -> Result<(), AppError> {
        NewJob {
            job_type: ASK_IN_SLACK_JOB,
            payload: &AskInSlackJob {
                tenant_id: **tenant,
                execution_id: *id,
                step: step.as_str().to_owned(),
            },
            tenant_id: **tenant,
            key: key_of(format!("{id}:{step}"), ASK_IN_SLACK_JOB)?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: SLACK_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }

    async fn about_pass(
        &self,
        tenant: &ScopedTenant,
        id: &WorkflowExecutionId,
        job_type: &'static str,
    ) -> Result<(), AppError> {
        NewJob {
            job_type,
            payload: &DriveJob {
                tenant_id: **tenant,
                execution_id: *id,
            },
            tenant_id: **tenant,
            key: key_of(id, job_type)?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: PASS_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }
}

/// Runs drive jobs through [`DriveUseCase`].
pub struct DriveHandler {
    job_type: JobType,
    drive: Arc<DriveUseCase>,
}

impl DriveHandler {
    /// A handler driving executions through `drive`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(drive: Arc<DriveUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(DRIVE_WORKFLOW_JOB)?;
        Ok(Self { job_type, drive })
    }
}

#[async_trait]
impl JobHandler for DriveHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Takes the execution as far as it goes now. One that is gone, ended
    /// or held by another worker is left alone.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: DriveJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        unless_gone(
            self.drive
                .execute(&tenant, &auditor, payload.execution_id)
                .await,
        )?;
        Ok(Handled::Done)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::workflows::driven;
    use crate::test_support::{block_on, test_ctx};

    /// An approval's window closes in an hour. A drive job is queued due
    /// then, for the tenant, naming the execution.
    #[test]
    fn a_wakeup_is_a_drive_job_due_at_its_time() {
        let queue = Arc::new(FakeJobQueue::new());
        let wakeups = Wakeups::new(queue.clone());
        let id = WorkflowExecutionId::new();
        let at = clock::now() + time::Duration::HOUR;

        block_on(wakeups.wake_at(&test_ctx().tenant(), &id, at)).unwrap();

        let jobs = queue.jobs_of(DRIVE_WORKFLOW_JOB);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].run_at(), at);
        assert_eq!(jobs[0].tenant_id(), Some(&test_ctx().tenant_id()));
        assert_eq!(driven(&jobs[0]).unwrap(), id);
    }

    /// The same wake-up asked for twice queues one job; one asked for a
    /// later time queues another.
    #[test]
    fn the_same_wakeup_is_queued_once() {
        let queue = Arc::new(FakeJobQueue::new());
        let wakeups = Wakeups::new(queue.clone());
        let id = WorkflowExecutionId::new();
        let at = clock::now();
        let tenant = test_ctx().tenant();

        block_on(wakeups.wake_at(&tenant, &id, at)).unwrap();
        block_on(wakeups.wake_at(&tenant, &id, at)).unwrap();
        block_on(wakeups.wake_at(&tenant, &id, at + time::Duration::MINUTE)).unwrap();

        assert_eq!(queue.jobs_of(DRIVE_WORKFLOW_JOB).len(), 2);
    }

    /// Two passes of Ann's loop end at once. The one that finds the loop
    /// busy is tried again within a second, not on the slow backoff of a
    /// failure; one taken in, or whose run is gone, is done.
    #[test]
    fn a_pass_that_finds_its_loop_busy_waits_its_turn() {
        let id = WorkflowExecutionId::new();
        let busy = Err(AppError::Conflict(ianua_domain::message!(
            "workflows-a-worker-is-driving-the-execution",
            "a worker is driving the execution"
        )));
        let missing = Err(AppError::NotFound(ianua_domain::message!(
            "app-entity-not-found",
            "entity not found"
        )));

        let waited = taken_in_turn(busy, &id).unwrap();
        let taken = taken_in_turn(Ok(()), &id).unwrap();
        let gone = taken_in_turn(missing, &id).unwrap();

        let Handled::Retry {
            when: RetryWhen::After(wait),
            ..
        } = waited
        else {
            panic!("a busy loop is tried again after a wait");
        };
        assert!(wait <= time::Duration::SECOND);
        assert!(matches!(taken, Handled::Done));
        assert!(matches!(gone, Handled::Done));
    }
}
