//! Running the steps of one tenant's multi-step process as jobs, the same
//! way for every process: a tenant's setup, its teardown.
//!
//! Each step is one job, queued once per tenant and step as it becomes
//! ready. The handler runs the step through the process's own use case; a
//! step that fails is tried again on the queue's backoff, and on its last
//! try it fails the process through the process's failing use case
//! instead, so no step is tried for ever. What each step does, and which
//! waits on which, stays with the process.
//!
//! A step job whose worker stopped is given up when its hold runs out, and
//! the platform hands the step out again under the same key. Once a later
//! job has done the step, the given-up job is marked superseded, so
//! operators do not find work among the dead that was finished.

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::steps::{PlanStep, RunOutcome};
use ianua_domain::types::{TenantId, UntrustedText};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::use_case::Command;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, PlanReport, key_of, payload_of, unless_gone,
};

/// One step of one tenant's process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepRequest<S> {
    /// The tenant the process is for.
    pub tenant_id: TenantId,
    /// The setup or teardown operation this request advances.
    pub step: S,
}

/// A step that failed on its last try, and why.
#[derive(Debug, Clone)]
pub struct StepFailure<S> {
    /// The step.
    pub request: StepRequest<S>,
    /// Why it failed, as its last try reported it.
    pub why: UntrustedText,
}

/// What a step job carries: which tenant, which step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct StepJob {
    tenant_id: TenantId,
    step: String,
}

/// Where one process's step jobs are queued, under which job type, and how
/// many tries each gets.
pub struct StepJobs<S> {
    job_type: &'static str,
    queue: Arc<dyn JobQueue>,
    attempts: NonZeroU32,
    steps: PhantomData<fn() -> S>,
}

impl<S> Clone for StepJobs<S> {
    fn clone(&self) -> Self {
        Self {
            job_type: self.job_type,
            queue: Arc::clone(&self.queue),
            attempts: self.attempts,
            steps: PhantomData,
        }
    }
}

impl<S: PlanStep> StepJobs<S> {
    /// Step jobs of `job_type` queued on `queue`, each tried `attempts`
    /// times.
    #[must_use]
    pub fn new(job_type: &'static str, queue: Arc<dyn JobQueue>, attempts: NonZeroU32) -> Self {
        Self {
            job_type,
            queue,
            attempts,
            steps: PhantomData,
        }
    }

    /// Queues the job running `step` for `tenant_id`, once: while one waits
    /// or runs, asking again adds nothing.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub async fn queue(&self, tenant_id: TenantId, step: S) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: self.job_type,
            payload: &StepJob {
                tenant_id,
                step: step.as_str().to_owned(),
            },
            tenant_id,
            key: key_of(format!("{}-{}", self.job_type, step.as_str()), tenant_id)?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }

    /// Queues the job of each of `steps` for `tenant_id`, each once.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a job cannot be built or queued. The jobs
    /// queued before it stay queued, and are not queued twice when asked
    /// again.
    pub async fn queue_each(
        &self,
        tenant_id: TenantId,
        steps: impl IntoIterator<Item = S>,
    ) -> Result<PlanReport, AppError> {
        let mut report = PlanReport::default();
        for step in steps {
            report = report.counting(self.queue(tenant_id, step).await?);
        }
        Ok(report)
    }
}

/// Runs one process's step jobs: each step through `Run`, and the process
/// failed through `Fail` once a step's tries are spent.
pub struct StepJobHandler<S, Run, Fail> {
    job_type: JobType,
    run: Arc<Run>,
    fail: Arc<Fail>,
    queue: Arc<dyn JobQueue>,
    steps: PhantomData<fn() -> S>,
}

impl<S, Run, Fail> StepJobHandler<S, Run, Fail>
where
    S: PlanStep,
    Run: Command<Caller = (), Input = StepRequest<S>, Output = Result<RunOutcome, AppError>>,
    Fail: Command<Caller = (), Input = StepFailure<S>, Output = Result<RunOutcome, AppError>>,
{
    /// A handler of `job_type` running steps through `run`, failing the
    /// process through `fail` once a step's tries are spent, and marking
    /// superseded on `queue` the given-up jobs of a step it did.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when `job_type` is not a job
    /// type.
    pub fn new(
        job_type: &'static str,
        run: Arc<Run>,
        fail: Arc<Fail>,
        queue: Arc<dyn JobQueue>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            job_type: JobType::new(job_type)?,
            run,
            fail,
            queue,
            steps: PhantomData,
        })
    }

    /// Done with `job`, which did its step: the jobs given up on the same
    /// step before it are superseded.
    async fn superseding(&self, job: &ScheduledJob) -> Result<Handled, AppError> {
        self.queue.supersede_dead(job).await.or_internal()?;
        Ok(Handled::Done)
    }

    /// The step `job` runs.
    fn request_of(job: &ScheduledJob) -> Result<StepRequest<S>, AppError> {
        let payload: StepJob = payload_of(job)?;
        let step = S::named(&payload.step)
            .ok_or_else(|| AppError::internal_msg("a step job names no step of its process"))?;
        Ok(StepRequest {
            tenant_id: payload.tenant_id,
            step,
        })
    }

    /// Fails the process at `request`'s step for `error`, the last try's.
    async fn give_up(
        &self,
        request: StepRequest<S>,
        error: &AppError,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let failure = StepFailure {
            request,
            why: UntrustedText::record(&error.to_string()),
        };
        unless_gone(self.fail.execute(&(), auditor, failure).await)?;
        Ok(Handled::Done)
    }
}

#[async_trait]
impl<S, Run, Fail> JobHandler for StepJobHandler<S, Run, Fail>
where
    S: PlanStep,
    Run: Command<Caller = (), Input = StepRequest<S>, Output = Result<RunOutcome, AppError>>
        + Send
        + Sync,
    Fail: Command<Caller = (), Input = StepFailure<S>, Output = Result<RunOutcome, AppError>>
        + Send
        + Sync,
{
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Runs the step. A tenant or process that is gone is done with; a step
    /// that failed is tried again on the queue's backoff, and on its last
    /// try it fails the process instead.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let request = Self::request_of(job)?;
        let ran = unless_gone(self.run.execute(&(), auditor, request).await);
        match ran {
            Ok(Some(RunOutcome::Running | RunOutcome::Done)) => self.superseding(job).await,
            Ok(Some(RunOutcome::Failed) | None) => Ok(Handled::Done),
            Err(error) if job.can_retry() => Err(error),
            Err(error) => self.give_up(request, &error, auditor).await,
        }
    }
}
