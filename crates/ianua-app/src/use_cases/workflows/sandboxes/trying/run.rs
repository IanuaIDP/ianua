//! Run trial: a worker runs a started trial's version on its input, in a
//! sandbox as a code step's run is made, and keeps how it went.
//!
//! It runs as a `sandbox.try` job, queued in the unit of work that started
//! the trial. The code runs outside any unit of work; only its end is kept,
//! and only while the trial still runs, so a second try that raced the
//! first changes nothing. No sandbox free is tried again; the last try ends
//! the trial as not run, so no trial runs for ever. A worker that stops
//! mid-run runs the code again: a version that names allowed hosts may then
//! call them twice, as its code steps may.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::trial::{SandboxTrial, TrialState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CodeRunId, SandboxTrialId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::JobQueue;
use crate::ports::workflows::{
    CodeRan, CodeRequest, CodeRunner, SandboxTrialStore, SandboxVersionStore,
};
use crate::services::ready_versions::ready_version;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::{
    Handled, JobHandler, NewJob, RetryWhen, key_of, payload_of, unless_gone,
};
use crate::use_cases::workflows::sandboxes::images::pulls::{ImagePulls, Pull};

/// The job type that runs a trial.
pub(crate) const TRY_SANDBOX_JOB: &str = "sandbox.try";

/// Tries a trial's job gets. A try that finds no sandbox waits on the
/// queue's backoff; the last ends the trial as not run.
const TRY_TRIES: NonZeroU32 = match NonZeroU32::new(10) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// What a trial's job carries: which trial of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct TrialJob {
    /// The scope owning the test execution to run.
    pub(crate) tenant_id: TenantId,
    /// The stored test execution waiting for a worker.
    pub(crate) trial_id: SandboxTrialId,
}

/// Where started trials ask for their run.
#[derive(Clone)]
pub struct SandboxTrials {
    queue: Arc<dyn JobQueue>,
}

impl SandboxTrials {
    /// Runs queued on `queue`.
    #[must_use]
    pub fn new(queue: Arc<dyn JobQueue>) -> Self {
        Self { queue }
    }

    /// Runs `trial` of `tenant` as soon as a worker is free. Asking twice
    /// queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn queue(
        &self,
        tenant: &ScopedTenant,
        trial: &SandboxTrialId,
    ) -> Result<(), AppError> {
        NewJob {
            job_type: TRY_SANDBOX_JOB,
            payload: &TrialJob {
                tenant_id: **tenant,
                trial_id: *trial,
            },
            tenant_id: **tenant,
            key: key_of(trial, TRY_SANDBOX_JOB)?,
            hold: KeyHold::WhileLive,
            run_at: clock::now(),
            attempts: TRY_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }
}

/// Whether a try is the trial's last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialTry {
    /// Another follows when no sandbox can take the run.
    NotLast,
    /// None follows: no sandbox ends the trial as not run.
    Last,
}

/// One try at running a trial.
#[derive(Debug, Clone, Copy)]
pub struct RunTrialRequest {
    /// The stored test execution waiting for a worker.
    pub trial_id: SandboxTrialId,
    /// Whether this try is the last.
    pub attempt: TrialTry,
}

/// What a try at a trial came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialTurn {
    /// The trial ended, or was gone or ended already.
    Settled,
    /// No sandbox could take the run; it is tried again.
    TryAgain,
}

/// The ports [`RunTrialUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunTrialPorts {
    /// Keeps the trials.
    pub trials: Arc<dyn SandboxTrialStore>,
    /// Keeps the versions whose code runs.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Runs the code in a sandbox.
    pub runner: Arc<dyn CodeRunner>,
    /// Opens the login a company's image is pulled with, and refuses one
    /// whose registry left the tenant's list.
    pub pulls: ImagePulls,
}

/// Runs started trials and keeps how they went.
pub struct RunTrialUseCase {
    ports: RunTrialPorts,
}

impl RunTrialUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RunTrialPorts) -> Self {
        Self { ports }
    }

    /// What running `trial` came to; `None` when no sandbox could take it
    /// and another try follows. A version gone or with no bundle ready
    /// ends it as not run, as do an image that may no longer be pulled and
    /// no sandbox on the last try.
    async fn outcome(
        &self,
        tenant: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
        attempt: TrialTry,
    ) -> Result<Option<CodeOutcome>, AppError> {
        let ready = ready_version(self.ports.versions.as_ref(), tenant, trial.version_id());
        let Some(version) = ready.await? else {
            return Ok(Some(CodeOutcome::not_run(
                "the sandbox version is gone or has no bundle",
            )));
        };
        let login = match self.ports.pulls.for_version(tenant, &version).await? {
            Pull::Allowed(login) => login,
            Pull::Refused(refusal) => return Ok(Some(CodeOutcome::not_run(refusal.reason()))),
        };
        let request = CodeRequest {
            run_id: CodeRunId::from_uuid(*trial.id().as_uuid()),
            version: &version,
            input: trial.input(),
            login: &login,
        };
        Ok(
            match (self.ports.runner.run(tenant, request).await, attempt) {
                (CodeRan::Ran(outcome), _) => Some(outcome),
                (CodeRan::Unavailable(_), TrialTry::NotLast) => None,
                (CodeRan::Unavailable(reason), TrialTry::Last) => {
                    Some(CodeOutcome::Failed(CodeFailure::NotRun(reason)))
                }
            },
        )
    }
}

impl Command for RunTrialUseCase {
    type Caller = ScopedTenant;
    type Input = RunTrialRequest;
    type Output = Result<TrialTurn, AppError>;

    /// Runs the trial `request` names, unless it is gone or ended, and
    /// keeps how it went.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        _auditor: &RequestAuditor,
        request: RunTrialRequest,
    ) -> Result<TrialTurn, AppError> {
        let Some(mut trial) = self
            .ports
            .trials
            .find_by_id(tenant, &request.trial_id)
            .await
            .or_internal()?
        else {
            return Ok(TrialTurn::Settled);
        };
        if trial.state() != &TrialState::Running {
            return Ok(TrialTurn::Settled);
        }
        let Some(outcome) = self.outcome(tenant, &trial, request.attempt).await? else {
            return Ok(TrialTurn::TryAgain);
        };
        trial.settle(outcome).map_err(AppError::from_domain)?;
        match self.ports.trials.save_end(tenant, &trial).await {
            Ok(()) | Err(DomainError::Conflict(_)) => Ok(TrialTurn::Settled),
            Err(error) => Err(AppError::from_domain(error)),
        }
    }
}

/// Runs trial jobs through [`RunTrialUseCase`].
pub struct TrialHandler {
    job_type: JobType,
    run: Arc<RunTrialUseCase>,
}

impl TrialHandler {
    /// A handler running trials through `run`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(run: Arc<RunTrialUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(TRY_SANDBOX_JOB)?;
        Ok(Self { job_type, run })
    }
}

#[async_trait]
impl JobHandler for TrialHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Runs the trial. One gone or ended is left alone; no sandbox free is
    /// tried again on the queue's backoff, until the last try ends it as
    /// not run.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: TrialJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let attempt = if job.can_retry() {
            TrialTry::NotLast
        } else {
            TrialTry::Last
        };
        let request = RunTrialRequest {
            trial_id: payload.trial_id,
            attempt,
        };
        let turn = unless_gone(self.run.execute(&tenant, &auditor, request).await)?;
        match turn {
            Some(TrialTurn::TryAgain) => Ok(Handled::Retry {
                reason: "no sandbox could take the trial",
                when: RetryWhen::OnBackoff,
            }),
            Some(TrialTurn::Settled) | None => Ok(Handled::Done),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::sandbox::Sandbox;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::test_support::workflows::{
        FakeCodeRunner, FakeSandboxTrialStore, FakeSandboxVersionStore, built_version_of, managing,
        person, python_sandbox,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A trial started on a built version, and the stores holding both.
    struct Running {
        trials: Arc<FakeSandboxTrialStore>,
        versions: Arc<FakeSandboxVersionStore>,
        id: SandboxTrialId,
    }

    impl Running {
        fn new() -> Self {
            let mut sandbox: Sandbox<ResolvedTenant> = python_sandbox();
            let version = built_version_of(&mut sandbox);
            let ann = person("ann@corp.test");
            let trial = sandbox
                .try_version(&managing(&ann), &version, FlowData::bool(true))
                .unwrap();
            Self {
                id: *trial.id(),
                trials: Arc::new(FakeSandboxTrialStore::holding(&trial)),
                versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
            }
        }

        fn run(&self, answer: CodeRan, attempt: TrialTry) -> (TrialTurn, Arc<FakeCodeRunner>) {
            let runner = Arc::new(FakeCodeRunner::answering(answer));
            let use_case = RunTrialUseCase::new(RunTrialPorts {
                trials: self.trials.clone(),
                versions: self.versions.clone(),
                runner: runner.clone(),
                ..RunTrialPorts::fakes()
            });
            let request = RunTrialRequest {
                trial_id: self.id,
                attempt,
            };
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            let turn = block_on(use_case.execute(&test_ctx().tenant(), &auditor, request));
            (turn.unwrap(), runner)
        }

        fn state(&self) -> TrialState {
            self.trials.stored(&self.id).unwrap().state().clone()
        }
    }

    /// The worker runs Tess's trial on its input, and keeps what the code
    /// gave back as its end.
    #[test]
    fn a_trial_ends_with_what_its_code_gave() {
        let running = Running::new();
        let gave = CodeOutcome::Succeeded(FlowData::bool(false));

        let (turn, runner) = running.run(CodeRan::Ran(gave.clone()), TrialTry::NotLast);

        assert_eq!(turn, TrialTurn::Settled);
        assert_eq!(runner.handed(), [FlowData::bool(true)]);
        assert_eq!(running.state(), TrialState::Ended(gave));
    }

    /// No sandbox is free: the trial waits for another try, still running.
    /// On the last try it ends as not run, so it never runs for ever.
    #[test]
    fn no_sandbox_is_tried_again_until_the_last_try() {
        let running = Running::new();
        let busy = || CodeRan::Unavailable(UntrustedText::record("every run is under way"));

        let (first, _) = running.run(busy(), TrialTry::NotLast);
        let still = running.state();
        let (last, _) = running.run(busy(), TrialTry::Last);

        assert_eq!(first, TrialTurn::TryAgain);
        assert_eq!(still, TrialState::Running);
        assert_eq!(last, TrialTurn::Settled);
        assert!(matches!(
            running.state(),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::NotRun(_)))
        ));
    }

    /// A trial that ended is not run again when its job is picked up again.
    #[test]
    fn an_ended_trial_is_not_run_again() {
        let running = Running::new();
        running.run(
            CodeRan::Ran(CodeOutcome::Failed(CodeFailure::TimedOut)),
            TrialTry::NotLast,
        );

        let (turn, runner) = running.run(
            CodeRan::Ran(CodeOutcome::Succeeded(FlowData::null())),
            TrialTry::NotLast,
        );

        assert_eq!(turn, TrialTurn::Settled);
        assert!(runner.handed().is_empty());
        assert_eq!(
            running.state(),
            TrialState::Ended(CodeOutcome::Failed(CodeFailure::TimedOut))
        );
    }
}
