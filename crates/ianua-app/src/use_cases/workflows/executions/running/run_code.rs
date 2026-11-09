//! Run code: a code step's run of its sandbox version, made by a worker in
//! the long lane, then settled on the execution read back afresh.
//!
//! The step is started and its job queued in one unit of work, so no step
//! waits on a run nobody will make. The code runs outside the execution's
//! lease, which is taken only to settle what came of it. A run is made
//! again when its job is picked up again, after a worker stopped or the
//! lease was busy at the end: code that reaches no network changes nothing
//! outside when run twice, and a version that names allowed hosts may call
//! them twice, which its code must bear. A run the step no longer waits
//! on, one settled or one whose execution ended, is never made.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::CodeRun;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CodeRunId, TenantId, WorkflowExecutionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    CodeRan, CodeRequest, CodeRunner, ExecutionLease, ExecutionVersion, SandboxVersionStore,
    WorkflowExecutionStore,
};
use crate::services::kept_together::kept_together;
use crate::services::ready_versions::ready_version;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::scheduling::{Handled, JobHandler, RetryWhen, payload_of};
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::executions::running::wakeups::taken_in_turn;
use crate::use_cases::workflows::sandboxes::images::pulls::{ImagePulls, Pull};

/// The job type that runs a code step's code.
pub const RUN_CODE_JOB: &str = "workflow.run_code";

/// Tries a code run's job gets. A try that finds no sandbox waits
/// [`SANDBOX_WAIT`]; one that finds the execution busy at the end waits
/// under a second. The last try that finds no sandbox fails the step, so
/// it never waits for good.
pub(crate) const CODE_TRIES: NonZeroU32 = match NonZeroU32::new(30) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// How long a run that found no sandbox waits before it asks again.
const SANDBOX_WAIT: time::Duration = time::Duration::seconds(30);

/// What a code run's job carries: which run of which step of which
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CodeJob {
    /// The scope containing the execution waiting on this code run.
    pub(crate) tenant_id: TenantId,
    /// The parent run whose code step is waiting.
    pub(crate) execution_id: WorkflowExecutionId,
    /// The code step's key.
    pub(crate) step: String,
    /// The run the step waits on.
    pub(crate) run_id: CodeRunId,
}

/// Whether this try of a code run's job is its last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeTry {
    /// Another try follows when no sandbox can take the run.
    NotLast,
    /// None follows: no sandbox fails the step.
    Last,
}

/// One run to make: the step of the execution that waits on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCodeRequest {
    /// The parent run whose code step is waiting.
    pub execution_id: WorkflowExecutionId,
    /// The code step.
    pub step: NodeKey,
    /// The run the step waits on.
    pub run_id: CodeRunId,
    /// Whether this try is the last.
    pub attempt: CodeTry,
}

/// What one try came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeTurn {
    /// The step was settled, or no longer waits on this run.
    Settled,
    /// No sandbox could take the run; a later try may find one.
    TryAgain,
}

/// The ports [`RunCodeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunCodePorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Keeps the sandbox versions whose code runs.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// Runs the code in a sandbox.
    pub runner: Arc<dyn CodeRunner>,
    /// Opens the login a company's image is pulled with, and refuses one
    /// whose registry left the tenant's list.
    pub pulls: ImagePulls,
    /// Keeps the driving worker and this settlement apart.
    pub lease: Arc<dyn ExecutionLease>,
    /// Drives the execution on once the step settled.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end.
    pub run_stops: StopPorts,
    /// Keeps the settled execution and its records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Runs code steps' code and settles what came of it.
pub struct RunCodeUseCase {
    ports: RunCodePorts,
}

impl RunCodeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RunCodePorts) -> Self {
        Self { ports }
    }

    /// What running `run` came to. `None` when no sandbox could take it
    /// and another try follows.
    ///
    /// A version that is gone or has no bundle ready fails the step, as do
    /// an image that may no longer be pulled and no sandbox on the last
    /// try.
    async fn outcome(
        &self,
        tenant: &ScopedTenant,
        run: &CodeRun,
        attempt: CodeTry,
    ) -> Result<Option<CodeOutcome>, AppError> {
        let Some(version) =
            ready_version(self.ports.versions.as_ref(), tenant, &run.version).await?
        else {
            return Ok(Some(CodeOutcome::not_run(
                "the sandbox version is gone or has no bundle",
            )));
        };
        let login = match self.ports.pulls.for_version(tenant, &version).await? {
            Pull::Allowed(login) => login,
            Pull::Refused(refusal) => return Ok(Some(CodeOutcome::not_run(refusal.reason()))),
        };
        let request = CodeRequest {
            run_id: run.run_id,
            version: &version,
            input: &run.input,
            login: &login,
        };
        let ran = self.ports.runner.run(tenant, request).await;
        Ok(match (ran, attempt) {
            (CodeRan::Ran(outcome), _) => Some(outcome),
            (CodeRan::Unavailable(_), CodeTry::NotLast) => None,
            (CodeRan::Unavailable(reason), CodeTry::Last) => {
                Some(CodeOutcome::Failed(CodeFailure::NotRun(reason)))
            }
        })
    }

    /// Settles `outcome` on the step `request` names, read afresh under the
    /// execution's lease, and keeps it.
    async fn settle(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: &RunCodeRequest,
        outcome: CodeOutcome,
    ) -> Result<(), AppError> {
        let id = &request.execution_id;
        if !self.ports.lease.try_claim(id).await.or_internal()? {
            return Err(AppError::Conflict(message!(
                "workflows-a-worker-is-driving-the-execution",
                "a worker is driving the execution"
            )));
        }
        let kept = self.keep(tenant, auditor, request, outcome).await;
        self.ports.lease.release(id).await;
        kept
    }

    /// Settles `outcome` on the execution as stored now and keeps it. An
    /// execution that is gone, or a step that no longer takes the outcome,
    /// is left as it is.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: &RunCodeRequest,
        outcome: CodeOutcome,
    ) -> Result<(), AppError> {
        let Some(mut execution) = self
            .ports
            .executions
            .find_by_id(tenant, &request.execution_id)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        let read = ExecutionVersion::of(&execution);
        let records = match execution.settle_code(&request.step, request.run_id, outcome) {
            Ok(records) => records,
            Err(refused) if is_settled_already(&refused) => return Ok(()),
            Err(refused) => return Err(AppError::from_domain(refused)),
        };
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        kept_together(
            self.ports.unit_of_work.as_ref(),
            keeping.keep(tenant, auditor, Kept::Changed(&execution, read), records),
        )
        .await
    }
}

impl Command for RunCodeUseCase {
    type Caller = ScopedTenant;
    type Input = RunCodeRequest;
    type Output = Result<CodeTurn, AppError>;

    /// Runs the code of the step `request` names, when the step still waits
    /// on that run, and settles what came of it.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` while a worker drives the execution, or when
    ///   a person changed it since it was read; the job runs again.
    /// - `AppError::Internal` when a store, the lease or the audit trail
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RunCodeRequest,
    ) -> Result<CodeTurn, AppError> {
        let Some(execution) = self
            .ports
            .executions
            .find_by_id(tenant, &request.execution_id)
            .await
            .or_internal()?
        else {
            return Ok(CodeTurn::Settled);
        };
        let Some(run) = execution
            .code_run(&request.step)
            .filter(|run| run.run_id == request.run_id)
        else {
            return Ok(CodeTurn::Settled);
        };
        let Some(outcome) = self.outcome(tenant, &run, request.attempt).await? else {
            return Ok(CodeTurn::TryAgain);
        };
        self.settle(tenant, auditor, &request, outcome).await?;
        Ok(CodeTurn::Settled)
    }
}

/// Runs code-run jobs through [`RunCodeUseCase`].
pub struct RunCodeHandler {
    job_type: JobType,
    run: Arc<RunCodeUseCase>,
}

impl RunCodeHandler {
    /// A handler running code through `run`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(run: Arc<RunCodeUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(RUN_CODE_JOB)?;
        Ok(Self { job_type, run })
    }
}

#[async_trait]
impl JobHandler for RunCodeHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Runs the step's code and settles it. A run no sandbox could take is
    /// tried again after [`SANDBOX_WAIT`]; one whose execution was busy at
    /// the end is tried again within a second.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: CodeJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let request = RunCodeRequest {
            execution_id: payload.execution_id,
            step: NodeKey::new(payload.step).map_err(AppError::internal)?,
            run_id: payload.run_id,
            attempt: try_of(job),
        };
        match self.run.execute(&tenant, &auditor, request).await {
            Ok(CodeTurn::TryAgain) => Ok(Handled::Retry {
                reason: "no sandbox could take the code run",
                when: RetryWhen::After(SANDBOX_WAIT),
            }),
            other => taken_in_turn(other.map(|_| ()), &payload.execution_id),
        }
    }
}

/// Whether `job` is on its last try.
fn try_of(job: &ScheduledJob) -> CodeTry {
    if job.can_retry() {
        return CodeTry::NotLast;
    }
    CodeTry::Last
}

/// Whether `refused` says the step no longer takes an outcome for this
/// run: it settled, it was stopped, or its execution ended or ran out of
/// time and the drive that ends it records that.
fn is_settled_already(refused: &DomainError) -> bool {
    matches!(
        refused,
        DomainError::InvalidTransition(_) | DomainError::Forbidden(_) | DomainError::Conflict(_)
    )
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::execution::step::{StepFailure, StepState};
    use ianua_domain::domains::workflows::execution::{CodeRun, WorkflowExecution};
    use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::test_support::workflows::{
        FakeCodeRunner, FakeExecutionLease, FakeSandboxVersionStore, FakeWorkflowExecutionStore,
        code_under_way, person, ready_version, step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann's run, waiting on its code step's run of a ready version.
    struct Running {
        executions: Arc<FakeWorkflowExecutionStore>,
        lease: Arc<FakeExecutionLease>,
        execution: WorkflowExecution<ResolvedTenant>,
        run: CodeRun,
    }

    impl Running {
        fn of(version: &SandboxVersion<ResolvedTenant>) -> Self {
            let (execution, run) = code_under_way(&person("ann@corp.test"), *version.id());
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(&execution)),
                lease: Arc::new(FakeExecutionLease::free()),
                execution,
                run,
            }
        }

        fn request(&self, attempt: CodeTry) -> RunCodeRequest {
            RunCodeRequest {
                execution_id: *self.execution.id(),
                step: step("clean"),
                run_id: self.run.run_id,
                attempt,
            }
        }

        fn ran(
            &self,
            versions: FakeSandboxVersionStore,
            runner: &Arc<FakeCodeRunner>,
            request: RunCodeRequest,
        ) -> CodeTurn {
            let use_case = RunCodeUseCase::new(RunCodePorts {
                executions: self.executions.clone(),
                versions: Arc::new(versions),
                runner: runner.clone(),
                lease: self.lease.clone(),
                ..RunCodePorts::fakes()
            });
            let sink = Arc::new(FakeEventDispatcher::new());
            block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(sink), request)).unwrap()
        }

        fn state(&self) -> StepState {
            self.executions
                .stored(self.execution.id())
                .unwrap()
                .step(&step("clean"))
                .unwrap()
                .clone()
        }
    }

    fn answering(answer: CodeRan) -> Arc<FakeCodeRunner> {
        Arc::new(FakeCodeRunner::answering(answer))
    }

    /// Ann's code gives back a cleaned title. The runner is handed what the
    /// step maps, the step succeeds with the title, and the lease is let go.
    #[test]
    fn what_the_code_gives_back_settles_the_step() {
        let version = ready_version();
        let running = Running::of(&version);
        let title = FlowData::text("Fix login").unwrap();
        let runner = answering(CodeRan::Ran(CodeOutcome::Succeeded(title.clone())));

        let turn = running.ran(
            FakeSandboxVersionStore::holding(&version),
            &runner,
            running.request(CodeTry::NotLast),
        );

        assert_eq!(turn, CodeTurn::Settled);
        assert_eq!(runner.handed(), std::slice::from_ref(&running.run.input));
        let StepState::Succeeded { output, .. } = running.state() else {
            panic!("the code step did not succeed");
        };
        assert_eq!(output, title);
        assert!(running.lease.was_released(running.execution.id()));
    }

    /// No sandbox can take Ann's run. Before the last try the step keeps
    /// waiting and the job is tried again; on the last it fails as not run,
    /// saying why.
    #[test]
    fn no_sandbox_is_tried_again_until_the_last_try() {
        let version = ready_version();
        let running = Running::of(&version);
        let runner = answering(CodeRan::Unavailable(UntrustedText::record(
            "the container runtime is down",
        )));

        let early = running.ran(
            FakeSandboxVersionStore::holding(&version),
            &runner,
            running.request(CodeTry::NotLast),
        );
        let waiting = running.state();
        let last = running.ran(
            FakeSandboxVersionStore::holding(&version),
            &runner,
            running.request(CodeTry::Last),
        );

        assert_eq!(early, CodeTurn::TryAgain);
        assert!(matches!(waiting, StepState::Running { .. }));
        assert_eq!(last, CodeTurn::Settled);
        assert_eq!(
            running.state(),
            StepState::Failed(StepFailure::CodeNotRun(UntrustedText::record(
                "the container runtime is down"
            )))
        );
    }

    /// A missing sandbox version fails the step as code not run without handing
    /// any input to the runner.
    #[test]
    fn a_version_that_is_gone_runs_nothing() {
        let version = ready_version();
        let running = Running::of(&version);
        let runner = answering(CodeRan::Ran(CodeOutcome::Succeeded(FlowData::null())));

        running.ran(
            FakeSandboxVersionStore::empty(),
            &runner,
            running.request(CodeTry::NotLast),
        );

        assert!(runner.handed().is_empty());
        assert!(matches!(
            running.state(),
            StepState::Failed(StepFailure::CodeNotRun(_))
        ));
    }

    /// The job for a run the step no longer waits on, picked up again after
    /// the run settled, makes no run and changes nothing.
    #[test]
    fn a_run_already_settled_is_not_made_again() {
        let version = ready_version();
        let running = Running::of(&version);
        let runner = answering(CodeRan::Ran(CodeOutcome::Succeeded(FlowData::null())));
        let stale = RunCodeRequest {
            run_id: CodeRunId::new(),
            ..running.request(CodeTry::NotLast)
        };

        let turn = running.ran(FakeSandboxVersionStore::holding(&version), &runner, stale);

        assert_eq!(turn, CodeTurn::Settled);
        assert!(runner.handed().is_empty());
        assert!(matches!(running.state(), StepState::Running { .. }));
    }
}
