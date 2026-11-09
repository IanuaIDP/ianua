//! Run evaluation: a worker moves an evaluation on, a look at a time, as
//! `workflow.evaluate` jobs.
//!
//! Each look takes in the test runs that ended, checking their results
//! against their cases, then starts as many waiting cases as there are
//! free places, each as a test run of the version tried, the same test a
//! person starts by hand. What a look changed is kept in one unit of work
//! with the test runs it started and the job for its next look, a few
//! seconds later, so no case runs without being recorded and no evaluation
//! waits on a look nobody will make.
//!
//! - A worker that stops mid-look keeps nothing of it; the look is tried
//!   again and starts the same cases afresh.
//! - Two looks that race write only over the evaluation as they read it;
//!   the later one is refused and changes nothing.
//! - The evaluation's deadline, or a job's last try, ends every case still
//!   open as not run, so no evaluation runs for ever. A job that failed
//!   every try leaves the evaluation to the sweep of overdue evaluations.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::design::workflow::{RunnableCode, Workflow};
use ianua_domain::domains::workflows::evaluation::case::EvaluationCase;
use ianua_domain::domains::workflows::evaluation::outcome::NotRunReason;
use ianua_domain::domains::workflows::evaluation::run::{Evaluation, EvaluationState};
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::{
    ActingAuthority, ExecutionStatus, WorkflowExecution,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{EvaluationId, TenantId};
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::scheduling::JobQueue;
use crate::ports::workflows::{
    EvaluationStore, SandboxStore, SandboxVersionStore, WorkflowExecutionStore, WorkflowStore,
};
use crate::services::account_now::AccountsNow;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::scheduling::{Handled, JobHandler, NewJob, key_of, payload_of, unless_gone};
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::runnable::Runnable;

/// The job type that takes one look at an evaluation.
pub(crate) const EVALUATE_JOB: &str = "workflow.evaluate";

/// Tries one look gets. A store that fails is tried again on the queue's
/// backoff; the last try ends the evaluation.
const EVALUATE_TRIES: NonZeroU32 = match NonZeroU32::new(5) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// How long after one look the next is taken, while cases are open.
const NEXT_LOOK: Duration = Duration::seconds(3);

/// What a look's job carries: which evaluation of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EvaluationJob {
    /// The tenant the evaluation is kept for.
    pub(crate) tenant_id: TenantId,
    /// The evaluation to look at.
    pub(crate) evaluation_id: EvaluationId,
}

/// Where evaluations ask for their next look.
#[derive(Clone)]
pub struct Evaluations {
    queue: Arc<dyn JobQueue>,
}

impl Evaluations {
    /// Looks queued on `queue`.
    #[must_use]
    pub fn new(queue: Arc<dyn JobQueue>) -> Self {
        Self { queue }
    }

    /// Looks at evaluation `id` of `tenant` at `at`, or at once when `at`
    /// has passed. Asking twice for the same second queues one job.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    pub(crate) async fn look_at(
        &self,
        tenant: &ScopedTenant,
        id: &EvaluationId,
        at: OffsetDateTime,
    ) -> Result<(), AppError> {
        NewJob {
            job_type: EVALUATE_JOB,
            payload: &EvaluationJob {
                tenant_id: **tenant,
                evaluation_id: *id,
            },
            tenant_id: **tenant,
            key: key_of(id, at.unix_timestamp())?,
            hold: KeyHold::WhileLive,
            run_at: at,
            attempts: EVALUATE_TRIES,
        }
        .queue(self.queue.as_ref())
        .await?;
        Ok(())
    }
}

/// Whether a look is its job's last try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationTry {
    /// Another follows when this one fails.
    NotLast,
    /// None follows: the evaluation ends with every open case not run.
    Last,
}

/// One look at an evaluation.
#[derive(Debug, Clone, Copy)]
pub struct RunRequest {
    /// The evaluation to look at.
    pub evaluation_id: EvaluationId,
    /// Whether this look is its job's last try.
    pub attempt: EvaluationTry,
}

/// What a look came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationTurn {
    /// Cases are still open; the next look is queued.
    Continues,
    /// The evaluation ended, now or before, or is gone.
    Ended,
}

/// The ports [`RunUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunPorts {
    /// Keeps the evaluations.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// The versions tried.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the cases' test runs.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// The sandboxes, for whether a code step's version reaches the network.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// The sandbox versions code steps name.
    pub sandbox_versions: Arc<dyn SandboxVersionStore>,
    /// What the person who started the evaluation holds now.
    pub accounts_now: Arc<AccountsNow>,
    /// Queues the next look.
    pub looks: Evaluations,
    /// Hands each test run started to a worker for its real steps.
    pub wakeups: Wakeups,
    /// Stops what a test run gives up, should it end.
    pub run_stops: StopPorts,
    /// Keeps a look, the runs it started and its next look together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// A test run a look started, with what it recorded.
struct Started {
    execution: WorkflowExecution<ResolvedTenant>,
    records: Vec<ExecutionRecord>,
}

/// What every case of one look starts its test run from: the version
/// tried, the person it acts for, and what of its steps may run.
struct CaseStart<'a> {
    workflow: &'a Workflow<ResolvedTenant>,
    evaluator: &'a ActingAuthority,
    runnable: &'a [RunnableCode],
}

/// What a look did, to keep: when it read the evaluation, and the test
/// runs it started.
struct Look {
    read_at: OffsetDateTime,
    started: Vec<Started>,
}

/// Moves evaluations on, a look at a time.
pub struct RunUseCase {
    ports: RunPorts,
}

impl RunUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RunPorts) -> Self {
        Self { ports }
    }

    /// Settles each case whose test run ended.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a store fails.
    /// - `AppError::Domain` when a run's results do not make one value.
    async fn take_in_ended_runs(
        &self,
        tenant: &ScopedTenant,
        evaluation: &mut Evaluation<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let running: Vec<_> = evaluation.running().copied().collect();
        for id in running {
            let run = self
                .ports
                .executions
                .find_by_id(tenant, &id)
                .await
                .or_internal()?;
            let Some(run) = run.filter(|run| run.status() != ExecutionStatus::Running) else {
                continue;
            };
            evaluation.settle(&run).map_err(AppError::from_domain)?;
        }
        Ok(())
    }

    /// Starts each case that may start now, as a test run of the version
    /// tried, acting for whoever started the evaluation. When that version
    /// changed, or its person may no longer act, the waiting cases could
    /// not run instead.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a store fails, or the person's records
    ///   name a role that is not there.
    async fn start_turns(
        &self,
        tenant: &ScopedTenant,
        evaluation: &mut Evaluation<ResolvedTenant>,
    ) -> Result<Vec<Started>, AppError> {
        let turns: Vec<(usize, EvaluationCase)> = evaluation
            .startable()
            .map(|(place, case)| (place, case.clone()))
            .collect();
        if turns.is_empty() {
            return Ok(Vec::new());
        }
        let Some(workflow) = self.version_tried(tenant, evaluation).await? else {
            return stopped(evaluation, NotRunReason::DraftChanged);
        };
        let Some(evaluator) = self.evaluator_now(tenant, evaluation).await? else {
            return stopped(evaluation, NotRunReason::EvaluatorMayNotAct);
        };
        let runnable = Runnable {
            sandboxes: self.ports.sandboxes.as_ref(),
            versions: self.ports.sandbox_versions.as_ref(),
        }
        .in_graph(tenant, workflow.graph())
        .await?;
        let start = CaseStart {
            workflow: &workflow,
            evaluator: &evaluator,
            runnable: &runnable,
        };
        turns
            .into_iter()
            .filter_map(|(place, case)| start_case(evaluation, place, &case, &start).transpose())
            .collect()
    }

    /// The version `evaluation` tries, while it still stands as it did;
    /// `None` once it changed or is gone.
    async fn version_tried(
        &self,
        tenant: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
    ) -> Result<Option<Workflow<ResolvedTenant>>, AppError> {
        let found = self
            .ports
            .workflows
            .find_version(tenant, evaluation.workflow_id(), evaluation.version())
            .await
            .or_internal()?;
        Ok(found.filter(|workflow| evaluation.tries(workflow)))
    }

    /// What the person who started `evaluation` holds now, or `None` when
    /// their account is gone or may not act.
    async fn evaluator_now(
        &self,
        tenant: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
    ) -> Result<Option<ActingAuthority>, AppError> {
        let Some(records) = self
            .ports
            .accounts_now
            .person(tenant, evaluation.started_by(), &[])
            .await?
        else {
            return Ok(None);
        };
        records.authority(|account, access, resources| {
            ActingAuthority::of_evaluator(evaluation, account, access, resources)
        })
    }

    /// Keeps the test runs `started` with what they recorded, then
    /// `evaluation` over the copy read at `read_at` with what it raised,
    /// and, while cases are open, queues its next look.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when another look changed the evaluation
    ///   since it was read.
    /// - `AppError::Internal` when anything cannot be kept or queued.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        evaluation: &mut Evaluation<ResolvedTenant>,
        look: Look,
    ) -> Result<EvaluationTurn, AppError> {
        let Look { read_at, started } = look;
        self.keep_started(tenant, auditor, started).await?;
        self.ports
            .evaluations
            .save_unchanged_since(tenant, evaluation, read_at)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch(&evaluation.take_events(tenant))
            .await
            .or_internal()?;
        if evaluation.state() != EvaluationState::Running {
            return Ok(EvaluationTurn::Ended);
        }
        let next = clock::now().saturating_add(NEXT_LOOK);
        self.ports
            .looks
            .look_at(tenant, evaluation.id(), next)
            .await?;
        Ok(EvaluationTurn::Continues)
    }

    /// Keeps each test run `started`, with what it recorded and the jobs
    /// that drive it.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a run cannot be kept or queued.
    async fn keep_started(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        started: Vec<Started>,
    ) -> Result<(), AppError> {
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        for Started { execution, records } in started {
            keeping
                .keep(tenant, auditor, Kept::Started(&execution), records)
                .await?;
        }
        Ok(())
    }

    /// Moves `evaluation` on as far as this look may: ends every open case
    /// past its deadline or on the last try, otherwise takes in the runs
    /// that ended and starts the cases whose turn came.
    async fn moved_on(
        &self,
        tenant: &ScopedTenant,
        evaluation: &mut Evaluation<ResolvedTenant>,
        attempt: EvaluationTry,
    ) -> Result<Vec<Started>, AppError> {
        if attempt == EvaluationTry::Last || evaluation.is_overdue(clock::now()) {
            evaluation.give_up().map_err(AppError::from_domain)?;
            return Ok(Vec::new());
        }
        self.take_in_ended_runs(tenant, evaluation).await?;
        if evaluation.state() != EvaluationState::Running {
            return Ok(Vec::new());
        }
        self.start_turns(tenant, evaluation).await
    }
}

impl Command for RunUseCase {
    type Caller = ScopedTenant;
    type Input = RunRequest;
    type Output = Result<EvaluationTurn, AppError>;

    /// Takes one look at the evaluation `request` names, unless it is gone
    /// or ended, and keeps what the look changed.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when another look changed it meanwhile.
    /// - `AppError::Internal` when a store, the queue or the audit trail
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RunRequest,
    ) -> Result<EvaluationTurn, AppError> {
        let found = self
            .ports
            .evaluations
            .find_by_id(tenant, &request.evaluation_id)
            .await
            .or_internal()?;
        let Some(mut evaluation) = found else {
            return Ok(EvaluationTurn::Ended);
        };
        if evaluation.state() != EvaluationState::Running {
            return Ok(EvaluationTurn::Ended);
        }
        let read_at = Aggregate::updated_at(&evaluation);
        let started = self
            .moved_on(tenant, &mut evaluation, request.attempt)
            .await?;
        kept_together(
            self.ports.unit_of_work.as_ref(),
            self.keep(tenant, auditor, &mut evaluation, Look { read_at, started }),
        )
        .await
    }
}

/// Runs look jobs through [`RunUseCase`].
pub struct EvaluationHandler {
    job_type: JobType,
    run: Arc<RunUseCase>,
}

impl EvaluationHandler {
    /// A handler taking looks through `run`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(run: Arc<RunUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(EVALUATE_JOB)?;
        Ok(Self { job_type, run })
    }
}

#[async_trait]
impl JobHandler for EvaluationHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Takes the look. An evaluation gone or ended is left alone, and a
    /// look that lost a race to another is done: the other queued the next.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: EvaluationJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        let attempt = match job.can_retry() {
            true => EvaluationTry::NotLast,
            false => EvaluationTry::Last,
        };
        let request = RunRequest {
            evaluation_id: payload.evaluation_id,
            attempt,
        };
        match unless_gone(self.run.execute(&tenant, &auditor, request).await) {
            Ok(_) | Err(AppError::Conflict(_)) => Ok(Handled::Done),
            Err(error) => Err(error),
        }
    }
}

/// Ends `evaluation`'s waiting cases as not run, for `reason`; no run
/// starts.
fn stopped(
    evaluation: &mut Evaluation<ResolvedTenant>,
    reason: NotRunReason,
) -> Result<Vec<Started>, AppError> {
    evaluation
        .stop_waiting(reason)
        .map_err(AppError::from_domain)?;
    Ok(Vec::new())
}

/// Starts the test run of `case`, at `place` in `evaluation`, as `start`
/// says, or ends the case as not run when the run is refused.
fn start_case(
    evaluation: &mut Evaluation<ResolvedTenant>,
    place: usize,
    case: &EvaluationCase,
    start: &CaseStart<'_>,
) -> Result<Option<Started>, AppError> {
    let begun = WorkflowExecution::start_case(
        start.workflow,
        start.evaluator.clone(),
        case,
        start.runnable,
    );
    match begun {
        Ok((execution, records)) => {
            evaluation
                .start_case(place, &execution)
                .map_err(AppError::from_domain)?;
            Ok(Some(Started { execution, records }))
        }
        Err(refused) => {
            evaluation
                .skip_case(place, not_run_for(&refused))
                .map_err(AppError::from_domain)?;
            Ok(None)
        }
    }
}

/// Why a case whose test run was refused as `refused` could not run.
fn not_run_for(refused: &DomainError) -> NotRunReason {
    match refused {
        DomainError::Forbidden(_) => NotRunReason::EvaluatorMayNotAct,
        _ => NotRunReason::Refused,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::evaluation::outcome::{CaseOutcome, Verdict};
    use ianua_domain::domains::workflows::evaluation::run::MAX_RUNNING_CASES;
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;

    use super::*;
    use crate::test_support::workflows::{
        FakeEvaluationStore, FakeWorkflowExecutionStore, FakeWorkflowStore, QueuedLooks,
        accounts_now_of, draft_by, evaluation_of, failing_case, parcel_case, person, set_for,
        tidy_step,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// What the person who starts an evaluation holds: leave to edit and
    /// run workflows.
    const TESTS: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::Update),
        SystemPermission::Workflows(WorkflowAction::Run),
    ];

    /// Ann's draft, an evaluation of it, and the stores a look works with.
    struct Looking {
        draft: Workflow<ResolvedTenant>,
        evaluations: Arc<FakeEvaluationStore>,
        executions: Arc<FakeWorkflowExecutionStore>,
        looks: QueuedLooks,
        sink: Arc<FakeEventDispatcher>,
        id: EvaluationId,
    }

    impl Looking {
        fn new(cases: Vec<EvaluationCase>) -> Self {
            let ann = person("ann@corp.test");
            let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
            let set = set_for(&draft, &ann, cases, PublishGate::Off);
            let evaluation = evaluation_of(&set, &draft, &ann);
            Self {
                id: *evaluation.id(),
                evaluations: Arc::new(FakeEvaluationStore::holding(&evaluation)),
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                looks: QueuedLooks::none(),
                sink: Arc::new(FakeEventDispatcher::new()),
                draft,
            }
        }

        fn look(&self, attempt: EvaluationTry) -> EvaluationTurn {
            let ann = self.evaluation().started_by().clone();
            let use_case = RunUseCase::new(RunPorts {
                evaluations: self.evaluations.clone(),
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.draft,
                ))),
                executions: self.executions.clone(),
                accounts_now: Arc::new(accounts_now_of(&[(&ann, &TESTS)])),
                looks: self.looks.looks(),
                unit_of_work: Arc::new(RecordingUnitOfWork::default()),
                ..RunPorts::fakes()
            });
            let request = RunRequest {
                evaluation_id: self.id,
                attempt,
            };
            let auditor = test_auditor(self.sink.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, request)).unwrap()
        }

        fn evaluation(&self) -> Evaluation<ResolvedTenant> {
            self.evaluations.stored(&self.id).unwrap()
        }
    }

    /// Ann's evaluation has seven cases. The first look starts five as
    /// test runs, which end at once; the next takes them in and starts the
    /// last two; the third ends the evaluation as passed.
    #[test]
    fn cases_run_five_at_a_time_until_the_evaluation_ends() {
        let cases = (0..7)
            .map(|index| parcel_case(&format!("case {index}")))
            .collect();
        let looking = Looking::new(cases);

        let first = looking.look(EvaluationTry::NotLast);
        let running = looking.evaluation().running().count();
        looking.look(EvaluationTry::NotLast);
        let last = looking.look(EvaluationTry::NotLast);

        let runs = looking.executions.all();
        let evaluation = looking.evaluation();
        let recorded = looking.sink.records.lock().unwrap().clone();
        assert_eq!(
            (first, running, last),
            (
                EvaluationTurn::Continues,
                MAX_RUNNING_CASES,
                EvaluationTurn::Ended
            )
        );
        assert_eq!(runs.len(), 7);
        assert!(runs.iter().all(|run| run.mode().is_test()));
        assert!(
            evaluation
                .outcomes()
                .iter()
                .all(|outcome| matches!(outcome, CaseOutcome::Passed { .. }))
        );
        assert!(recorded.contains(&"workflows.evaluation_ended".to_owned()));
    }

    /// A case expecting what the draft does not hand on fails, and the
    /// evaluation with it.
    #[test]
    fn a_case_that_differs_fails_the_evaluation() {
        let looking = Looking::new(vec![parcel_case("ok"), failing_case("wrong")]);

        looking.look(EvaluationTry::NotLast);
        looking.look(EvaluationTry::NotLast);

        let outcomes = looking.evaluation().outcomes().to_vec();
        assert!(matches!(outcomes[0], CaseOutcome::Passed { .. }));
        assert!(matches!(outcomes[1], CaseOutcome::Failed { .. }));
        assert_eq!(
            looking.evaluation().state(),
            EvaluationState::Ended(Verdict::Failed)
        );
    }

    /// On its job's last try, a look starts nothing and ends every open
    /// case as not run, so the evaluation never stays open.
    #[test]
    fn the_last_try_ends_the_evaluation() {
        let looking = Looking::new(vec![parcel_case("ok")]);

        let turn = looking.look(EvaluationTry::Last);

        assert_eq!(turn, EvaluationTurn::Ended);
        assert!(looking.executions.all().is_empty());
        assert!(matches!(
            looking.evaluation().outcomes()[0],
            CaseOutcome::NotRun {
                reason: NotRunReason::OutOfTime
            }
        ));
    }

    /// An evaluation that ended is looked at again: nothing changes and
    /// no run starts.
    #[test]
    fn an_ended_evaluation_is_left_alone() {
        let looking = Looking::new(vec![parcel_case("ok")]);
        looking.look(EvaluationTry::Last);

        let again = looking.look(EvaluationTry::NotLast);

        assert_eq!(again, EvaluationTurn::Ended);
        assert!(looking.executions.all().is_empty());
    }
}
