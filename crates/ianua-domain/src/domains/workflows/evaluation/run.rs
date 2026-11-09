//! One evaluation: a workflow version tried against every case of its set,
//! each case as a test run, and what each case came to.
//!
//! The cases are copied in when it starts, so editing the set while it runs
//! changes nothing it reports. At most [`MAX_RUNNING_CASES`] test runs are
//! under way at once; the others wait their turn. Each case ends one of
//! three ways: passed, every check held; failed, with what differed or how
//! its run ended; or could not run, with why. Once none is left waiting or
//! running, the evaluation ends, passed only when every case passed.
//!
//! It runs for at most [`EVALUATION_TIME`]. A case still waiting or running
//! then could not run, so no evaluation stays open for ever.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::workflow::{Revision, Workflow, WorkflowStatus};
use crate::domains::workflows::evaluation::case::EvaluationCase;
use crate::domains::workflows::evaluation::outcome::{
    CaseOutcome, Difference, NotRunReason, RunEnd, Verdict,
};
use crate::domains::workflows::evaluation::set::{EvaluationSet, MAX_CASES};
use crate::domains::workflows::evaluation::view::EvaluationView;
use crate::domains::workflows::events::{EvaluationEnded, EvaluationRef, EvaluationStarted};
use crate::domains::workflows::execution::record::ExecutionEnd;
use crate::domains::workflows::execution::step::StepState;
use crate::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{EvaluationId, Human, WorkflowExecutionId, WorkflowId};

/// The most test runs one evaluation has under way at once.
pub const MAX_RUNNING_CASES: usize = 5;

/// How long an evaluation may run before every case still open could not
/// run.
pub const EVALUATION_TIME: Duration = Duration::hours(1);

/// How long an ended evaluation is kept, in days. The last one of a draft
/// is what its publishing gate reads, so it outlives any draft worked on.
pub const EVALUATIONS_KEPT_DAYS: i64 = 30;

/// Where an evaluation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationState {
    /// Cases still wait or run.
    Running,
    /// Every case came to an end, and this is the verdict.
    Ended(Verdict),
}

/// An evaluation as stored.
pub struct EvaluationRow {
    /// The identity its job and its test runs' records name.
    pub id: EvaluationId,
    /// The workflow it tries.
    pub workflow_id: WorkflowId,
    /// The version it tries.
    pub version: u32,
    /// The revision of that version it tries.
    pub revision: Revision,
    /// The cases, as the set held them when it started.
    pub cases: Vec<EvaluationCase>,
    /// What each case came to, in the cases' order.
    pub outcomes: Vec<CaseOutcome>,
    /// The person who started it, whom its test runs act for.
    pub started_by: Human,
    /// Where it stands.
    pub state: EvaluationState,
    /// When every case still open could not run.
    pub deadline: OffsetDateTime,
    /// When it started.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// One evaluation of a workflow version against its sample cases.
#[derive(Debug, Clone)]
pub struct Evaluation<T: TenantScope> {
    id: EvaluationId,
    workflow_id: WorkflowId,
    version: u32,
    revision: Revision,
    cases: Vec<EvaluationCase>,
    outcomes: Vec<CaseOutcome>,
    started_by: Human,
    state: EvaluationState,
    deadline: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Evaluation<T> {
    /// `by` starts an evaluation of `workflow`, its latest version as it
    /// stands, against every case of `set`. Raises
    /// `workflows.evaluation_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit or run workflows.
    /// - [`DomainError::Conflict`] when `set` is another workflow's, or
    ///   `workflow` is archived.
    /// - [`DomainError::Validation`] when `set` holds no case.
    pub fn start(
        set: &EvaluationSet<T>,
        workflow: &Workflow<T>,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        ensure_startable(set, workflow, by)?;
        let now = crate::shared::clock::now();
        let mut evaluation = Self {
            id: EvaluationId::new(),
            workflow_id: *workflow.id(),
            version: workflow.version(),
            revision: workflow.revision(),
            cases: set.cases().to_vec(),
            outcomes: vec![CaseOutcome::Waiting; set.cases().len()],
            started_by: by.by().clone(),
            state: EvaluationState::Running,
            deadline: now.saturating_add(EVALUATION_TIME),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        let started = EvaluationStarted {
            evaluation: evaluation.reference(),
            cases: evaluation.cases.len(),
            occurred_at: now,
        };
        evaluation.raised.raise(started);
        Ok(evaluation)
    }

    /// Rebuilds an evaluation from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when its times are out of order,
    ///   its cases and outcomes do not pair up or exceed their limits, more
    ///   runs are under way than may be, a failed check names no check of
    ///   its case, or its state contradicts its outcomes.
    pub fn reconstitute(row: EvaluationRow) -> Result<Self, DomainError> {
        ensure_row_whole(&row)?;
        Ok(Self {
            id: row.id,
            workflow_id: row.workflow_id,
            version: row.version,
            revision: row.revision,
            cases: row.cases,
            outcomes: row.outcomes,
            started_by: row.started_by,
            state: row.state,
            deadline: row.deadline,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The cases that may start now, with their places: those waiting, as
    /// many as there are free places among the runs under way.
    pub fn startable(&self) -> impl Iterator<Item = (usize, &EvaluationCase)> {
        let free = MAX_RUNNING_CASES.saturating_sub(self.running().count());
        self.outcomes
            .iter()
            .enumerate()
            .filter(|(_, outcome)| matches!(outcome, CaseOutcome::Waiting))
            .take(free)
            .filter_map(|(place, _)| self.cases.get(place).map(|case| (place, case)))
    }

    /// The test runs under way.
    pub fn running(&self) -> impl Iterator<Item = &WorkflowExecutionId> {
        self.outcomes.iter().filter_map(|outcome| match outcome {
            CaseOutcome::Running { execution } => Some(execution),
            CaseOutcome::Waiting
            | CaseOutcome::Passed { .. }
            | CaseOutcome::Failed { .. }
            | CaseOutcome::NotRun { .. } => None,
        })
    }

    /// The case at `place` started its test run, `execution`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the evaluation ended, or
    ///   the case does not wait.
    /// - [`DomainError::Conflict`] when every place is taken, or
    ///   `execution` is no test of the version it tries.
    pub fn start_case(
        &mut self,
        place: usize,
        execution: &WorkflowExecution<T>,
    ) -> Result<(), DomainError> {
        self.ensure_waiting(place)?;
        if self.running().count() >= MAX_RUNNING_CASES {
            return Err(DomainError::conflict(message!(
                "workflows-every-place-for-a-case-is-taken",
                "every place for a case's run is taken; it waits its turn"
            )));
        }
        if !self.is_its_test(execution) {
            return Err(DomainError::conflict(message!(
                "workflows-the-run-is-no-test-of-the-evaluated-version",
                "the run is no test of the version this evaluation tries"
            )));
        }
        self.record(
            place,
            CaseOutcome::Running {
                execution: *execution.id(),
            },
        )?;
        self.touch();
        Ok(())
    }

    /// The case at `place` could not start its test run, for `reason`.
    /// The evaluation ends when no case is left open.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the evaluation ended, or
    ///   the case does not wait.
    pub fn skip_case(&mut self, place: usize, reason: NotRunReason) -> Result<(), DomainError> {
        self.ensure_waiting(place)?;
        self.record(place, CaseOutcome::NotRun { reason })?;
        self.end_when_done();
        Ok(())
    }

    /// `execution`, the test run of one of its cases, ended: the case
    /// passes when the run succeeded and every check holds in its results,
    /// and fails otherwise, with what differed. The evaluation ends when no
    /// case is left open.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the evaluation ended, or
    ///   the run has not.
    /// - [`DomainError::Conflict`] when `execution` is no run under way of
    ///   its cases.
    /// - [`DomainError::Validation`] when the run's results do not make
    ///   one value.
    pub fn settle(&mut self, execution: &WorkflowExecution<T>) -> Result<(), DomainError> {
        self.ensure_running()?;
        let ExecutionStatus::Ended(end) = execution.status() else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-case-run-has-not-ended",
                "the case's run has not ended yet"
            )));
        };
        let Some(place) = self.place_running(execution.id()) else {
            return Err(DomainError::conflict(message!(
                "workflows-the-run-is-no-case-of-this-evaluation",
                "the run is not one of this evaluation's cases under way"
            )));
        };
        let case = self.cases.get(place).ok_or_else(no_such_case)?;
        let outcome = outcome_of(case, execution, end)?;
        self.record(place, outcome)?;
        self.end_when_done();
        Ok(())
    }

    /// Every case still waiting could not run, for `reason`, such as the
    /// draft having changed. Runs under way are left to end. The
    /// evaluation ends when no case is left open.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the evaluation ended.
    pub fn stop_waiting(&mut self, reason: NotRunReason) -> Result<(), DomainError> {
        self.ensure_running()?;
        for outcome in &mut self.outcomes {
            if matches!(outcome, CaseOutcome::Waiting) {
                *outcome = CaseOutcome::NotRun { reason };
            }
        }
        self.end_when_done();
        Ok(())
    }

    /// The evaluation ran out of time, or its last try came: every case
    /// still waiting or running could not run, and it ends.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it ended already.
    pub fn give_up(&mut self) -> Result<(), DomainError> {
        self.ensure_running()?;
        for outcome in &mut self.outcomes {
            if outcome.is_open() {
                *outcome = CaseOutcome::NotRun {
                    reason: NotRunReason::OutOfTime,
                };
            }
        }
        self.end_when_done();
        Ok(())
    }

    /// Whether it still runs at `now`, past its deadline.
    #[must_use]
    pub fn is_overdue(&self, now: OffsetDateTime) -> bool {
        self.state == EvaluationState::Running && now >= self.deadline
    }

    /// Whether it tries `workflow` as it stands now: the same version, at
    /// the same revision.
    #[must_use]
    pub fn tries(&self, workflow: &Workflow<T>) -> bool {
        workflow.id() == &self.workflow_id
            && workflow.version() == self.version
            && workflow.revision() == self.revision
    }

    /// Whether it tried `draft` as it stands now, and every case passed.
    #[must_use]
    pub fn passed_for(&self, draft: &Workflow<T>) -> bool {
        self.tries(draft) && self.state == EvaluationState::Ended(Verdict::Passed)
    }

    /// The identity its job and its test runs' records name.
    #[must_use]
    pub fn id(&self) -> &EvaluationId {
        &self.id
    }

    /// The workflow it tries.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// The version it tries.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The revision of that version it tries.
    #[must_use]
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// The cases, as the set held them when it started.
    #[must_use]
    pub fn cases(&self) -> &[EvaluationCase] {
        &self.cases
    }

    /// What each case came to so far, in the cases' order.
    #[must_use]
    pub fn outcomes(&self) -> &[CaseOutcome] {
        &self.outcomes
    }

    /// The person who started it, whom its test runs act for.
    #[must_use]
    pub fn started_by(&self) -> &Human {
        &self.started_by
    }

    /// Where it stands.
    #[must_use]
    pub fn state(&self) -> EvaluationState {
        self.state
    }

    /// When every case still open could not run.
    #[must_use]
    pub fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }

    fn ensure_running(&self) -> Result<(), DomainError> {
        if self.state == EvaluationState::Running {
            return Ok(());
        }
        Err(DomainError::invalid_transition(message!(
            "workflows-the-evaluation-ended-already",
            "the evaluation ended already"
        )))
    }

    fn ensure_waiting(&self, place: usize) -> Result<(), DomainError> {
        self.ensure_running()?;
        if matches!(self.outcomes.get(place), Some(CaseOutcome::Waiting)) {
            return Ok(());
        }
        Err(DomainError::invalid_transition(message!(
            "workflows-the-case-does-not-wait",
            "the case does not wait for its run"
        )))
    }

    /// Keeps `outcome` as what the case at `place` came to.
    fn record(&mut self, place: usize, outcome: CaseOutcome) -> Result<(), DomainError> {
        let kept = self.outcomes.get_mut(place).ok_or_else(no_such_case)?;
        *kept = outcome;
        Ok(())
    }

    fn place_running(&self, id: &WorkflowExecutionId) -> Option<usize> {
        self.outcomes.iter().position(
            |outcome| matches!(outcome, CaseOutcome::Running { execution } if execution == id),
        )
    }

    fn is_its_test(&self, execution: &WorkflowExecution<T>) -> bool {
        execution.mode().is_test()
            && execution.workflow_id() == &self.workflow_id
            && execution.version() == self.version
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// Ends the evaluation once no case is left open. Raises
    /// `workflows.evaluation_ended` then.
    fn end_when_done(&mut self) {
        self.touch();
        let EvaluationState::Ended(verdict) = state_of(&self.outcomes) else {
            return;
        };
        self.state = EvaluationState::Ended(verdict);
        let ended = EvaluationEnded {
            evaluation: self.reference(),
            verdict,
            passed: self.counted(|outcome| matches!(outcome, CaseOutcome::Passed { .. })),
            failed: self.counted(|outcome| matches!(outcome, CaseOutcome::Failed { .. })),
            not_run: self.counted(|outcome| matches!(outcome, CaseOutcome::NotRun { .. })),
            occurred_at: self.updated_at,
        };
        self.raised.raise(ended);
    }

    /// How many cases came to an outcome `wanted` picks.
    fn counted(&self, wanted: fn(&CaseOutcome) -> bool) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| wanted(outcome))
            .count()
    }

    fn reference(&self) -> EvaluationRef {
        EvaluationRef {
            evaluation_id: self.id,
            workflow_id: self.workflow_id,
            version: self.version,
        }
    }
    /// This evaluation as `viewer` may read it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `viewer` may not view workflows.
    pub fn viewed_by(self, viewer: WorkflowControl<'_>) -> Result<EvaluationView<T>, DomainError> {
        viewer.ensure_may(WorkflowAction::View)?;
        Ok(EvaluationView {
            clearance: viewer.authority().data_clearance(),
            evaluation: self,
        })
    }

    /// This evaluation as `author`, who just started it, may read it back:
    /// what is above their clearance withheld. Bob may test workflows and
    /// sees internal data only; the set holds Ann's confidential payroll
    /// case. Starting the evaluation does not show him its input.
    #[must_use]
    pub fn seen_by_author(self, author: WorkflowControl<'_>) -> EvaluationView<T> {
        EvaluationView {
            clearance: author.authority().data_clearance(),
            evaluation: self,
        }
    }
}

impl<T: TenantScope> Raises for Evaluation<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Evaluation<T> {
    type Id = EvaluationId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Where an evaluation with `outcomes` stands: running while one is open,
/// passed once all passed, failed otherwise.
fn state_of(outcomes: &[CaseOutcome]) -> EvaluationState {
    if outcomes.iter().any(CaseOutcome::is_open) {
        return EvaluationState::Running;
    }
    let all_passed = outcomes
        .iter()
        .all(|outcome| matches!(outcome, CaseOutcome::Passed { .. }));
    EvaluationState::Ended(match all_passed {
        true => Verdict::Passed,
        false => Verdict::Failed,
    })
}

/// Whether every check `outcome` says did not hold is one of `case`'s.
fn names_its_checks((case, outcome): (&EvaluationCase, &CaseOutcome)) -> bool {
    let CaseOutcome::Failed { differences, .. } = outcome else {
        return true;
    };
    differences.iter().all(|difference| match difference {
        Difference::RunEnded { .. } => true,
        Difference::Check { index, .. } => *index < case.checks().len(),
    })
}

/// What `case` came to once its run `execution` ended as `end`.
fn outcome_of<T: TenantScope>(
    case: &EvaluationCase,
    execution: &WorkflowExecution<T>,
    end: ExecutionEnd,
) -> Result<CaseOutcome, DomainError> {
    let id = *execution.id();
    let exposure = highest_exposure(execution);
    let Some(ended) = unsuccessful(end) else {
        let differences = differences_in(case, &execution.results()?);
        return Ok(match differences.is_empty() {
            true => CaseOutcome::Passed { execution: id },
            false => CaseOutcome::Failed {
                execution: id,
                differences,
                exposure,
            },
        });
    };
    Ok(CaseOutcome::Failed {
        execution: id,
        differences: vec![Difference::RunEnded { end: ended }],
        exposure,
    })
}

/// How a run that ended as `end` failed, or `None` when it succeeded.
fn unsuccessful(end: ExecutionEnd) -> Option<RunEnd> {
    match end {
        ExecutionEnd::Succeeded => None,
        ExecutionEnd::Failed => Some(RunEnd::Failed),
        ExecutionEnd::Cancelled(_) | ExecutionEnd::LoopEnded => Some(RunEnd::Cancelled),
        ExecutionEnd::TimedOut => Some(RunEnd::TimedOut),
    }
}

/// The checks of `case` that do not hold in `results`.
fn differences_in(
    case: &EvaluationCase,
    results: &crate::domains::workflows::data::FlowData,
) -> Vec<Difference> {
    case.checks()
        .iter()
        .enumerate()
        .filter_map(|(index, check)| {
            check
                .verdict(results)
                .err()
                .map(|found| Difference::Check { index, found })
        })
        .collect()
}

/// Refuses a stored evaluation whose times are out of order, whose
/// outcomes do not pair with its cases, or whose state they contradict.
fn ensure_row_whole(row: &EvaluationRow) -> Result<(), DomainError> {
    let running = row
        .outcomes
        .iter()
        .filter(|outcome| matches!(outcome, CaseOutcome::Running { .. }))
        .count();
    RowCheck::of("evaluation")
        .in_order(row.created_at, row.updated_at, "changed before it started")
        .in_order(row.created_at, row.deadline, "due before it started")
        .holds(
            row.cases.len() == row.outcomes.len(),
            "outcomes that do not pair with its cases",
        )
        .holds(
            (1..=MAX_CASES).contains(&row.cases.len()),
            "more cases than a set holds, or none",
        )
        .holds(
            running <= MAX_RUNNING_CASES,
            "more runs under way than may be",
        )
        .holds(
            row.cases.iter().zip(&row.outcomes).all(names_its_checks),
            "a difference naming no check of its case",
        )
        .holds(
            row.state == state_of(&row.outcomes),
            "a state its outcomes contradict",
        )
        .finish()
}

/// Refuses an evaluation `by` may not start of `workflow` against `set`:
/// without the rights to edit and run workflows, against another
/// workflow's set, of an archived version, or with no case.
fn ensure_startable<T: TenantScope>(
    set: &EvaluationSet<T>,
    workflow: &Workflow<T>,
    by: &WorkflowControl<'_>,
) -> Result<(), DomainError> {
    by.ensure_may(WorkflowAction::Update)?;
    by.ensure_may(WorkflowAction::Run)?;
    set.ensure_of(workflow)?;
    if workflow.status() == WorkflowStatus::Archived {
        return Err(DomainError::conflict(message!(
            "workflows-an-archived-version-is-not-evaluated",
            "an archived version is not evaluated; draft the next one"
        )));
    }
    if set.cases().is_empty() {
        return Err(DomainError::invalid(message!(
            "workflows-an-evaluation-needs-a-case",
            "save at least one sample case before evaluating"
        )));
    }
    Ok(())
}

/// A place no case of the evaluation holds, which its own outcomes always
/// match: only a corrupted evaluation reaches it.
fn no_such_case() -> DomainError {
    DomainError::conflict(message!(
        "workflows-the-run-is-no-case-of-this-evaluation",
        "the run is not one of this evaluation's cases under way"
    ))
}

/// The most sensitive data `execution` holds: its trigger's, or any
/// finished step's.
fn highest_exposure<T: TenantScope>(execution: &WorkflowExecution<T>) -> DataClassLevel {
    execution
        .steps()
        .filter_map(|(_, state)| match state {
            StepState::Succeeded { exposure, .. } => Some(*exposure),
            StepState::Waiting
            | StepState::Ready { .. }
            | StepState::Running { .. }
            | StepState::Failed(_)
            | StepState::Skipped
            | StepState::Stopped
            | StepState::Abandoned { .. } => None,
        })
        .fold(execution.exposure(), DataClassLevel::max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::evaluation::set::PublishGate;
    use crate::domains::workflows::evaluation::tests::{
        case_expecting, edit, evaluator, set_of_cases, set_with, tested, viewer, workflow,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;

    type Tried = Evaluation<ResolvedTenant>;

    /// An evaluation of `draft` with `cases` cases, each expecting the
    /// tidy step to copy `ok: true`.
    fn started(draft: &Workflow<ResolvedTenant>, cases: usize) -> Tried {
        let set = set_of_cases(draft, cases, PublishGate::Off);
        Evaluation::start(&set, draft, &evaluator()).unwrap()
    }

    /// Ann evaluates her draft with seven cases. Five start at once; the
    /// other two wait their turn.
    #[test]
    fn at_most_five_cases_run_at_once() {
        let draft = workflow();
        let mut evaluation = started(&draft, 7);
        let places: Vec<usize> = evaluation.startable().map(|(place, _)| place).collect();

        for place in &places {
            let (run, _) = tested(&draft, &evaluation.cases()[*place]);
            evaluation.start_case(*place, &run).unwrap();
        }

        assert_eq!(places, [0, 1, 2, 3, 4]);
        assert_eq!(evaluation.startable().count(), 0);
        assert_eq!(evaluation.running().count(), MAX_RUNNING_CASES);
    }

    /// A case whose run hands on what it expects passes; once it is the
    /// last open case, the evaluation ends as passed.
    #[test]
    fn a_case_passes_when_every_check_holds() {
        let draft = workflow();
        let mut evaluation = started(&draft, 1);
        let (run, _) = tested(&draft, &evaluation.cases()[0]);
        evaluation.start_case(0, &run).unwrap();

        evaluation.settle(&run).unwrap();

        assert!(matches!(
            evaluation.outcomes()[0],
            CaseOutcome::Passed { .. }
        ));
        assert_eq!(evaluation.state(), EvaluationState::Ended(Verdict::Passed));
        assert!(evaluation.passed_for(&draft));
    }

    /// A case expecting a value the run never hands on fails, saying
    /// which check and that nothing was found; the evaluation fails.
    #[test]
    fn a_case_fails_with_what_differed() {
        let draft = workflow();
        let set = set_with(&draft, vec![case_expecting("missing", "tidy.nothing")]);
        let mut evaluation = Evaluation::start(&set, &draft, &evaluator()).unwrap();
        let (run, _) = tested(&draft, &evaluation.cases()[0]);
        evaluation.start_case(0, &run).unwrap();

        evaluation.settle(&run).unwrap();

        let CaseOutcome::Failed { differences, .. } = &evaluation.outcomes()[0] else {
            panic!("the case failed");
        };
        assert_eq!(
            differences,
            &[Difference::Check {
                index: 0,
                found: None
            }]
        );
        assert_eq!(evaluation.state(), EvaluationState::Ended(Verdict::Failed));
        assert!(!evaluation.passed_for(&draft));
    }

    /// The draft changes while cases wait: they could not run, and the
    /// evaluation no longer counts for the draft as it stands.
    #[test]
    fn a_changed_draft_stops_the_waiting_cases() {
        let mut draft = workflow();
        let mut evaluation = started(&draft, 2);
        edit(&mut draft);

        evaluation.stop_waiting(NotRunReason::DraftChanged).unwrap();

        assert!(!evaluation.tries(&draft));
        assert!(evaluation.outcomes().iter().all(|outcome| matches!(
            outcome,
            CaseOutcome::NotRun {
                reason: NotRunReason::DraftChanged
            }
        )));
        assert_eq!(evaluation.state(), EvaluationState::Ended(Verdict::Failed));
    }

    /// Out of time, every open case could not run and the evaluation ends;
    /// giving up twice is refused.
    #[test]
    fn giving_up_ends_every_open_case_once() {
        let draft = workflow();
        let mut evaluation = started(&draft, 3);
        let (run, _) = tested(&draft, &evaluation.cases()[0]);
        evaluation.start_case(0, &run).unwrap();

        evaluation.give_up().unwrap();
        let again = evaluation.give_up();

        assert_eq!(evaluation.running().count(), 0);
        assert_eq!(evaluation.state(), EvaluationState::Ended(Verdict::Failed));
        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
    }

    /// A run that is not one of its cases is refused, as is settling a
    /// case twice.
    #[test]
    fn only_its_own_runs_settle_its_cases() {
        let draft = workflow();
        let mut evaluation = started(&draft, 2);
        let (run, _) = tested(&draft, &evaluation.cases()[0]);
        let (stranger, _) = tested(&draft, &evaluation.cases()[1]);
        evaluation.start_case(0, &run).unwrap();

        let refused = evaluation.settle(&stranger);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// Someone who may only view workflows cannot start an evaluation.
    #[test]
    fn evaluating_needs_the_right_to_edit_and_run() {
        let draft = workflow();
        let set = set_of_cases(&draft, 1, PublishGate::Off);

        let refused = Evaluation::start(&set, &draft, &viewer());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A stored evaluation whose state says passed while a case failed is
    /// refused as corrupt.
    #[test]
    fn a_stored_evaluation_contradicting_itself_is_corrupt() {
        let draft = workflow();
        let evaluation = started(&draft, 1);
        let row = EvaluationRow {
            id: *evaluation.id(),
            workflow_id: *evaluation.workflow_id(),
            version: evaluation.version(),
            revision: evaluation.revision(),
            cases: evaluation.cases().to_vec(),
            outcomes: vec![CaseOutcome::NotRun {
                reason: NotRunReason::OutOfTime,
            }],
            started_by: evaluation.started_by().clone(),
            state: EvaluationState::Ended(Verdict::Passed),
            deadline: evaluation.deadline(),
            created_at: Aggregate::created_at(&evaluation),
            updated_at: Aggregate::updated_at(&evaluation),
        };

        assert!(refused_as_corrupt(&Tried::reconstitute(row)));
    }
}
