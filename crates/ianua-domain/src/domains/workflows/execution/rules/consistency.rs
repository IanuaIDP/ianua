//! The rules a stored execution must keep to be rebuilt.
//!
//! They are everything its changes keep, checked again on the row.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::looping::MAX_LOOP_ITEMS;
use crate::domains::workflows::design::node::{Join, Node, NodeKey, NodeKind};
use crate::domains::workflows::design::publish_rules::{
    ensure_high_risk_actions_approved, ensure_paths_name_earlier_steps,
};
use crate::domains::workflows::design::workflow::MAX_RUN_TIME;
use crate::domains::workflows::execution::record::ExecutionEnd;
use crate::domains::workflows::execution::rules::holding::{holding_fits, pause_fits};
use crate::domains::workflows::execution::step::{Attempt, Holding, LONGEST_ROUND_GAP, StepState};
use crate::domains::workflows::execution::steps::deferral::RUN_LIMIT_PAUSE;
use crate::domains::workflows::execution::steps::schedule::{
    Readiness, TriggerData, has_pending_lead, input_of, is_led_to, leading_steps, readiness,
};
use crate::domains::workflows::execution::{
    Cause, ExecutionMode, ExecutionStatus, WorkflowExecutionRow,
};
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;

/// Refuses a stored row that breaks a rule an execution keeps.
pub(in crate::domains::workflows::execution) fn ensure_consistent(
    row: &WorkflowExecutionRow,
) -> Result<(), DomainError> {
    let check = steps_keep_their_rules(RowCheck::of("workflow execution"), row);
    let check = flow_keeps_its_rules(check, row);
    times_keep_their_rules(check, row)
        .holds(
            row.mode.mode().is_test() || ensure_high_risk_actions_approved(&row.graph).is_ok(),
            "a graph with a high-risk action not approved right before it",
        )
        .holds(
            test_fits(row),
            "a test standing in for a step its graph does not have, or not started by hand",
        )
        .holds(
            ensure_paths_name_earlier_steps(&row.graph).is_ok(),
            "a graph with a step reading a step that cannot come before it",
        )
        .holds(row.version >= 1, "a version below one")
        .holds(
            row.cause
                .chain_depth()
                .is_ok_and(|depth| depth == row.chain_depth),
            "a chain depth its cause does not lead to",
        )
        .holds(
            pass_fits(row),
            "a pass of a loop no loop could have started",
        )
        .finish()
}

/// Whether a test is one a person could have started: by hand, standing in
/// only for steps of its own graph. A real run stands in for nothing.
fn test_fits(row: &WorkflowExecutionRow) -> bool {
    let ExecutionMode::Test(plan) = row.mode.mode() else {
        return true;
    };
    row.cause == Cause::Manual
        && plan
            .stand_ins()
            .iter()
            .all(|key| row.graph.every_node().any(|node| node.key() == key))
}

/// Whether a pass of a loop is one a loop could have started.
///
/// It runs a loop's own steps, which hold no loop, for an item within the
/// most any loop goes through. Only a pass ends because its loop did.
fn pass_fits(row: &WorkflowExecutionRow) -> bool {
    let stopped_with_loop = row.status == ExecutionStatus::Ended(ExecutionEnd::LoopEnded);
    let Some(of) = &row.pass else {
        return !stopped_with_loop;
    };
    let holds_a_loop = row
        .graph
        .nodes()
        .iter()
        .any(|node| matches!(node.kind(), NodeKind::Loop(_)));
    of.index < MAX_LOOP_ITEMS && !holds_a_loop
}

/// `check` with the rules that tie each step to the steps that led to it,
/// and to its own kind.
fn flow_keeps_its_rules(check: RowCheck, row: &WorkflowExecutionRow) -> RowCheck {
    let pairs = || row.graph.nodes().iter().zip(&row.steps);
    check
        .holds(
            pairs().all(|(node, state)| fits_what_led_to_it(row, node, state)),
            "a step that did not wait for, see or carry what led to it",
        )
        .holds(
            pairs().all(|(node, state)| fits_its_kind(node, state, row)),
            "a step in a state its kind never takes",
        )
        .holds(
            nothing_left_undecided(row),
            "a running execution with a waiting step that could have moved on",
        )
        .holds(
            ready_inputs_rebuild(row),
            "a ready step holding an input its earlier steps did not produce",
        )
}

/// Whether every ready step holds exactly the input the steps it saw and
/// the trigger make.
///
/// So a row cannot hand an integration or an agent data no step produced.
fn ready_inputs_rebuild(row: &WorkflowExecutionRow) -> bool {
    let trigger = TriggerData {
        input: &row.input,
        exposure: row.exposure,
    };
    row.steps.iter().all(|state| {
        let StepState::Ready { input, seen, .. } = state else {
            return true;
        };
        input_of(&row.graph, &row.steps, seen, trigger).is_ok_and(|rebuilt| rebuilt == *input)
    })
}

/// Whether a step that something reached fits what led to it.
///
/// When it joins all the steps before it, it waited for every one. It sees
/// exactly what led to it. It carries the exposure that makes. That is
/// exactly so while the domain alone decides it, and at least so once
/// outside work has added to it.
fn fits_what_led_to_it(row: &WorkflowExecutionRow, node: &Node, state: &StepState) -> bool {
    let (graph, steps) = (&row.graph, row.steps.as_slice());
    let (exposure, seen, carried) = match state {
        StepState::Ready { exposure, seen, .. } | StepState::Running { exposure, seen, .. } => {
            (*exposure, seen.as_slice(), Carried::AsStarted)
        }
        StepState::Succeeded { exposure, seen, .. } => {
            (*exposure, seen.as_slice(), Carried::after(node.kind()))
        }
        StepState::Waiting
        | StepState::Failed(_)
        | StepState::Skipped
        | StepState::Stopped
        | StepState::Abandoned { .. } => return true,
    };
    let waited = node.join() == Join::Any || !has_pending_lead(graph, steps, node);
    let started_with = row.exposure.max(seen_exposure(graph, steps, seen));
    let carries = match carried {
        Carried::AsStarted => exposure == started_with,
        Carried::AtLeastAsStarted => exposure >= started_with,
    };
    waited && carries && sees_what_led_here(graph, steps, node, seen)
}

/// How a step's exposure relates to the one it started with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carried {
    /// Unchanged. The domain did the step's work, or nobody has yet.
    AsStarted,
    /// Raised or kept by what an agent, an integration or a loop's passes
    /// returned.
    AtLeastAsStarted,
}

impl Carried {
    fn after(kind: &NodeKind) -> Self {
        match kind {
            NodeKind::AgentRun(_) | NodeKind::Action(_) | NodeKind::Loop(_) => {
                Self::AtLeastAsStarted
            }
            NodeKind::Condition(_)
            | NodeKind::Transform(_)
            | NodeKind::Approval(_)
            | NodeKind::Wait(_)
            | NodeKind::Code(_)
            | NodeKind::Guardrail(_) => Self::AsStarted,
        }
    }
}

/// Whether `seen` is exactly what a step starting now would see.
///
/// That is the steps that led it here and everything they saw, every one
/// of them finished. A step joining all its leads sees all of them. One
/// joining any sees at least one. An entry step sees nothing.
fn sees_what_led_here(
    graph: &WorkflowGraph,
    steps: &[StepState],
    node: &Node,
    seen: &[NodeKey],
) -> bool {
    let leads = leading_steps(graph, steps, node);
    let seen_leads: Vec<&[NodeKey]> = leads
        .iter()
        .filter(|(lead, _)| seen.contains(lead.key()))
        .filter_map(|(_, state)| state.seen())
        .collect();
    let reached = |key: &NodeKey| {
        leads.iter().any(|(lead, _)| lead.key() == key)
            || seen_leads.iter().any(|before| before.contains(key))
    };
    let closed = seen_leads
        .iter()
        .all(|before| before.iter().all(|key| seen.contains(key)));
    let enough = match (graph.incoming(node.key()).next(), node.join()) {
        (None, _) => seen.is_empty(),
        (Some(_), Join::All) => seen_leads.len() == leads.len(),
        (Some(_), Join::Any) => !seen_leads.is_empty(),
    };
    closed && enough && seen.iter().all(reached)
}

/// The most sensitive data the steps `seen` carry.
///
/// It counts what a step saw when it started, not what led to it later. So
/// a lead that finished after a step joining any of its leads started does
/// not count against it.
fn seen_exposure(graph: &WorkflowGraph, steps: &[StepState], seen: &[NodeKey]) -> DataClassLevel {
    graph
        .nodes()
        .iter()
        .zip(steps)
        .filter(|(node, _)| seen.contains(node.key()))
        .filter_map(|(_, state)| state.exposure())
        .max()
        .unwrap_or(DataClassLevel::Public)
}

/// Whether a step is in a state its kind takes.
///
/// The rules:
/// - a condition or transform settles the moment it is reached, so it is
///   never ready, running or abandoned,
/// - a pause ends no later than its own window,
/// - an approval's first approver is neither the person it acts for nor an
///   author, on a step that needs two,
/// - nothing started before the execution did or after it last changed,
/// - only an approval holds for a while, names who gave it, and holds no
///   longer than its window or the execution's deadline allow.
fn fits_its_kind(node: &Node, state: &StepState, row: &WorkflowExecutionRow) -> bool {
    let settled_here = matches!(node.kind(), NodeKind::Condition(_) | NodeKind::Transform(_));
    match state {
        StepState::Ready { attempt, .. } => {
            !settled_here && attempt_fits(node.kind(), *attempt, row)
        }
        StepState::Running {
            underway,
            started_at,
            ..
        } => {
            !settled_here
                && (row.created_at..=row.updated_at).contains(started_at)
                && pause_fits(node.kind(), underway, *started_at, row)
        }
        StepState::Abandoned { .. } => !settled_here,
        StepState::Succeeded { holds, .. } => {
            holding_fits(node.kind(), holds, row)
                || (row.mode.mode().stands_in(node.key()) && *holds == Holding::ForGood)
        }
        StepState::Waiting | StepState::Failed(_) | StepState::Skipped | StepState::Stopped => true,
    }
}

/// Whether a ready step's attempt fits its kind.
///
/// Only an action calls again. Its call was made fewer times than it may
/// be, and the next try falls inside the run, no later than the pause after
/// the last change. Only an agent run, or a code step starting the agent its
/// version holds, is put off for the plan's limit, due
/// again by the run's deadline and no later than the pause after the last
/// change.
fn attempt_fits(kind: &NodeKind, attempt: Attempt, row: &WorkflowExecutionRow) -> bool {
    match attempt {
        Attempt::First => true,
        Attempt::Again { tries, due } => {
            matches!(kind, NodeKind::Action(_))
                && tries.next().is_some()
                && row.created_at < due
                && due < row.deadline
                && due <= row.updated_at.saturating_add(tries.pause_before_next())
        }
        Attempt::Deferred { due } => {
            matches!(kind, NodeKind::AgentRun(_) | NodeKind::Code(_))
                && row.created_at < due
                && due <= row.deadline
                && due <= row.updated_at.saturating_add(RUN_LIMIT_PAUSE)
        }
        Attempt::NextRound { due } => {
            matches!(kind, NodeKind::Action(_))
                && row.created_at <= due
                && due <= row.deadline
                && due <= row.updated_at.saturating_add(LONGEST_ROUND_GAP)
        }
    }
}

/// Whether a running execution leaves no waiting step that could already
/// have started or been skipped.
///
/// An execution moves on as far as it can at every change. So a row that
/// did not is not one it wrote.
fn nothing_left_undecided(row: &WorkflowExecutionRow) -> bool {
    if row.status != ExecutionStatus::Running {
        return true;
    }
    let trigger = TriggerData {
        input: &row.input,
        exposure: row.exposure,
    };
    row.graph
        .nodes()
        .iter()
        .zip(&row.steps)
        .filter(|(_, state)| matches!(state, StepState::Waiting))
        .all(|(node, _)| readiness(&row.graph, &row.steps, node, trigger) == Readiness::Wait)
}

/// `check` with the rules every step's state keeps.
fn steps_keep_their_rules(check: RowCheck, row: &WorkflowExecutionRow) -> RowCheck {
    let one_per_step = row.steps.len() == row.graph.nodes().len();
    check
        .holds(
            one_per_step,
            "a state per step that does not match its graph",
        )
        .holds(
            work_fits_kinds(&row.graph, &row.steps),
            "a step waiting on work its kind does not do",
        )
        .holds(
            status_fits_steps(row.status, &row.steps),
            "a status its steps contradict",
        )
        .holds(
            every_reached_step_was_led_to(&row.graph, &row.steps),
            "a step reached by no path",
        )
        .holds(
            ports_fit_kinds(&row.graph, &row.steps),
            "a step that left by a way out its kind does not have",
        )
        .holds(
            row.steps
                .iter()
                .filter_map(StepState::exposure)
                .all(|exposure| exposure >= row.exposure),
            "a step holding less sensitive data than its trigger",
        )
}

/// `check` with the rules the execution's times keep.
fn times_keep_their_rules(check: RowCheck, row: &WorkflowExecutionRow) -> RowCheck {
    check
        .in_order(row.created_at, row.updated_at, "changed before it started")
        .holds(
            row.created_at < row.deadline,
            "a deadline before it started",
        )
        .holds(
            row.deadline <= row.created_at.saturating_add(MAX_RUN_TIME),
            "a deadline past the longest any execution may run",
        )
}

/// Whether every step whose work is under way, or was when the execution
/// ended, waits on the work its kind does.
fn work_fits_kinds(graph: &WorkflowGraph, steps: &[StepState]) -> bool {
    graph
        .nodes()
        .iter()
        .zip(steps)
        .all(|(node, state)| match state {
            StepState::Running { underway, .. } | StepState::Abandoned { underway, .. } => {
                underway.fits(node.kind())
            }
            StepState::Waiting
            | StepState::Ready { .. }
            | StepState::Succeeded { .. }
            | StepState::Failed(_)
            | StepState::Skipped
            | StepState::Stopped => true,
        })
}

/// Whether `status` is one the steps could have led to.
///
/// The rules:
/// - a running execution has no failed or left-behind step, and some step
///   still to settle,
/// - an ended one has no step ready or running,
/// - a succeeded one has every step finished,
/// - a failed one has a failed step.
fn status_fits_steps(status: ExecutionStatus, steps: &[StepState]) -> bool {
    match (status, StepsPicture::of(steps)) {
        (ExecutionStatus::Running, StepsPicture::Going | StepsPicture::Idle)
        | (ExecutionStatus::Ended(ExecutionEnd::Succeeded), StepsPicture::AllFinished)
        | (ExecutionStatus::Ended(ExecutionEnd::Failed), StepsPicture::Failed)
        | (
            ExecutionStatus::Ended(
                ExecutionEnd::Cancelled(_) | ExecutionEnd::TimedOut | ExecutionEnd::LoopEnded,
            ),
            StepsPicture::Failed
            | StepsPicture::LeftBehind
            | StepsPicture::AllFinished
            | StepsPicture::Idle,
        ) => true,
        (
            ExecutionStatus::Running | ExecutionStatus::Ended(_),
            StepsPicture::Going
            | StepsPicture::Idle
            | StepsPicture::AllFinished
            | StepsPicture::Failed
            | StepsPicture::LeftBehind
            | StepsPicture::Mixed,
        ) => false,
    }
}

/// What the steps of a stored execution show, taken together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepsPicture {
    /// Work is ready or under way, and nothing failed or was left behind.
    Going,
    /// Nothing is ready or under way, nothing failed or was left behind,
    /// and some step still waits.
    Idle,
    /// Every step finished, and none failed or was left behind.
    AllFinished,
    /// A step failed, and nothing is ready or under way.
    Failed,
    /// Steps were left behind when the execution ended, nothing failed,
    /// and nothing is ready or under way.
    LeftBehind,
    /// Work is ready or under way beside a failure or a step left behind,
    /// which no execution leaves.
    Mixed,
}

impl StepsPicture {
    fn of(steps: &[StepState]) -> Self {
        let has = |test: fn(&StepState) -> bool| steps.iter().any(test);
        let live =
            has(|state| matches!(state, StepState::Ready { .. } | StepState::Running { .. }));
        let failed = has(|state| matches!(state, StepState::Failed(_)));
        let left = has(|state| matches!(state, StepState::Stopped | StepState::Abandoned { .. }));
        if live && (failed || left) {
            return Self::Mixed;
        }
        if live {
            return Self::Going;
        }
        if failed {
            return Self::Failed;
        }
        if left {
            return Self::LeftBehind;
        }
        if steps.iter().all(StepState::is_settled) {
            return Self::AllFinished;
        }
        Self::Idle
    }
}

/// Whether every step something reached is an entry, or has an edge its
/// step led along. A step no path reached is waiting or skipped.
fn every_reached_step_was_led_to(graph: &WorkflowGraph, steps: &[StepState]) -> bool {
    graph
        .nodes()
        .iter()
        .zip(steps)
        .all(|(node, state)| match state {
            StepState::Waiting | StepState::Skipped => true,
            StepState::Ready { .. }
            | StepState::Running { .. }
            | StepState::Succeeded { .. }
            | StepState::Failed(_)
            | StepState::Stopped
            | StepState::Abandoned { .. } => is_led_to(graph, steps, node),
        })
}

/// Whether every finished step left by a way out its kind has.
fn ports_fit_kinds(graph: &WorkflowGraph, steps: &[StepState]) -> bool {
    graph
        .nodes()
        .iter()
        .zip(steps)
        .all(|(node, state)| match state {
            StepState::Succeeded { port, .. } => node.kind().ports().contains(port),
            StepState::Waiting
            | StepState::Ready { .. }
            | StepState::Running { .. }
            | StepState::Failed(_)
            | StepState::Skipped
            | StepState::Stopped
            | StepState::Abandoned { .. } => true,
        })
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::domains::workflows::account::IntegrationAccount;
    use crate::domains::workflows::data::FlowData;
    use crate::domains::workflows::design::node::{Join, Mapping, NodeKind, Port, Source};
    use crate::domains::workflows::execution::step::{
        ActionOutcome, ApprovalHold, ApprovalWait, ApprovedBy, CallTries, FirstApproval, Holding,
        Underway,
    };
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, acting, action, ann, append, append_row, approval, approval_of, approve_as, bob,
        by_hand, cid, condition, deciding, edge, field, key, managing, node, offered, path,
        published, sheet_account, spec_of, start_as, started, stored, transform,
    };
    use crate::domains::workflows::execution::{ActionClearance, ActionStart, HoursBegin, Offer};
    use crate::domains::workflows::integration::{ActionAccount, ActionStep};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{ActionCallId, ActionClass, DeclaredAction, Human, IntegrationAccountId};

    fn asking() -> Execution {
        let mut execution = started(
            vec![approval("check"), transform("after", Join::All)],
            vec![edge("check", Port::Next, "after")],
        );
        execution
            .request_approval(&crate::domains::workflows::execution::tests::fixtures::key(
                "check",
            ))
            .unwrap();
        execution
    }

    /// A stored execution of [`asking`] with the steps `make` builds from
    /// the time it started, so a step's times belong to this row.
    fn with_steps(make: impl FnOnce(OffsetDateTime) -> Vec<StepState>) -> WorkflowExecutionRow {
        let base = stored(&asking());
        WorkflowExecutionRow {
            steps: make(base.created_at),
            ..base
        }
    }

    fn running(underway: Underway, started_at: OffsetDateTime) -> StepState {
        StepState::Running {
            exposure: DataClassLevel::Internal,
            seen: Vec::new(),
            underway,
            started_at,
        }
    }

    fn ready(exposure: DataClassLevel) -> StepState {
        StepState::Ready {
            input: FlowData::null(),
            exposure,
            seen: Vec::new(),
            attempt: Attempt::First,
        }
    }

    fn refused(row: WorkflowExecutionRow) -> bool {
        refused_as_corrupt(&Execution::reconstitute(row))
    }

    /// An execution waiting on an approval is stored as it is and read
    /// back without complaint.
    #[test]
    fn a_stored_execution_keeping_every_rule_is_rebuilt() {
        assert!(Execution::reconstitute(stored(&asking())).is_ok());
    }

    /// A row for a two-step graph holds only one step state. It is refused
    /// as corrupt.
    #[test]
    fn a_state_per_step_that_does_not_match_the_graph_is_corrupt() {
        assert!(refused(with_steps(|_| vec![StepState::Waiting])));
    }

    /// A stored approval step says it waits on an integration call. It is
    /// refused as corrupt.
    #[test]
    fn a_step_waiting_on_work_its_kind_does_not_do_is_corrupt() {
        assert!(refused(with_steps(|at| vec![
            running(
                Underway::Action {
                    call_id: ActionCallId::new(),
                    tries: CallTries::FIRST,
                },
                at,
            ),
            StepState::Waiting,
        ])));
    }

    /// A row marked succeeded with its approval still open, one marked
    /// cancelled with the same open approval, and a running one with a
    /// stopped step are each refused as corrupt.
    #[test]
    fn a_status_its_steps_contradict_is_corrupt() {
        let succeeded_unsettled = WorkflowExecutionRow {
            status: ExecutionStatus::Ended(ExecutionEnd::Succeeded),
            ..stored(&asking())
        };
        let cancelled_still_running = WorkflowExecutionRow {
            status: ExecutionStatus::Ended(ExecutionEnd::Cancelled(ann().principal())),
            ..stored(&asking())
        };
        let running_with_a_stopped_step =
            with_steps(|_| vec![StepState::Stopped, StepState::Waiting]);

        assert!(refused(succeeded_unsettled));
        assert!(refused(cancelled_still_running));
        assert!(refused(running_with_a_stopped_step));
    }

    /// A stored execution with a ready step after an approval that is still
    /// open is rejected as corrupt.
    #[test]
    fn a_step_reached_by_no_path_is_corrupt() {
        assert!(refused(with_steps(|at| {
            let wait = ApprovalWait {
                closes_at: at.saturating_add(Duration::HOUR),
                first: FirstApproval::NotGiven,
            };
            vec![
                running(Underway::Approval(wait), at),
                ready(DataClassLevel::Internal),
            ]
        })));
    }

    /// A stored approval says it left "when true", a way out only a
    /// condition has. It is refused as corrupt.
    #[test]
    fn a_step_that_left_by_a_way_out_its_kind_does_not_have_is_corrupt() {
        assert!(refused(with_steps(|at| vec![
            approved(at, Port::WhenTrue),
            StepState::Waiting,
        ])));
    }

    /// An approval as [`asking`]'s row would hold it, had Bob given it at
    /// `at` and it left by `port`.
    fn approved(at: OffsetDateTime, port: Port) -> StepState {
        StepState::Succeeded {
            output: FlowData::null(),
            exposure: DataClassLevel::Internal,
            seen: Vec::new(),
            port,
            holds: Holding::Approved(ApprovalHold {
                by: ApprovedBy::One(bob()),
                from: at,
                until: at.saturating_add(Duration::HOUR),
            }),
        }
    }

    /// A stored execution where `approvers` approved "check", a step of
    /// `class`, and the step after it ran.
    fn finished(class: DeclaredAction, approvers: &[Human]) -> WorkflowExecutionRow {
        let mut execution = started(
            vec![approval_of("check", class), transform("after", Join::All)],
            vec![edge("check", Port::Next, "after")],
        );
        execution.request_approval(&key("check")).unwrap();
        for approver in approvers {
            approve_as(&mut execution, "check", approver).unwrap();
        }
        stored(&execution)
    }

    fn sending() -> DeclaredAction {
        DeclaredAction::Declared(ActionClass::Communicate)
    }

    fn paying() -> DeclaredAction {
        DeclaredAction::Declared(ActionClass::Financial)
    }

    /// `row` with its first step holding as `holds` says.
    fn holding(row: &WorkflowExecutionRow, holds: Holding) -> WorkflowExecutionRow {
        let mut steps = row.steps.clone();
        if let Some(StepState::Succeeded { holds: slot, .. }) = steps.first_mut() {
            *slot = holds;
        }
        WorkflowExecutionRow {
            steps,
            ..stored_like(row)
        }
    }

    /// `row` with the approval its first step holds changed by `change`.
    fn rehold(
        row: &WorkflowExecutionRow,
        change: impl FnOnce(&mut ApprovalHold),
    ) -> WorkflowExecutionRow {
        let mut steps = row.steps.clone();
        if let Some(StepState::Succeeded {
            holds: Holding::Approved(hold),
            ..
        }) = steps.first_mut()
        {
            change(hold);
        }
        WorkflowExecutionRow {
            steps,
            ..stored_like(row)
        }
    }

    /// A stored approval that holds for good, past the deadline, or only
    /// until the moment it was given is refused. So is a transform that
    /// holds until the deadline, since it should hold for good.
    #[test]
    fn a_step_holding_otherwise_than_its_kind_does_is_corrupt() {
        let base = finished(sending(), &[bob()]);
        let transform_until = {
            let execution = started(
                vec![transform("first", Join::All), approval("elsewhere")],
                Vec::new(),
            );
            let row = stored(&execution);
            holding(
                &row,
                Holding::Approved(ApprovalHold {
                    by: ApprovedBy::One(bob()),
                    from: row.created_at,
                    until: row.deadline,
                }),
            )
        };

        assert!(refused(holding(&base, Holding::ForGood)));
        assert!(refused(rehold(&base, |hold| {
            hold.until = base.deadline.saturating_add(Duration::SECOND);
        })));
        assert!(refused(rehold(&base, |hold| hold.until = hold.from)));
        assert!(refused(transform_until));
        assert!(Execution::reconstitute(stored_like(&base)).is_ok());
    }

    /// An approval stored as lasting beyond its one-hour window or as given
    /// before the execution started makes the row corrupt. An approval
    /// lasting exactly one hour reads back.
    #[test]
    fn an_approval_holding_longer_than_approving_gives_is_corrupt() {
        let base = finished(sending(), &[bob()]);
        let held_for =
            |length: Duration| rehold(&base, |hold| hold.until = hold.from.saturating_add(length));
        let given_before_the_start = rehold(&base, |hold| {
            hold.from = base.created_at.saturating_sub(Duration::SECOND);
        });

        assert!(refused(held_for(Duration::HOUR + Duration::SECOND)));
        assert!(refused(given_before_the_start));
        let control = Execution::reconstitute(held_for(Duration::HOUR));
        assert!(control.is_ok(), "{:?}", control.err());
    }

    /// Reconstitution rejects a message approval naming the acting person
    /// Ann or two approvers when it needs one, and a payment approval naming
    /// only Bob or Bob twice. A payment approved by Bob and Cid reads back.
    #[test]
    fn a_finished_approval_naming_people_who_could_not_give_it_is_corrupt() {
        let message = finished(sending(), &[bob()]);
        let payment = finished(paying(), &[bob(), cid()]);
        let approved_by =
            |row: &WorkflowExecutionRow, by: ApprovedBy| rehold(row, |hold| hold.by = by);
        let two = |first: Human, second: Human| ApprovedBy::Two { first, second };

        assert!(refused(approved_by(&message, ApprovedBy::One(ann()))));
        assert!(refused(approved_by(&message, two(bob(), cid()))));
        assert!(refused(approved_by(&payment, ApprovedBy::One(bob()))));
        assert!(refused(approved_by(&payment, two(bob(), bob()))));
        let control = Execution::reconstitute(stored_like(&payment));
        assert!(control.is_ok(), "{:?}", control.err());
    }

    /// The trigger is internal, and a stored step says it holds public
    /// data. It is refused, since a step never holds less than its trigger.
    #[test]
    fn a_step_holding_less_sensitive_data_than_its_trigger_is_corrupt() {
        assert!(refused(with_steps(|_| vec![
            ready(DataClassLevel::Public),
            StepState::Waiting,
        ])));
    }

    /// An approval with a one-hour window is stored closing one second past
    /// the hour, and is refused. Stored closing at the hour, it reads back.
    #[test]
    fn an_approval_open_past_its_own_window_is_corrupt() {
        let closing_after = |open_for: Duration| {
            with_steps(|at| {
                let wait = ApprovalWait {
                    closes_at: at.saturating_add(open_for),
                    first: FirstApproval::NotGiven,
                };
                vec![running(Underway::Approval(wait), at), StepState::Waiting]
            })
        };

        assert!(refused(closing_after(Duration::HOUR + Duration::SECOND)));
        assert!(!refused(closing_after(Duration::HOUR)));
    }

    /// A one-hour wait is stored ending one second past the hour. It is
    /// refused as corrupt.
    #[test]
    fn a_wait_ending_past_its_own_duration_is_corrupt() {
        let wait = node(
            "pause",
            NodeKind::Wait(
                crate::domains::workflows::design::node::WaitStep::new(
                    crate::types::Lifetime::seconds(3600).unwrap(),
                )
                .unwrap(),
            ),
            Join::All,
        );
        let execution = started(vec![wait], Vec::new());
        let at = execution.created_at;
        let row = WorkflowExecutionRow {
            steps: vec![running(
                Underway::Timer {
                    until: at.saturating_add(Duration::HOUR + Duration::SECOND),
                },
                at,
            )],
            ..stored(&execution)
        };

        assert!(refused(row));
    }

    /// A stored execution whose graph contains a payment without a preceding
    /// approval is rejected as corrupt.
    #[test]
    fn a_graph_with_an_unapproved_high_risk_action_is_corrupt() {
        let pay = ActionStep::new(
            &spec_of(ActionClass::Financial, DataClassLevel::Internal),
            ActionAccount::Account(IntegrationAccountId::new()),
            Mapping::new(vec![(field("values"), Source::Input(path("trigger")))]).unwrap(),
        )
        .unwrap();
        let graph = WorkflowGraph::new(
            vec![node("pay", NodeKind::Action(pay), Join::All)],
            Vec::new(),
        )
        .unwrap();
        let row = WorkflowExecutionRow {
            graph,
            steps: vec![StepState::Waiting],
            ..stored(&asking())
        };

        assert!(refused(row));
    }

    /// A stored graph where "first" reads "later", which runs after it, is
    /// refused. The same row with "later" reading "first" reads back.
    #[test]
    fn a_graph_reading_a_later_step_is_corrupt() {
        let graph = WorkflowGraph::new(
            vec![
                crate::domains::workflows::execution::tests::fixtures::copy(
                    "first",
                    &[("rows", "later")],
                ),
                approval("later"),
            ],
            vec![edge("first", Port::Next, "later")],
        )
        .unwrap();
        let cancelled = |graph: WorkflowGraph| WorkflowExecutionRow {
            graph,
            steps: vec![StepState::Waiting, StepState::Waiting],
            status: ExecutionStatus::Ended(ExecutionEnd::Cancelled(ann().principal())),
            ..stored(&asking())
        };
        let reading_earlier = WorkflowGraph::new(
            vec![
                transform("first", Join::All),
                crate::domains::workflows::execution::tests::fixtures::copy(
                    "later",
                    &[("rows", "first")],
                ),
            ],
            vec![edge("first", Port::Next, "later")],
        )
        .unwrap();

        assert!(refused(cancelled(graph)));
        assert!(!refused(cancelled(reading_earlier)));
    }

    /// A stored execution of version 0 is refused, since versions count
    /// from one.
    #[test]
    fn a_version_below_one_is_corrupt() {
        assert!(refused(WorkflowExecutionRow {
            version: 0,
            ..stored(&asking())
        }));
    }

    /// A row changed before it started, one whose deadline is its start,
    /// and one whose deadline is past the longest run allowed are each
    /// refused.
    #[test]
    fn times_out_of_order_or_past_their_limits_are_corrupt() {
        let row = stored(&asking());
        let created = row.created_at;
        let changed_first = WorkflowExecutionRow {
            updated_at: created.saturating_sub(Duration::SECOND),
            ..stored(&asking())
        };
        let deadline_first = WorkflowExecutionRow {
            deadline: created,
            ..stored(&asking())
        };

        assert!(refused(changed_first));
        assert!(refused(deadline_first));
        assert!(refused(WorkflowExecutionRow {
            deadline: row
                .created_at
                .saturating_add(MAX_RUN_TIME + Duration::SECOND),
            ..row
        }));
    }

    /// An execution is stored waiting, after Bob approves, after Ann
    /// cancels, and after Bob refuses. Each row reads back.
    #[test]
    fn an_execution_stored_at_any_point_is_rebuilt() {
        let fresh = asking();
        let mut finished = asking();
        approve(&mut finished);
        let mut cancelled = asking();
        cancelled.cancel(&managing(&ann())).unwrap();
        let mut denied = asking();
        denied.deny(&key("check"), &deciding(&bob())).unwrap();

        for execution in [fresh, finished, cancelled, denied] {
            assert!(Execution::reconstitute(stored(&execution)).is_ok());
        }
    }

    /// Bob gives the first of two approvals an undeclared step needs. The
    /// execution is stored while it waits for the second, and reads back.
    #[test]
    fn an_execution_waiting_for_its_second_approval_is_rebuilt() {
        let mut execution = started(
            vec![approval_of(
                "check",
                crate::types::DeclaredAction::Undeclared,
            )],
            Vec::new(),
        );
        execution.request_approval(&key("check")).unwrap();
        approve_as(&mut execution, "check", &bob()).unwrap();

        let rebuilt = Execution::reconstitute(stored(&execution));

        assert!(rebuilt.is_ok(), "{:?}", rebuilt.err());
    }

    /// Bob refuses an approval while a wait runs beside it. The failed
    /// execution, with the wait left behind, is stored and reads back.
    #[test]
    fn an_execution_that_failed_beside_waiting_work_is_rebuilt() {
        let mut execution = started(
            vec![
                approval("asked"),
                crate::domains::workflows::execution::tests::fixtures::wait("pause"),
            ],
            Vec::new(),
        );
        execution
            .begin_wait(&key("pause"), HoursBegin::NotAsked)
            .unwrap();
        execution.request_approval(&key("asked")).unwrap();
        execution.deny(&key("asked"), &deciding(&bob())).unwrap();

        let rebuilt = Execution::reconstitute(stored(&execution));

        assert!(rebuilt.is_ok(), "{:?}", rebuilt.err());
    }

    /// A sign-off waiting for any lead opens after "early". Then "late"
    /// finishes with confidential data the sign-off never saw. The stored
    /// row still reads back.
    #[test]
    fn a_step_that_started_before_a_more_sensitive_lead_finished_is_rebuilt() {
        let account = sheet_account(&ann(), "google-sheets");
        let mut execution = early_approval(*account.id());
        execution.request_approval(&key("sign-off")).unwrap();
        let clearance = sheet_clearance(&account);
        let ActionStart::Call(call, _) = execution
            .begin_action(
                &key("late"),
                Offer::Current(&offered(append_row())),
                &clearance,
                &acting(&ann()),
            )
            .unwrap()
        else {
            panic!("the action was not called");
        };
        execution
            .settle_action(
                &key("late"),
                call.call_id,
                ActionOutcome::Succeeded {
                    output: FlowData::null(),
                    exposure: DataClassLevel::Confidential,
                },
            )
            .unwrap();

        let rebuilt = Execution::reconstitute(stored(&execution));

        assert!(rebuilt.is_ok(), "{:?}", rebuilt.err());
    }

    /// Grants the acting owner permission for the late sheet action's append operation.
    fn sheet_clearance(
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> ActionClearance<ResolvedTenant> {
        ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        )
    }

    /// Makes the approval ready from an early transform while its parallel sheet action waits.
    fn early_approval(account: IntegrationAccountId) -> Execution {
        started(
            vec![
                transform("early", Join::All),
                action("late", account),
                approval_joining_any("sign-off"),
            ],
            vec![
                edge("early", Port::Next, "sign-off"),
                edge("late", Port::Next, "sign-off"),
            ],
        )
    }

    fn approval_joining_any(name: &str) -> Node {
        let step = approval(name);
        Node::new(
            step.key().clone(),
            step.name().clone(),
            step.kind().clone(),
            Join::Any,
        )
    }

    fn approve(execution: &mut Execution) {
        approve_as(execution, "check", &bob()).unwrap();
    }

    /// Marking the stored transform "first" confidential while its following
    /// approval remains internal makes the execution row corrupt.
    #[test]
    fn a_step_carrying_less_than_a_step_that_led_to_it_is_corrupt() {
        let execution = started(
            vec![transform("first", Join::All), approval("check")],
            vec![edge("first", Port::Next, "check")],
        );
        let mut row = stored(&execution);
        if let Some(StepState::Succeeded { exposure, .. }) = row.steps.first_mut() {
            *exposure = DataClassLevel::Confidential;
        }

        assert!(refused(row));
    }

    /// Step "c" waits for both "a" and "b". A row where "c" is ready while
    /// "b" is still ready is refused as corrupt.
    #[test]
    fn a_step_joining_all_that_started_before_every_lead_settled_is_corrupt() {
        let execution = started(
            vec![approval("a"), approval("b"), joining_all("c")],
            vec![edge("a", Port::Next, "c"), edge("b", Port::Next, "c")],
        );
        let mut row = stored(&execution);
        row.steps = vec![
            approved(row.created_at, Port::Next),
            ready(DataClassLevel::Internal),
            ready(DataClassLevel::Internal),
        ];

        assert!(refused(row));
    }

    fn joining_all(name: &str) -> Node {
        let step = approval(name);
        Node::new(
            step.key().clone(),
            step.name().clone(),
            step.kind().clone(),
            Join::All,
        )
    }

    /// A stored row has a condition ready for outside work. A condition
    /// settles the moment it is reached, so the row is refused.
    #[test]
    fn a_condition_waiting_on_outside_work_is_corrupt() {
        let execution = started(vec![condition("check"), approval("elsewhere")], Vec::new());
        let mut row = stored(&execution);
        if let Some(first) = row.steps.first_mut() {
            *first = ready(DataClassLevel::Internal);
        }

        assert!(refused(row));
    }

    /// A stored row has an approval given and the step after it still
    /// waiting. Every change moves a run on as far as it goes, so the row
    /// is refused.
    #[test]
    fn a_waiting_step_that_could_have_moved_on_is_corrupt() {
        let mut row = stored(&asking());
        row.steps = vec![approved(row.created_at, Port::Next), StepState::Waiting];

        assert!(refused(row));
    }

    /// A stored row says Bob gave the first approval on a step that needs
    /// only one. It is refused. With no first approval, it reads back.
    #[test]
    fn a_first_approval_that_could_not_have_been_given_is_corrupt() {
        let base = stored(&asking());
        let at = base.created_at;
        let by_someone = |first: FirstApproval| WorkflowExecutionRow {
            steps: vec![
                running(
                    Underway::Approval(ApprovalWait {
                        closes_at: at.saturating_add(Duration::MINUTE),
                        first,
                    }),
                    at,
                ),
                StepState::Waiting,
            ],
            ..stored_like(&base)
        };

        assert!(refused(by_someone(FirstApproval::GivenBy(bob()))));
        let control = Execution::reconstitute(by_someone(FirstApproval::NotGiven));
        assert!(control.is_ok(), "{:?}", control.err());
    }

    /// Cid runs Ann's payment workflow. A stored first approval from its
    /// author Ann makes the row corrupt; the same row naming Bob reads back.
    #[test]
    fn a_first_approval_by_an_author_is_corrupt() {
        let payment = approval_of("check", DeclaredAction::Declared(ActionClass::Financial));
        let workflow = published(vec![payment], Vec::new());
        let (mut execution, _) =
            start_as(&workflow, &cid(), by_hand(DataClassLevel::Internal)).unwrap();
        execution.request_approval(&key("check")).unwrap();
        let base = stored(&execution);
        let first_by = |person: Human| {
            let mut steps = base.steps.clone();
            if let Some(StepState::Running {
                underway: Underway::Approval(wait),
                ..
            }) = steps.first_mut()
            {
                wait.first = FirstApproval::GivenBy(person);
            }
            WorkflowExecutionRow {
                steps,
                ..stored_like(&base)
            }
        };

        assert!(refused(first_by(ann())));
        let control = Execution::reconstitute(first_by(bob()));
        assert!(control.is_ok(), "{:?}", control.err());
    }

    /// A run started by hand is stored at chain depth 2. A manual start is
    /// always depth 1, so the row is refused.
    #[test]
    fn a_chain_depth_its_cause_does_not_lead_to_is_corrupt() {
        let row = WorkflowExecutionRow {
            chain_depth: crate::shared::events::chain::ChainDepth::from_stored(2).unwrap(),
            ..stored(&asking())
        };

        assert!(refused(row));
    }

    /// A stored approval started one second before its execution did. It
    /// is refused. Started at the same instant, it reads back.
    #[test]
    fn a_step_started_before_its_execution_is_corrupt() {
        let base = stored(&asking());
        let at = base.created_at;
        let wait = ApprovalWait {
            closes_at: at.saturating_add(Duration::MINUTE),
            first: FirstApproval::NotGiven,
        };
        let at_start = |started_at: OffsetDateTime| WorkflowExecutionRow {
            steps: vec![
                running(Underway::Approval(wait.clone()), started_at),
                StepState::Waiting,
            ],
            ..stored_like(&base)
        };

        assert!(refused(at_start(at.saturating_sub(Duration::SECOND))));
        assert!(!refused(at_start(at)));
    }

    fn stored_like(row: &WorkflowExecutionRow) -> WorkflowExecutionRow {
        WorkflowExecutionRow {
            id: row.id,
            workflow_id: row.workflow_id,
            version: row.version,
            graph: row.graph.clone(),
            acting_for: row.acting_for.clone(),
            authors: row.authors.clone(),
            failure_alert: row.failure_alert,
            mode: row.mode.clone(),
            cause: row.cause,
            pass: row.pass.clone(),
            chain_depth: row.chain_depth,
            input: row.input.clone(),
            exposure: row.exposure,
            steps: row.steps.clone(),
            status: row.status,
            deadline: row.deadline,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    /// Replacing a ready approval's stored input with "pay account 999",
    /// which no earlier step produced, makes the row corrupt. The original
    /// execution reads back.
    #[test]
    fn a_ready_step_holding_an_input_no_step_produced_is_corrupt() {
        let execution = started(
            vec![transform("first", Join::All), approval("check")],
            vec![edge("first", Port::Next, "check")],
        );
        let honest = stored(&execution);
        let mut tampered = stored(&execution);
        if let Some(StepState::Ready { input, .. }) = tampered.steps.get_mut(1) {
            *input = FlowData::text("pay account 999").unwrap();
        }

        assert!(Execution::reconstitute(honest).is_ok());
        assert!(refused(tampered));
    }

    /// A stored step after "first" leaves "first" out of the steps it saw.
    /// That would hide where its input came from, so the row is refused.
    #[test]
    fn a_step_not_seeing_a_step_that_led_to_it_is_corrupt() {
        let execution = started(
            vec![transform("first", Join::All), approval("check")],
            vec![edge("first", Port::Next, "check")],
        );
        let mut row = stored(&execution);
        if let Some(StepState::Ready { seen, .. }) = row.steps.get_mut(1) {
            seen.clear();
        }

        assert!(Execution::reconstitute(stored(&execution)).is_ok());
        assert!(refused(row));
    }

    /// A transform saw internal data, and a stored row marks it restricted.
    /// The domain settles a transform at exactly what it saw, so the row is
    /// refused.
    #[test]
    fn a_step_the_domain_settled_carrying_another_exposure_is_corrupt() {
        let execution = started(
            vec![transform("first", Join::All), approval("elsewhere")],
            Vec::new(),
        );
        let mut row = stored(&execution);
        if let Some(StepState::Succeeded { exposure, .. }) = row.steps.first_mut() {
            *exposure = DataClassLevel::Restricted;
        }

        assert!(refused(row));
    }

    /// A stored step lists "aside" among the steps it saw, though no edge
    /// leads from "aside" to it. The row is refused as corrupt.
    #[test]
    fn a_step_seeing_a_step_that_does_not_lead_to_it_is_corrupt() {
        let execution = started(
            vec![transform("aside", Join::All), approval("check")],
            Vec::new(),
        );
        let mut row = stored(&execution);
        if let Some(StepState::Ready { seen, .. }) = row.steps.get_mut(1) {
            seen.push(key("aside"));
        }

        assert!(refused(row));
    }
}
