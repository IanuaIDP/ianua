//! The rules a stored step that holds or pauses must keep.
//!
//! A finished approval names who gave it and holds no longer than approving
//! gives. A wait, an approval or a loop under way keeps to its own step.

use time::OffsetDateTime;

use crate::domains::workflows::data::MAX_SIZE;
use crate::domains::workflows::design::node::{
    LoopStep, NodeKind, WaitUntil, WorkflowApprovalStep,
};
use crate::domains::workflows::design::working_hours::LONGEST_WAIT_FOR_HOURS;
use crate::domains::workflows::execution::WorkflowExecutionRow;
use crate::domains::workflows::execution::step::{
    ApprovalHold, ApprovalWait, ApprovedBy, FirstApproval, Holding, ItemsApproval, LoopProgress,
    Underway,
};
use crate::domains::workflows::execution::steps::approval::ACT_ON_APPROVAL;
use crate::shared::validation::distinct::first_repeat;
use crate::types::Human;

/// Whether a finished step holds as its kind does.
///
/// An approval names the people who gave it and holds for the time
/// approving gives. Everything else holds for good.
pub(in crate::domains::workflows::execution) fn holding_fits(
    kind: &NodeKind,
    holds: &Holding,
    row: &WorkflowExecutionRow,
) -> bool {
    match (kind, holds) {
        (NodeKind::Approval(step), Holding::Approved(hold)) => {
            approvers_fit(step, &hold.by, row) && hold_fits(step, hold, row)
        }
        (NodeKind::Approval(_), Holding::ForGood) => false,
        (
            NodeKind::AgentRun(_)
            | NodeKind::Action(_)
            | NodeKind::Condition(_)
            | NodeKind::Transform(_)
            | NodeKind::Wait(_)
            | NodeKind::Loop(_)
            | NodeKind::Code(_)
            | NodeKind::Guardrail(_),
            holding,
        ) => *holding == Holding::ForGood,
    }
}

/// Whether the people a finished approval names could have given it.
///
/// A step that needs one approval names one person, and a step that needs
/// two names two different people. None of them is the person the
/// execution acts for. On a step that needs two, none is an author.
fn approvers_fit(step: &WorkflowApprovalStep, by: &ApprovedBy, row: &WorkflowExecutionRow) -> bool {
    match by {
        ApprovedBy::One(only) => {
            step.approvers_needed() == 1 && !only.is_same_person_as(&row.acting_for)
        }
        ApprovedBy::Two { first, second } => {
            step.approvers_needed() == 2
                && may_approve(first, row)
                && may_approve(second, row)
                && !first.is_same_person_as(second)
        }
    }
}

/// Whether the whole time a finished approval holds lies where approving
/// puts it.
///
/// It began while the execution ran, by its last change. It ends after it
/// began and by the deadline. Its window opened before it began, so it ends
/// no later than the window's length or [`ACT_ON_APPROVAL`] after it began,
/// whichever is longer.
fn hold_fits(step: &WorkflowApprovalStep, hold: &ApprovalHold, row: &WorkflowExecutionRow) -> bool {
    let longest = step.window().duration().max(ACT_ON_APPROVAL);
    (row.created_at..=row.updated_at).contains(&hold.from)
        && hold.from < hold.until
        && hold.until <= row.deadline
        && hold.until <= hold.from.saturating_add(longest)
}

/// Whether a pause under way keeps to its own step.
///
/// A wait ends no later than its duration and not before it began. An
/// approval's decision keeps to its window and approvers. A loop keeps to
/// its limits and to its approval of every item.
pub(in crate::domains::workflows::execution) fn pause_fits(
    kind: &NodeKind,
    underway: &Underway,
    started_at: OffsetDateTime,
    row: &WorkflowExecutionRow,
) -> bool {
    match (kind, underway) {
        (NodeKind::Wait(wait), Underway::Timer { until }) => {
            let longest = match wait.until() {
                WaitUntil::Elapsed(duration) => duration.duration(),
                WaitUntil::WorkingHours(_) => LONGEST_WAIT_FOR_HOURS,
            };
            started_at <= *until && *until <= started_at.saturating_add(longest)
        }
        (NodeKind::Approval(step), Underway::Approval(wait)) => {
            decision_fits(step, wait, started_at, row)
        }
        (NodeKind::Loop(step), Underway::Loop(progress)) => {
            loop_fits(step, progress) && items_approval_fits(step, progress, started_at, row)
        }
        (
            _,
            Underway::AgentRun(_)
            | Underway::Action { .. }
            | Underway::Timer { .. }
            | Underway::Approval(_)
            | Underway::Loop(_)
            | Underway::Code(_),
        ) => true,
    }
}

/// Whether a decision under way keeps to the approval asking it: it closes
/// no later than its window and after it opened, and a first approval came
/// from someone other than the person the execution acts for and the
/// workflow's authors, on an approval that needs a second.
fn decision_fits(
    step: &WorkflowApprovalStep,
    wait: &ApprovalWait,
    started_at: OffsetDateTime,
    row: &WorkflowExecutionRow,
) -> bool {
    let first_fits = match &wait.first {
        FirstApproval::NotGiven => true,
        FirstApproval::GivenBy(first) => step.approvers_needed() == 2 && may_approve(first, row),
    };
    first_fits
        && started_at < wait.closes_at
        && wait.closes_at <= started_at.saturating_add(step.window().duration())
}

/// Whether a running loop's approval of every item is one its steps could
/// have asked.
///
/// Nobody is asked when its steps hold no such approval or a test stands
/// in for it. A decision under way keeps to that approval. A given one
/// names people who could have given it, after the loop started and by the
/// run's last change.
fn items_approval_fits(
    step: &LoopStep,
    progress: &LoopProgress,
    started_at: OffsetDateTime,
    row: &WorkflowExecutionRow,
) -> bool {
    let asked = step.items_approval();
    match (progress.approval(), asked) {
        (ItemsApproval::NotAsked, None) => true,
        (ItemsApproval::NotAsked, Some((node, _))) => row.mode.mode().stands_in(node.key()),
        (ItemsApproval::Waiting(wait), Some((_, approval))) => {
            decision_fits(approval, wait, started_at, row)
        }
        (ItemsApproval::Given(given), Some((_, approval))) => {
            approvers_fit(approval, &given.by, row)
                && (started_at..=row.updated_at).contains(&given.at)
        }
        (ItemsApproval::Waiting(_) | ItemsApproval::Given(_), None) => false,
    }
}

/// Whether a running loop's progress is one its passes could have made.
///
/// It holds no more items than the loop allows, a pass for no item past
/// them, each pass's execution once, and what the finished passes gave back
/// within what workflow data may hold. Some pass is still to give back.
/// While people are asked about every item no pass started; otherwise
/// exactly as many run as the loop allows at once or as are left.
fn loop_fits(step: &LoopStep, progress: &LoopProgress) -> bool {
    let items = progress.items().len();
    let left = items.saturating_sub(progress.done());
    let at_once = usize::try_from(step.at_once()).unwrap_or(usize::MAX);
    let running_fits = match progress.approval() {
        ItemsApproval::Waiting(_) => progress.passes().is_empty(),
        ItemsApproval::NotAsked | ItemsApproval::Given(_) => {
            progress.running().count() == left.min(at_once)
        }
    };
    items <= usize::try_from(step.most()).unwrap_or(usize::MAX)
        && progress.passes().len() <= items
        && left > 0
        && running_fits
        && first_repeat(progress.executions()).is_none()
        && progress.output_size() <= MAX_SIZE
}

/// Whether `first` could have given the first of two approvals: they are
/// neither the person the execution acts for nor one of its authors.
fn may_approve(first: &Human, row: &WorkflowExecutionRow) -> bool {
    !first.is_same_person_as(&row.acting_for) && !row.authors.includes(first)
}
