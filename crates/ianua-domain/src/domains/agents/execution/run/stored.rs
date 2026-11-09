//! The rules a stored run must keep to be read back.

use crate::domains::agents::execution::run::call::PendingCall;
use crate::domains::agents::execution::run::check::checks_fit;
use crate::domains::agents::execution::run::params::AgentRunRow;
use crate::domains::agents::execution::run::spend::SpendCheck;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;

/// Refuses a stored run that breaks a rule a run keeps.
///
/// # Errors
///
/// Returns [`DomainError::Infrastructure`] for steps not numbered from one, excess
/// tool calls, exposure below a step's reads, or a held call at the wrong next step.
/// Step times must be ordered within the run's lifetime, as must held-call approval.
/// A run over budget must end; its approval threshold must be below the cap, and
/// reaching it must end or owe approval. Changes cannot precede the run's start.
/// A run turns back no more answers than its check allows.
pub(super) fn ensure_consistent(row: &AgentRunRow) -> Result<(), DomainError> {
    ensure_held_call_fits(row)?;
    ensure_spend_fits(row)?;
    ensure_checks_fit(row)?;
    RowCheck::of("agent run")
        .holds(
            steps_in_order(row),
            "steps not numbered one after another from the first",
        )
        .holds(
            within_step_limit(row),
            "more tool calls than its step limit",
        )
        .holds(
            row.steps.iter().all(|step| step.read() <= row.exposure),
            "an exposure below what its steps read",
        )
        .holds(
            steps_timed_in_order(row),
            "steps recorded out of order or outside the run's lifetime",
        )
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was started",
        )
        .finish()
}

/// Refuses a stored run that turned back more answers than its check
/// allows, or any while held to no check.
fn ensure_checks_fit(row: &AgentRunRow) -> Result<(), DomainError> {
    RowCheck::of("agent run")
        .holds(
            checks_fit(row),
            "more answers turned back than its check allows, or any without a check",
        )
        .finish()
}

/// Refuses a stored run whose held call is not at its next step, or was
/// approved outside the run's lifetime.
fn ensure_held_call_fits(row: &AgentRunRow) -> Result<(), DomainError> {
    let approved_at = row.state.pending().and_then(PendingCall::approved_at);
    RowCheck::of("agent run")
        .holds(
            row.state
                .pending()
                .is_none_or(|held| next_step(row) == Some(held.at_step())),
            "a held call that is not at its next step",
        )
        .holds(
            approved_at.is_none_or(|at| row.created_at <= at && at <= row.updated_at),
            "a call approved outside the run's lifetime",
        )
        .finish()
}

/// Refuses a stored run that spent past its limit, or past what it asks a
/// person at, and still goes on, or that asks at no less than its limit.
fn ensure_spend_fits(row: &AgentRunRow) -> Result<(), DomainError> {
    let ended = row.state.status().is_terminal();
    RowCheck::of("agent run")
        .holds(
            within_spend_limit(row) || ended,
            "spent past its limit yet still going",
        )
        .holds(
            spend_check_below_limit(row),
            "asks a person at no less than its spend limit",
        )
        .holds(
            asks_once_spent(row) || ended,
            "spent what it asks a person at yet does not ask",
        )
        .finish()
}

/// Whether the run's steps are numbered 1, 2, 3 and so on.
fn steps_in_order(row: &AgentRunRow) -> bool {
    row.steps
        .iter()
        .zip(1..)
        .all(|(step, seq)| step.seq() == seq)
}

/// Whether the run made no more tool calls than its step limit allows.
fn within_step_limit(row: &AgentRunRow) -> bool {
    let tool_calls = row.steps.iter().filter(|step| step.is_tool_call()).count();
    u32::try_from(tool_calls).is_ok_and(|calls| calls <= row.max_steps)
}

/// Whether each step was recorded no earlier than the one before, and all
/// of them within the run's lifetime.
fn steps_timed_in_order(row: &AgentRunRow) -> bool {
    let mut previous = row.created_at;
    row.steps.iter().all(|step| {
        let in_order = previous <= step.at() && step.at() <= row.updated_at;
        previous = step.at();
        in_order
    })
}

/// Whether the amount the run asks a person at is below its spend limit,
/// when it has both.
fn spend_check_below_limit(row: &AgentRunRow) -> bool {
    match (row.spend_check.mark(), row.spend_limit.limit()) {
        (Some(mark), Some(limit)) => mark < *limit,
        _ => true,
    }
}

/// Whether a run still waiting to reach the amount it asks a person at
/// has not reached it.
fn asks_once_spent(row: &AgentRunRow) -> bool {
    match row.spend_check {
        SpendCheck::AskAt(mark) => row.spent < mark,
        SpendCheck::Off | SpendCheck::Due(_) | SpendCheck::Asked(_) => true,
    }
}

/// Whether the run spent no more than its limit, when it has one.
fn within_spend_limit(row: &AgentRunRow) -> bool {
    row.spend_limit
        .limit()
        .is_none_or(|limit| row.spent <= *limit)
}

/// The number the run's next step takes.
fn next_step(row: &AgentRunRow) -> Option<u32> {
    u32::try_from(row.steps.len()).ok()?.checked_add(1)
}
