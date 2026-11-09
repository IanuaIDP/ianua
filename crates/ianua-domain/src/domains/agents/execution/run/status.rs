//! Where a run stands, and the moves between those states.

use crate::domains::agents::execution::run::PendingCall;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::transition::{InvalidTransition, checked};

/// Where a run stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RunStatus {
    /// Taking steps.
    Running,
    /// Produced a final answer.
    Completed,
    /// Stopped without an answer, at the step limit or on an error.
    Failed,
    /// Stopped early because an operator asked.
    Cancelled,
    /// Stopped because the agent may not act. It is suspended, revoked or
    /// must re-attest. A run may not use authority its agent lost.
    Halted,
    /// Paused until a person approves a tool call. It goes back to `Running`
    /// on approval or denial.
    AwaitingApproval,
    /// Paused between steps because a person asked. It goes back to
    /// `Running` when a person resumes it.
    Paused,
    /// Stopped because it spent its budget, or spent what could not be
    /// measured under one.
    OverBudget,
}

impl RunStatus {
    /// Moves to `to` when the move is allowed.
    ///
    /// A running run may complete, end any other way, pause for approval or
    /// be paused by a person. A run waiting on a person, either way, may
    /// resume or end, but never complete unseen.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, Self::permits)
    }

    fn permits(from: Self, to: Self) -> bool {
        let ends = matches!(
            to,
            Self::Failed | Self::Cancelled | Self::Halted | Self::OverBudget
        );
        match from {
            Self::Running => {
                ends || matches!(to, Self::Completed | Self::AwaitingApproval | Self::Paused)
            }
            Self::AwaitingApproval | Self::Paused => ends || to == Self::Running,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Halted | Self::OverBudget => {
                false
            }
        }
    }

    /// The stored string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Halted => "halted",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Paused => "paused",
            Self::OverBudget => "over_budget",
        }
    }

    /// Whether the run has stopped and takes no more steps.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Halted | Self::OverBudget
        )
    }

    /// Reads a value a caller sent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the value when it is not one of
    ///   the known names.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::named(value).ok_or_else(|| {
            DomainError::invalid(message!(
                "agents-unknown-run-status",
                format!("unknown run status: {value}")
            ))
        })
    }

    /// Reads a stored value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored name is not one of
    ///   the known names. The row is corrupt, not the caller's input.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::named(value).ok_or_else(|| DomainError::corrupt_row("agent run", "an unknown status"))
    }

    /// The value a name stands for.
    fn named(value: &str) -> Option<Self> {
        match value {
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "halted" => Some(Self::Halted),
            "awaiting_approval" => Some(Self::AwaitingApproval),
            "paused" => Some(Self::Paused),
            "over_budget" => Some(Self::OverBudget),
            _ => None,
        }
    }
}

/// What a running run does next: ask the model, or run a call a person has
/// just approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextCall {
    /// Ask the model for its next step.
    Model,
    /// Run this call, which a person approved.
    Approved(PendingCall),
}

/// Where a run stands, with the call it holds when it holds one.
///
/// It is one value, not a status beside an optional call. So a paused run
/// always holds the call it paused on. And an approved call waits only on a
/// run that is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    /// Taking steps, perhaps with an approved call to run first.
    Running(NextCall),
    /// Paused on this call until a person decides.
    AwaitingApproval(PendingCall),
    /// Paused by a person between steps, with what it does once resumed.
    Paused(NextCall),
    /// Produced a final answer.
    Completed,
    /// Stopped without an answer.
    Failed,
    /// Stopped because an operator asked.
    Cancelled,
    /// Stopped because the agent may not act.
    Halted,
    /// Stopped because it spent its budget.
    OverBudget,
}

impl RunState {
    /// The status label this state carries.
    #[must_use]
    pub fn status(&self) -> RunStatus {
        match self {
            Self::Running(_) => RunStatus::Running,
            Self::AwaitingApproval(_) => RunStatus::AwaitingApproval,
            Self::Paused(_) => RunStatus::Paused,
            Self::Completed => RunStatus::Completed,
            Self::Failed => RunStatus::Failed,
            Self::Cancelled => RunStatus::Cancelled,
            Self::Halted => RunStatus::Halted,
            Self::OverBudget => RunStatus::OverBudget,
        }
    }

    /// Reads a state back from its stored status and held call.
    ///
    /// A run that ended while paused may still have its call stored. An
    /// ended run holds nothing, so the call is dropped.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a run awaiting approval holds
    ///   no call, or holds an approved one.
    /// - [`DomainError::Infrastructure`] when a running run, or one a person
    ///   paused, holds a call nobody approved.
    pub fn from_stored(
        status: RunStatus,
        pending: Option<PendingCall>,
    ) -> Result<Self, DomainError> {
        match (status, pending) {
            (RunStatus::Running, next) => next_call(next).map(Self::Running),
            (RunStatus::Paused, next) => next_call(next).map(Self::Paused),
            (RunStatus::AwaitingApproval, Some(call)) if !call.is_approved() => {
                Ok(Self::AwaitingApproval(call))
            }
            (RunStatus::AwaitingApproval, _) => Err(DomainError::infra_msg(
                "a stored run awaiting approval holds no call waiting for a person",
            )),
            (RunStatus::Completed, _) => Ok(Self::Completed),
            (RunStatus::Failed, _) => Ok(Self::Failed),
            (RunStatus::Cancelled, _) => Ok(Self::Cancelled),
            (RunStatus::Halted, _) => Ok(Self::Halted),
            (RunStatus::OverBudget, _) => Ok(Self::OverBudget),
        }
    }

    /// The call held, either paused on or approved to run. Storage keeps it
    /// in this form.
    #[must_use]
    pub fn pending(&self) -> Option<&PendingCall> {
        match self {
            Self::AwaitingApproval(call)
            | Self::Running(NextCall::Approved(call))
            | Self::Paused(NextCall::Approved(call)) => Some(call),
            Self::Running(NextCall::Model)
            | Self::Paused(NextCall::Model)
            | Self::Completed
            | Self::Failed
            | Self::Cancelled
            | Self::Halted
            | Self::OverBudget => None,
        }
    }
}

/// What a running or person-paused run does next, read from the call it
/// stored.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when it holds a call nobody approved.
fn next_call(pending: Option<PendingCall>) -> Result<NextCall, DomainError> {
    match pending {
        None => Ok(NextCall::Model),
        Some(call) if call.is_approved() => Ok(NextCall::Approved(call)),
        Some(_) => Err(DomainError::infra_msg(
            "a stored run going on holds a call nobody approved",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::run::{CallApproval, ToolCall};
    use crate::types::ActionClass;

    /// Each of the eight statuses has its expected stored name, reads back
    /// from it, and no two share one. A shared name would make a paused run
    /// look finished.
    #[test]
    fn every_run_status_has_its_own_stored_name() {
        let statuses = [
            (RunStatus::Running, "running"),
            (RunStatus::Completed, "completed"),
            (RunStatus::Failed, "failed"),
            (RunStatus::Cancelled, "cancelled"),
            (RunStatus::Halted, "halted"),
            (RunStatus::AwaitingApproval, "awaiting_approval"),
            (RunStatus::Paused, "paused"),
            (RunStatus::OverBudget, "over_budget"),
        ];

        for (status, name) in statuses {
            assert_eq!(status.as_str(), name);
            assert_eq!(RunStatus::from_stored(name).unwrap(), status);
        }

        let mut seen: Vec<&str> = statuses.iter().map(|(_, name)| *name).collect();
        seen.sort_unstable();
        let total = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), total);
    }

    /// A running run may move to completed, failed, cancelled, halted or
    /// awaiting approval. Each move is allowed.
    #[test]
    fn a_running_run_may_end_any_way_or_pause_for_approval() {
        for to in [
            RunStatus::Completed,
            RunStatus::Failed,
            RunStatus::Cancelled,
            RunStatus::Halted,
            RunStatus::AwaitingApproval,
        ] {
            assert_eq!(RunStatus::Running.try_transition(to), Ok(to));
        }
    }

    /// A run waiting on a person may resume or be cancelled. It may not jump
    /// to completed while the call it paused on is undecided.
    #[test]
    fn a_paused_run_resumes_or_ends_but_never_completes_unseen() {
        let paused = RunStatus::AwaitingApproval;

        assert!(paused.try_transition(RunStatus::Running).is_ok());
        assert!(paused.try_transition(RunStatus::Cancelled).is_ok());
        assert!(paused.try_transition(RunStatus::Completed).is_err());
    }

    /// A completed, failed, cancelled, halted or over-budget run cannot go
    /// back to running or move to failed. An ended run stays ended.
    #[test]
    fn an_ended_run_moves_nowhere() {
        for from in [
            RunStatus::Completed,
            RunStatus::Failed,
            RunStatus::Cancelled,
            RunStatus::Halted,
            RunStatus::OverBudget,
        ] {
            assert!(from.is_terminal());
            assert!(from.try_transition(RunStatus::Running).is_err());
            assert!(from.try_transition(RunStatus::Failed).is_err());
        }
    }

    /// A run a person paused may resume or end, but never completes while
    /// paused, nor pauses for approval without running first.
    #[test]
    fn a_run_a_person_paused_resumes_or_ends() {
        let paused = RunStatus::Paused;

        assert!(!paused.is_terminal());
        assert!(paused.try_transition(RunStatus::Running).is_ok());
        assert!(paused.try_transition(RunStatus::Cancelled).is_ok());
        assert!(paused.try_transition(RunStatus::Completed).is_err());
        assert!(paused.try_transition(RunStatus::AwaitingApproval).is_err());
    }

    /// A stored paused run holding no call reads back asking the model
    /// next. One holding a call nobody approved is refused as corrupt.
    #[test]
    fn a_stored_paused_run_holds_only_an_approved_call() {
        let unapproved = PendingCall {
            call: ToolCall::new("t", "{}").unwrap(),
            class: ActionClass::Delete,
            at_step: 1,
            approved: CallApproval::Awaiting,
        };

        assert_eq!(
            RunState::from_stored(RunStatus::Paused, None).unwrap(),
            RunState::Paused(NextCall::Model)
        );
        assert!(matches!(
            RunState::from_stored(RunStatus::Paused, Some(unapproved)),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
