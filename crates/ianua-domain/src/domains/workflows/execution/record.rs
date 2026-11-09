//! What happened in an execution, as each change reports it.
//!
//! Every change to an execution hands back what it did, one record per
//! event. The use case that made the change turns each record into an audit
//! event. So no step starts, succeeds, fails or is skipped without a record.

use time::OffsetDateTime;

use crate::domains::workflows::design::node::{NodeKey, Port};
use crate::domains::workflows::execution::step::{CallTries, StepFailure};
use crate::domains::workflows::guardrail::finding::GuardrailFound;
use crate::types::{PrincipalRef, UntrustedText};

/// How an execution ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionEnd {
    /// Every step that was reached finished without failing.
    Succeeded,
    /// A step failed.
    Failed,
    /// This person stopped it.
    Cancelled(PrincipalRef),
    /// It ran past its workflow's run limit.
    TimedOut,
    /// It was a pass of a loop, and the loop's execution ended or the loop
    /// failed first, so it was stopped.
    LoopEnded,
}

impl ExecutionEnd {
    /// The stored and audited name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled(_) => "cancelled",
            Self::TimedOut => "timed_out",
            Self::LoopEnded => "loop_ended",
        }
    }
}

/// One thing that happened in an execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionRecord {
    /// The execution started.
    Started,
    /// Something happened to one step.
    Step {
        /// The step.
        key: NodeKey,
        /// What happened to it.
        happened: StepRecord,
    },
    /// The execution ended.
    Ended(ExecutionEnd),
}

impl ExecutionRecord {
    /// That `happened` to the step called `key`.
    pub(super) fn step(key: &NodeKey, happened: StepRecord) -> Self {
        Self::Step {
            key: key.clone(),
            happened,
        }
    }
}

/// What happened to one step.
#[derive(Debug, Clone, PartialEq)]
pub enum StepRecord {
    /// Its work started outside the domain.
    Started,
    /// It finished and the workflow went on through this way out.
    Succeeded(Port),
    /// In a test, it stood in instead of doing its work, and the workflow
    /// went on as if it had.
    StoodIn,
    /// The work ended unsuccessfully with a typed reason for the record.
    Failed(StepFailure),
    /// No path reached it.
    Skipped,
    /// The execution ended while it was ready or under way.
    Abandoned,
    /// This person approved going on past it.
    ApprovalGranted(PrincipalRef),
    /// This person approved every item of the loop, having been shown each
    /// of them first.
    ItemsApprovalGranted(ItemsShown),
    /// Its integration turned its call away, and the call is made again.
    CallTurnedAway(TurnedAwayCall),
    /// It was put off: an agent run while the tenant's plan had no room
    /// for another run in flight, or a step whose round left its work
    /// undone. It is tried again from `due` on.
    StartDeferred {
        /// When it is tried again.
        due: OffsetDateTime,
    },
    /// Its guardrail found these, recorded by kind and place, whatever the
    /// step then did about them.
    GuardrailFound(GuardrailFound),
}

/// What one approver of every item of a loop was shown before saying yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemsShown {
    /// Who approved.
    pub by: PrincipalRef,
    /// How many items the loop will act on, every one of them shown.
    pub items: u32,
    /// How many pages of items they opened.
    pub pages: u32,
    /// When the last item they had not yet seen was shown to them.
    pub every_item_at: OffsetDateTime,
}

/// A call an integration turned away, which is made again.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnedAwayCall {
    /// How many times the call was made so far.
    pub tries: CallTries,
    /// When it may be made again.
    pub due: OffsetDateTime,
    /// Why the integration turned it away.
    pub reason: UntrustedText,
}
