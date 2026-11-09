//! Where each step of an execution stands, and what came of the ones that
//! finished.

use time::{Duration, OffsetDateTime};

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::{FieldName, FlowData};
use crate::domains::workflows::design::node::{NodeKey, NodeKind, Port};
pub use crate::domains::workflows::execution::steps::code_work::{
    CodeFailure, CodeOutcome, CodeWork,
};
pub use crate::domains::workflows::execution::steps::passes::{
    ItemsApproval, ItemsApproved, LoopProgress, Pass,
};
use crate::domains::workflows::guardrail::finding::{GuardrailCheck, Unchecked};
use crate::shared::errors::DomainError;
use crate::types::{ActionCallId, AgentRunId, Human, PrincipalRef, UntrustedText};

/// The work a running step is waiting on.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Underway {
    /// Waits for the named model-driven execution to report its outcome.
    AgentRun(AgentRunId),
    /// This call of the step's integration operation.
    Action {
        /// The call, which its outcome is reported under.
        call_id: ActionCallId,
        /// Which try it is.
        tries: CallTries,
    },
    /// People's decision.
    Approval(ApprovalWait),
    /// The clock, until this instant.
    Timer {
        /// When the wait is over.
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::domains::workflows::stored::instant")
        )]
        until: OffsetDateTime,
    },
    /// The passes of a loop, one per item.
    Loop(LoopProgress),
    /// This run of the step's sandbox version.
    Code(CodeWork),
}

impl Underway {
    /// The decision people are asked for: an approval step's, or a loop's
    /// approval of every item while its passes wait for it. `None` for any
    /// other work.
    #[must_use]
    pub fn decision_wait(&self) -> Option<&ApprovalWait> {
        match self {
            Self::Approval(wait) => Some(wait),
            Self::Loop(progress) => progress.approval().waiting(),
            Self::AgentRun(_) | Self::Action { .. } | Self::Timer { .. } | Self::Code(_) => None,
        }
    }

    /// Whether this is the work a step of `kind` does. A code step whose
    /// version holds an agent waits on that agent's run.
    pub(super) fn fits(&self, kind: &NodeKind) -> bool {
        matches!(
            (self, kind),
            (Self::AgentRun(_), NodeKind::AgentRun(_) | NodeKind::Code(_))
                | (Self::Action { .. }, NodeKind::Action(_))
                | (Self::Approval(_), NodeKind::Approval(_))
                | (Self::Timer { .. }, NodeKind::Wait(_))
                | (Self::Loop(_), NodeKind::Loop(_))
                | (Self::Code(_), NodeKind::Code(_))
        )
    }
}

/// The most times an action step's call is made, the first one included.
pub(crate) const MAX_CALL_TRIES: u8 = 3;

/// How many times an action step's call was made, the one under way
/// included.
///
/// An integration that turned the call away is called again, up to
/// `MAX_CALL_TRIES` in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallTries(u8);

impl CallTries {
    /// The first call.
    pub const FIRST: Self = Self(1);

    /// Reads a stored count.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a count below one or above
    ///   `MAX_CALL_TRIES`.
    pub fn from_stored(tries: u8) -> Result<Self, DomainError> {
        if !(1..=MAX_CALL_TRIES).contains(&tries) {
            return Err(DomainError::corrupt_row(
                "workflow execution",
                "a call try count outside its range",
            ));
        }
        Ok(Self(tries))
    }

    /// The count.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }

    /// The count once the call is made again. `None` once it was made
    /// `MAX_CALL_TRIES` times.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        self.0
            .checked_add(1)
            .filter(|tries| *tries <= MAX_CALL_TRIES)
            .map(Self)
    }

    /// How long to wait before the next try.
    ///
    /// Thirty seconds after the first, two minutes after any later one. So
    /// an integration that is down or limiting the rate gets room to
    /// recover.
    #[must_use]
    pub fn pause_before_next(self) -> Duration {
        match self.0 {
            0 | 1 => Duration::seconds(30),
            _ => Duration::minutes(2),
        }
    }
}

/// Whether a ready step starts for the first time, calls again an
/// integration that turned its call away, waits for room under the
/// tenant's plan, or comes back for another round of its work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Attempt {
    /// Its work has not started before.
    First,
    /// Its call was turned away. It is made again from `due` on.
    Again {
        /// How many times the call was made so far.
        tries: CallTries,
        /// When it may be made again.
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::domains::workflows::stored::instant")
        )]
        due: OffsetDateTime,
    },
    /// Its agent run was put off, because the tenant already had as many
    /// runs in flight as its plan allows. It is tried again from `due` on.
    Deferred {
        /// When it may be tried again.
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::domains::workflows::stored::instant")
        )]
        due: OffsetDateTime,
    },
    /// Its last round left the work undone. It is made again from `due` on.
    NextRound {
        /// When the next round is made.
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::domains::workflows::stored::instant")
        )]
        due: OffsetDateTime,
    },
}

/// The longest one round of a step's work may wait for the next: a week.
pub(crate) const LONGEST_ROUND_GAP: Duration = Duration::days(7);

/// An approval step waiting for its decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApprovalWait {
    /// When it can no longer be approved.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::domains::workflows::stored::instant")
    )]
    pub closes_at: OffsetDateTime,
    /// Whether the first of two approvals was given.
    pub first: FirstApproval,
}

/// The first of two approvals a step that may be high-risk needs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FirstApproval {
    /// None was given yet.
    NotGiven,
    /// This person gave it.
    GivenBy(Human),
}

impl FirstApproval {
    /// The people who approved, once `last` gave the approval that let the
    /// step go on.
    pub(super) fn completed_by(self, last: &Human) -> ApprovedBy {
        match self {
            Self::NotGiven => ApprovedBy::One(last.clone()),
            Self::GivenBy(first) => ApprovedBy::Two {
                first,
                second: last.clone(),
            },
        }
    }
}

/// The people who approved a finished approval step.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ApprovedBy {
    /// One person, on a step that needs one.
    One(Human),
    /// Two different people, on a step that may be high-risk.
    Two {
        /// Who gave the first approval.
        first: Human,
        /// Who gave the second, which let the workflow go on.
        second: Human,
    },
}

/// What a given approval covers: who gave it, and for how long it counts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApprovalHold {
    /// The people who approved.
    pub by: ApprovedBy,
    /// When the approval that let the step go on was given.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::domains::workflows::stored::instant")
    )]
    pub from: OffsetDateTime,
    /// When it stops counting.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::domains::workflows::stored::instant")
    )]
    pub until: OffsetDateTime,
}

/// How long the result of a finished step stays valid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Holding {
    /// The result has no approval window limiting later use.
    ForGood,
    /// For the time an approval covers. Used for an approval, which counts
    /// only inside its window.
    Approved(ApprovalHold),
}

impl Holding {
    /// Whether it still holds at `now`.
    #[must_use]
    pub fn holds_at(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::ForGood => true,
            Self::Approved(hold) => now < hold.until,
        }
    }
}

/// Why a step was refused before its work started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StepRefusal {
    /// No live delegation from the person the execution acts for backs the
    /// agent run.
    NoDelegation,
    /// The step's agent may not act. It is suspended, revoked, held until
    /// it attests again, or not the step's agent.
    AgentMayNotAct,
    /// The person the execution acts for no longer holds what the step
    /// needs. They may not run workflows or use its model provider, or they
    /// lost something the agent's delegation grants.
    PersonLacksAuthority,
    /// The step's account may not be used for it.
    AccountNotUsable,
    /// The step's integration no longer offers its operation.
    OperationWithdrawn,
    /// The operation changed since the version was published.
    OperationChanged,
    /// The step's sandbox version is not kept, or has no bundle ready.
    SandboxUnavailable,
}

impl StepRefusal {
    /// Whether a step of `kind` can be refused for this reason.
    ///
    /// An agent run is refused over its delegation or agent. An action is
    /// refused over its account or operation. Code is refused over its
    /// sandbox version, and over the delegation or agent of the agent its
    /// version holds. Any of them is refused over the person's authority.
    pub(super) fn fits(self, kind: &NodeKind) -> bool {
        match (self, kind) {
            (
                Self::PersonLacksAuthority,
                NodeKind::AgentRun(_) | NodeKind::Action(_) | NodeKind::Code(_),
            )
            | (
                Self::NoDelegation | Self::AgentMayNotAct,
                NodeKind::AgentRun(_) | NodeKind::Code(_),
            )
            | (
                Self::AccountNotUsable | Self::OperationWithdrawn | Self::OperationChanged,
                NodeKind::Action(_),
            )
            | (Self::SandboxUnavailable, NodeKind::Code(_)) => true,
            (
                Self::NoDelegation
                | Self::AgentMayNotAct
                | Self::PersonLacksAuthority
                | Self::AccountNotUsable
                | Self::OperationWithdrawn
                | Self::OperationChanged
                | Self::SandboxUnavailable,
                _,
            ) => false,
        }
    }

    /// A stable name for the refusal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoDelegation => "no_delegation",
            Self::AgentMayNotAct => "agent_may_not_act",
            Self::PersonLacksAuthority => "person_lacks_authority",
            Self::AccountNotUsable => "account_not_usable",
            Self::OperationWithdrawn => "operation_withdrawn",
            Self::OperationChanged => "operation_changed",
            Self::SandboxUnavailable => "sandbox_unavailable",
        }
    }
}

/// Why a step failed.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StepFailure {
    /// Whatever did the work said why. For example, an agent run did not
    /// complete, or an integration refused or broke.
    Reported(UntrustedText),
    /// Its input held data more sensitive than its operation may be
    /// handed. So the operation was never called.
    DataAboveCeiling {
        /// How sensitive the input was.
        exposure: DataClassLevel,
        /// The most sensitive data the operation may be handed.
        ceiling: DataClassLevel,
    },
    /// Something its work needs before it may run was missing.
    Refused(StepRefusal),
    /// The person asked to approve it refused.
    ApprovalDenied(PrincipalRef),
    /// Nobody approved it before its decision window closed.
    ApprovalLapsed,
    /// What the steps before it produced, taken together, was more than
    /// workflow data may hold.
    InputTooLarge,
    /// An input its operation needs came to nothing in this run. So the
    /// operation was never called.
    MissingInput(FieldName),
    /// What it produced was more than workflow data may hold.
    OutputTooLarge,
    /// A loop found no list where it was told to look.
    NotAList,
    /// A loop's list held more items than the loop allows. No pass ran, so
    /// no item was left out unnoticed.
    TooManyItems {
        /// How many items the list held.
        count: u32,
        /// The most the loop allows.
        most: u32,
    },
    /// The pass for this item, counted from zero, did not succeed. The
    /// passes still running were stopped.
    PassFailed(u32),
    /// The code raised an error, or exited without giving anything back.
    /// This is the end of what it wrote about it.
    CodeRaised(UntrustedText),
    /// The code ran past its version's time limit and was stopped.
    CodeTimedOut,
    /// The code used more memory than its version allows and was stopped.
    CodeOutOfMemory,
    /// What the code gave back was no JSON, or more than workflow data may
    /// hold.
    CodeOutputUnreadable,
    /// The code could not be run: its version is gone, or no sandbox could
    /// take it on any try. This is why.
    CodeNotRun(UntrustedText),
    /// A guardrail found what its author said stops the run, by these
    /// checks, in the order they run. What it found is in the run's record,
    /// never the text itself.
    GuardrailFound(Vec<GuardrailCheck>),
    /// A guardrail could not check its text, so the run stopped whatever
    /// the step says a finding does.
    GuardrailUnchecked(Unchecked),
}

impl StepFailure {
    /// A stable name for the kind of failure.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Reported(_) => "reported",
            Self::DataAboveCeiling { .. } => "data_above_ceiling",
            Self::Refused(_) => "refused",
            Self::ApprovalDenied(_) => "approval_denied",
            Self::ApprovalLapsed => "approval_lapsed",
            Self::InputTooLarge => "input_too_large",
            Self::MissingInput(_) => "missing_input",
            Self::OutputTooLarge => "output_too_large",
            Self::NotAList => "not_a_list",
            Self::TooManyItems { .. } => "too_many_items",
            Self::PassFailed(_) => "pass_failed",
            Self::CodeRaised(_) => "code_raised",
            Self::CodeTimedOut => "code_timed_out",
            Self::CodeOutOfMemory => "code_out_of_memory",
            Self::CodeOutputUnreadable => "code_output_unreadable",
            Self::CodeNotRun(_) => "code_not_run",
            Self::GuardrailFound(_) => "guardrail_found",
            Self::GuardrailUnchecked(_) => "guardrail_unchecked",
        }
    }

    /// What else is known about the failure, safe to store and show.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Reported(reason) | Self::CodeRaised(reason) | Self::CodeNotRun(reason) => {
                reason.as_str().to_owned()
            }
            Self::DataAboveCeiling { exposure, ceiling } => {
                format!("{} above {}", exposure.as_str(), ceiling.as_str())
            }
            Self::Refused(refusal) => refusal.as_str().to_owned(),
            Self::ApprovalDenied(by) => by.label(),
            Self::MissingInput(field) => field.as_str().to_owned(),
            Self::TooManyItems { count, most } => format!("{count} above {most}"),
            Self::PassFailed(index) => index.to_string(),
            Self::GuardrailFound(checks) => checks
                .iter()
                .map(|check| check.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            Self::GuardrailUnchecked(why) => why.as_str().to_owned(),
            Self::ApprovalLapsed
            | Self::InputTooLarge
            | Self::OutputTooLarge
            | Self::NotAList
            | Self::CodeTimedOut
            | Self::CodeOutOfMemory
            | Self::CodeOutputUnreadable => String::new(),
        }
    }
}

/// Where one step stands.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StepState {
    /// The steps before it have not finished yet.
    Waiting,
    /// It may start, with this input.
    Ready {
        /// What the earlier steps it sees produced, and the trigger's data.
        input: FlowData,
        /// The most sensitive data in that input.
        exposure: DataClassLevel,
        /// The earlier steps whose outputs are in that input.
        seen: Vec<NodeKey>,
        /// Whether its work starts for the first time.
        attempt: Attempt,
    },
    /// Its work is under way. The input it started with went to that work.
    /// The step keeps only how sensitive it was and whose outputs it held.
    Running {
        /// The most sensitive data in the input it started with.
        exposure: DataClassLevel,
        /// The earlier steps whose outputs were in that input.
        seen: Vec<NodeKey>,
        /// What it waits on.
        underway: Underway,
        /// When it started.
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::domains::workflows::stored::instant")
        )]
        started_at: OffsetDateTime,
    },
    /// It finished and the workflow goes on through `port`.
    Succeeded {
        /// What it produced.
        output: FlowData,
        /// The most sensitive data its output may carry.
        exposure: DataClassLevel,
        /// The earlier steps it saw, which the steps after it see too.
        seen: Vec<NodeKey>,
        /// The way out it left by.
        port: Port,
        /// How long its result stays valid. An approval is valid until its
        /// decision window closes, so the action it covers must start by
        /// then, and names who gave it. Anything else is valid for good.
        holds: Holding,
    },
    /// It did not finish, and the execution stopped.
    Failed(StepFailure),
    /// No path reached it.
    Skipped,
    /// It was ready when the execution ended, and never started.
    Stopped,
    /// Its work was under way when the execution ended. What came of that
    /// work is still recorded when it is reported.
    Abandoned {
        /// The most sensitive data its input held.
        exposure: DataClassLevel,
        /// The earlier steps it saw when it started, which a late result
        /// still carries on.
        seen: Vec<NodeKey>,
        /// The work that was under way.
        underway: Underway,
    },
}

/// Where a step stands, without what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepPhase {
    /// The steps before it have not finished yet.
    Waiting,
    /// It may start.
    Ready,
    /// Its work is under way.
    Running,
    /// It finished.
    Succeeded,
    /// It did not finish, and the execution stopped.
    Failed,
    /// No path reached it.
    Skipped,
    /// It was ready when the execution ended, and never started.
    Stopped,
    /// Its work was under way when the execution ended.
    Abandoned,
}

impl StepState {
    /// Where it stands, without what it holds.
    #[must_use]
    pub fn phase(&self) -> StepPhase {
        match self {
            Self::Waiting => StepPhase::Waiting,
            Self::Ready { .. } => StepPhase::Ready,
            Self::Running { .. } => StepPhase::Running,
            Self::Succeeded { .. } => StepPhase::Succeeded,
            Self::Failed(_) => StepPhase::Failed,
            Self::Skipped => StepPhase::Skipped,
            Self::Stopped => StepPhase::Stopped,
            Self::Abandoned { .. } => StepPhase::Abandoned,
        }
    }

    /// Whether the workflow no longer waits on it.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        match self {
            Self::Succeeded { .. }
            | Self::Failed(_)
            | Self::Skipped
            | Self::Stopped
            | Self::Abandoned { .. } => true,
            Self::Waiting | Self::Ready { .. } | Self::Running { .. } => false,
        }
    }

    /// How sensitive the data that reached it is. `None` while nothing has
    /// reached it.
    pub(super) fn exposure(&self) -> Option<DataClassLevel> {
        match self {
            Self::Ready { exposure, .. }
            | Self::Running { exposure, .. }
            | Self::Succeeded { exposure, .. }
            | Self::Abandoned { exposure, .. } => Some(*exposure),
            Self::Waiting | Self::Failed(_) | Self::Skipped | Self::Stopped => None,
        }
    }

    /// The earlier steps this one saw. `None` until it is ready.
    pub(super) fn seen(&self) -> Option<&[NodeKey]> {
        match self {
            Self::Ready { seen, .. }
            | Self::Running { seen, .. }
            | Self::Succeeded { seen, .. }
            | Self::Abandoned { seen, .. } => Some(seen),
            Self::Waiting | Self::Failed(_) | Self::Skipped | Self::Stopped => None,
        }
    }
}

/// How an integration's operation went, as its adapter reports it.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionOutcome {
    /// It did its work and produced this.
    Succeeded {
        /// What it produced.
        output: FlowData,
        /// The most sensitive data it read, which its output may carry.
        exposure: DataClassLevel,
    },
    /// It did not. This is why.
    Failed(UntrustedText),
    /// It did this round of its work, and the work is not done yet: a
    /// reminder sent while the request it is about is still open. The step
    /// is made again at `due`, or when the run ends, whichever is first.
    NotYet {
        /// When the next round is made.
        due: OffsetDateTime,
    },
    /// The integration turned the call away and did nothing: it was down,
    /// busy or limiting the rate. This is why.
    ///
    /// The call is made again, after a pause, up to `MAX_CALL_TRIES` in
    /// all. Report [`ActionOutcome::Failed`] whenever the call may have
    /// acted, so nothing is done twice.
    TurnedAway(UntrustedText),
}
