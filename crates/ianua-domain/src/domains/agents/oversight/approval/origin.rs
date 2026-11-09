//! What an approval request is about, and where it came from.

use crate::domains::agents::execution::run::{AgentRun, PendingCallRef, RunState};
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::EventOrigin;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{
    ActionClass, AgentId, AgentRunId, DeclaredAction, HttpMethod, Human, Initiator,
};

text_value! {
    /// A human-readable summary of the action awaiting approval.
    pub struct ApprovalAction;
}

impl TextValue for ApprovalAction {
    const FIELD: &'static str = "action";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(Self::MAX_LEN)
    }
}

impl ApprovalAction {
    /// Maximum length of an action summary.
    const MAX_LEN: usize = 500;

    /// The action a call takes: its method and target, exactly. An approval
    /// is matched to the call by this text.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `target` is not a request path.
    /// - [`DomainError::Validation`] when the result is not a valid action
    ///   summary.
    pub fn for_call(method: HttpMethod, target: &str) -> Result<Self, DomainError> {
        Validator::new("target", target)
            .request_target(2048)
            .validate_first()?;
        Ok(Self::new(format!("{} {target}", method.as_str()))?)
    }
}

/// Where an approval request came from, and so who may not decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOrigin {
    /// Opened by hand, by this initiator.
    Opened(Initiator),
    /// Raised by a run that paused on a call.
    Run(RunOrigin),
}

impl ApprovalOrigin {
    /// Whether `by` put the action there, through any of their accounts.
    /// That is the person who opened the request, or who started its run.
    #[must_use]
    pub(crate) fn is_requester(&self, by: &Human) -> bool {
        match self {
            Self::Opened(opener) => opener.is(by),
            Self::Run(run) => run.started_by().is(by),
        }
    }

    /// The most sensitive data an approver reads in the request.
    ///
    /// A run's request carries the call's arguments, which the model drew
    /// from what the run read. So it carries the run's exposure. A person
    /// writes a request they open by hand, so it is public. A request an
    /// agent or a consumer opened carries text nobody checked. It counts as
    /// restricted.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        match self {
            Self::Run(run) => run.exposure,
            Self::Opened(Initiator::Human(_)) => DataClassLevel::Public,
            Self::Opened(Initiator::Agent(_) | Initiator::Consumer(_)) => {
                DataClassLevel::Restricted
            }
        }
    }

    /// Reads a stored origin back, with the class its request was stored
    /// under.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a run's request is stored with
    ///   no class. Its class comes from the paused tool, which always has
    ///   one.
    pub fn from_stored(
        stored: StoredApprovalOrigin,
        action_class: DeclaredAction,
    ) -> Result<Self, DomainError> {
        match (stored, action_class) {
            (StoredApprovalOrigin::Opened(by), _) => Ok(Self::Opened(by)),
            (StoredApprovalOrigin::Run(run), DeclaredAction::Declared(class)) => {
                Ok(Self::Run(RunOrigin::stored(run, class)))
            }
            (StoredApprovalOrigin::Run(_), DeclaredAction::Undeclared) => Err(
                DomainError::corrupt_row("approval request", "a run's request with no class"),
            ),
        }
    }
}

/// A paused run, as the approval request it raises names it.
///
/// [`of`](Self::of) takes it from the run itself. So the request carries the
/// run's real starter and the exact call it holds. Whoever opens the request
/// cannot leave either out or name a different one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOrigin {
    run_id: AgentRunId,
    agent_id: AgentId,
    started_by: Initiator,
    pending_call: PendingCallRef,
    class: ActionClass,
    exposure: DataClassLevel,
    chain: EventOrigin,
}

impl RunOrigin {
    /// The origin of a request raised by `run` while it is paused on a call.
    ///
    /// A run that is not paused raises nothing, even one holding a call
    /// already approved.
    #[must_use]
    pub fn of<T: TenantScope>(run: &AgentRun<T>) -> Option<Self> {
        let RunState::AwaitingApproval(pending) = run.state() else {
            return None;
        };
        Some(Self {
            run_id: *run.id(),
            agent_id: *run.agent_id(),
            started_by: run.started_by().clone(),
            pending_call: PendingCallRef::of(pending),
            class: pending.class(),
            exposure: run.exposure(),
            chain: run.origin(),
        })
    }

    /// The origin as it was stored, for a request read back from storage
    /// whose class is `class`.
    fn stored(stored: StoredRunOrigin, class: ActionClass) -> Self {
        Self {
            run_id: stored.run_id,
            agent_id: stored.agent_id,
            started_by: stored.started_by,
            pending_call: stored.pending_call,
            class,
            exposure: stored.exposure,
            chain: stored.chain,
        }
    }

    /// The class of action the paused call takes.
    #[must_use]
    pub fn class(&self) -> ActionClass {
        self.class
    }

    /// The most sensitive data the run had read when it paused.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.exposure
    }

    /// Where the run came from: outside any workflow, or a workflow
    /// execution at its depth.
    #[must_use]
    pub fn chain(&self) -> EventOrigin {
        self.chain
    }

    /// The paused execution that raised this approval request.
    #[must_use]
    pub fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }

    /// The agent running it.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Who started the run, and so put the paused call there.
    #[must_use]
    pub fn started_by(&self) -> &Initiator {
        &self.started_by
    }

    /// The call the run holds.
    #[must_use]
    pub fn pending_call(&self) -> &PendingCallRef {
        &self.pending_call
    }
}

/// Where a stored request came from, as its columns hold it.
///
/// It is kept apart from [`ApprovalOrigin`]. When a request is opened, the
/// only way to name a run's starter and call is [`RunOrigin::of`]. These
/// parts become an origin only when a request is read back.
pub enum StoredApprovalOrigin {
    /// Opened by hand, by this initiator.
    Opened(Initiator),
    /// Raised by a run that paused on a call.
    Run(StoredRunOrigin),
}

/// A run origin's stored columns.
pub struct StoredRunOrigin {
    /// The paused execution whose call awaits a decision.
    pub run_id: AgentRunId,
    /// The agent running it.
    pub agent_id: AgentId,
    /// Who started the run.
    pub started_by: Initiator,
    /// The call the run held.
    pub pending_call: PendingCallRef,
    /// The most sensitive data the run had read when it paused.
    pub exposure: DataClassLevel,
    /// Where the run came from.
    pub chain: EventOrigin,
}
