//! What an approval request announces: that it waits for a person, and how
//! it was decided.
//!
//! The audit trail names the request's agent as the tenant knows it, which
//! the request does not hold, so the agent's name is handed in. Where the
//! request stands picks the record: a grant, a first of two signatures, a
//! refusal or a withdrawal. Every record is marked with where the request's
//! run came from when it is taken, so deciding a request a workflow's run
//! raised continues that workflow's chain rather than starting a new one.

use time::OffsetDateTime;

use crate::domains::agents::authority::delegation::{ActingUnder, Delegation};
use crate::domains::agents::events::oversight::{
    AgentApprovalDenied, AgentApprovalGranted, AgentApprovalRequested, AgentApprovalSigned,
    AgentApprovalWithdrawn,
};
use crate::domains::agents::oversight::approval::{
    ApprovalOrigin, ApprovalRequest, ApprovalState, FirstOfTwo,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::EventOrigin;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::{AgentId, ApprovalId, EventLabel};

/// How a request was decided, and when.
enum Decided {
    /// Approved: the action may run.
    Granted(OffsetDateTime),
    /// The first of two approvals was given.
    Signed(OffsetDateTime),
    /// Refused.
    Denied(OffsetDateTime),
    /// Taken back because its run was stopped.
    Withdrawn(OffsetDateTime),
}

/// How `state` was decided, when it was.
fn decided(state: &ApprovalState) -> Option<Decided> {
    match state {
        ApprovalState::Approved { approval, .. } => Some(Decided::Granted(approval.at)),
        ApprovalState::Pending(FirstOfTwo::Given(first)) => Some(Decided::Signed(first.at)),
        ApprovalState::Denied { decision, .. } => Some(Decided::Denied(decision.at())),
        ApprovalState::Withdrawn { decision, .. } => Some(Decided::Withdrawn(decision.at())),
        ApprovalState::Pending(FirstOfTwo::NotGiven)
        | ApprovalState::Consumed { .. }
        | ApprovalState::Expired(_) => None,
    }
}

/// Raises `agents.approval_requested` for `request`, open under
/// `delegation`.
pub(super) fn raise_request<T: TenantScope>(
    request: &mut ApprovalRequest<T>,
    delegation: &Delegation<T>,
) -> Result<(), DomainError> {
    if request.delegation_id != ActingUnder::Delegation(*delegation.id()) {
        return Err(DomainError::invalid(message!(
            "agents-the-delegation-is-not-the-one",
            "the delegation is not the one the request uses"
        )));
    }
    if !request.is_pending() {
        return Err(DomainError::invalid_transition(message!(
            "agents-only-a-request-still-waiting-for",
            "only a request still waiting for a decision is announced"
        )));
    }
    let event = AgentApprovalRequested {
        delegation_id: *delegation.id(),
        delegation_label: delegation_label(delegation),
        approval_id: request.id,
        approval_label: action_label(request),
        occurred_at: clock::now(),
    };
    request.raised.raise_latest(event);
    Ok(())
}

/// Raises the record of how `request` was decided, its agent named
/// `agent_label`, and nothing when it is undecided.
pub(super) fn decision<T: TenantScope>(request: &mut ApprovalRequest<T>, agent_label: EventLabel) {
    let Some(decided) = decided(&request.state) else {
        return;
    };
    let named = Named {
        agent_id: request.agent_id,
        agent_label,
        approval_id: request.id,
        approval_label: action_label(request),
        requested_at: request.created_at,
    };
    match decided {
        Decided::Granted(at) => request.raised.raise_latest(named.granted(at)),
        Decided::Signed(at) => request.raised.raise_latest(named.signed(at)),
        Decided::Denied(at) => request.raised.raise_latest(named.denied(at)),
        Decided::Withdrawn(at) => request.raised.raise_latest(named.withdrawn(at)),
    }
}

/// What every decision on a request names: the agent, the request, and
/// when it was asked for.
struct Named {
    agent_id: AgentId,
    agent_label: EventLabel,
    approval_id: ApprovalId,
    approval_label: EventLabel,
    requested_at: OffsetDateTime,
}

impl Named {
    /// How long the request had waited at `at`, in whole seconds.
    fn waited_until(&self, at: OffsetDateTime) -> i64 {
        crate::shared::clock::between(self.requested_at, at).whole_seconds()
    }

    fn granted(self, at: OffsetDateTime) -> AgentApprovalGranted {
        AgentApprovalGranted {
            seconds_to_decide: self.waited_until(at),
            agent_id: self.agent_id,
            agent_label: self.agent_label,
            approval_id: self.approval_id,
            approval_label: self.approval_label,
            occurred_at: at,
        }
    }

    fn signed(self, at: OffsetDateTime) -> AgentApprovalSigned {
        AgentApprovalSigned {
            seconds_to_decide: self.waited_until(at),
            agent_id: self.agent_id,
            agent_label: self.agent_label,
            approval_id: self.approval_id,
            approval_label: self.approval_label,
            occurred_at: at,
        }
    }

    fn denied(self, at: OffsetDateTime) -> AgentApprovalDenied {
        AgentApprovalDenied {
            agent_id: self.agent_id,
            agent_label: self.agent_label,
            approval_id: self.approval_id,
            approval_label: self.approval_label,
            occurred_at: at,
        }
    }

    fn withdrawn(self, at: OffsetDateTime) -> AgentApprovalWithdrawn {
        AgentApprovalWithdrawn {
            agent_id: self.agent_id,
            agent_label: self.agent_label,
            approval_id: self.approval_id,
            approval_label: self.approval_label,
            occurred_at: at,
        }
    }
}

/// The name a request is recorded under: the action it waits on.
fn action_label<T: TenantScope>(request: &ApprovalRequest<T>) -> EventLabel {
    EventLabel::of(request.action.as_str())
}

/// The name a delegation is recorded under: its own, or its id when it has
/// none.
fn delegation_label<T: TenantScope>(delegation: &Delegation<T>) -> EventLabel {
    delegation.name().map_or_else(
        || EventLabel::of(&delegation.id().to_string()),
        |name| EventLabel::of(name.as_str()),
    )
}

/// Where the events of a request from `origin` come from: its run's chain,
/// or outside any workflow for a request opened by hand.
fn chain(origin: &ApprovalOrigin) -> EventOrigin {
    match origin {
        ApprovalOrigin::Run(run) => run.chain(),
        ApprovalOrigin::Opened(_) => EventOrigin::Outside,
    }
}

impl<T: TenantScope> Raises for ApprovalRequest<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        let chain = chain(&self.origin);
        self.raised
            .take(saved_for)
            .into_iter()
            .map(|event| chain.mark(event))
            .collect()
    }
}
