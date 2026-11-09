//! Gate an agent action on a person's decision: the gateway side of
//! `requires_approval`.
//!
//! A delegation that requires approval lets no action through on the agent's
//! word alone. The gateway asks the API to spend a person's approval of
//! exactly this action; when there is none, it asks the API to hold the
//! action for a person, and refuses it. The gateway never writes approvals:
//! both questions go through the [`ApprovalBroker`], and the API opens,
//! records and spends approvals through [`HoldActionUseCase`] and
//! [`SpendUseCase`].
//!
//! [`HoldActionUseCase`]: crate::use_cases::agents::approvals::HoldActionUseCase
//! [`SpendUseCase`]: crate::use_cases::agents::approvals::SpendUseCase

use std::sync::Arc;

use ianua_domain::types::ApprovalId;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::agents::{ApprovalBroker, GatedAction, Held, RequestOpened, Spending};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What the gate decided about one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalGate {
    /// A person approved exactly this action; the approval is now spent.
    Admitted,
    /// Awaiting a person's decision on the named request.
    AwaitingDecision {
        /// The request a person decides.
        approval_id: ApprovalId,
        /// Whether this attempt opened the request, as opposed to finding one
        /// already open.
        opened: RequestOpened,
    },
    /// Too many requests are already open under this delegation.
    TooManyOpen,
}

/// The ports [`GateActionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GateActionPorts {
    /// Asks the API to spend an approval or hold the action.
    pub broker: Arc<dyn ApprovalBroker>,
}

/// Decides whether an approval-gated agent action may proceed.
pub struct GateActionUseCase {
    ports: GateActionPorts,
}

impl GateActionUseCase {
    /// The gate, asking through `ports`.
    #[must_use]
    pub fn new(ports: GateActionPorts) -> Self {
        Self { ports }
    }
}

impl Command for GateActionUseCase {
    type Caller = ScopedTenant;
    type Input = GatedAction;
    type Output = Result<ApprovalGate, AppError>;

    /// Admits the action if the API spent a person's approval of exactly it
    /// on the live delegation, and otherwise has the API find or open the
    /// request a person decides. The gateway records nothing here: the API
    /// records the request it opens, and the gateway records the action
    /// itself, allowed or refused.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the API refused: the delegation is not
    ///   the agent's, or no longer live.
    /// - `AppError::Internal` when the API cannot be reached in time or its
    ///   answer does not read. The caller must refuse the action: an
    ///   unanswered gate is a closed one.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        _auditor: &RequestAuditor,
        action: GatedAction,
    ) -> Result<ApprovalGate, AppError> {
        let broker = self.ports.broker.as_ref();
        let spending = broker
            .spend(tenant, &action)
            .await
            .map_err(AppError::from_domain)?;
        if spending == Spending::Spent {
            return Ok(ApprovalGate::Admitted);
        }
        let held = broker
            .hold(tenant, &action)
            .await
            .map_err(AppError::from_domain)?;
        Ok(gate_of(held))
    }
}

/// What the gate says of an action the API held.
fn gate_of(held: Held) -> ApprovalGate {
    match held {
        Held::AwaitingDecision {
            approval_id,
            opened,
        } => ApprovalGate::AwaitingDecision {
            approval_id,
            opened,
        },
        Held::TooManyOpen => ApprovalGate::TooManyOpen,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{AgentId, DeclaredAction, DelegationId, HttpMethod};

    use super::*;
    use crate::test_support::agents::FakeApprovalBroker;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn payment() -> GatedAction {
        GatedAction {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            method: HttpMethod::Post,
            target: "/payments".to_owned(),
            declared: DeclaredAction::Undeclared,
        }
    }

    fn attempt(
        broker: &Arc<FakeApprovalBroker>,
        action: &GatedAction,
    ) -> Result<ApprovalGate, AppError> {
        let gate = GateActionUseCase::new(GateActionPorts {
            broker: broker.clone(),
        });
        block_on(gate.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            action.clone(),
        ))
    }

    /// The agent first tries a payment nobody approved. The API holds it
    /// for a person, and the payment is not let through.
    #[test]
    fn an_unapproved_action_awaits_a_decision() {
        let broker = Arc::new(FakeApprovalBroker::answering());

        let gate = attempt(&broker, &payment()).unwrap();

        assert!(matches!(
            gate,
            ApprovalGate::AwaitingDecision {
                opened: RequestOpened::Now,
                ..
            }
        ));
    }

    /// Carol approved the payment. The agent's next attempt is let through
    /// once, and the attempt after waits on a person again.
    #[test]
    fn an_approved_action_is_admitted_once() {
        let broker = Arc::new(FakeApprovalBroker::answering());
        let action = payment();
        broker.grant(&action);

        let first = attempt(&broker, &action).unwrap();
        let second = attempt(&broker, &action).unwrap();

        assert_eq!(first, ApprovalGate::Admitted);
        assert_ne!(second, ApprovalGate::Admitted);
    }

    /// An unreachable approval broker returns an error despite holding an
    /// approval for the action.
    #[test]
    fn an_unreachable_api_admits_nothing() {
        let broker = Arc::new(FakeApprovalBroker::unreachable());
        let action = payment();
        broker.grant(&action);

        let gate = attempt(&broker, &action);

        assert!(gate.is_err());
    }

    /// A broker refusal returns a forbidden error despite an approval for
    /// the action.
    #[test]
    fn a_refusing_api_admits_nothing() {
        let broker = Arc::new(FakeApprovalBroker::refusing());
        let action = payment();
        broker.grant(&action);

        let gate = attempt(&broker, &action);

        assert!(matches!(gate, Err(AppError::Forbidden(_))));
    }

    /// A broker at its open-request limit returns the gate's too-many-open
    /// outcome.
    #[test]
    fn too_many_open_admits_nothing() {
        let broker = Arc::new(FakeApprovalBroker::full());

        let gate = attempt(&broker, &payment()).unwrap();

        assert_eq!(gate, ApprovalGate::TooManyOpen);
    }
}
