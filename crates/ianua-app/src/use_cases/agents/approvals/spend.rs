//! Spend a person's approval of an agent's action, once: asked by the
//! gateway over the sealed channel as the agent attempts the action again.
//!
//! Once a person approves, the agent's next attempt at exactly that action
//! is let through, once. The approval is spent on it, so approving a
//! payment approves one payment, not every payment that looks the same from
//! then on. Nothing passes on a delegation that is no longer live, however
//! it was approved.

use std::sync::Arc;

use ianua_domain::shared::clock;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{ApprovalStore, DelegationStore, GatedAction, Spending};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::action_authority::loaded_authority;
use crate::use_cases::agents::approvals::gated::{acting_under, approval_action, live_delegation};

/// The ports [`SpendUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SpendPorts {
    /// Spends approvals, atomically.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// The delegation the action uses, and the chain above it.
    pub delegation_store: Arc<dyn DelegationStore>,
}

/// Spends an approval of exactly one agent action.
pub struct SpendUseCase {
    ports: SpendPorts,
}

impl SpendUseCase {
    /// A use case spending through `ports`.
    #[must_use]
    pub fn new(ports: SpendPorts) -> Self {
        Self { ports }
    }
}

impl Command for SpendUseCase {
    type Caller = ScopedTenant;
    type Input = GatedAction;
    type Output = Result<Spending, AppError>;

    /// Spends one approved, unexpired approval of exactly this action on
    /// the live delegation. Two attempts racing for the same approval
    /// cannot both spend it. The spend records nothing itself: the action
    /// it lets through is recorded by the gateway as
    /// `agents.action_authorized`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the delegation is gone, or was granted to
    ///   another agent.
    /// - `AppError::Forbidden` when the delegation, or one above it, is
    ///   revoked or expired. The approval stays unspent.
    /// - `AppError::Domain` when the action cannot be summarized.
    /// - `AppError::Internal` on persistence failure. The gateway refuses
    ///   the action on it.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        _auditor: &RequestAuditor,
        action: GatedAction,
    ) -> Result<Spending, AppError> {
        let approval = approval_action(&action)?;
        let now = clock::now();
        let loaded = loaded_authority(
            self.ports.delegation_store.as_ref(),
            tenant,
            &acting_under(&action),
        )
        .await?;
        live_delegation(&action, &loaded, now)?;
        let spent = self
            .ports
            .approval_store
            .consume_for_action(tenant, &action.delegation_id, &approval, now)
            .await
            .or_internal()?;
        if spent {
            return Ok(Spending::Spent);
        }
        Ok(Spending::NoneGranted)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::{Delegation, DelegationStatus};
    use ianua_domain::domains::agents::identity::control::AgentControl;
    use ianua_domain::domains::agents::oversight::approval::{
        ActionParties, ApprovalOrigin, ApprovalRequest, Approver, Presence, RequestApprovalParams,
    };
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{
        AgentId, ApprovalId, DeclaredAction, DelegationId, HttpMethod, Human, Initiator, Seconds,
    };

    use super::*;
    use crate::test_support::agents::{
        FakeApprovalStore, FakeDelegationStore, delegation_row, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::agents::approvals::gated::action_class;

    /// Ann's delegation to an agent, and the API spending approvals under
    /// it.
    struct Spend {
        use_case: SpendUseCase,
        store: Arc<FakeApprovalStore>,
        delegations: Arc<FakeDelegationStore>,
        agent: AgentId,
        ann: Human,
        delegation: Delegation<ResolvedTenant>,
    }

    fn spend() -> Spend {
        let agent = AgentId::new();
        let ann = someone("ann@corp.test");
        let delegation = Delegation::reconstitute(delegation_row(agent, ann.principal())).unwrap();
        let (store, delegations) = (
            Arc::new(FakeApprovalStore::empty()),
            Arc::new(FakeDelegationStore::empty()),
        );
        block_on(delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
        Spend {
            use_case: SpendUseCase::new(SpendPorts {
                approval_store: store.clone(),
                delegation_store: delegations.clone(),
            }),
            store,
            delegations,
            agent,
            ann,
            delegation,
        }
    }

    impl Spend {
        fn action(&self, target: &str) -> GatedAction {
            GatedAction {
                agent_id: self.agent,
                delegation_id: *self.delegation.id(),
                method: HttpMethod::Post,
                target: target.to_owned(),
                declared: DeclaredAction::Undeclared,
            }
        }

        fn attempt(&self, action: GatedAction) -> Result<Spending, AppError> {
            block_on(self.use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                action,
            ))
        }

        /// A request for `target`, approved by as many people as it needs,
        /// saved.
        fn approved(&self, target: &str) -> ApprovalId {
            let mut approval = self.request(target);
            approve(&mut approval);
            block_on(self.store.save(&test_ctx().tenant(), &approval)).unwrap();
            *approval.id()
        }

        /// Bob owns the agent while Ann delegates the requested action.
        fn request(&self, target: &str) -> ApprovalRequest<ResolvedTenant> {
            let action = self.action(target);
            ApprovalRequest::request(RequestApprovalParams {
                agent_id: self.agent,
                delegation_id: acting_under(&action),
                origin: ApprovalOrigin::Opened(Initiator::Agent(self.agent)),
                parties: ActionParties::from_stored(
                    someone("bob@corp.test"),
                    vec![self.ann.clone()],
                ),
                action_class: action_class(&action),
                action: approval_action(&action).unwrap(),
                ttl_seconds: Seconds::new(15 * 60),
            })
            .unwrap()
        }

        fn status(&self, approval_id: ApprovalId) -> ApprovalStatus {
            self.store
                .all()
                .into_iter()
                .find(|approval| approval.id() == &approval_id)
                .unwrap()
                .status()
        }

        fn revoke(&self) {
            let mut row = delegation_row(self.agent, *self.delegation.delegator());
            row.id = *self.delegation.id();
            row.status = DelegationStatus::Revoked;
            let revoked = Delegation::reconstitute(row).unwrap();
            block_on(self.delegations.save(&test_ctx().tenant(), &revoked)).unwrap();
        }
    }

    /// Carol and Dave provide the number of independent approvals the action requires.
    fn approve(approval: &mut ApprovalRequest<ResolvedTenant>) {
        let deciders = ["carol@corp.test", "dave@corp.test"];
        for address in &deciders[..usize::from(approval.approvers_needed())] {
            let decider = TenantAuthority::assumed(
                someone(address),
                test_ctx().tenant_id(),
                SystemPermission::all(),
                &[],
            );
            let approver = Approver::assumed(
                AgentControl::new(&decider),
                DataClassLevel::Restricted,
                Presence::Proven,
            );
            approval.approve(&approver).unwrap();
        }
    }

    /// Carol approved the payment. The agent's attempt spends it, and the
    /// approval is used up.
    #[test]
    fn an_approved_action_is_spent() {
        let s = spend();
        let approval_id = s.approved("/payments");

        let spending = s.attempt(s.action("/payments")).unwrap();

        assert_eq!(spending, Spending::Spent);
        assert_eq!(s.status(approval_id), ApprovalStatus::Consumed);
    }

    /// Attempting the same approved payment again finds no approval to spend.
    #[test]
    fn an_approval_is_spent_once() {
        let s = spend();
        s.approved("/payments");
        s.attempt(s.action("/payments")).unwrap();

        let again = s.attempt(s.action("/payments")).unwrap();

        assert_eq!(again, Spending::NoneGranted);
    }

    /// Changing the approved payment's amount finds no matching approval
    /// and leaves the original approval unspent.
    #[test]
    fn an_approval_spends_on_its_own_action_only() {
        let s = spend();
        let approval_id = s.approved("/payments?amount=10");

        let spending = s.attempt(s.action("/payments?amount=10000")).unwrap();

        assert_eq!(spending, Spending::NoneGranted);
        assert_eq!(s.status(approval_id), ApprovalStatus::Approved);
    }

    /// Revoking the delegation refuses a spend and leaves its payment
    /// approval unspent.
    #[test]
    fn nothing_is_spent_on_a_revoked_delegation() {
        let s = spend();
        let approval_id = s.approved("/payments");
        s.revoke();

        let spending = s.attempt(s.action("/payments"));

        assert!(matches!(spending, Err(AppError::Forbidden(_))));
        assert_eq!(s.status(approval_id), ApprovalStatus::Approved);
    }

    /// Spending under another agent's delegation reports it as missing and
    /// leaves the approval unspent.
    #[test]
    fn a_delegation_of_another_agent_spends_nothing() {
        let s = spend();
        let approval_id = s.approved("/payments");
        let action = GatedAction {
            agent_id: AgentId::new(),
            ..s.action("/payments")
        };

        let spending = s.attempt(action);

        assert!(matches!(spending, Err(AppError::NotFound(_))));
        assert_eq!(s.status(approval_id), ApprovalStatus::Approved);
    }

    /// Spending under an unknown delegation reports it as missing.
    #[test]
    fn an_unknown_delegation_is_not_found() {
        let s = spend();
        let action = GatedAction {
            delegation_id: DelegationId::new(),
            ..s.action("/payments")
        };

        let spending = s.attempt(action);

        assert!(matches!(spending, Err(AppError::NotFound(_))));
    }
}
