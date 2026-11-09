//! Hold an agent's action for a person's decision: the API side of
//! `requires_approval`, asked by the gateway over the sealed channel.
//!
//! A delegation that requires approval lets no action through on the
//! agent's word alone. The first time the agent attempts an action, a
//! pending request is opened for a person to decide, and the gateway
//! refuses the action. Trying again before anyone decides finds the same
//! request. The gateway never writes approvals: this is where they are
//! opened and recorded.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::oversight::approval::{
    ApprovalAction, ApprovalOrigin, ApprovalRequest, RequestApprovalParams,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActingFor, ActorRef, AgentId, Initiator, Seconds};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentStore, ApprovalStore, DelegationStore, GatedAction, Held, RequestOpened,
};
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::services::limits::room::{PlanSources, ensure_room_for_tenant};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::action_authority::{LoadedAuthority, loaded_authority};
use crate::use_cases::agents::approvals::gated::{
    acting_under, action_class, approval_action, live_delegation,
};
use crate::use_cases::agents::approvals::parties::{PeoplePorts, parties_behind};

/// How long a paused action waits for a person, and how many may wait.
#[derive(Debug, Clone, Copy)]
pub struct GatePolicy {
    /// How long a person has to decide an action the gateway paused.
    pub decision_window: Seconds,
    /// The most undecided requests one delegation may have open. Past it the
    /// agent is refused outright: a flood of distinct actions must not
    /// become a flood of prompts for a person to rubber-stamp.
    pub max_open_per_delegation: u32,
}

/// The ports [`HoldActionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct HoldActionPorts {
    /// Finds and opens approval requests.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// The delegation the action uses, and the chain above it.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The agent, whose owner may not approve.
    pub agent_store: Arc<dyn AgentStore>,
    /// The people behind the delegation, who may not approve either.
    pub people: PeoplePorts,
    /// Reads the tenant's plan, which no gateway question carries.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// Enforces the tenant's plan limit on open requests.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

impl PlanSources for HoldActionPorts {
    fn plan_limits(&self) -> &dyn PlanLimitsSource {
        self.plan_limits.as_ref()
    }

    fn limit_enforcer(&self) -> &dyn LimitEnforcer {
        self.limit_enforcer.as_ref()
    }
}

/// Finds or opens the request a person decides for an agent's action.
pub struct HoldActionUseCase {
    policy: GatePolicy,
    ports: HoldActionPorts,
}

impl HoldActionUseCase {
    /// Holds actions under `policy`.
    #[must_use]
    pub fn new(policy: GatePolicy, ports: HoldActionPorts) -> Self {
        Self { policy, ports }
    }
}

impl Command for HoldActionUseCase {
    type Caller = ScopedTenant;
    type Input = GatedAction;
    type Output = Result<Held, AppError>;

    /// Finds the request already open for exactly this action on the live
    /// delegation, or opens one, unless the delegation already has too many
    /// open or the tenant's plan has no room for another. A request opened
    /// now records `agents.approval_requested`, by the agent, which prompts
    /// the people who may decide it.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the delegation or the agent is gone, the
    ///   delegation was granted to another agent, or the tenant's plan
    ///   cannot be found.
    /// - `AppError::Forbidden` when the delegation, or one above it, is
    ///   revoked or expired, or the tenant's plan allows no more open
    ///   requests.
    /// - `AppError::Domain` when the action cannot be summarized, or a
    ///   person behind the delegation can no longer be read.
    /// - `AppError::Internal` on persistence or audit failure. The gateway
    ///   refuses the action on it: an unanswered gate is a closed one.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        action: GatedAction,
    ) -> Result<Held, AppError> {
        let approval = approval_action(&action)?;
        let loaded = loaded_authority(
            self.ports.delegation_store.as_ref(),
            tenant,
            &acting_under(&action),
        )
        .await?;
        let delegation = live_delegation(&action, &loaded, clock::now())?;
        let store = self.ports.approval_store.as_ref();
        if let Some(held) = standing(store, self.policy, tenant, &action, &approval).await? {
            return Ok(held);
        }
        ensure_room_for_tenant(
            self.ports.plan_room(),
            tenant,
            ResourceKind::PendingApprovals,
        )
        .await?;
        let mut opened = opened_request(&self.ports, self.policy, tenant, &action, &loaded).await?;
        record_opened(auditor, tenant, &mut opened, delegation, &action.agent_id).await?;
        Ok(Held::AwaitingDecision {
            approval_id: *opened.id(),
            opened: RequestOpened::Now,
        })
    }
}

/// Records the request `opened` for the agent `agent_id` under
/// `delegation`, the agent acting for itself.
///
/// # Errors
///
/// - `AppError::Domain` when the request is for another delegation.
/// - `AppError::Internal` on audit failure.
async fn record_opened(
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    opened: &mut ApprovalRequest<ResolvedTenant>,
    delegation: &Delegation<ResolvedTenant>,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    opened
        .announce_request(delegation)
        .map_err(AppError::from_domain)?;
    let by_agent = ActorRef::Agent {
        id: *agent_id,
        on_behalf_of: ActingFor::Itself,
    };
    auditor
        .dispatch_by(&by_agent, opened.take_events(tenant))
        .await
        .or_internal()
}

/// What holding the action comes to when no request has to be opened: the
/// request already open for exactly this action, or too many open under
/// the delegation. `None` when a new request is to be opened.
async fn standing(
    store: &dyn ApprovalStore,
    policy: GatePolicy,
    tenant: &ScopedTenant,
    action: &GatedAction,
    approval: &ApprovalAction,
) -> Result<Option<Held>, AppError> {
    let now = clock::now();
    let open = store
        .find_pending_for_action(tenant, &action.delegation_id, approval, now)
        .await
        .or_internal()?;
    if let Some(open) = open {
        return Ok(Some(Held::AwaitingDecision {
            approval_id: *open.id(),
            opened: RequestOpened::Before,
        }));
    }
    let count = store
        .count_pending_for_delegation(tenant, &action.delegation_id, now)
        .await
        .or_internal()?;
    Ok((count >= policy.max_open_per_delegation).then_some(Held::TooManyOpen))
}

/// A request the agent raised for the action, naming the people who may
/// not approve it, saved.
async fn opened_request(
    ports: &HoldActionPorts,
    policy: GatePolicy,
    tenant: &ScopedTenant,
    action: &GatedAction,
    loaded: &LoadedAuthority,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    let agent = existing_agent(ports.agent_store.as_ref(), tenant, &action.agent_id).await?;
    let parties = parties_behind(&ports.people, tenant, &agent, loaded).await?;
    let approval = ApprovalRequest::request(RequestApprovalParams {
        agent_id: action.agent_id,
        delegation_id: acting_under(action),
        origin: ApprovalOrigin::Opened(Initiator::Agent(action.agent_id)),
        parties,
        action_class: action_class(action),
        action: approval_action(action)?,
        ttl_seconds: policy.decision_window,
    })
    .map_err(AppError::from_domain)?;
    ports
        .approval_store
        .save(tenant, &approval)
        .await
        .or_internal()?;
    Ok(approval)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::DelegationStatus;
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::{
        ActionClass, ApprovalId, DeclaredAction, DelegationId, HttpMethod, Human, HumanAccount,
        PersonKey, UserId,
    };

    use super::*;
    use crate::test_support::agents::{
        FakeAgentStore, FakeApprovalStore, FakeDelegationStore, agent_owned_by, delegation_row,
        someone,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    const POLICY: GatePolicy = GatePolicy {
        decision_window: Seconds::new(15 * 60),
        max_open_per_delegation: 20,
    };

    /// Ann's delegation to Bob's agent, which requires approval, and the
    /// API holding the agent's actions under it.
    struct Hold {
        use_case: HoldActionUseCase,
        store: Arc<FakeApprovalStore>,
        delegations: Arc<FakeDelegationStore>,
        agent: AgentId,
        delegation: Delegation<ResolvedTenant>,
        sink: Arc<FakeEventDispatcher>,
    }

    fn hold() -> Hold {
        hold_under(|ports| ports)
    }

    /// The hold, its ports changed by `change`.
    fn hold_under(change: impl FnOnce(HoldActionPorts) -> HoldActionPorts) -> Hold {
        let ann_account = UserId::new();
        let ann = ann(ann_account);
        let agent = agent_owned_by(AgentId::new(), someone("bob@corp.test"));
        let delegation =
            Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
        let tenant = test_ctx().tenant();
        let (store, delegations, agents) = (
            Arc::new(FakeApprovalStore::empty()),
            Arc::new(FakeDelegationStore::empty()),
            Arc::new(FakeAgentStore::empty()),
        );
        block_on(agents.save(&tenant, &agent)).unwrap();
        block_on(delegations.save(&tenant, &delegation)).unwrap();
        let ports = HoldActionPorts {
            approval_store: store.clone(),
            delegation_store: delegations.clone(),
            agent_store: agents,
            people: people_for(ann_account),
            ..HoldActionPorts::fakes()
        };
        Hold {
            use_case: HoldActionUseCase::new(POLICY, change(ports)),
            store,
            delegations,
            agent: *agent.id(),
            delegation,
            sink: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Ann's account and mailbox identify the delegation's human grantor.
    fn ann(account: UserId) -> Human {
        Human::new(
            HumanAccount::User(account),
            PersonKey::new("ann@corp.test").unwrap(),
        )
    }

    /// The account lookup resolves Ann's delegation to her mailbox identity.
    fn people_for(ann: UserId) -> PeoplePorts {
        PeoplePorts {
            user_store: Arc::new(FakeUserStore::with_user(ann, "ann@corp.test")),
            ..PeoplePorts::fakes()
        }
    }

    impl Hold {
        fn action(&self, method: HttpMethod, target: &str) -> GatedAction {
            GatedAction {
                agent_id: self.agent,
                delegation_id: *self.delegation.id(),
                method,
                target: target.to_owned(),
                declared: DeclaredAction::Undeclared,
            }
        }

        fn attempt(&self, method: HttpMethod, target: &str) -> Result<Held, AppError> {
            self.submit(self.action(method, target))
        }

        fn submit(&self, action: GatedAction) -> Result<Held, AppError> {
            block_on(self.use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                action,
            ))
        }

        fn stored(&self, approval_id: ApprovalId) -> ApprovalRequest<ResolvedTenant> {
            self.store
                .all()
                .into_iter()
                .find(|approval| approval.id() == &approval_id)
                .unwrap()
        }

        fn revoke(&self) {
            let mut row = delegation_row(self.agent, *self.delegation.delegator());
            row.id = *self.delegation.id();
            row.status = DelegationStatus::Revoked;
            let revoked = Delegation::reconstitute(row).unwrap();
            block_on(self.delegations.save(&test_ctx().tenant(), &revoked)).unwrap();
        }
    }

    fn newly_opened(held: Result<Held, AppError>) -> ApprovalId {
        match held.unwrap() {
            Held::AwaitingDecision {
                approval_id,
                opened: RequestOpened::Now,
            } => approval_id,
            other => panic!("expected a newly opened request, got {other:?}"),
        }
    }

    /// Bob's agent first tries a payment. A request is opened for a person
    /// to decide.
    #[test]
    fn the_first_attempt_opens_a_request() {
        let h = hold();

        let approval_id = newly_opened(h.attempt(HttpMethod::Post, "/payments"));

        assert_eq!(h.stored(approval_id).status(), ApprovalStatus::Pending);
    }

    /// Bob's agent tries a payment. The request it opens is on record,
    /// naming the request, so a person is prompted and the trail shows who
    /// asked. Trying again before anyone decides records nothing more.
    #[test]
    fn opening_a_request_is_recorded_once() {
        let h = hold();

        let approval_id = newly_opened(h.attempt(HttpMethod::Post, "/payments"));
        h.attempt(HttpMethod::Post, "/payments").unwrap();

        assert_eq!(
            h.sink.records.lock().unwrap().as_slice(),
            ["agents.approval_requested"]
        );
        let payload = h.sink.payload_of("agents.approval_requested");
        let Some(FieldValue::Reference(approval)) = payload.value("approval") else {
            panic!("the record names the request");
        };
        assert_eq!(approval.id(), approval_id.to_string());
    }

    /// The agent tries the payment again before anyone decided. It finds
    /// the same request, and no second one is opened.
    #[test]
    fn retrying_before_a_decision_finds_the_same_request() {
        let h = hold();
        let approval_id = newly_opened(h.attempt(HttpMethod::Post, "/payments"));

        let again = h.attempt(HttpMethod::Post, "/payments").unwrap();

        assert_eq!(
            again,
            Held::AwaitingDecision {
                approval_id,
                opened: RequestOpened::Before
            }
        );
        assert_eq!(h.store.count(), 1);
    }

    /// The agent opened the request, so it is recorded as its requester,
    /// with Bob, its owner, and Ann, its delegator, among those who may not
    /// approve it.
    #[test]
    fn the_agent_is_the_requester_and_its_people_are_named() {
        let h = hold();
        let approval_id = newly_opened(h.attempt(HttpMethod::Post, "/orders"));

        let approval = h.stored(approval_id);

        assert_eq!(
            approval.origin(),
            &ApprovalOrigin::Opened(Initiator::Agent(h.agent))
        );
        assert_eq!(
            approval.action_class(),
            DeclaredAction::Declared(ActionClass::Write)
        );
        assert_eq!(
            approval.parties().owner().person().as_str(),
            "bob@corp.test"
        );
        assert_eq!(approval.parties().delegators().len(), 1);
    }

    /// The person deciding sees the class the route declares, and a route
    /// declared financial needs a second person even at a plain path.
    #[test]
    fn the_request_carries_the_routes_declared_class() {
        let h = hold();
        let action = GatedAction {
            declared: DeclaredAction::Declared(ActionClass::Financial),
            ..h.action(HttpMethod::Post, "/orders")
        };

        let approval_id = newly_opened(h.submit(action));

        let approval = h.stored(approval_id);
        assert_eq!(
            approval.action_class(),
            DeclaredAction::Declared(ActionClass::Financial)
        );
        assert_eq!(approval.approvers_needed(), 2);
    }

    /// Distinct payments fill the delegation's request limit; another
    /// returns too-many-open without increasing the stored count.
    #[test]
    fn a_flood_of_distinct_actions_stops_opening_requests() {
        let h = hold();
        let max_open = POLICY.max_open_per_delegation;
        for n in 0..max_open {
            newly_opened(h.attempt(HttpMethod::Post, &format!("/payments/{n}")));
        }

        let one_more = h.attempt(HttpMethod::Post, "/payments/one-more").unwrap();

        assert_eq!(one_more, Held::TooManyOpen);
        assert_eq!(h.store.count(), usize::try_from(max_open).unwrap());
    }

    /// A revoked delegation refuses a payment hold without saving a request.
    #[test]
    fn nothing_is_held_on_a_revoked_delegation() {
        let h = hold();
        h.revoke();

        let attempt = h.attempt(HttpMethod::Post, "/payments");

        assert!(matches!(attempt, Err(AppError::Forbidden(_))));
        assert_eq!(h.store.count(), 0);
    }

    /// Holding under another agent's delegation reports it as missing and
    /// saves no request.
    #[test]
    fn a_delegation_of_another_agent_is_not_found() {
        let h = hold();
        let action = GatedAction {
            agent_id: AgentId::new(),
            ..h.action(HttpMethod::Post, "/payments")
        };

        let attempt = h.submit(action);

        assert!(matches!(attempt, Err(AppError::NotFound(_))));
        assert_eq!(h.store.count(), 0);
    }

    /// Holding under an unknown delegation reports it as missing and saves
    /// no request.
    #[test]
    fn an_unknown_delegation_is_not_found() {
        let h = hold();
        let action = GatedAction {
            delegation_id: DelegationId::new(),
            ..h.action(HttpMethod::Post, "/payments")
        };

        let attempt = h.submit(action);

        assert!(matches!(attempt, Err(AppError::NotFound(_))));
        assert_eq!(h.store.count(), 0);
    }

    /// Plan-limit rejection refuses a payment hold without saving a request
    /// or recording an approval event.
    #[test]
    fn hold_action_rejects_when_plan_limit_reached() {
        let h = hold_under(|ports| HoldActionPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports
        });

        let attempt = h.attempt(HttpMethod::Post, "/payments");

        assert!(matches!(attempt, Err(AppError::Forbidden(_))));
        assert_eq!(h.store.count(), 0);
        assert!(h.sink.records.lock().unwrap().is_empty());
    }
}
