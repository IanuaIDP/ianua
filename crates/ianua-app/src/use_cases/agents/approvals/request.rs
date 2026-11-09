//! Request approval: open, by hand, a person's decision on an agent call.
//!
//! A pending [`ApprovalRequest`] is recorded against a delegation of the
//! agent and an `AgentApprovalRequested` event is dispatched, which the
//! notification fanout turns into a prompt. Opening one takes the right to
//! update the agent, or owning it; deciding it takes another person.
//! Requests the gateway opens for a delegation that flags
//! `requires_approval` go through
//! [`gate_action_approval`](crate::use_cases::agents::approvals::gate_action)
//! instead.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::{ActingUnder, Delegation};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{
    ActionParties, ApprovalAction, ApprovalOrigin, ApprovalRequest, RequestApprovalParams,
};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    ActionClass, AgentId, DeclaredAction, DelegationId, HttpMethod, Initiator, Seconds,
};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, ApprovalStore, DelegationStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::ApprovalLimits;
use crate::use_cases::agents::approvals::action_authority::loaded_from;
use crate::use_cases::agents::approvals::parties::{PeoplePorts, parties_behind};
use crate::use_cases::agents::lookup::{AgentReach, owned_agent, owned_delegation};

/// Request to open a person's approval for an agent's call.
pub struct RequestRequest {
    /// The agent whose call waits.
    pub agent_id: AgentId,
    /// The delegation supplying the authority the call uses.
    pub delegation_id: DelegationId,
    /// The method of the call.
    pub method: HttpMethod,
    /// The path of the call, with its query.
    pub target: String,
    /// How long a person has to decide, in seconds.
    pub ttl_seconds: Seconds,
}

impl RequestRequest {
    /// The exact call a person approves. The call itself is named, never a
    /// free-text summary of it, so the request's class is read from what the
    /// call does rather than from what the requester says it does.
    fn action(&self) -> Result<ApprovalAction, AppError> {
        if self.method == HttpMethod::Any {
            return Err(AppError::from_domain(DomainError::invalid(message!(
                "agents-method-must-name-one-http-method",
                "method must name one HTTP method, not '*'"
            ))));
        }
        ApprovalAction::for_call(self.method, &self.target).map_err(AppError::from_domain)
    }

    fn action_class(&self) -> DeclaredAction {
        DeclaredAction::Declared(ActionClass::for_call(
            self.method,
            &self.target,
            DeclaredAction::Undeclared,
        ))
    }
}

/// The ports [`RequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestPorts {
    /// Enforces the tenant's plan limit on open requests.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// The agent the request is for.
    pub agent_store: Arc<dyn AgentStore>,
    /// The delegation the call uses, and the chain above it.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Saves approval requests.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// The people behind the delegation, who may not approve.
    pub people: PeoplePorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Opens an approval request by hand.
pub struct RequestUseCase {
    limits: ApprovalLimits,
    ports: RequestPorts,
}

impl RequestUseCase {
    /// A use case working through `ports`, opening requests under `limits`.
    #[must_use]
    pub fn new(limits: ApprovalLimits, ports: RequestPorts) -> Self {
        Self { limits, ports }
    }
}

impl Command for RequestUseCase {
    type Caller = CallerContext;
    type Input = RequestRequest;
    type Output = Result<ApprovalRequest<ResolvedTenant>, AppError>;

    /// Opens a pending approval for the person `ctx` names, who is recorded
    /// as its requester and so may not decide it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` at the plan's limit.
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the agent or delegation is unknown, the
    ///   delegation was granted to another agent, or the caller neither owns
    ///   the agent nor may update agents, so that an agent of someone else's
    ///   answers as one that does not exist.
    /// - `AppError::Domain` when the call or the decision window is invalid,
    ///   or a person behind the delegation can no longer be read.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: RequestRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        ensure_room_for_another(&self.ports, ctx).await?;
        ensure_window_allowed(self.limits, req.ttl_seconds)?;
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let agents = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let agent = owned_agent(agents, &tenant, &req.agent_id, &control, reach).await?;
        let delegation = owned_delegation(
            self.ports.delegation_store.as_ref(),
            &tenant,
            &req.agent_id,
            &req.delegation_id,
        )
        .await?;
        let parties = parties_of(&self.ports, &tenant, &agent, delegation.clone()).await?;
        let mut approval = hand_opened(&authority, &req, parties, &delegation)?;
        self.ports
            .approval_store
            .save(&tenant, &approval)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), approval.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(approval)
    }
}

/// Refuses another open request once the tenant's plan allows no more.
async fn ensure_room_for_another(
    ports: &RequestPorts,
    ctx: &CallerContext,
) -> Result<(), AppError> {
    ports
        .limit_enforcer
        .check_tenant_limit(
            ctx.plan_limits(),
            &ctx.tenant(),
            ResourceKind::PendingApprovals,
        )
        .await
        .map_err(AppError::from_domain)
}

/// Refuses a decision window longer than the longest allowed.
fn ensure_window_allowed(limits: ApprovalLimits, ttl: Seconds) -> Result<(), AppError> {
    if ttl.duration() <= limits.max_ttl {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::invalid(message!(
        "agents-an-approval-stays-open-at-most",
        format!(
            "an approval stays open at most {} seconds",
            limits.max_ttl.whole_seconds()
        )
    ))))
}

/// The people answerable for a call of `agent` on `delegation`.
async fn parties_of(
    ports: &RequestPorts,
    tenant: &ScopedTenant,
    agent: &AgentIdentity<ResolvedTenant>,
    delegation: Delegation<ResolvedTenant>,
) -> Result<ActionParties, AppError> {
    let loaded = loaded_from(ports.delegation_store.as_ref(), tenant, delegation).await?;
    parties_behind(&ports.people, tenant, agent, &loaded).await
}

/// A pending request `authority`'s person opened by hand for `req`'s call
/// under `delegation`, announced to the people who may decide it. There is
/// no run behind it.
fn hand_opened(
    authority: &TenantAuthority,
    req: &RequestRequest,
    parties: ActionParties,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    let mut approval = ApprovalRequest::request(RequestApprovalParams {
        agent_id: req.agent_id,
        delegation_id: ActingUnder::Delegation(req.delegation_id),
        origin: ApprovalOrigin::Opened(Initiator::Human(authority.who().clone())),
        parties,
        action_class: req.action_class(),
        action: req.action()?,
        ttl_seconds: req.ttl_seconds,
    })
    .map_err(AppError::from_domain)?;
    approval
        .announce_request(delegation)
        .map_err(AppError::from_domain)?;
    Ok(approval)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeApprovalStore, FakeDelegationStore, agent_owned_by, approval_limits,
        caller_person, delegation_row, someone,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, reference_label, test_auditor,
        test_ctx,
    };

    /// The caller's agent, and Ann's delegation to it.
    struct Fixture {
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        users: Arc<FakeUserStore>,
        agent_id: AgentId,
        delegation_id: DelegationId,
    }

    fn fixture() -> Fixture {
        fixture_owned_by(caller_person())
    }

    fn fixture_owned_by(owner: Human) -> Fixture {
        let tenant = test_ctx().tenant();
        let ann_account = UserId::new();
        let ann = Human::new(
            HumanAccount::User(ann_account),
            PersonKey::new("ann@corp.test").unwrap(),
        );
        let agent = agent_owned_by(AgentId::new(), owner);
        let delegation =
            Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
        let (agents, delegations) = (
            Arc::new(FakeAgentStore::empty()),
            Arc::new(FakeDelegationStore::empty()),
        );
        block_on(agents.save(&tenant, &agent)).unwrap();
        block_on(delegations.save(&tenant, &delegation)).unwrap();
        Fixture {
            agents,
            delegations,
            users: Arc::new(FakeUserStore::with_user(ann_account, "ann@corp.test")),
            agent_id: *agent.id(),
            delegation_id: *delegation.id(),
        }
    }

    impl Fixture {
        fn req(&self, ttl_seconds: u32) -> RequestRequest {
            RequestRequest {
                agent_id: self.agent_id,
                delegation_id: self.delegation_id,
                method: HttpMethod::Post,
                target: "/vendors/7/transfers".to_owned(),
                ttl_seconds: Seconds::new(ttl_seconds),
            }
        }

        fn ports(&self, approval_store: &Arc<FakeApprovalStore>) -> RequestPorts {
            RequestPorts {
                agent_store: self.agents.clone(),
                delegation_store: self.delegations.clone(),
                approval_store: approval_store.clone(),
                people: PeoplePorts {
                    user_store: self.users.clone(),
                    ..PeoplePorts::fakes()
                },
                ..RequestPorts::fakes()
            }
        }
    }

    fn open(
        ports: RequestPorts,
        sink: &Arc<FakeEventDispatcher>,
        req: RequestRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        let use_case = RequestUseCase::new(approval_limits(), ports);
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    fn quietly(
        ports: RequestPorts,
        req: RequestRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        open(ports, &Arc::new(FakeEventDispatcher::new()), req)
    }

    /// The caller asks a person to approve their agent's transfer. A
    /// pending request is saved and announced.
    #[test]
    fn a_pending_request_is_opened_and_announced() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let sink = Arc::new(FakeEventDispatcher::new());

        let approval = open(f.ports(&store), &sink, f.req(900)).unwrap();

        assert!(approval.is_pending());
        assert_eq!(store.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.approval_requested"]
        );
    }

    /// The announcement names the exact call, and the delegation by its id,
    /// since it has no name.
    #[test]
    fn the_announcement_names_the_call_and_the_delegation() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let sink = Arc::new(FakeEventDispatcher::new());

        open(f.ports(&store), &sink, f.req(900)).unwrap();

        let payloads = sink.all_payloads();
        let delegation = f.delegation_id.to_string();
        assert_eq!(
            reference_label(&payloads[0], "approval"),
            Some("POST /vendors/7/transfers")
        );
        assert_eq!(
            reference_label(&payloads[0], "delegation"),
            Some(delegation.as_str())
        );
    }

    /// The caller opens the request, so they are its requester, and the
    /// owner and Ann, behind the delegation, are named as parties.
    #[test]
    fn the_caller_is_the_requester_and_the_people_behind_it_are_named() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();

        let approval = quietly(f.ports(&store), f.req(900)).unwrap();

        assert_eq!(
            approval.origin(),
            &ApprovalOrigin::Opened(Initiator::Human(caller_person()))
        );
        let delegators = approval.parties().delegators();
        assert_eq!(delegators.len(), 1);
        assert_eq!(delegators[0].person().as_str(), "ann@corp.test");
    }

    /// A request is classed by the call it names, its query aside.
    #[test]
    fn a_request_is_classed_by_the_call_it_names() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let req = RequestRequest {
            method: HttpMethod::Delete,
            target: "/orders/1?dry_run=true".to_owned(),
            ..f.req(900)
        };

        let approval = quietly(f.ports(&store), req).unwrap();

        assert_eq!(
            approval.action_class(),
            DeclaredAction::Declared(ActionClass::Delete)
        );
    }

    /// A window of no time at all is refused, and nothing is saved.
    #[test]
    fn a_zero_window_is_refused() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();

        let result = quietly(f.ports(&store), f.req(0));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A window longer than a day is refused, and nothing is saved.
    #[test]
    fn a_window_longer_than_a_day_is_refused() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();

        let result = quietly(f.ports(&store), f.req(24 * 60 * 60 + 1));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A free-text summary in place of a path is refused.
    #[test]
    fn a_request_naming_no_path_is_refused() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let req = RequestRequest {
            target: "transfer $5000 to vendor".to_owned(),
            ..f.req(900)
        };

        let result = quietly(f.ports(&store), req);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A request for any method at all is refused: it names no one call.
    #[test]
    fn a_request_for_any_method_is_refused() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let req = RequestRequest {
            method: HttpMethod::Any,
            ..f.req(900)
        };

        let result = quietly(f.ports(&store), req);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A request for an agent the tenant does not have is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let req = RequestRequest {
            agent_id: AgentId::new(),
            ..f.req(900)
        };

        let result = quietly(f.ports(&store), req);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(store.count(), 0);
    }

    /// A request naming a delegation that does not exist is not found.
    #[test]
    fn an_unknown_delegation_is_not_found() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let req = RequestRequest {
            delegation_id: DelegationId::new(),
            ..f.req(900)
        };

        let result = quietly(f.ports(&store), req);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(store.count(), 0);
    }

    /// Pairing an agent with another agent's delegation reports the
    /// delegation as missing and saves no approval request.
    #[test]
    fn another_agents_delegation_is_not_found() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let other = fixture();
        let foreign = block_on(
            other
                .delegations
                .find_by_id(&test_ctx().tenant(), &other.delegation_id),
        )
        .unwrap()
        .unwrap();
        block_on(f.delegations.save(&test_ctx().tenant(), &foreign)).unwrap();
        let req = RequestRequest {
            delegation_id: other.delegation_id,
            ..f.req(900)
        };

        let result = quietly(f.ports(&store), req);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(store.count(), 0);
    }

    /// A viewer who neither owns the agent nor may update it sees it as
    /// missing when opening an approval, and no request is saved.
    #[test]
    fn a_caller_with_no_say_over_the_agent_is_refused() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture_owned_by(someone("owner@corp.test"));
        let ports = RequestPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..f.ports(&store)
        };

        let result = quietly(ports, f.req(900));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out caller cannot open an approval request; none is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let ports = RequestPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..f.ports(&store)
        };

        let result = quietly(ports, f.req(900));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// The tenant's plan allows no more open requests. The request is
    /// refused and nothing is saved.
    #[test]
    fn request_approval_rejects_when_plan_limit_reached() {
        let store = Arc::new(FakeApprovalStore::empty());
        let f = fixture();
        let ports = RequestPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..f.ports(&store)
        };

        let result = quietly(ports, f.req(900));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }
}
