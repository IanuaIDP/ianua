//! Authorize agent: a dry run of whether an agent may perform an action.
//!
//! A person asks what the proxy would decide for one of the agents they may
//! watch, without issuing a token or forwarding anything. It decides by the
//! gateway's own rule, `proxy::access::decide`, once for each live
//! delegation's token, as a real request presents exactly one: the route's
//! policy, what the token names and its delegator still holds, the task's
//! intent and resource scope, and the tenant's live policy.
//!
//! A dry run knows nothing of where a request would come from: no country,
//! device, risk or time of day. A tenant rule on one reads it as unknown, so
//! a refusing rule matches and an allowing rule does not. It assumes the
//! agent proves its key where its token is bound to one. Every path that
//! finds no answer denies: an agent that may not act now, a request no
//! active route takes, a policy no delegation can meet.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::proxy::access::holds_right;
use ianua_domain::domains::proxy::access::question::{
    Asked, Lookup, MethodClaim, OnBehalf, Records,
};
use ianua_domain::domains::routing::route::{Route, RouteRequest, resolve_route};
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, CanonicalPath, Fact, HttpMethod, PrincipalRef, ServiceId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::ports::authorization::{AccessRecordStore, PolicyStore};
use crate::ports::organization::MemberStandings;
use crate::ports::routing::{PolicyDecisionPoint, RouteStore, ServiceStore};
use crate::services::authorization::held::{RecordSources, held, records_of};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::agents::access::token::{Token, token_of};
use crate::use_cases::agents::access::verdict::{decisions_through, delegations_outcome};
use crate::use_cases::agents::evidence::watching::watched_agent;
use crate::use_cases::agents::lookup::live_delegations;

/// The most routes a dry run reads to find the one a request takes.
const ROUTE_TABLE_LIMIT: u32 = 100_000;

/// What a dry-run authorization check evaluates.
pub enum AuthorizeCheckTarget {
    /// A bare `domain:action` permission the agent's delegations must grant.
    Action(SystemPermission),
    /// A specific request. Resolved against the tenant's routes to find the
    /// route policy governing it, then evaluated the way the proxy would
    /// evaluate it for this agent's delegated authority.
    Request {
        /// The request's HTTP method.
        method: HttpMethod,
        /// The request's path, in its canonical spelling.
        path: CanonicalPath,
    },
}

/// Which agent to check, and against what.
pub struct AuthorizeAgentRequest {
    /// The agent whose delegated authority is checked.
    pub agent_id: AgentId,
    /// The permission or request to evaluate.
    pub target: AuthorizeCheckTarget,
}

/// Outcome of an agent authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAuthorizeOutcome {
    /// The agent may act.
    Allowed {
        /// Human-readable explanation of the decision.
        reason: String,
    },
    /// The agent may not act.
    Denied {
        /// Human-readable explanation of the decision.
        reason: String,
    },
}

impl AgentAuthorizeOutcome {
    pub(crate) fn allow(reason: impl Into<String>) -> Self {
        Self::Allowed {
            reason: reason.into(),
        }
    }

    pub(crate) fn deny(reason: impl Into<String>) -> Self {
        Self::Denied {
            reason: reason.into(),
        }
    }

    /// Whether the agent may act.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Why the check came out the way it did.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Allowed { reason } | Self::Denied { reason } => reason,
        }
    }
}

/// The ports [`AuthorizeAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AuthorizeAgentPorts {
    /// Loads current agent status before evaluating delegated access.
    pub agent_store: Arc<dyn AgentStore>,
    /// The agent's delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Which route, and so which policy, takes a request.
    pub route_store: Arc<dyn RouteStore>,
    /// Which services are serving, as the gateway skips the rest.
    pub service_store: Arc<dyn ServiceStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Whether the records know each delegator and let them act now.
    pub policy_decisions: Arc<dyn PolicyDecisionPoint>,
    /// What the agent and its delegators hold.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// A delegator who is an organization member, as the tenant reads them.
    pub member_standings: Arc<dyn MemberStandings>,
    /// The tenant's live access policy, which the gateway reads last.
    pub policy_store: Arc<dyn PolicyStore>,
}

/// Runs the dry-run authorization check for an agent.
pub struct AuthorizeAgentUseCase {
    ports: AuthorizeAgentPorts,
}

impl AuthorizeAgentUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: AuthorizeAgentPorts) -> Self {
        Self { ports }
    }

    /// The token the gateway would see for each of `active`, with what the
    /// records say of its delegator now.
    async fn tokens(
        &self,
        tenant: &ScopedTenant,
        agent_id: AgentId,
        active: &[Delegation<ResolvedTenant>],
    ) -> Vec<Token> {
        let mut tokens = Vec::with_capacity(active.len());
        for delegation in active {
            let on_behalf = self.on_behalf(tenant, agent_id, delegation).await;
            tokens.push(token_of(agent_id, delegation, on_behalf));
        }
        tokens
    }

    /// Whose authority `delegation` hands on: the agent's own when it
    /// delegated to itself, its delegator's as the records say otherwise.
    async fn on_behalf(
        &self,
        tenant: &ScopedTenant,
        agent_id: AgentId,
        delegation: &Delegation<ResolvedTenant>,
    ) -> OnBehalf {
        let delegator = *delegation.delegator();
        if delegator == PrincipalRef::Agent(agent_id) {
            return OnBehalf::Own;
        }
        let sources = RecordSources {
            decisions: self.ports.policy_decisions.as_ref(),
            access: self.ports.access_records.as_ref(),
            members: self.ports.member_standings.as_ref(),
        };
        OnBehalf::Of(records_of(sources, tenant, delegator).await)
    }

    /// What the records give the agent itself.
    async fn own_records(
        &self,
        tenant: &ScopedTenant,
        agent_id: AgentId,
    ) -> Result<Records, AppError> {
        let principal = PrincipalRef::Agent(agent_id);
        let own = held(self.ports.access_records.as_ref(), tenant, principal)
            .await
            .or_internal()?;
        Ok(Records::Holds(own))
    }

    /// The decision for `method path`: the route the gateway would pick,
    /// then whether one of `tokens` carries the request through it.
    async fn request_outcome(
        &self,
        tenant: &ScopedTenant,
        agent_id: AgentId,
        tokens: &[Token],
        asked: &Asked,
    ) -> Result<AgentAuthorizeOutcome, AppError> {
        let (Fact::Known(method), Fact::Known(path)) = (asked.method, &asked.path) else {
            return Ok(AgentAuthorizeOutcome::deny(
                "no route matches a request of no known method or path",
            ));
        };
        let routes = active_routes(self.ports.route_store.as_ref(), tenant).await?;
        let serving = serving_services(self.ports.service_store.as_ref(), tenant, &routes).await?;
        let request = RouteRequest {
            method,
            path,
            host: Fact::Unknown,
            values: Fact::Unknown,
        };
        let Some(route) = resolve_route(&routes, &request, |id| serving.contains(id)) else {
            return Ok(AgentAuthorizeOutcome::deny(format!(
                "no route matches {method:?} {}, so the request is denied",
                path.as_str(),
            )));
        };
        let own = self.own_records(tenant, agent_id).await?;
        let policy = live_policy(self.ports.policy_store.as_ref(), tenant).await?;
        let decisions = decisions_through(route, tokens, &own, asked, &policy);
        Ok(delegations_outcome(route, &decisions))
    }

    /// Whether one of `tokens` holds `permission`, by the gateway's route
    /// rule for a route asking for it alone.
    async fn permission_outcome(
        &self,
        tenant: &ScopedTenant,
        agent_id: AgentId,
        tokens: &[Token],
        permission: SystemPermission,
    ) -> Result<AgentAuthorizeOutcome, AppError> {
        let own = self.own_records(tenant, agent_id).await?;
        if tokens
            .iter()
            .any(|token| holds_right(token.asker(&own), permission))
        {
            return Ok(AgentAuthorizeOutcome::allow(
                "granted via an active delegation",
            ));
        }
        Ok(AgentAuthorizeOutcome::deny("capability not delegated"))
    }
}

impl Query for AuthorizeAgentUseCase {
    type Caller = CallerContext;
    type Input = AuthorizeAgentRequest;
    type Output = Result<AgentAuthorizeOutcome, AppError>;

    /// Whether the agent's live delegations grant a permission, or would
    /// carry a specific request through the gateway's decision.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: AuthorizeAgentRequest,
    ) -> Result<AgentAuthorizeOutcome, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let agent = watched_agent(
            self.ports.agent_store.as_ref(),
            &authority,
            &tenant,
            &request.agent_id,
        )
        .await?;
        if !agent.may_act_at(clock::now()) {
            return Ok(AgentAuthorizeOutcome::deny("agent may not act now"));
        }
        let agent_id = *agent.id();
        let active =
            live_delegations(self.ports.delegation_store.as_ref(), &tenant, &agent_id).await?;
        let tokens = self.tokens(&tenant, agent_id, &active).await;
        match request.target {
            AuthorizeCheckTarget::Action(permission) => {
                self.permission_outcome(&tenant, agent_id, &tokens, permission)
                    .await
            }
            AuthorizeCheckTarget::Request { method, path } => {
                let asked = asked_for(method, path);
                self.request_outcome(&tenant, agent_id, &tokens, &asked)
                    .await
            }
        }
    }
}

/// The tenant's active routes.
async fn active_routes(
    store: &dyn RouteStore,
    tenant: &ScopedTenant,
) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
    let routes = store
        .list_all(
            tenant,
            Some(RouteStatus::Active),
            &SortOrder::default(),
            &PageRequest::first(Limit::internal(ROUTE_TABLE_LIMIT)),
        )
        .await
        .or_internal()?
        .items;
    Ok(routes)
}

/// The services behind `routes` that are serving.
async fn serving_services(
    store: &dyn ServiceStore,
    tenant: &ScopedTenant,
    routes: &[Route<ResolvedTenant>],
) -> Result<Vec<ServiceId>, AppError> {
    let ids: Vec<ServiceId> = routes.iter().map(|route| *route.service_id()).collect();
    Ok(store
        .find_by_ids(tenant, &ids)
        .await
        .or_internal()?
        .iter()
        .filter(|service| service.is_active())
        .map(|service| *service.id())
        .collect())
}

/// The tenant's live policy, or that it has none.
async fn live_policy(
    store: &dyn PolicyStore,
    tenant: &ScopedTenant,
) -> Result<Lookup<PolicySet>, AppError> {
    let policy = store.find_active(tenant).await.or_internal()?;
    Ok(policy.map_or(Lookup::Missing, Lookup::Found))
}

/// The request `method path`, sent as it is meant.
fn asked_for(method: HttpMethod, path: CanonicalPath) -> Asked {
    Asked {
        method: Fact::Known(method),
        path: Fact::Known(path),
        method_claim: MethodClaim::AsSent,
        host: Fact::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, DelegationConstraints, ResourceScope,
    };
    use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
    use ianua_domain::domains::agents::authority::intent::{
        DriftPolicy, DriftThreshold, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{
        AgentAction, CustomPermission, RoutingAction,
    };
    use ianua_domain::domains::proxy::access::question::Standing;
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::types::{ActionClass, Scope, Seconds, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, StoredGrant, callers_agent, stored_delegation,
    };
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakePolicyStore, FakeRoleAssignmentStore,
        FakeRoleStore, stored_assignment, stored_role,
    };
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakePolicyDecisionPoint, FakeRouteStore, FakeServiceStore, RouteShape, pinned_upstream,
        route_of, service_named,
    };
    use crate::test_support::{block_on, test_ctx};

    const SUPPORT: &str = "/api/support";

    struct Fixture {
        agent_id: AgentId,
        delegator: UserId,
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        routes: Arc<FakeRouteStore>,
        services: Arc<FakeServiceStore>,
        records: Arc<FakeAccessRecordStore>,
    }

    fn routing_view() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    fn limits() -> DelegationConstraints {
        DelegationConstraints::new(Seconds::new(600), 1).unwrap()
    }

    /// Records in which `person` holds `rights` through a role.
    fn holding(person: UserId, rights: Vec<SystemPermission>) -> Arc<FakeAccessRecordStore> {
        let tenant = test_ctx().tenant_id();
        let role = stored_role("delegator", rights, Vec::new());
        let given = stored_assignment(PrincipalRef::User(person), *role.id());
        Arc::new(FakeAccessRecordStore::reading(AccessSources {
            roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, [given])),
            ..AccessSources::default()
        }))
    }

    /// The caller's agent, holding one delegation granting `routing:view`
    /// under `constraints`, from a person who holds every right.
    fn setup_with_constraints(constraints: DelegationConstraints) -> Fixture {
        let agent_id = AgentId::new();
        let delegator = UserId::new();
        let f = Fixture {
            agent_id,
            delegator,
            agents: Arc::new(callers_agent(agent_id)),
            delegations: Arc::new(FakeDelegationStore::empty()),
            routes: Arc::new(FakeRouteStore::empty()),
            services: Arc::new(FakeServiceStore::empty()),
            records: holding(delegator, SystemPermission::all().to_vec()),
        };
        f.delegate(constraints);
        f
    }

    fn setup() -> Fixture {
        setup_with_constraints(limits())
    }

    fn read_intent(classes: impl IntoIterator<Item = ActionClass>) -> IntentBinding {
        IntentBinding::new(
            IntentStatement::new("read only").unwrap(),
            IntentDigest::new([1u8; 32]),
            DriftPolicy::Enforce(DriftThreshold::from_basis_points(5000).unwrap()),
            IntentEnvelope::new(classes),
        )
    }

    impl Fixture {
        fn delegate(&self, constraints: DelegationConstraints) {
            let delegation = stored_delegation(StoredGrant {
                delegator: PrincipalRef::User(self.delegator),
                delegate: self.agent_id,
                granted: routing_view(),
                constraints,
                lineage: Lineage::Root,
                status: DelegationStatus::Active,
            });
            block_on(self.delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
        }

        fn route(&self, policy: RoutePolicy) {
            let service = service_named("support", pinned_upstream("https://backend:8080", "api"));
            block_on(self.services.save(&test_ctx().tenant(), &service)).unwrap();
            let route = route_of(
                RouteShape {
                    name: "support",
                    path: SUPPORT,
                    policy,
                    hosts: RouteHosts::Any,
                },
                &service,
                &test_pipeline(),
            );
            block_on(self.routes.save(&test_ctx().tenant(), &route)).unwrap();
        }

        fn check_in(
            &self,
            authorities: FakeTenantAuthorities,
            standing: Standing,
            target: AuthorizeCheckTarget,
        ) -> Result<AgentAuthorizeOutcome, AppError> {
            let use_case = AuthorizeAgentUseCase::new(AuthorizeAgentPorts {
                agent_store: self.agents.clone(),
                delegation_store: self.delegations.clone(),
                route_store: self.routes.clone(),
                service_store: self.services.clone(),
                tenant_authorities: Arc::new(authorities),
                policy_decisions: Arc::new(FakePolicyDecisionPoint::in_standing(standing)),
                access_records: self.records.clone(),
                member_standings: crate::test_support::Fake::fake(),
                policy_store: Arc::new(FakePolicyStore::empty()),
            });
            block_on(use_case.execute(
                &test_ctx(),
                AuthorizeAgentRequest {
                    agent_id: self.agent_id,
                    target,
                },
            ))
        }

        fn check_with(
            &self,
            authorities: FakeTenantAuthorities,
            target: AuthorizeCheckTarget,
        ) -> Result<AgentAuthorizeOutcome, AppError> {
            self.check_in(authorities, Standing::Good, target)
        }

        fn check(&self, target: AuthorizeCheckTarget) -> AgentAuthorizeOutcome {
            self.check_with(FakeTenantAuthorities::holding(&[]), target)
                .unwrap()
        }

        fn post_support(&self) -> AgentAuthorizeOutcome {
            self.check(post_to_support())
        }
    }

    fn post_to_support() -> AuthorizeCheckTarget {
        AuthorizeCheckTarget::Request {
            method: HttpMethod::Post,
            path: CanonicalPath::new(SUPPORT).unwrap(),
        }
    }

    fn requiring(action: RoutingAction) -> RoutePolicy {
        RoutePolicy::RequireSystemPermission(vec![SystemPermission::Routing(action)])
    }

    /// Ann asks whether her agent may view routes. One of its delegations
    /// grants that, so it may.
    #[test]
    fn a_delegated_permission_is_allowed() {
        let f = setup();

        let outcome = f.check(AuthorizeCheckTarget::Action(SystemPermission::Routing(
            RoutingAction::View,
        )));

        assert!(outcome.is_allowed());
    }

    /// A delegation granting route viewing cannot authorize route management.
    #[test]
    fn an_undelegated_permission_is_denied() {
        let f = setup();

        let outcome = f.check(AuthorizeCheckTarget::Action(SystemPermission::Routing(
            RoutingAction::Manage,
        )));

        assert!(!outcome.is_allowed());
    }

    /// A delegator without route-view permission cannot authorize it for the
    /// agent, either as a permission check or a routed request.
    #[test]
    fn what_the_delegator_lost_is_denied() {
        let f = setup();
        let f = Fixture {
            records: holding(f.delegator, Vec::new()),
            ..f
        };
        f.route(requiring(RoutingAction::View));

        let permission = f.check(AuthorizeCheckTarget::Action(SystemPermission::Routing(
            RoutingAction::View,
        )));

        assert!(!permission.is_allowed());
        assert!(!f.post_support().is_allowed());
    }

    /// A barred delegator causes the agent's request to be denied with the
    /// delegator's standing identified as the reason.
    #[test]
    fn a_barred_delegator_denies_the_request() {
        let f = setup();
        f.route(requiring(RoutingAction::View));

        let outcome = f
            .check_in(
                FakeTenantAuthorities::holding(&[]),
                Standing::Barred,
                post_to_support(),
            )
            .unwrap();

        assert!(!outcome.is_allowed());
        assert!(
            outcome.reason().contains("delegator_barred"),
            "{}",
            outcome.reason()
        );
    }

    /// The support route asks for `routing:view`, which the agent's
    /// delegation grants. The request goes through.
    #[test]
    fn a_request_whose_routes_permission_is_delegated_is_allowed() {
        let f = setup();
        f.route(requiring(RoutingAction::View));

        assert!(f.post_support().is_allowed());
    }

    /// A request is denied when its route requires an undelegated permission.
    #[test]
    fn a_request_whose_routes_permission_is_not_delegated_is_denied() {
        let f = setup();
        f.route(requiring(RoutingAction::Manage));

        assert!(!f.post_support().is_allowed());
    }

    /// A public route lets the request through whatever the agent holds.
    #[test]
    fn a_public_route_is_allowed() {
        let f = setup();
        f.route(RoutePolicy::Public);

        assert!(f.post_support().is_allowed());
    }

    /// A write request under a read-only delegation is denied because of its
    /// bound intent.
    #[test]
    fn a_delegation_whose_intent_excludes_the_action_is_denied() {
        let f = setup_with_constraints(limits().with_intent(read_intent([ActionClass::Read])));
        f.route(requiring(RoutingAction::View));

        let outcome = f.post_support();

        assert!(!outcome.is_allowed());
        assert!(
            outcome.reason().contains("bound intent"),
            "{}",
            outcome.reason()
        );
    }

    /// The delegation's intent covers writes, so the write goes through.
    #[test]
    fn a_delegation_whose_intent_covers_the_action_is_allowed() {
        let f = setup_with_constraints(limits().with_intent(read_intent([ActionClass::Write])));
        f.route(requiring(RoutingAction::View));

        assert!(f.post_support().is_allowed());
    }

    /// A request outside the delegated paths is denied for its resource scope.
    #[test]
    fn a_delegation_whose_resource_scope_excludes_the_path_is_denied() {
        let scope = ResourceScope::new(["/api/other".to_owned()]).unwrap();
        let f = setup_with_constraints(limits().with_resource_scope(scope));
        f.route(requiring(RoutingAction::View));

        let outcome = f.post_support();

        assert!(!outcome.is_allowed());
        assert!(
            outcome.reason().contains("resource scope"),
            "{}",
            outcome.reason()
        );
    }

    /// One delegation is bound to a read-only intent, another is not. The
    /// write goes through on the second, as a real request would carry its
    /// token.
    #[test]
    fn a_second_unbound_delegation_carries_what_the_first_may_not() {
        let f = setup_with_constraints(limits().with_intent(read_intent([ActionClass::Read])));
        f.delegate(limits());
        f.route(requiring(RoutingAction::View));

        assert!(f.post_support().is_allowed());
    }

    /// A route that asks only who is calling is met by any live delegation.
    #[test]
    fn an_authenticated_route_is_met_by_any_delegation() {
        let f = setup();
        f.route(RoutePolicy::Authenticated);

        assert!(f.post_support().is_allowed());
    }

    /// An authenticated route still denies a write outside the only
    /// delegation's read-only intent.
    #[test]
    fn an_authenticated_route_outside_the_only_intent_is_denied() {
        let f = setup_with_constraints(limits().with_intent(read_intent([ActionClass::Read])));
        f.route(RoutePolicy::Authenticated);

        assert!(!f.post_support().is_allowed());
    }

    /// A route requiring an undelegated custom permission is denied with that
    /// requirement identified in the reason.
    #[test]
    fn a_route_requiring_a_custom_permission_is_denied() {
        let f = setup();
        f.route(RoutePolicy::RequireCustomPermission(vec![
            CustomPermission::new("support", "reply").unwrap(),
        ]));

        let outcome = f.post_support();

        assert!(!outcome.is_allowed());
        assert!(outcome.reason().contains("custom permission"));
    }

    /// A route requiring an undelegated OAuth scope is denied with the scope
    /// requirement identified in the reason.
    #[test]
    fn a_route_requiring_a_scope_is_denied() {
        let f = setup();
        f.route(RoutePolicy::RequireScope(vec![
            Scope::new("support:write").unwrap(),
        ]));

        let outcome = f.post_support();

        assert!(!outcome.is_allowed());
        assert!(outcome.reason().contains("scope"));
    }

    /// An unmatched request is denied with the missing route identified.
    #[test]
    fn a_request_no_route_takes_is_denied() {
        let f = setup();

        let outcome = f.post_support();

        assert!(!outcome.is_allowed());
        assert!(outcome.reason().contains("no route matches"));
    }

    /// A suspended agent is denied on a public route because it cannot act.
    #[test]
    fn a_suspended_agent_is_denied_even_on_a_public_route() {
        let f = setup();
        f.agents.add_with_status(f.agent_id, AgentStatus::Suspended);
        f.route(RoutePolicy::Public);

        let outcome = f
            .check_with(
                FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
                post_to_support(),
            )
            .unwrap();

        assert!(!outcome.is_allowed());
        assert_eq!(outcome.reason(), "agent may not act now");
    }

    /// A caller without agent-view permission sees another owner's agent as
    /// missing when checking its authority.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let f = setup();
        let f = Fixture {
            agents: Arc::new(FakeAgentStore::with_active(f.agent_id)),
            ..f
        };

        let result = f.check_with(
            FakeTenantAuthorities::holding(&[]),
            AuthorizeCheckTarget::Action(SystemPermission::Routing(RoutingAction::View)),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Checking an unknown agent's authority reports it as missing.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let f = setup();
        let f = Fixture {
            agent_id: AgentId::new(),
            ..f
        };

        let result = f.check_with(
            FakeTenantAuthorities::holding_everything(),
            AuthorizeCheckTarget::Action(SystemPermission::Routing(RoutingAction::View)),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A revoked delegation cannot authorize the route-view permission it names.
    #[test]
    fn a_revoked_delegation_grants_nothing() {
        let agent_id = AgentId::new();
        let delegator = UserId::new();
        let f = Fixture {
            agent_id,
            delegator,
            agents: Arc::new(callers_agent(agent_id)),
            delegations: Arc::new(FakeDelegationStore::empty()),
            routes: Arc::new(FakeRouteStore::empty()),
            services: Arc::new(FakeServiceStore::empty()),
            records: holding(delegator, SystemPermission::all().to_vec()),
        };
        let revoked = stored_delegation(StoredGrant {
            delegator: PrincipalRef::User(delegator),
            delegate: agent_id,
            granted: routing_view(),
            constraints: limits(),
            lineage: Lineage::Root,
            status: DelegationStatus::Revoked,
        });
        block_on(f.delegations.save(&test_ctx().tenant(), &revoked)).unwrap();

        let outcome = f.check(AuthorizeCheckTarget::Action(SystemPermission::Routing(
            RoutingAction::View,
        )));

        assert!(!outcome.is_allowed());
    }

    /// A signed-out caller cannot check an agent's authority.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = setup();

        let result = f.check_with(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            AuthorizeCheckTarget::Action(SystemPermission::Routing(RoutingAction::View)),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
