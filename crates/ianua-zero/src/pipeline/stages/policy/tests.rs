use async_trait::async_trait;
use http::Request;
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::PolicyStore;
use ianua_app::ports::routing::RouteStore;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::test_support::agents::{FakeApprovalBroker, FakeExposureGate};
use ianua_app::test_support::authorization::{FakePolicyStore, policy_in};
use ianua_app::test_support::data_classification::FakeClassificationStore;
use ianua_app::test_support::proxy::test_pipeline;
use ianua_app::test_support::routing::{
    FakeRouteStore, RouteShape, pinned_upstream, route_of, service_named,
};
use ianua_app::test_support::{
    FailingEventDispatcher, FakeEventDispatcher, test_auditor, test_ctx,
};
use ianua_app::use_cases::agents::approvals::{GateActionPorts, GateActionUseCase};
use ianua_app::use_cases::agents::enforcement::AdmitActionPorts;
use ianua_app::use_cases::proxy::DecideAccessPorts;
use ianua_app::use_cases::proxy::credentials::{Identification, Proven};
use ianua_domain::domains::agents::authority::capability::{ActionApproval, McpGrant};
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authorization::held::Held;
use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::condition::PolicyCondition;
use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::status::PolicyStatus;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::access::question::{DpopBinding, PostureFinding};
use ianua_domain::domains::proxy::observation::DecidingRule;
use ianua_domain::domains::proxy::request::context::{
    AgentLimits, Authorization, Caller, CallerClaims, KeyBinding, Metering, UserSignIn, Verified,
};
use ianua_domain::domains::proxy::stages::decision::ChallengeType;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    AgentId, CorrelationId, DelegationId, DenialStatus, Expiry, Label, PathPrefix, PermissionName,
    PipelineId, PrincipalRef, Text, UserId,
};

use super::*;

const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

/// A route on `/app` holding callers to `policy`.
fn route(policy: RoutePolicy) -> Arc<Route<ResolvedTenant>> {
    let service = service_named("app", pinned_upstream("https://backend:8080", "app"));
    Arc::new(route_of(
        RouteShape {
            policy,
            ..RouteShape::public("app", "/app")
        },
        &service,
        &test_pipeline(),
    ))
}

/// What the stages read from: the tenant's stores, the API the approval
/// gate asks, and where actions are recorded.
struct Fixture {
    routes: Arc<FakeRouteStore>,
    policies: Arc<dyn PolicyStore>,
    broker: Arc<FakeApprovalBroker>,
    sink: Arc<dyn EventDispatcher>,
    recorded: Arc<FakeEventDispatcher>,
}

impl Fixture {
    /// Acme with `route` stored, no live policy, an API answering every
    /// approval question, and actions recorded.
    async fn with(route: &Route<ResolvedTenant>) -> Self {
        let routes = Arc::new(FakeRouteStore::empty());
        routes.save(&test_ctx().tenant(), route).await.unwrap();
        let recorded = Arc::new(FakeEventDispatcher::new());
        Self {
            routes,
            policies: Arc::new(FakePolicyStore::empty()),
            broker: Arc::new(FakeApprovalBroker::answering()),
            sink: recorded.clone(),
            recorded,
        }
    }

    fn stages(&self) -> PolicyStages {
        let decide_access = DecideAccessUseCase::new(DecideAccessPorts {
            route_store: self.routes.clone(),
            policy_store: self.policies.clone(),
            ..DecideAccessPorts::fakes()
        });
        let gate = GateActionUseCase::new(GateActionPorts {
            broker: self.broker.clone(),
        });
        let admit_action = AdmitActionUseCase::new(
            AdmitActionPorts {
                exposure: Arc::new(FakeExposureGate::default()),
            },
            Arc::new(gate),
        );
        PolicyStages::new(PolicyStagesParts {
            decide_access: Arc::new(decide_access),
            admit_action: Arc::new(admit_action),
            classifications: Arc::new(FakeClassificationStore::empty()),
            events: Arc::new(ianua_app::test_support::FakeEventDispatcher::new()),
            call_timeout: Duration::from_secs(1),
        })
    }

    fn auditor(&self) -> RequestAuditor {
        test_auditor(self.sink.clone())
    }

    /// A `GET` to `/app` on `route`, its actions recorded here.
    fn get_app(&self, route: &Arc<Route<ResolvedTenant>>) -> RequestFacts {
        let request = Request::get("/app").header("host", "shop.acme.com");
        let mut facts = RequestFacts::sent(request.body(()).unwrap());
        facts.auditor = self.auditor();
        facts.route = Arc::clone(route);
        facts
    }

    fn recorded(&self, event: &str) -> bool {
        self.recorded
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|kind| kind == event)
    }
}

/// A request on its way through the pipeline: its context, with the
/// caller the Identity stage wrote, and the proof it handed over.
struct Arrival {
    ctx: PipelineContext,
    identification: Identification,
}

impl Arrival {
    fn anonymous() -> Self {
        Self {
            ctx: context(),
            identification: Identification::Anonymous,
        }
    }

    fn proven(caller: Caller, held: Held, claims: CallerClaims) -> Self {
        let verified = Verified {
            caller,
            expiry: Expiry::Never,
        };
        let mut ctx = context();
        ctx.authenticate(verified.clone()).unwrap();
        Self {
            ctx,
            identification: Identification::Proven(Box::new(Proven {
                verified,
                claims,
                held,
                established_at: clock::now(),
                binding: DpopBinding::Unbound,
            })),
        }
    }
}

fn context() -> PipelineContext {
    PipelineContext::new(
        test_ctx().tenant_id(),
        PipelineId::new(),
        CorrelationId::new(),
    )
}

fn person(system: &[SystemPermission]) -> Arrival {
    let ann = Caller::User {
        user_id: UserId::new(),
        sign_in: UserSignIn::Token,
    };
    Arrival::proven(
        ann,
        Held::assumed(system, &[], &[], &[]),
        CallerClaims::default(),
    )
}

/// An agent acting for itself under a task capped at `max_data_class`,
/// whose delegation asks a person to approve `approval`, and whose token
/// names one app permission no route here asks for: a token naming
/// nothing reaches no route.
fn agent(max_data_class: Restriction<DataClassLevel>, approval: ActionApproval) -> Arrival {
    let agent_id = AgentId::new();
    let helper = Caller::Agent {
        agent_id,
        delegation_id: DelegationId::new(),
        acting_for: PrincipalRef::Agent(agent_id),
        limits: Box::new(AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class,
            key_binding: KeyBinding::Bearer,
            approval,
            metering: Metering::Unmetered,
        }),
    };
    let token = CallerClaims {
        permissions: vec![PermissionName::new("reports:read").unwrap()],
        ..CallerClaims::default()
    };
    Arrival::proven(helper, Held::default(), token)
}

fn an_agent() -> Arrival {
    agent(Restriction::Unrestricted, ActionApproval::NotRequired)
}

/// Runs the Policy stage for `arrival` on `route`.
async fn run(
    f: &Fixture,
    route: &Arc<Route<ResolvedTenant>>,
    arrival: Arrival,
) -> (StageDecision, PipelineContext) {
    let Arrival {
        mut ctx,
        identification,
    } = arrival;
    let facts = f.get_app(route);
    let earlier = EarlierFindings {
        identification,
        posture: PostureFinding::NotAsked,
    };
    let decision = f.stages().policy(&mut ctx, &facts, earlier).await.unwrap();
    (decision, ctx)
}

fn denial(decision: &StageDecision) -> (DenialStatus, &str) {
    let StageDecision::Deny { status, reason } = decision else {
        panic!("expected a denial, got {decision:?}");
    };
    (*status, reason.as_str())
}

/// Ann's role lets her view users, and the route asks for that. She passes
/// and the request is marked authorized.
#[tokio::test]
async fn passes_permitted_requests_with_authorization() {
    let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
    let f = Fixture::with(&route).await;

    let (decision, ctx) = run(&f, &route, person(&[VIEW_USERS])).await;

    assert!(matches!(decision, StageDecision::Pass { .. }));
    assert_eq!(ctx.authorization(), Authorization::Granted);
}

/// An anonymous caller receives 401 on an authenticated route and remains unauthorized.
#[tokio::test]
async fn a_missing_token_is_refused() {
    let route = route(RoutePolicy::Authenticated);
    let f = Fixture::with(&route).await;

    let (decision, ctx) = run(&f, &route, Arrival::anonymous()).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::UNAUTHORIZED, "sign_in_required")
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// A caller missing the route's permission receives 403 with the permission
/// reason and remains unauthorized.
#[tokio::test]
async fn callers_without_permission_are_refused() {
    let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
    let f = Fixture::with(&route).await;

    let (decision, ctx) = run(&f, &route, person(&[])).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::FORBIDDEN, "permission_missing")
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// A public route absent from storage receives 403 with the unknown-route reason.
#[tokio::test]
async fn refuses_deleted_routes() {
    let stored = route(RoutePolicy::Public);
    let f = Fixture::with(&stored).await;
    let gone = route(RoutePolicy::Public);

    let (decision, _) = run(&f, &gone, Arrival::anonymous()).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::FORBIDDEN, "route_unknown")
    );
}

/// Acme's policy asks for AAL2 under `/app`, and Ann's sign-in carries no
/// level. She is challenged to step up, not let through.
#[tokio::test]
async fn stronger_assurance_requirements_challenge_callers() {
    let route = route(RoutePolicy::Authenticated);
    let mut f = Fixture::with(&route).await;
    let mfa = PolicyRule::new(
        Label::new("rule_name", "mfa").unwrap(),
        vec![PolicyCondition::PathPrefix(
            PathPrefix::new("/app").unwrap(),
        )],
        PolicyAction::RequireAal(AssuranceLevel::Aal2),
        10,
    )
    .unwrap();
    f.policies = Arc::new(FakePolicyStore::holding(
        test_ctx().tenant_id(),
        policy_in(PolicyStatus::Active, vec![mfa]),
    ));

    let (decision, ctx) = run(&f, &route, person(&[])).await;

    assert!(matches!(
        decision,
        StageDecision::Challenge {
            challenge_type: ChallengeType::Mfa,
            ..
        }
    ));
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// Acme's policy refuses everyone under `/app` by its rule "closed". Ann is
/// refused; the context names the rule and the version that ruled, so her
/// request's record says which rule of which policy refused her.
#[tokio::test]
async fn refusals_identify_the_rule_and_version() {
    let route = route(RoutePolicy::Authenticated);
    let mut f = Fixture::with(&route).await;
    let closed = Label::new("rule_name", "closed").unwrap();
    let rule = PolicyRule::new(
        closed.clone(),
        vec![PolicyCondition::PathPrefix(
            PathPrefix::new("/app").unwrap(),
        )],
        PolicyAction::Deny {
            reason: Text::new("reason", "closed for the day").unwrap(),
        },
        10,
    )
    .unwrap();
    f.policies = Arc::new(FakePolicyStore::holding(
        test_ctx().tenant_id(),
        policy_in(PolicyStatus::Active, vec![rule]),
    ));

    let (decision, ctx) = run(&f, &route, person(&[])).await;

    assert_eq!(denial(&decision).1, "tenant_rule");
    assert_eq!(ctx.refusing_rule, DecidingRule::Named(closed));
    assert!(matches!(ctx.tenant_ruling, TenantRuling::Decided { .. }));
}

/// Ann is let through with no live policy. Nothing ruled and no rule is
/// named.
#[tokio::test]
async fn absent_policies_produce_no_ruling() {
    let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
    let f = Fixture::with(&route).await;

    let (_, ctx) = run(&f, &route, person(&[VIEW_USERS])).await;

    assert_eq!(ctx.tenant_ruling, TenantRuling::NoPolicy);
    assert_eq!(ctx.refusing_rule, DecidingRule::Unnamed);
}

/// An unreadable tenant policy yields 503 on a public route and leaves
/// the request unauthorized.
#[tokio::test]
async fn an_unreadable_policy_refuses() {
    let route = route(RoutePolicy::Public);
    let mut f = Fixture::with(&route).await;
    f.policies = Arc::new(DownPolicies);

    let (decision, ctx) = run(&f, &route, Arrival::anonymous()).await;

    assert_eq!(
        denial(&decision),
        (
            DenialStatus::SERVICE_UNAVAILABLE,
            "tenant_policy_unreadable"
        )
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// An anonymous proof contradicting the context's authenticated person
/// yields 403 and leaves the request unauthorized.
#[tokio::test]
async fn inconsistent_caller_proofs_are_refused() {
    let route = route(RoutePolicy::Public);
    let f = Fixture::with(&route).await;
    let mut disagreeing = person(&[]);
    disagreeing.identification = Identification::Anonymous;

    let (decision, ctx) = run(&f, &route, disagreeing).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::FORBIDDEN, "identification_disagrees")
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// An agent's request every control admits passes once its action is
/// recorded as authorized.
#[tokio::test]
async fn records_admitted_agent_actions() {
    let route = route(RoutePolicy::Authenticated);
    let f = Fixture::with(&route).await;

    let (decision, ctx) = run(&f, &route, an_agent()).await;

    assert!(matches!(decision, StageDecision::Pass { .. }));
    assert_eq!(ctx.authorization(), Authorization::Granted);
    assert!(f.recorded("agents.action_authorized"));
}

/// The agent's delegation asks a person to approve each action. Its first
/// attempt is held for consent, not forwarded and not recorded as refused.
#[tokio::test]
async fn agent_actions_wait_for_approval() {
    let route = route(RoutePolicy::Authenticated);
    let f = Fixture::with(&route).await;
    let gated = agent(Restriction::Unrestricted, ActionApproval::PerAction);

    let (decision, ctx) = run(&f, &route, gated).await;

    assert!(matches!(
        decision,
        StageDecision::Challenge {
            challenge_type: ChallengeType::Consent,
            ..
        }
    ));
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
    assert!(!f.recorded("agents.action_authorized"));
    assert!(!f.recorded("agents.action_denied"));
}

/// An agent limited to public data receives 403 on an internal route,
/// remains unauthorized and records an action denial.
#[tokio::test]
async fn clearance_refusals_are_recorded() {
    let route = route(RoutePolicy::Authenticated);
    let f = Fixture::with(&route).await;
    let capped = agent(
        Restriction::To(DataClassLevel::Public),
        ActionApproval::NotRequired,
    );

    let (decision, ctx) = run(&f, &route, capped).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::FORBIDDEN, "agent_above_task")
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
    assert!(f.recorded("agents.action_denied"));
}

/// An unreachable approval broker yields 503, leaves the agent unauthorized
/// and records an action denial.
#[tokio::test]
async fn refuses_when_agent_controls_never_answer() {
    let route = route(RoutePolicy::Authenticated);
    let mut f = Fixture::with(&route).await;
    f.broker = Arc::new(FakeApprovalBroker::unreachable());
    let gated = agent(Restriction::Unrestricted, ActionApproval::PerAction);

    let (decision, ctx) = run(&f, &route, gated).await;

    assert_eq!(
        denial(&decision),
        (
            DenialStatus::SERVICE_UNAVAILABLE,
            "agent_controls_unanswered"
        )
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
    assert!(f.recorded("agents.action_denied"));
}

/// An agent missing the route's required permission receives 403 and records an action denial.
#[tokio::test]
async fn agent_permission_refusals_are_recorded() {
    let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
    let f = Fixture::with(&route).await;

    let (decision, _) = run(&f, &route, an_agent()).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::FORBIDDEN, "permission_missing")
    );
    assert!(f.recorded("agents.action_denied"));
}

/// Failure to record an admitted agent action yields 503 and leaves the request unauthorized.
#[tokio::test]
async fn stops_unrecorded_agent_actions_before_forwarding() {
    let route = route(RoutePolicy::Authenticated);
    let mut f = Fixture::with(&route).await;
    f.sink = Arc::new(FailingEventDispatcher);

    let (decision, ctx) = run(&f, &route, an_agent()).await;

    assert_eq!(
        denial(&decision),
        (DenialStatus::SERVICE_UNAVAILABLE, "agent_action_unrecorded")
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// Recording a rate-limit refusal for an agent emits an action-denied event.
#[tokio::test]
async fn later_agent_refusals_are_recorded() {
    let route = route(RoutePolicy::Authenticated);
    let f = Fixture::with(&route).await;
    let facts = f.get_app(&route);
    let refusal = StageDecision::Deny {
        status: DenialStatus::TOO_MANY_REQUESTS,
        reason: "rate_limited".to_owned(),
    };

    f.stages()
        .record_agent_refusal(&an_agent().ctx, &facts, &refusal)
        .await;

    assert!(f.recorded("agents.action_denied"));
}

/// A policy store that cannot be reached.
struct DownPolicies;

impl TenantScoped for DownPolicies {}

fn down() -> DomainError {
    DomainError::infra_msg("the policy store is unreachable")
}

#[async_trait]
impl PolicyStore for DownPolicies {
    async fn find_versions(
        &self,
        _tenant_id: &ScopedTenant,
    ) -> Result<Vec<PolicySet>, DomainError> {
        Err(down())
    }

    async fn find_active(
        &self,
        _tenant_id: &ScopedTenant,
    ) -> Result<Option<PolicySet>, DomainError> {
        Err(down())
    }

    async fn save(
        &self,
        _tenant_id: &ScopedTenant,
        _policy: &PolicySet,
    ) -> Result<(), DomainError> {
        Err(down())
    }

    async fn save_activation(
        &self,
        _tenant_id: &ScopedTenant,
        _activated: &PolicySet,
        _replaced: Option<&PolicySet>,
    ) -> Result<(), DomainError> {
        Err(down())
    }
}
