use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use http::Request;
use http::request::Builder;
use ianua_app::ports::authentication::{AppSessionClaim, IssuedUnder, PersonToken, TenantToken};
use ianua_app::ports::authorization::AccessRecords;
use ianua_app::ports::pages::{ErrorPage, ErrorPageKind};
use ianua_app::ports::proxy::{ResponseStageExecutor, ResponseStageOutcome, StageExecutor};
use ianua_app::ports::routing::RouteStore;
use ianua_app::test_support::agents::{FakeApprovalBroker, FakeExposureGate};
use ianua_app::test_support::authentication::{
    FakeAppSessionCheck, FakeGeolocator, FakePresentedTokens,
};
use ianua_app::test_support::authorization::{FakeAccessRecordStore, FakePolicyStore};
use ianua_app::test_support::data_classification::FakeClassificationStore;
use ianua_app::test_support::identity::FakeUserStore;
use ianua_app::test_support::oauth::test_issuer;
use ianua_app::test_support::pages::FakePageRenderer;
use ianua_app::test_support::proxy::{
    FakePipelineStore, FakeWasmModuleStore, test_pipeline, test_pipeline_id, test_pipeline_running,
};
use ianua_app::test_support::routing::{
    FakeRouteStore, RouteShape, pinned_upstream, route_of, service_named,
};
use ianua_app::test_support::{FakeEventDispatcher, test_auditor, test_ctx};
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::agents::approvals::{GateActionPorts, GateActionUseCase};
use ianua_app::use_cases::agents::enforcement::{AdmitActionPorts, AdmitActionUseCase};
use ianua_app::use_cases::proxy::credentials::{AuthenticatePorts, PersonPorts};
use ianua_app::use_cases::proxy::{DecideAccessPorts, DecideAccessUseCase, PipelineVerdict};
use ianua_domain::domains::agents::authority::capability::{ActionApproval, McpGrant};
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::request::body::{BodyExtent, CapturedBody};
use ianua_domain::domains::proxy::request::context::{
    AgentLimits, Authorization, Caller, KeyBinding, Metering, PipelineContext, RouteRequirements,
    UserSignIn, Verified,
};
use ianua_domain::domains::proxy::request::transform::{RequestMutation, ResponseMutation};
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::{
    CanaryToken, CanaryTokenConfig, FlaggedClients, IpReputationConfig, MandatoryStage,
    RateLimitKey, StageConfig, StageKind, StageRemoval, TokenExchangeConfig, WafConfig, WafRuleSet,
};
use ianua_domain::domains::proxy::stages::token_budget::{
    LlmDialect, TokenRateLimitConfig, TokenRateLimitParams, UnknownUsage,
};
use ianua_domain::domains::routing::backend::upstream::TokenAudience;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    AgentId, Audience, CidrRange, CorrelationId, DelegationId, DenialStatus, Expiry, Fact,
    HeaderName, HeaderValue, IpAddress, PrincipalRef, Scope, Seconds, ServiceId, SessionId, UserId,
};
use ianua_infra::reading::DocumentGraphQlAnalyzer;
use time::Duration as Span;

use super::{RequestRun, StageDispatch, StageGroups};
use crate::pipeline::facts::RequestFacts;
use crate::pipeline::stages::checks::{CheckStages, CheckStagesParts};
use crate::pipeline::stages::counters::fakes::Rig;
use crate::pipeline::stages::identity::{IdentityStages, fixtures};
use crate::pipeline::stages::policy::{PolicyStages, PolicyStagesParts};
use crate::pipeline::stages::response::fixtures::{Fakes, json};
use crate::respond::error_page;
use crate::wasm::{WasmBounds, WasmEngine, WasmRuntime};

/// The token Ann's app presents.
const TOKEN: &str = "a.signed.token";

/// The address every test request comes from.
const CLIENT: &str = "203.0.113.7";

/// Acme's gateway: Ann, active and signed in to the app, its `/app` route
/// stored for signed-in callers, and every counter, cache and inbox in
/// memory.
struct Gateway {
    ann: UserId,
    route: Arc<Route<ResolvedTenant>>,
    routes: Arc<FakeRouteStore>,
    counters: Rig,
    response: Fakes,
    recorded: Arc<FakeEventDispatcher>,
}

impl Gateway {
    async fn new() -> Self {
        let service = service_named("app", pinned_upstream("https://backend:8080", "app"));
        let route = Arc::new(route_of(
            RouteShape {
                policy: RoutePolicy::Authenticated,
                ..RouteShape::public("app", "/app")
            },
            &service,
            &test_pipeline(),
        ));
        let routes = Arc::new(FakeRouteStore::empty());
        routes.save(&test_ctx().tenant(), &route).await.unwrap();
        Self {
            ann: UserId::new(),
            route,
            routes,
            counters: Rig::counting(),
            response: Fakes::default(),
            recorded: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn dispatch(&self) -> Arc<StageDispatch> {
        Arc::new(StageDispatch::new(StageGroups {
            identity: self.identity(),
            policy: self.policy(),
            counters: self.counters.stages(),
            checks: checks(),
            response: self.response.stages(),
        }))
    }

    /// Who signs in: Ann's token read for her, her account and session
    /// live.
    fn identity(&self) -> IdentityStages {
        let authenticate = AuthenticatePorts {
            tokens: Arc::new(FakePresentedTokens::reading_bearer(token_of(self.ann))),
            access_records: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                AccessRecords::default(),
            )),
            people: PersonPorts {
                user_store: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                app_sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                ..PersonPorts::fakes()
            },
            ..AuthenticatePorts::fakes()
        };
        IdentityStages::new(fixtures::parts_with(authenticate))
    }

    /// What may pass: the stored route, no tenant policy, every agent
    /// action admitted.
    fn policy(&self) -> PolicyStages {
        let decide_access = DecideAccessUseCase::new(DecideAccessPorts {
            route_store: self.routes.clone(),
            policy_store: Arc::new(FakePolicyStore::empty()),
            ..DecideAccessPorts::fakes()
        });
        let gate = GateActionUseCase::new(GateActionPorts {
            broker: Arc::new(FakeApprovalBroker::answering()),
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

    /// `build` sent to the app's host, its actions recorded here.
    fn run(&self, build: Builder) -> Arc<RequestRun> {
        let request = build.header("host", "app.acme.test").body(()).unwrap();
        let mut facts = RequestFacts::sent(request);
        facts.auditor = test_auditor(self.recorded.clone());
        facts.route = Arc::clone(&self.route);
        self.dispatch().for_request(facts)
    }

    /// Whether an event of `kind` was recorded through the request's
    /// auditor.
    fn recorded(&self, kind: &str) -> bool {
        self.recorded
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|recorded| recorded == kind)
    }
}

/// The check stages, with no country known and no module stored.
fn checks() -> CheckStages {
    let engine = WasmEngine::new().unwrap();
    let modules = Arc::new(FakeWasmModuleStore::empty());
    let wasm = WasmRuntime::new(&engine, modules, WasmBounds::default()).unwrap();
    CheckStages::new(CheckStagesParts {
        geolocator: Arc::new(FakeGeolocator { location: None }),
        graphql: Arc::new(DocumentGraphQlAnalyzer),
        wasm: Arc::new(wasm),
        lookup_timeout: Duration::from_millis(50),
    })
}

/// A token Acme signed for `user_id` under a live app session, at AAL2.
fn token_of(user_id: UserId) -> TenantToken {
    TenantToken::Person(PersonToken {
        user_id,
        scopes: Vec::new(),
        assurance: Fact::Known(AssuranceLevel::Aal2),
        expires_at: clock::now() + Span::hours(1),
        issued_under: IssuedUnder::AppSession(AppSessionClaim {
            session_id: SessionId::new(),
            user_id,
            service_id: ServiceId::new(),
            idle_timeout: None,
            signed_in_from: Fact::Unknown,
        }),
        claims: Vec::new(),
    })
}

/// A request to Acme's app from [`CLIENT`], on the route that needs a
/// signed-in caller, before any stage ran.
fn context() -> PipelineContext {
    let mut ctx = PipelineContext::new(
        test_ctx().tenant_id(),
        test_pipeline_id(),
        CorrelationId::new(),
    );
    ctx.ip_address = Fact::Known(IpAddress::new(CLIENT).unwrap());
    ctx.route = RouteRequirements {
        expected_issuer: Fact::Known(test_issuer()),
        token_audience: TokenAudience::Pinned(Audience::new("app").unwrap()),
        policy: Fact::Known(RoutePolicy::Authenticated),
        ..RouteRequirements::default()
    };
    ctx
}

/// A `GET /app` carrying Ann's token.
fn with_bearer() -> Builder {
    Request::get("/app").header("authorization", format!("Bearer {TOKEN}"))
}

fn stage(kind: StageKind) -> StageConfig {
    StageConfig::new(kind, 50, StageRemoval::Allowed).unwrap()
}

fn identity_stage() -> StageConfig {
    StageConfig::locked(MandatoryStage::Identity)
}

fn policy_stage() -> StageConfig {
    StageConfig::locked(MandatoryStage::Policy)
}

/// A denylist holding every address [`CLIENT`] is in.
fn denying_the_client() -> StageKind {
    StageKind::IpReputation(IpReputationConfig {
        denylist: vec![CidrRange::new("203.0.113.0/24").unwrap()],
        deny_platform_flagged: FlaggedClients::Ignore,
    })
}

/// A token limit counted per address, on OpenAI's usage fields.
fn token_limit() -> TokenRateLimitConfig {
    TokenRateLimitConfig::new(TokenRateLimitParams {
        max_tokens: 10_000,
        window_seconds: Seconds::new(3_600),
        key_by: RateLimitKey::IpAddress,
        dialect: LlmDialect::OpenAi,
        on_unknown: UnknownUsage::default(),
    })
    .unwrap()
}

/// An agent acting for itself, unmetered and holding a bearer token.
fn an_agent() -> Caller {
    let agent_id = AgentId::new();
    Caller::Agent {
        agent_id,
        delegation_id: DelegationId::new(),
        acting_for: PrincipalRef::Agent(agent_id),
        limits: Box::new(AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class: Restriction::Unrestricted,
            key_binding: KeyBinding::Bearer,
            approval: ActionApproval::NotRequired,
            metering: Metering::Unmetered,
        }),
    }
}

/// `ctx`, its caller already proven as `caller`.
fn proven_as(caller: Caller, mut ctx: PipelineContext) -> PipelineContext {
    ctx.authenticate(Verified {
        caller,
        expiry: Expiry::Never,
    })
    .unwrap();
    ctx
}

/// The reason a decision is recorded with, when it refuses.
fn refused_for(decision: &StageDecision) -> Option<(DenialStatus, &str)> {
    let StageDecision::Deny { status, reason } = decision else {
        return None;
    };
    Some((*status, reason.as_str()))
}

/// Each kind before forwarding reaches the group that runs it, and comes
/// back with that group's own answer.
#[tokio::test]
async fn each_kind_reaches_its_group() {
    let gateway = Gateway::new().await;
    let exchange = StageKind::TokenExchange(TokenExchangeConfig {
        target_audience: Audience::new("billing-service").unwrap(),
        scopes: vec![Scope::new("invoices:read").unwrap()],
        ttl_seconds: Seconds::new(60),
    });
    let cases = [
        (exchange, "token_exchange_anonymous"),
        (
            StageKind::RequestTransform(RequestMutation::default()),
            "request_transform: applied",
        ),
        (
            denying_the_client(),
            "the address is on the tenant's denylist",
        ),
        (
            StageKind::CanaryToken(CanaryTokenConfig {
                tokens: vec![CanaryToken::new("sk-decoy-0123456789abcdef").unwrap()],
            }),
            "no canary token presented",
        ),
    ];

    for (kind, reason) in cases {
        let run = gateway.run(Request::get("/app"));

        let decision = run.execute(&stage(kind), &mut context()).await.unwrap();

        assert_eq!(decision.reason(), reason);
    }
}

/// A kind acting on the answer reaches the response group there.
#[tokio::test]
async fn response_stages_reach_the_response_group() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let transform = stage(StageKind::ResponseTransform(ResponseMutation::default()));

    let outcome = run
        .execute_response(
            &transform,
            &context(),
            &json(),
            CapturedBody::new(b"{}", BodyExtent::Whole),
        )
        .await
        .unwrap();

    assert!(matches!(
        outcome,
        ResponseStageOutcome::Pass { reason } if reason == "nothing to transform"
    ));
}

/// A response transform run during request processing yields 503 for an out-of-phase stage.
#[tokio::test]
async fn response_stages_cannot_run_before_forwarding() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let transform = stage(StageKind::ResponseTransform(ResponseMutation::default()));

    let decision = run.execute(&transform, &mut context()).await.unwrap();

    assert_eq!(
        refused_for(&decision),
        Some((DenialStatus::SERVICE_UNAVAILABLE, "stage_out_of_phase"))
    );
}

/// A WAF stage run during response processing blocks the answer with 503.
#[tokio::test]
async fn request_stages_cannot_process_responses() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let waf = stage(StageKind::Waf(WafConfig {
        rule_sets: vec![WafRuleSet::Sqli],
        anomaly_threshold: 5,
        max_body_bytes: 1024,
    }));

    let outcome = run
        .execute_response(
            &waf,
            &context(),
            &json(),
            CapturedBody::new(b"{}", BodyExtent::Whole),
        )
        .await
        .unwrap();

    assert!(matches!(
        outcome,
        ResponseStageOutcome::Block { status, .. } if status == DenialStatus::SERVICE_UNAVAILABLE
    ));
}

/// Ann's app presents her token. The Identity stage proves her, and the
/// Policy stage after it decides on that proof and lets her through.
#[tokio::test]
async fn policy_uses_the_proven_identity() {
    let gateway = Gateway::new().await;
    let run = gateway.run(with_bearer());
    let mut ctx = context();

    let identity = run.execute(&identity_stage(), &mut ctx).await.unwrap();
    let policy = run.execute(&policy_stage(), &mut ctx).await.unwrap();

    assert!(matches!(identity, StageDecision::Pass { .. }));
    assert!(matches!(policy, StageDecision::Pass { .. }));
    assert_eq!(ctx.authorization(), Authorization::Granted);
}

/// Policy run before Identity yields 403 for missing established identity
/// and leaves the request unauthorized.
#[tokio::test]
async fn policy_requires_an_established_identity() {
    let gateway = Gateway::new().await;
    let run = gateway.run(with_bearer());
    let mut ctx = context();

    let policy = run.execute(&policy_stage(), &mut ctx).await.unwrap();

    assert_eq!(
        refused_for(&policy),
        Some((DenialStatus::FORBIDDEN, "identity_not_established"))
    );
    assert_eq!(ctx.authorization(), Authorization::NotGranted);
}

/// A request's token limit sets a typical exchange's tokens aside, and
/// the answer settles what it really cost against them.
#[tokio::test]
async fn reservations_offset_the_actual_token_charge() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let config = token_limit();
    let limit = stage(StageKind::TokenRateLimit(config.clone()));
    let mut ctx = context();
    let usage = br#"{"usage":{"prompt_tokens":120,"completion_tokens":380}}"#;

    let admitted = run.execute(&limit, &mut ctx).await.unwrap();
    run.execute_response(
        &limit,
        &ctx,
        &json(),
        CapturedBody::new(usage, BodyExtent::Whole),
    )
    .await
    .unwrap();
    run.release_unspent(&ctx).await;

    assert!(matches!(admitted, StageDecision::Pass { .. }));
    let reserved = i64::from(config.reservation());
    assert_eq!(gateway.response.ledger.settled(), [500 - reserved]);
}

/// Releasing an unsettled token reservation refunds its entire amount to the ledger.
#[tokio::test]
async fn refunds_unsettled_token_reservations() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let config = token_limit();
    let mut ctx = context();

    run.execute(&stage(StageKind::TokenRateLimit(config.clone())), &mut ctx)
        .await
        .unwrap();
    run.release_unspent(&ctx).await;

    let reserved = i64::from(config.reservation());
    assert_eq!(gateway.response.ledger.settled(), [-reserved]);
}

/// A response without a token reservation is blocked and creates no ledger settlement.
#[tokio::test]
async fn withholds_unreserved_token_responses() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));

    let outcome = run
        .execute_response(
            &stage(StageKind::TokenRateLimit(token_limit())),
            &context(),
            &json(),
            CapturedBody::new(b"{}", BodyExtent::Whole),
        )
        .await
        .unwrap();

    assert!(matches!(outcome, ResponseStageOutcome::Block { .. }));
    assert!(gateway.response.ledger.settled().is_empty());
}

/// Eve is over her rate limit. Her refusal carries the `Retry-After` the
/// pipeline set, beside the refusal's own headers.
#[tokio::test]
async fn a_refusal_carries_the_pipelines_headers() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let mut ctx = context();
    ctx.response_headers.push(HeaderEntry::new(
        HeaderName::new("retry-after").unwrap(),
        HeaderValue::new("30").unwrap(),
    ));
    let page = ErrorPage::new(ErrorPageKind::TooManyRequests, ctx.correlation_id);

    let answer = error_page::error_response(&run.facts().headers, &page, &FakePageRenderer);
    let answer = error_page::with_pipeline_headers(answer, &ctx.response_headers);

    assert_eq!(answer.headers()["retry-after"], "30");
    assert_eq!(answer.status().as_u16(), 429);
}

/// Identity run on an authenticated context yields 503 for stage failure
/// without including the presented token in the reason.
#[tokio::test]
async fn stage_failures_refuse_the_request() {
    let gateway = Gateway::new().await;
    let run = gateway.run(with_bearer());
    let mallory = Caller::User {
        user_id: UserId::new(),
        sign_in: UserSignIn::Token,
    };
    let mut ctx = proven_as(mallory, context());

    let decision = run.execute(&identity_stage(), &mut ctx).await.unwrap();

    assert_eq!(
        refused_for(&decision),
        Some((DenialStatus::SERVICE_UNAVAILABLE, "stage_failed"))
    );
    assert!(!decision.reason().contains(TOKEN));
}

/// An identity failure denies the whole pipeline after its first decision.
#[tokio::test]
async fn stage_failures_stop_the_pipeline() {
    let gateway = Gateway::new().await;
    let run = gateway.run(with_bearer());
    let pipelines = Arc::new(FakePipelineStore::holding(
        test_ctx().tenant_id(),
        test_pipeline_running(PipelineStatus::Active, Vec::new()),
    ));
    let mallory = Caller::User {
        user_id: UserId::new(),
        sign_in: UserSignIn::Token,
    };
    let ctx = proven_as(mallory, context());

    let result = run
        .evaluation(pipelines)
        .execute(&test_ctx().tenant(), ctx)
        .await
        .unwrap();

    assert_eq!(result.verdict, PipelineVerdict::Denied);
    assert_eq!(result.decisions.len(), 1);
}

/// Ann's request through the whole pipeline, Identity then Policy, is
/// allowed.
#[tokio::test]
async fn proven_permitted_requests_pass_the_pipeline() {
    let gateway = Gateway::new().await;
    let run = gateway.run(with_bearer());
    let pipelines = Arc::new(FakePipelineStore::holding(
        test_ctx().tenant_id(),
        test_pipeline_running(PipelineStatus::Active, Vec::new()),
    ));

    let result = run
        .evaluation(pipelines)
        .execute(&test_ctx().tenant(), context())
        .await
        .unwrap();

    assert_eq!(result.verdict, PipelineVerdict::Allowed);
}

/// A denylist stage returns a terminal decision for an authenticated agent
/// and records an action denial.
#[tokio::test]
async fn later_agent_refusals_are_recorded() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let mut ctx = proven_as(an_agent(), context());

    let decision = run
        .execute(&stage(denying_the_client()), &mut ctx)
        .await
        .unwrap();

    assert!(decision.is_terminal());
    assert!(gateway.recorded("agents.action_denied"));
}

/// A person refused by the same stage is no agent, and nothing is recorded
/// as an agent's action.
#[tokio::test]
async fn person_refusals_record_no_agent_action() {
    let gateway = Gateway::new().await;
    let run = gateway.run(Request::get("/app"));
    let ann = Caller::User {
        user_id: gateway.ann,
        sign_in: UserSignIn::Token,
    };
    let mut ctx = proven_as(ann, context());

    run.execute(&stage(denying_the_client()), &mut ctx)
        .await
        .unwrap();

    assert!(!gateway.recorded("agents.action_denied"));
}
