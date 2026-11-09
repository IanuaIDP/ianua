use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hyper::body::Bytes;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::WasmModuleStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::test_support::authentication::{FakeGeolocator, UnreachableGeolocator};
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::proxy::request::body::BodyExtent;
use ianua_domain::domains::proxy::request::forwarded::ClientScheme;
use ianua_domain::domains::proxy::request::transform::RequestMutationRules;
use ianua_domain::domains::proxy::stages::stage::{
    CorsCredentials, FingerprintAction, ModuleRef, WafRuleSet,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CorrelationId, HeaderName, HeaderValue, HttpMethod, IpAddress, Origin, PipelineId, Seconds,
    TenantId,
};
use ianua_infra::reading::DocumentGraphQlAnalyzer;

use super::*;
use crate::listen::{ClientCertificate, ConnectionFacts, ConnectionParts};
use crate::request::BodyRead;
use crate::wasm::{WasmBounds, WasmEngine};

/// A module store holding nothing.
struct NoModules;

impl TenantScoped for NoModules {}

#[async_trait]
impl WasmModuleStore for NoModules {
    async fn save(&self, _: &ScopedTenant, _: &[u8]) -> Result<ModuleRef, DomainError> {
        Err(DomainError::infra_msg("this store is read-only"))
    }

    async fn find(&self, _: &ScopedTenant, _: &ModuleRef) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(None)
    }
}

/// A geolocator that never answers.
struct Silent;

#[async_trait]
impl Geolocator for Silent {
    async fn locate(&self, _: &IpAddress) -> Result<Option<IpGeolocation>, DomainError> {
        std::future::pending().await
    }
}

fn stages(geolocator: Arc<dyn Geolocator>) -> CheckStages {
    let engine = WasmEngine::new().unwrap();
    let wasm = WasmRuntime::new(&engine, Arc::new(NoModules), WasmBounds::default()).unwrap();
    CheckStages::new(CheckStagesParts {
        geolocator,
        graphql: Arc::new(DocumentGraphQlAnalyzer),
        wasm: Arc::new(wasm),
        lookup_timeout: Duration::from_millis(50),
    })
}

fn placed_in(code: &str) -> Arc<dyn Geolocator> {
    let place = IpGeolocation::new(52.5, 13.4, CountryCode::new(code).unwrap(), None).unwrap();
    Arc::new(FakeGeolocator {
        location: Some(place),
    })
}

/// A request as the gateway read it.
struct Sent {
    facts: RequestFacts,
}

impl Sent {
    fn new(builder: http::request::Builder, body: BodyRead) -> Self {
        let mut facts = RequestFacts::sent(builder.body(()).unwrap());
        let address = "203.0.113.9:443".parse().unwrap();
        facts.tenant = ScopedTenant::for_test(TenantId::new());
        facts.body = body;
        facts.connection = ConnectionFacts::new(ConnectionParts {
            client: address,
            peer: address,
            scheme: ClientScheme::Https,
            server_name: Fact::Unknown,
            client_certificate: ClientCertificate::NotAsked,
            ja4: Fact::Unknown,
        });
        Self { facts }
    }

    fn get(uri: &str) -> Self {
        Self::new(
            http::Request::get(uri).header("host", "shop.acme.com"),
            whole(b""),
        )
    }

    fn request(&self) -> &RequestFacts {
        &self.facts
    }

    fn context(&self) -> PipelineContext {
        PipelineContext::new(*self.facts.tenant, PipelineId::new(), CorrelationId::new())
    }

    /// The context of a request the edge saw come from `address`.
    fn context_from(&self, address: &str) -> PipelineContext {
        let mut ctx = self.context();
        ctx.ip_address = Fact::Known(IpAddress::new(address).unwrap());
        ctx
    }
}

fn whole(bytes: &'static [u8]) -> BodyRead {
    BodyRead::Read {
        prefix: Bytes::from_static(bytes),
        extent: BodyExtent::Whole,
    }
}

fn fence(allowed: &[&str], blocked: &[&str]) -> GeoFenceConfig {
    let codes = |list: &[&str]| -> Vec<CountryCode> {
        list.iter()
            .map(|code| CountryCode::new(*code).unwrap())
            .collect()
    };
    GeoFenceConfig {
        allowed_countries: codes(allowed),
        blocked_countries: codes(blocked),
    }
}

fn waf() -> WafConfig {
    WafConfig {
        rule_sets: vec![WafRuleSet::Sqli, WafRuleSet::Xss],
        anomaly_threshold: 5,
        max_body_bytes: 1024,
    }
}

#[tokio::test]
async fn passes_and_retains_allowed_countries() {
    let sent = Sent::get("/");
    let mut ctx = sent.context_from("203.0.113.9");

    let decision = stages(placed_in("DE"))
        .geo_fence(&fence(&["DE"], &[]), &mut ctx)
        .await;

    assert!(!decision.is_terminal());
    assert_eq!(
        ctx.country_code,
        Fact::Known(CountryCode::new("DE").unwrap())
    );
}

#[tokio::test]
async fn refuses_blocked_countries() {
    let sent = Sent::get("/");
    let mut ctx = sent.context_from("203.0.113.9");

    let decision = stages(placed_in("CN"))
        .geo_fence(&fence(&[], &["CN"]), &mut ctx)
        .await;

    assert!(decision.is_terminal());
}

/// A failed geolocation lookup refuses the request and keeps its country unknown.
#[tokio::test]
async fn a_failed_country_lookup_is_refused() {
    let sent = Sent::get("/");
    let mut ctx = sent.context_from("203.0.113.9");

    let decision = stages(Arc::new(UnreachableGeolocator))
        .geo_fence(&fence(&["DE"], &[]), &mut ctx)
        .await;

    assert!(decision.is_terminal());
    assert_eq!(ctx.country_code, Fact::Unknown);
}

#[tokio::test]
async fn silent_country_lookups_time_out() {
    let sent = Sent::get("/");
    let mut ctx = sent.context_from("203.0.113.9");

    let decision = stages(Arc::new(Silent))
        .geo_fence(&fence(&["DE"], &[]), &mut ctx)
        .await;

    assert!(decision.is_terminal());
}

/// A country block list refuses a client whose address has no geolocation result.
#[tokio::test]
async fn country_block_lists_refuse_unknown_locations() {
    let sent = Sent::get("/");
    let mut ctx = sent.context_from("203.0.113.9");

    let decision = stages(Arc::new(FakeGeolocator::default()))
        .geo_fence(&fence(&[], &["CN"]), &mut ctx)
        .await;

    assert!(decision.is_terminal());
}

#[tokio::test]
async fn missing_client_addresses_fail_country_checks() {
    let sent = Sent::get("/");
    let mut ctx = sent.context();

    let decision = stages(placed_in("DE"))
        .geo_fence(&fence(&["DE"], &[]), &mut ctx)
        .await;

    assert!(decision.is_terminal());
}

/// A module the tenant named but nobody stored reaches no verdict, and the
/// request is refused.
#[tokio::test]
async fn missing_custom_modules_deny_requests() {
    let sent = Sent::get("/orders");
    let ctx = sent.context();
    let stage = WasmStageRef {
        module_ref: ModuleRef::new("tenant/modules/missing.wasm").unwrap(),
        timeout_ms: 1_000,
        max_memory_bytes: 64 * 1024,
    };

    let decision = stages(placed_in("DE"))
        .custom(&stage, sent.request(), &ctx)
        .await;

    assert!(matches!(
        decision,
        StageDecision::Deny { status, .. } if status == DenialStatus::FORBIDDEN
    ));
}

#[tokio::test]
async fn waf_distinguishes_attacks_from_clean_requests() {
    let clean = Sent::get("/orders?page=2");
    let attack = Sent::get("/orders?id=1%20union%20select%20password%20from%20users");
    let checks = stages(placed_in("DE"));

    assert!(!checks.waf(&waf(), clean.request()).await.is_terminal());
    assert!(checks.waf(&waf(), attack.request()).await.is_terminal());
}

#[tokio::test]
async fn waf_refuses_unread_request_bodies() {
    let sent = Sent::new(
        http::Request::post("/orders").header("host", "shop.acme.com"),
        BodyRead::Unread,
    );

    let decision = stages(placed_in("DE")).waf(&waf(), sent.request()).await;

    assert!(decision.is_terminal());
}

#[tokio::test]
async fn the_waf_scans_the_body_prefix() {
    let sent = Sent::new(
        http::Request::post("/orders").header("host", "shop.acme.com"),
        whole(br#"{"q":"<script>alert(1)</script>"}"#),
    );

    let decision = stages(placed_in("DE")).waf(&waf(), sent.request()).await;

    assert!(decision.is_terminal());
}

#[tokio::test]
async fn cors_admits_only_allowed_origins() {
    let config = app_cors();
    let allowed = Sent::new(
        http::Request::get("/")
            .header("host", "shop.acme.com")
            .header("origin", "https://app.acme.com"),
        whole(b""),
    );
    let other = Sent::new(
        http::Request::get("/")
            .header("host", "shop.acme.com")
            .header("origin", "https://evil.example"),
        whole(b""),
    );
    let checks = stages(placed_in("DE"));
    let mut ctx = allowed.context();

    assert!(
        !checks
            .cors(&config, allowed.request(), &mut ctx)
            .await
            .is_terminal()
    );
    assert!(!ctx.response_headers.is_empty());
    assert!(
        checks
            .cors(&config, other.request(), &mut other.context())
            .await
            .is_terminal()
    );
}

/// Only the app origin may issue credential-free GET requests.
fn app_cors() -> CorsConfig {
    CorsConfig {
        allowed_origins: vec![Origin::new("https://app.acme.com").unwrap()],
        allowed_methods: vec![HttpMethod::Get],
        allowed_headers: Vec::new(),
        exposed_headers: Vec::new(),
        max_age_secs: Seconds::new(600),
        allow_credentials: CorsCredentials::Withheld,
    }
}

#[tokio::test]
async fn denying_automation_preserves_browser_access() {
    let bot = Sent::new(
        http::Request::get("/")
            .header("host", "shop.acme.com")
            .header("user-agent", "curl/8.4.0"),
        whole(b""),
    );
    let person = Sent::new(
        http::Request::get("/")
            .header("host", "shop.acme.com")
            .header("user-agent", "Mozilla/5.0"),
        whole(b""),
    );
    let config = FingerprintConfig {
        action: FingerprintAction::Deny,
    };
    let checks = stages(placed_in("DE"));

    assert!(
        checks
            .fingerprint(&config, bot.request())
            .await
            .is_terminal()
    );
    assert!(
        !checks
            .fingerprint(&config, person.request())
            .await
            .is_terminal()
    );
}

#[tokio::test]
async fn graphql_refuses_queries_beyond_depth_limits() {
    let cheap = Sent::new(
        http::Request::post("/graphql").header("host", "shop.acme.com"),
        whole(br#"{"query":"{ user { name } }"}"#),
    );
    let deep = Sent::new(
        http::Request::post("/graphql").header("host", "shop.acme.com"),
        whole(br#"{"query":"{ a { b { c { d } } } }"}"#),
    );
    let limits = GraphQlLimits::new(2, 1_000, 0).unwrap();
    let checks = stages(placed_in("DE"));

    assert!(!checks.graphql(&limits, cheap.request()).await.is_terminal());
    assert!(checks.graphql(&limits, deep.request()).await.is_terminal());
}

#[tokio::test]
async fn mcp_requires_grants_for_tool_calls() {
    let sent = Sent::new(
        http::Request::post("/mcp").header("host", "shop.acme.com"),
        whole(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#),
    );
    let listing = Sent::new(
        http::Request::post("/mcp").header("host", "shop.acme.com"),
        whole(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
    );
    let checks = stages(placed_in("DE"));

    assert!(
        checks
            .mcp(sent.request(), &sent.context())
            .await
            .is_terminal()
    );
    assert!(
        !checks
            .mcp(listing.request(), &listing.context())
            .await
            .is_terminal()
    );
}

#[tokio::test]
async fn request_transforms_return_configured_mutations() {
    let mutation = RequestMutation::configured(RequestMutationRules {
        set_headers: vec![(
            HeaderName::new("x-api-version").unwrap(),
            HeaderValue::new("2").unwrap(),
        )],
        ..RequestMutationRules::default()
    })
    .unwrap();

    let decision = stages(placed_in("DE")).request_transform(&mutation).await;

    let StageDecision::Transform {
        mutation: handed, ..
    } = decision
    else {
        panic!("a transform changes the request");
    };
    assert_eq!(handed, mutation);
}

#[tokio::test]
async fn terminate_answers_from_its_configuration() {
    let sent = Sent::get("/");
    let mut ctx = sent.context();
    let config = TerminateConfig::new(410, "text/plain", "gone").unwrap();

    let decision = stages(placed_in("DE")).terminate(&config, &mut ctx).await;

    assert!(!decision.is_terminal());
    let ready = ctx.response.ready().unwrap();
    assert_eq!(ready.status, 410);
    assert_eq!(ready.body, b"gone");
}
