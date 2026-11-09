//! What the API's tests run on: the router over the app's fakes, with the
//! app's test organization and tenant seeded and a bearer for each kind of
//! caller.
//!
//! The ids are the app's own test ids (`test_ctx`, `test_org_caller`,
//! `test_operator_caller`), so a fake seeded the way the app's tests seed it
//! answers the API's requests too.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use ianua_app::context::{CallerIdentity, Credential};
use ianua_app::ports::organization::OrgSessionStore;
use ianua_app::ports::shared::{ResolvedCaller, TokenResolver};
pub use ianua_app::test_support::Fake;
use ianua_app::test_support::agents::{approval_limits, step_limits};
use ianua_app::test_support::authentication::{app_sign_in_lifetimes, lockout};
use ianua_app::test_support::operator::{operator_key, test_operator_id};
use ianua_app::test_support::organization::{
    RecordingOrgSessionStore, org_store_with, test_org_owning, test_org_session,
};
use ianua_app::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
use ianua_app::test_support::{test_ctx, test_org_caller, test_session_id};
use ianua_assembly::deps::{Adapters, Settings};
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator as _;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::fakes::FakeRefreshTokenGenerator;

use crate::state::Deps;
use crate::state::http::{ApiDocs, HttpSettings, ListenerLimits, RateLimits, RateWindow};

/// The organization slug of the app's test organization.
pub const ORG: &str = "acme";

/// The tenant slug of the app's test tenant.
pub const TENANT: &str = "acme";

/// The bearer of the app's test tenant user, signed in with the test
/// session.
pub const TENANT_USER: &str = "tenant-user-token";

/// The bearer of the app's test organization member, signed in with the
/// test session.
pub const ORG_MEMBER: &str = "org-member-token";

/// The bearer of the app's test operator, with their own key.
pub const OPERATOR: &str = "operator-token";

/// The API over the app's fakes, with the test organization and tenant
/// seeded and the three test bearers known. `adapters` may replace any
/// fake; start from [`adapters`].
pub fn router(adapters: Adapters) -> Router {
    router_with(adapters, settings())
}

/// The API over `adapters` under `settings`, every request from a loopback
/// peer. Start from [`settings`] to change one setting the use cases are
/// built with, such as a lifetime.
pub fn router_with(adapters: Adapters, settings: Settings) -> Router {
    router_over(&Deps {
        settings,
        ..deps(adapters)
    })
}

/// The API over `deps`, every request from a loopback peer. Start from
/// [`deps`] to change how the HTTP layer behaves, such as a listener's
/// limits or the trusted proxies.
pub fn router_over(deps: &Deps) -> Router {
    crate::router::build(deps).layer(axum::middleware::from_fn(from_loopback))
}

/// Everything the API is built from in tests: `adapters`, under the test
/// settings and the test HTTP settings, trusting no proxy.
#[must_use]
pub fn deps(adapters: Adapters) -> Deps {
    Deps {
        adapters,
        settings: settings(),
        http: http_settings(),
        trusted_proxies: Default::default(),
    }
}

/// The internal listener's API over `adapters`, under the test settings:
/// the probes and the scrape no public ingress reaches.
pub fn internal_router(adapters: Adapters) -> Router {
    crate::router::build_internal(&deps(adapters))
}

/// The relay listener's API over `adapters`, under the test settings: the
/// gateway's sealed questions no public ingress reaches.
pub fn relay_router(adapters: Adapters) -> Router {
    crate::router::build_relay(&deps(adapters))
}

/// Gives every test request a loopback peer, as a real connection has, so
/// the per-address limits have an address to count.
async fn from_loopback(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            50000,
        ))));
    next.run(request).await
}

/// Every port faked, with the test organization and tenant seeded, the
/// test bearers known and the member's session kept.
#[must_use]
pub fn adapters() -> Adapters {
    let ctx = test_ctx();
    Adapters {
        organization_store: org_store_with([test_org_owning(
            ctx.organization_id(),
            ORG,
            &[*test_tenant_for_ctx().id()],
        )]),
        tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
        token_resolver: Arc::new(KnownBearers::of_the_test_callers()),
        org_session_store: Arc::new(RecordingOrgSessionStore::holding([test_org_session()])),
        ..Adapters::fakes()
    }
}

/// The settings the use cases are built with in tests.
#[must_use]
pub fn settings() -> Settings {
    Settings {
        domain_limits: ianua_domain::shared::config::DomainLimits::default(),
        tunables: test_tunables(),
        app_base_url: Fake::fake(),
        upstream_networks: ianua_domain::shared::security::ssrf::UpstreamNetworks::public_only(),
        compliance_limits: Default::default(),
        enrollment: ianua_app::use_cases::onboarding::Enrollment::Open,
        cloud_console_template: None,
        device_verification_uri: Fake::fake(),
        base_domain: ianua_domain::types::DomainName::new("ianua.test").expect("a valid domain"),
        platform_addressing: ianua_domain::domains::tenant::hosts::PlatformAddressing::Nested,
        platform_hosts: Vec::new(),
        custom_domains: ianua_assembly::domain::CustomDomainSettings {
            nameservers: Vec::new(),
            proxy_address: None,
            trusted: Default::default(),
            claim_lifetimes:
                ianua_domain::domains::tenant::custom_domains::registered_domain::ClaimLifetimes {
                    unproved: ianua_domain::types::Lifetime::seconds(7 * 86_400)
                        .expect("a week is a lifetime"),
                    failed_grace: ianua_domain::types::Lifetime::seconds(14 * 86_400)
                        .expect("two weeks is a lifetime"),
                },
        },
        agent_token_audience: ianua_domain::types::Audience::new("https://ianua.test/token")
            .expect("a valid audience"),
        own_images: ianua_app::ports::workflows::OwnImages::On,
    }
}

/// The tuning API tests run under: the documented defaults.
// This exhaustive fixture names every tunable once, keeping the test configuration reviewable.
#[allow(clippy::too_many_lines)]
fn test_tunables() -> ianua_assembly::tunables::Tunables {
    ianua_assembly::tunables::Tunables {
        mfa_lockout: lockout(),
        sent_code: sent_code_policy(),
        org_invitation_lifetime: ianua_domain::types::Lifetime::seconds(86_400)
            .expect("a day is a lifetime"),
        org_verification_lifetime: ianua_domain::types::Lifetime::seconds(86_400)
            .expect("a day is a lifetime"),
        jwks_grace: ianua_domain::types::Lifetime::seconds(86_400).expect("a day is a lifetime"),
        verification_lifetime: ianua_domain::types::Lifetime::seconds(3600)
            .expect("an hour is a lifetime"),
        email_change_lifetime: ianua_domain::types::Lifetime::seconds(86_400)
            .expect("a day is a lifetime"),
        operator_key_lifetime: ianua_domain::types::Lifetime::seconds(43_200)
            .expect("twelve hours is a lifetime"),
        invitation_lifetime: ianua_domain::types::Lifetime::seconds(86_400)
            .expect("a day is a lifetime"),
        erasure_grace: ianua_domain::domains::identity::privacy::erasure::GracePeriod::days(30)
            .expect("thirty days is a grace period"),
        resend_cooldown: ianua_app::test_support::resend_cooldown(),
        password_reset_ttl: ianua_domain::types::Lifetime::seconds(3600)
            .expect("an hour is a lifetime"),
        magic_link_ttl: ianua_domain::types::Lifetime::seconds(900)
            .expect("fifteen minutes is a lifetime"),
        sign_in_confirmation_ttl: ianua_domain::types::Lifetime::seconds(900)
            .expect("fifteen minutes is a lifetime"),
        breach_policy:
            ianua_domain::domains::authentication::credentials::breach::BreachPolicy::Off,
        device_trust: ianua_domain::domains::authentication::device_trust::TrustWindow::standard(),
        unnamed_org_challenge_threshold: Default::default(),
        mfa_issuer: ianua_domain::types::Label::new("issuer", "Ianua").expect("a valid label"),
        password_history_count: 5,
        password_min_age_seconds: 0,
        break_glass_max_seconds: 86_400,
        max_trusted_devices_per_user: 10,
        max_passkeys_per_user: 10,
        passkey_ceremony_ttl: ianua_app::test_support::authentication::ceremony_lifetime(),
        ldap_certificate_validity:
            ianua_domain::domains::authentication::ldap_certificate::CertificateValidity::days(90)
                .expect("ninety days is a validity"),
        sign_in_code_ttl: ianua_domain::types::Lifetime::seconds(60)
            .expect("a minute is a lifetime"),
        app_sign_in: app_sign_in_lifetimes(),
        token_terms: ianua_app::test_support::oauth::test_terms(),
        device_code: device_code_timing(),
        credential_lifetimes:
            ianua_domain::domains::agents::identity::credential::CredentialLifetimes::default(),
        approval_limits: approval_limits(),
        run_steps: step_limits(),
        run_approval_ttl: time::Duration::days(1),
        approval_facts_window: time::Duration::days(1),
        gate_policy: approval_gate_policy(),
        task_token_max_ttl: ianua_domain::types::Lifetime::seconds(3600)
            .expect("an hour is a lifetime"),
        attestation_challenge_ttl: ianua_domain::types::Lifetime::seconds(120)
            .expect("two minutes is a lifetime"),
        agent_credential_ttl: ianua_domain::types::Seconds::new(900),
        certificate_attempts: 5,
        audit_export_limits: ianua_app::use_cases::audit::exports::ExportLimits {
            pending_per_log: std::num::NonZeroU32::new(3).expect("three is not zero"),
        },
        scim_group_member_cap: ianua_app::use_cases::scim::groups::MemberCap::default(),
    }
}

/// Mailed and texted codes remain answerable for ten minutes, with a resend cooldown.
fn sent_code_policy() -> ianua_app::use_cases::authentication::mfa::SentCodePolicy {
    ianua_app::use_cases::authentication::mfa::SentCodePolicy {
        lifetime: ianua_domain::types::Lifetime::seconds(600).expect("ten minutes is a lifetime"),
        resend_after: time::Duration::seconds(30),
    }
}

/// Device authorization uses a ten-minute code and the domain's polling interval.
fn device_code_timing() -> ianua_app::use_cases::oauth::flows::DeviceCodeTiming {
    ianua_app::use_cases::oauth::flows::DeviceCodeTiming {
        lifetime: ianua_domain::types::Lifetime::seconds(600).expect("ten minutes is a lifetime"),
        poll_interval:
            ianua_domain::domains::oauth::grants::device_authorization::PollInterval::DEFAULT,
    }
}

/// Gateway approval requests have fifteen minutes and a per-delegation budget.
fn approval_gate_policy() -> ianua_app::use_cases::agents::approvals::GatePolicy {
    ianua_app::use_cases::agents::approvals::GatePolicy {
        decision_window: ianua_domain::types::Seconds::new(900),
        max_open_per_delegation: 20,
    }
}

/// How the HTTP layer behaves in tests.
#[must_use]
pub fn http_settings() -> HttpSettings {
    HttpSettings {
        streams: Arc::new(crate::ws_limits::StreamLimiter::new(5)),
        stream_recheck: Duration::from_secs(30),
        stream_lifetime: Duration::from_secs(30 * 60),
        credential_use: Arc::new(crate::credential_use::RecentUse::new(
            Duration::from_secs(60),
            100_000,
        )),
        sso_cookie_lifetime_secs: 600,
        api_docs: ApiDocs::Hidden,
        cors_origin: None,
        rate: rate_limits(),
        sign_ins: crate::middleware::sign_in_admission::SignInAdmission::new(
            std::num::NonZeroUsize::new(4).expect("four is not zero"),
            Duration::from_millis(500),
        ),
        public_listener: ListenerLimits {
            max_concurrency: 500,
            max_body_bytes: 1024 * 1024,
            timeout: Duration::from_secs(30),
        },
        internal_listener: ListenerLimits {
            max_concurrency: 200,
            max_body_bytes: 16 * 1024,
            timeout: Duration::from_secs(15),
        },
    }
}

/// Address and caller budgets shared by API test routers.
fn rate_limits() -> RateLimits {
    let five_minutes = Duration::from_secs(300);
    RateLimits {
        login_per_minute: 20,
        agent_relay_per_minute: 600,
        sso: RateWindow {
            max: 60,
            window: five_minutes,
        },
        sensitive: RateWindow {
            max: 10,
            window: five_minutes,
        },
        user: RateWindow {
            max: 10,
            window: five_minutes,
        },
        max_tracked_ips: 100_000,
        api_default_per_minute: 200,
        scim_per_minute: 600,
        limit_cache_ttl: Duration::from_secs(60),
    }
}

/// A token resolver that knows a fixed set of bearers.
pub struct KnownBearers {
    callers: HashMap<String, ResolvedCaller>,
}

impl KnownBearers {
    /// The test tenant user, organization member and operator, under
    /// [`TENANT_USER`], [`ORG_MEMBER`] and [`OPERATOR`].
    #[must_use]
    pub fn of_the_test_callers() -> Self {
        let callers = HashMap::from([
            (TENANT_USER.to_owned(), tenant_caller()),
            (ORG_MEMBER.to_owned(), member_caller()),
            (OPERATOR.to_owned(), operator_caller()),
        ]);
        Self { callers }
    }

    /// These bearers, and `token` too, resolving to `caller`.
    #[must_use]
    pub fn and(mut self, token: &str, caller: ResolvedCaller) -> Self {
        self.callers.insert(token.to_owned(), caller);
        self
    }
}

/// Resolves the tenant fixture's bearer to its session and organization scope.
fn tenant_caller() -> ResolvedCaller {
    let ctx = test_ctx();
    ResolvedCaller {
        identity: *ctx.identity(),
        credential: ctx.credential().clone(),
        organization_id: Some(ctx.organization_id()),
        tenant_id: Some(ctx.tenant_id()),
        kept_until: ianua_domain::types::Expiry::Never,
    }
}

/// Resolves the member fixture's bearer without a selected tenant.
fn member_caller() -> ResolvedCaller {
    let member = test_org_caller();
    ResolvedCaller {
        identity: CallerIdentity::OrgUser(*member.member()),
        credential: Credential::OrgSession(test_session_id()),
        organization_id: Some(member.organization_id()),
        tenant_id: None,
        kept_until: ianua_domain::types::Expiry::Never,
    }
}

/// Resolves the operator fixture's bearer without an organization scope.
fn operator_caller() -> ResolvedCaller {
    ResolvedCaller {
        identity: CallerIdentity::Operator(test_operator_id()),
        credential: Credential::OperatorKey(operator_key()),
        organization_id: None,
        tenant_id: None,
        kept_until: ianua_domain::types::Expiry::Never,
    }
}

#[async_trait]
impl TokenResolver for KnownBearers {
    async fn resolve(&self, token: &Secret) -> Result<Option<ResolvedCaller>, DomainError> {
        Ok(self.callers.get(token.expose()).cloned())
    }
}

/// A token resolver that knows the test bearers, and the refresh token of
/// every organization session kept in a store, digested as the fake refresh
/// token generator digests it.
///
/// It answers as the platform's lookup does: a session neither revoked nor
/// expired resolves to its member, whether or not it finished signing in,
/// and what it may do is left to the app.
pub struct StoredOrgSessions {
    known: KnownBearers,
    sessions: Arc<dyn OrgSessionStore>,
}

impl StoredOrgSessions {
    /// The test bearers, and the refresh tokens of the sessions in
    /// `sessions`.
    #[must_use]
    pub fn over(sessions: Arc<dyn OrgSessionStore>) -> Self {
        Self {
            known: KnownBearers::of_the_test_callers(),
            sessions,
        }
    }
}

#[async_trait]
impl TokenResolver for StoredOrgSessions {
    async fn resolve(&self, token: &Secret) -> Result<Option<ResolvedCaller>, DomainError> {
        if let Some(caller) = self.known.resolve(token).await? {
            return Ok(Some(caller));
        }
        let hash = FakeRefreshTokenGenerator::new().hash_raw(token.expose());
        let session = self.sessions.find_by_refresh_token_hash(&hash).await?;
        Ok(session
            .filter(is_live)
            .map(|session| member_signed_in(&session)))
    }
}

/// Whether `session` still answers its refresh token: neither revoked nor
/// expired.
fn is_live(session: &OrgSession) -> bool {
    session.status() != SessionStatus::Revoked && session.expires_at() > clock::now()
}

/// The member of `session`, acting on their organization through it.
fn member_signed_in(session: &OrgSession) -> ResolvedCaller {
    ResolvedCaller {
        identity: CallerIdentity::OrgUser(*session.org_user_id()),
        credential: Credential::OrgSession(*session.id()),
        organization_id: Some(*session.organization_id()),
        tenant_id: None,
        kept_until: ianua_domain::types::Expiry::Never,
    }
}
