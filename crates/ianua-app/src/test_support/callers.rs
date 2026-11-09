//! The callers, links and audit context a test acts with.

use std::sync::Arc;

use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
use ianua_domain::domains::proxy::observation::{
    ObservedPath, ObservedPrincipal, RequestObservation, RequestOutcome, RouteMatch, RulingPolicy,
    Traced,
};
use ianua_domain::types::{OrgUserId, OrganizationId, SessionId, TenantId, UserId};

use crate::context::{CallerContext, CallerIdentity, Credential, OrgCaller, OrgCredential};
use crate::ports::shared::EventDispatcher;

/// A request the proxy observed, with `outcome`, as a test needs it.
#[must_use]
pub fn request_observation(outcome: RequestOutcome) -> RequestObservation {
    RequestObservation {
        correlation_id: ianua_domain::types::CorrelationId::new(),
        tenant_id: ianua_domain::types::Fact::Unknown,
        route: RouteMatch::default(),
        method: ianua_domain::types::UntrustedText::record("GET"),
        path: ObservedPath::record("/orders"),
        client: std::net::IpAddr::from([10, 0, 0, 1]),
        principal: ObservedPrincipal::default(),
        outcome,
        trace: Traced::NotTraced,
        latency: time::Duration::milliseconds(12),
        classification: Vec::new(),
        policy: RulingPolicy::NoTenantVersion,
        occurred_at: ianua_domain::shared::clock::now(),
    }
}

/// The tenant scope emailed links carry in tests.
#[must_use]
pub fn test_link_scope() -> crate::email::LinkScope {
    crate::email::LinkScope::tenant(test_slug("acme"), test_slug("prod"))
}

/// The organization scope emailed links carry in tests.
#[must_use]
pub fn test_org_link_scope() -> crate::email::LinkScope {
    crate::email::LinkScope::organization(test_slug("acme"))
}

fn test_slug(value: &str) -> ianua_domain::types::TenantSlug {
    ianua_domain::types::TenantSlug::new(
        value,
        &ianua_domain::shared::config::SlugLimits::default(),
    )
    .expect("test slug is valid")
}

/// Creates a `CallerContext` for tests with Free plan limits: the test
/// caller, signed in to the test tenant with [`test_session_id`].
pub fn test_ctx() -> CallerContext {
    test_ctx_with(
        OrganizationId::from_uuid(TEST_ORG),
        TenantId::from_uuid(TEST_TENANT),
        UserId::from_uuid(TEST_CALLER),
    )
}

/// The session every test caller signs in with. A test that resolves the
/// caller's authority seeds a session under this id.
#[must_use]
pub fn test_session_id() -> SessionId {
    SessionId::from_uuid(TEST_SESSION)
}

/// The tenant every [`test_ctx`] belongs to.
///
/// Fixed rather than random so seeding a fake and calling a use case agree on
/// the tenant. The fakes filter by it, so a use case that passes the wrong
/// tenant still finds nothing, which is the point. A test that wants a
/// *different* tenant asks for one explicitly through [`test_ctx_with`].
const TEST_TENANT: uuid::Uuid = uuid::uuid!("019f0000-0000-7000-8000-000000007e57");
const TEST_ORG: uuid::Uuid = uuid::uuid!("019f0000-0000-7000-8000-0000000000a6");
const TEST_CALLER: uuid::Uuid = uuid::uuid!("019f0000-0000-7000-8000-0000000000c1");
const TEST_SESSION: uuid::Uuid = uuid::uuid!("019f0000-0000-7000-8000-0000000005e5");

/// A member of the test organization, signed in to it with a session.
#[must_use]
pub fn test_org_caller() -> OrgCaller {
    OrgCaller::new(
        OrgUserId::from_uuid(TEST_CALLER),
        OrgCredential::Session(test_session_id()),
        OrganizationId::from_uuid(TEST_ORG),
    )
}

/// Creates a `CallerContext` for tests with specific IDs and Free plan limits.
pub fn test_ctx_with(
    org_id: OrganizationId,
    tenant_id: TenantId,
    caller_id: UserId,
) -> CallerContext {
    CallerContext::new(
        CallerIdentity::TenantUser(caller_id),
        Credential::TenantSession(test_session_id()),
        org_id,
        tenant_id,
        OrganizationPlan::Free.default_limits(),
    )
    .expect("a tenant session fits a tenant user")
}

/// Creates a `CallerContext` with specific plan limits.
pub fn test_ctx_with_limits(limits: PlanLimits) -> CallerContext {
    CallerContext::new(
        CallerIdentity::TenantUser(UserId::new()),
        Credential::TenantSession(test_session_id()),
        OrganizationId::new(),
        TenantId::new(),
        limits,
    )
    .expect("a tenant session fits a tenant user")
}

/// Creates a system-origin `AuditContext` for tests.
pub fn test_audit() -> AuditContext {
    AuditContext::system()
}

/// Creates a system-origin [`RequestAuditor`](crate::auditor::RequestAuditor)
/// backed by `sink`, for use-case tests. Use when a test drives an `execute`
/// that takes `&RequestAuditor`.
#[must_use]
pub fn test_auditor(sink: Arc<dyn EventDispatcher>) -> crate::auditor::RequestAuditor {
    crate::auditor::RequestAuditor::system(sink)
}

/// The wait between resent emails that tests run under, in seconds.
pub const RESEND_COOLDOWN_SECONDS: u64 = 60;

/// The resend cooldown tests run under: [`RESEND_COOLDOWN_SECONDS`].
#[must_use]
pub fn resend_cooldown() -> crate::email::ResendCooldown {
    crate::email::ResendCooldown::new(time::Duration::seconds(60))
}
