//! A credential acts only in its own plane: the organization and tenant the
//! path names must be the caller's own, whatever the endpoint.

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, TENANT, TENANT_USER, adapters, router};

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// The notification inbox address of `tenant` in `org`.
fn tenant_inbox(org: &str, tenant: &str) -> String {
    format!("/api/v1/organizations/{org}/tenants/{tenant}/notifications")
}

/// A request with no bearer is refused before anything is read.
#[tokio::test]
async fn a_request_without_a_bearer_is_unauthenticated() {
    let response = server().get(&tenant_inbox(ORG, TENANT)).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A bearer nobody issued counts as none.
#[tokio::test]
async fn an_unknown_bearer_is_unauthenticated() {
    let response = server()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer("forged")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An authenticated request naming a nonexistent organization returns 404.
#[tokio::test]
async fn an_organization_that_does_not_exist_is_not_found() {
    let response = server()
        .get(&tenant_inbox("globex", TENANT))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A tenant the organization does not hold is not found either.
#[tokio::test]
async fn a_tenant_the_organization_does_not_hold_is_not_found() {
    let response = server()
        .get(&tenant_inbox(ORG, "staging"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An operator's own key acts on the platform, not inside a tenant: that
/// takes an impersonation grant.
#[tokio::test]
async fn an_operator_key_does_not_act_inside_a_tenant() {
    let response = server()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A tenant user's session does not act on the organization.
#[tokio::test]
async fn a_tenant_session_does_not_act_on_the_organization() {
    let response = server()
        .get(&format!("/api/v1/organizations/{ORG}/notifications"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Neither does it act on the platform.
#[tokio::test]
async fn a_tenant_session_does_not_act_on_the_platform() {
    let response = server()
        .get("/api/v1/notifications")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A server whose test tenant was suspended.
fn suspended() -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_store: ianua_app::test_support::tenant::tenant_store_in_status(
            ianua_domain::domains::tenant::status::TenantStatus::Suspended,
        ),
        ..adapters()
    }))
    .unwrap()
}

/// A suspended tenant returns 403 with the tenant-unavailable error.
#[tokio::test]
async fn a_suspended_tenant_takes_no_request_in_its_name() {
    let response = suspended()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "tenant_unavailable"
    );
}

/// A member of the organization does not act inside a suspended tenant
/// either.
#[tokio::test]
async fn an_org_member_does_not_act_inside_a_suspended_tenant() {
    let response = suspended()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(ianua_api::test_support::ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Sends `path` with `body` from the same address until the limiter
/// answers, and gives the status of the last answer after `tries` requests.
async fn status_after(
    server: &TestServer,
    path: &str,
    body: serde_json::Value,
    tries: usize,
) -> StatusCode {
    let mut last = StatusCode::OK;
    for _ in 0..tries {
        last = server.post(path).json(&body).await.status_code();
    }
    last
}

/// Repeated sign-ups from one address eventually receive 429.
#[tokio::test]
async fn sign_ups_from_one_address_are_limited() {
    let server = TestServer::new(router(adapters())).unwrap();
    let path = format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/auth/sign-up");
    let body = serde_json::json!({"email": "x@attacker.test", "display_name": "x", "password": "Correct-Horse-Battery-9"});

    let last = status_after(&server, &path, body, 60).await;

    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

/// Repeated token requests exhaust the address's allowance and receive 429.
#[tokio::test]
async fn the_token_endpoint_is_limited_per_address() {
    let server = TestServer::new(router(adapters())).unwrap();
    let path = format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/oauth/token");
    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": "guess",
        "client_id": "tv"
    });

    let last = status_after(&server, &path, body, 260).await;

    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

/// A notification response carries no-store and no-cache headers.
#[tokio::test]
async fn answers_are_never_cached() {
    let response = TestServer::new(router(adapters()))
        .unwrap()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(TENANT_USER)
        .await;

    assert_eq!(response.header("cache-control"), "no-store");
    assert_eq!(response.header("pragma"), "no-cache");
}

/// The email logo chooses its own caching, which is kept.
#[tokio::test]
async fn an_answer_with_its_own_caching_keeps_it() {
    let response = TestServer::new(router(adapters()))
        .unwrap()
        .get("/email-logo.png")
        .await;

    assert!(
        response
            .header("cache-control")
            .to_str()
            .unwrap()
            .starts_with("public")
    );
}

/// A rate limiter that refuses every allowance but a tenant's.
struct TenantsOnly;

#[async_trait::async_trait]
impl ianua_app::ports::limits::RateLimiter for TenantsOnly {
    async fn check_and_increment(
        &self,
        budget: &ianua_app::ports::limits::RateBudget,
        limit_per_minute: u32,
    ) -> Result<u32, ianua_domain::shared::errors::DomainError> {
        match budget {
            ianua_app::ports::limits::RateBudget::Tenant(_) => Ok(limit_per_minute),
            _ => Err(ianua_domain::shared::errors::DomainError::forbidden(
                "rate limit exceeded",
            )),
        }
    }
}

/// A server whose limiter has spent every allowance but a tenant's.
fn limited_outside_tenants() -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        rate_limiter: std::sync::Arc::new(TenantsOnly),
        ..adapters()
    }))
    .unwrap()
}

/// An organization member receives 429 when only tenant requests have a
/// remaining allowance.
#[tokio::test]
async fn an_org_member_spends_the_organizations_allowance() {
    let response = limited_outside_tenants()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(ianua_api::test_support::ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// An operator's requests count against an allowance of their own.
#[tokio::test]
async fn an_operator_spends_an_allowance_of_their_own() {
    let response = limited_outside_tenants()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// A tenant user's requests count against the tenant's allowance alone.
#[tokio::test]
async fn a_tenant_user_spends_the_tenants_allowance() {
    let response = limited_outside_tenants()
        .get(&tenant_inbox(ORG, TENANT))
        .authorization_bearer(TENANT_USER)
        .await;

    assert_ne!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}
