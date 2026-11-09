//! The tenant endpoints: provisioning and reading tenants, their settings
//! and overview, and in what shape they answer.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::ports::tenant::TenantSetupStore as _;
use ianua_app::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
use ianua_app::test_support::authentication::REENTERED_PASSWORD;
use ianua_app::test_support::tenant::{
    FakeTenantSetupStore, FakeTenantStore, test_tenant_for_ctx, test_tenant_in,
};
use ianua_app::test_support::{RejectingLimitEnforcer, test_ctx};
use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup};
use ianua_domain::types::UntrustedText;
use serde_json::{Value, json};

/// The test organization's tenant list address.
fn tenants() -> String {
    format!("/api/v1/organizations/{ORG}/tenants")
}

/// The test tenant's address, followed by `rest`.
fn tenant(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// Ann reads her tenant and sees it in the shape the dashboard reads: its
/// slug and status, where its users sign in, and where its data lives.
#[tokio::test]
async fn a_tenant_user_reads_their_tenant() {
    let server = server();

    let response = server
        .get(&tenant(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["slug"], TENANT);
    assert!(body["status"].is_string());
    assert!(
        body["login_url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/organizations/{ORG}/tenants/{TENANT}/login"))
    );
    assert_eq!(body["residency"]["kind"], "platform");
}

/// Ann's tenant is provisioning and its signing key failed for good. She
/// reads it: its status is still `Provisioning`, and its setup says it
/// failed at that step.
#[tokio::test]
async fn a_tenant_whose_setup_failed_says_so() {
    let mut setup = TenantSetup::begin(&test_tenant_for_ctx()).unwrap();
    setup
        .fail(SetupStep::SigningKey, UntrustedText::record("no key store"))
        .unwrap();
    let setups = Arc::new(FakeTenantSetupStore::empty());
    setups.save(&setup).await.unwrap();
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_setup_store: setups,
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenant(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["status"], "Provisioning");
    assert_eq!(
        body["setup"],
        json!({ "state": "failed", "failed_step": "signing_key" })
    );
}

/// An organization member lists the organization's tenants as a page.
#[tokio::test]
async fn a_member_lists_the_organizations_tenants() {
    let server = server();

    let response = server
        .get(&tenants())
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert!(page["items"].is_array());
    assert!(page.get("next_cursor").is_some());
}

/// An owner provisions a tenant and gets its id back.
#[tokio::test]
async fn a_member_provisions_a_tenant() {
    let server = server();

    let response = server
        .post(&tenants())
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "slug": "beta",
            "display_name": "Beta",
            "contact_email": "ops@beta.test",
            "timezone": "Europe/Berlin",
            "locale": "en-US"
        }))
        .await;

    response.assert_status(StatusCode::CREATED);
    assert!(response.json::<Value>()["id"].is_string());
}

/// A slug that is no slug is refused before the app sees it.
#[tokio::test]
async fn a_tenant_with_an_invalid_slug_is_refused() {
    let server = server();

    let response = server
        .post(&tenants())
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "slug": "Not A Slug!",
            "display_name": "Beta",
            "contact_email": "ops@beta.test",
            "timezone": "Europe/Berlin",
            "locale": "en-US"
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A tenant user's credential does not act on the organization's tenants:
/// provisioning is refused before any use case runs.
#[tokio::test]
async fn a_tenant_user_cannot_provision() {
    let server = server();

    let response = server
        .post(&tenants())
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "slug": "beta",
            "display_name": "Beta",
            "contact_email": "ops@beta.test",
            "timezone": "Europe/Berlin",
            "locale": "en-US"
        }))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A signed-out organization member receives 401 when listing tenants.
#[tokio::test]
async fn a_member_the_app_no_longer_honours_is_unauthenticated() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenants())
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// The sign-in settings read back whole, step-up policy included.
#[tokio::test]
async fn the_auth_config_reads_back_whole() {
    let server = server();

    let response = server
        .get(&tenant("/auth-config"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let config: Value = response.json();
    assert!(config["enabled_methods"].is_array());
    assert!(config["session_lifetime_secs"].is_u64());
    assert!(config["step_up"]["baseline_aal"].is_string());
}

/// Hostnames expose a permanent random label and leave readable names off.
#[tokio::test]
async fn the_hostnames_sit_under_the_base_domain() {
    let server = server();

    let response = server
        .get(&tenant("/hostname"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let names: Value = response.json();
    assert!(names["slug_subdomain"].is_null());
    assert_eq!(names["readable_address"], false);
    let label = names["platform_label"].as_str().unwrap();
    assert_eq!(
        names["uuid_subdomain"],
        format!(
            "{label}.{}",
            ianua_api::test_support::settings().base_domain
        )
    );
}

/// The compliance posture answers its three parts.
#[tokio::test]
async fn the_compliance_posture_reads_back() {
    let server = server();

    let response = server
        .get(&tenant("/compliance"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let posture: Value = response.json();
    assert!(posture["audit_retention_days"].is_u64());
    assert!(posture["operator_impersonation"].is_boolean());
}

/// The metrics overview is headed by what it shows of the tenant.
#[tokio::test]
async fn the_metrics_overview_names_the_tenant() {
    let server = server();

    let response = server
        .get(&tenant("/metrics"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let overview: Value = response.json();
    assert_eq!(overview["company"]["slug"], TENANT);
    assert!(overview["window"]["start"].is_string());
}

/// Changing tenant settings without authority returns 403.
#[tokio::test]
async fn a_settings_change_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .patch(&tenant(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"display_name": "Acme Two"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A body still naming the issuer, which moved to the sign-in settings, is
/// refused rather than silently dropped.
#[tokio::test]
async fn a_settings_change_naming_the_issuer_is_refused() {
    let server = server();

    let response = server
        .patch(&tenant(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"jwt_issuer": "https://issuer.acme.test"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann labels her tenant as staging, and the tenant reads back so.
#[tokio::test]
async fn a_tenant_labelled_staging_reads_back_staging() {
    let server = server();

    server
        .put(&tenant("/environment"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"environment": "staging"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let body: Value = server
        .get(&tenant(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(body["environment"], "staging");
}

/// A stage the platform does not know is refused before the app sees it.
#[tokio::test]
async fn an_unknown_environment_is_refused() {
    let response = server()
        .put(&tenant("/environment"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"environment": "prod"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A server whose organization has the test tenant and a staging tenant,
/// with the staging tenant's id.
fn with_staging() -> (TestServer, uuid::Uuid) {
    let staging = test_tenant_in(test_ctx().organization_id(), "staging", "staging.acme.com");
    let staging_id = *staging.id().as_uuid();
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_store: Arc::new(FakeTenantStore::holding_all([
            test_tenant_for_ctx(),
            staging,
        ])),
        ..adapters()
    }))
    .unwrap();
    (server, staging_id)
}

/// The test organization's clones, followed by `rest`.
fn clones(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenant-clones{rest}")
}

/// Bob copies the test tenant's settings and routes into the staging
/// tenant, then follows the copy.
#[tokio::test]
async fn a_member_starts_a_clone_and_follows_it() {
    let (server, staging) = with_staging();

    let started = server
        .post(&clones(""))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "source_tenant_id": test_ctx().tenant_id(),
            "target_tenant_id": staging,
            "parts": ["settings", "routes"],
        }))
        .await;

    started.assert_status(StatusCode::ACCEPTED);
    let id = started.json::<Value>()["id"].as_str().unwrap().to_owned();
    let clone: Value = server
        .get(&clones(&format!("/{id}")))
        .authorization_bearer(ORG_MEMBER)
        .await
        .json();
    assert_eq!(clone["state"], "copying");
    assert_eq!(clone["parts"], json!(["settings", "routes"]));
    assert_eq!(clone["copied"], json!([]));
}

/// A part the platform cannot copy, such as users, is refused before the
/// app sees it.
#[tokio::test]
async fn a_clone_naming_users_is_refused() {
    let (server, staging) = with_staging();

    let response = server
        .post(&clones(""))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "source_tenant_id": test_ctx().tenant_id(),
            "target_tenant_id": staging,
            "parts": ["users"],
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Reading an unknown tenant clone returns 404.
#[tokio::test]
async fn an_unknown_clone_is_not_found() {
    let response = server()
        .get(&clones(&format!("/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// The test tenant's audit streams, followed by `rest`.
fn streams(rest: &str) -> String {
    tenant(&format!("/audit-streams{rest}"))
}

/// A Splunk stream, with the caller's sign-in typed as `password`.
fn splunk_stream(password: &str) -> Value {
    json!({
        "name": "Splunk production",
        "destination": {
            "kind": "splunk",
            "endpoint": "https://splunk.example.com:8088/services/collector",
            "token": "hec-token-secret",
            "index": "ianua_audit",
        },
        "events": ["authentication.login_failed"],
        "proof": {"password": password},
    })
}

/// Ann adds a Splunk stream with her password typed again. It lists with
/// its address and index, active, and never with its token.
#[tokio::test]
async fn an_added_stream_lists_without_its_token() {
    let server = server();

    server
        .post(&streams(""))
        .authorization_bearer(TENANT_USER)
        .json(&splunk_stream(REENTERED_PASSWORD))
        .await
        .assert_status(StatusCode::CREATED);

    let listed = server
        .get(&streams(""))
        .authorization_bearer(TENANT_USER)
        .await;
    let streams: Value = listed.json();
    assert_eq!(streams[0]["destination"]["kind"], "splunk");
    assert_eq!(streams[0]["destination"]["index"], "ianua_audit");
    assert_eq!(streams[0]["state"], "active");
    assert_eq!(streams[0]["events"], json!(["authentication.login_failed"]));
    assert!(!listed.text().contains("hec-token-secret"));
}

/// Creating an audit stream with an incorrect password returns 403.
#[tokio::test]
async fn a_stream_without_the_right_password_is_forbidden() {
    let response = server()
        .post(&streams(""))
        .authorization_bearer(TENANT_USER)
        .json(&splunk_stream("not the password"))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A plan refusal makes audit-stream creation return 403.
#[tokio::test]
async fn a_stream_past_the_plan_limit_is_refused() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&streams(""))
        .authorization_bearer(TENANT_USER)
        .json(&splunk_stream(REENTERED_PASSWORD))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A destination that is no public HTTPS address is refused before the app
/// sees it.
#[tokio::test]
async fn a_stream_to_a_plain_http_address_is_refused() {
    let mut body = splunk_stream(REENTERED_PASSWORD);
    body["destination"]["endpoint"] = json!("http://splunk.example.com/services/collector");

    let response = server()
        .post(&streams(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Pausing a stream nobody added finds nothing to pause.
#[tokio::test]
async fn pausing_an_unknown_stream_is_not_found() {
    let response = server()
        .post(&streams(&format!("/{}/pause", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
