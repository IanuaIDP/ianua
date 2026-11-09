//! The organization endpoints: reading and changing the organization, its
//! plan, its metrics and who may reach them.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::{Value, json};

/// The test organization's address, followed by `rest`.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// Ann reads her organization, in the shape the dashboard reads.
#[tokio::test]
async fn a_member_reads_their_organization() {
    let response = server()
        .get(&org_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let organization: Value = response.json();
    assert_eq!(organization["slug"], "acme");
    assert!(organization["status"].is_string());
    assert!(organization["plan"].is_string());
    assert!(organization["tenant_count"].is_number());
}

/// The operator lists every organization as a page.
#[tokio::test]
async fn an_operator_lists_organizations() {
    let response = server()
        .get("/api/v1/organizations")
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert!(page["items"].is_array());
}

/// An address that is not one is refused before anything changes.
#[tokio::test]
async fn an_update_with_a_malformed_address_is_refused() {
    let response = server()
        .patch(&org_path(""))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"contact_email": "not an address"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The sign-in settings read back whole.
#[tokio::test]
async fn the_sign_in_settings_read_back_whole() {
    let response = server()
        .get(&org_path("/auth-config"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let config: Value = response.json();
    assert!(config["enabled_methods"].is_array());
    assert!(config["step_up"]["baseline_aal"].is_string());
}

/// Reading an organization without authority returns 403.
#[tokio::test]
async fn a_member_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&org_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// An organization member receives 403 when changing its plan.
#[tokio::test]
async fn a_member_cannot_change_the_plan() {
    let response = server()
        .post(&org_path("/plan"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"plan": "Business"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A metrics window reaching back further than allowed is refused.
#[tokio::test]
async fn a_metrics_window_beyond_the_maximum_is_refused() {
    let response = server()
        .get(&org_path(
            "/metrics?since=2025-01-01T00:00:00Z&until=2026-01-01T00:00:00Z",
        ))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
