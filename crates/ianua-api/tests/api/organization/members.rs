//! The member endpoints: the listing, adding members and changing them.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use ianua_app::test_support::organization::{org_user_store_with, stored_caller};
use ianua_domain::domains::organization::members::membership::OrgRole;
use serde_json::{Value, json};

/// The test organization's address, followed by `rest`.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// The member listing answers a page.
#[tokio::test]
async fn the_member_listing_is_a_page() {
    let response = server()
        .get(&org_path("/users?status=PendingInvitation"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert!(page["items"].is_array());
    assert!(page.get("next_cursor").is_some());
}

/// A member added with an address that is not one is refused.
#[tokio::test]
async fn adding_a_member_with_a_malformed_address_is_refused() {
    let response = server()
        .post(&org_path("/users/create"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "email": "nope",
            "display_name": "Bea",
            "password": "Chosen-password-123!"
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A status no member can be moved to by hand is refused.
#[tokio::test]
async fn an_unknown_status_is_refused() {
    let response = server()
        .patch(&org_path(&format!(
            "/users/{}/status",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"status": "Invited"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Creating an organization member without authority returns 403.
#[tokio::test]
async fn adding_a_member_without_the_right_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&org_path("/users/create"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "email": "bea@acme.test",
            "display_name": "Bea",
            "password": "Chosen-password-123!"
        }))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A tenant credential receives 403 when listing organization members.
#[tokio::test]
async fn a_tenant_user_cannot_list_members() {
    let response = server()
        .get(&org_path("/users"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Unlinking an account with an address that is not one is refused.
#[tokio::test]
async fn unlinking_with_a_malformed_address_is_refused() {
    let response = server()
        .delete(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/identities"
        ))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"email": "nope", "tenant_id": uuid::Uuid::now_v7()}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann reads her own account and what it reaches, in the shape the
/// dashboard reads on almost every page.
#[tokio::test]
async fn a_member_reads_their_own_account() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_user_store: Arc::new(org_user_store_with([stored_caller(
            OrgRole::Owner,
            "Correct-Horse-Battery-9",
        )])),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&org_path("/me"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let me: Value = response.json();
    assert_eq!(me["email"], "caller@example.test");
    assert_eq!(me["role"], "Owner");
    assert_eq!(me["access"]["role"], "Owner");
    assert!(me["access"]["tenants"].is_array());
}

/// Transferring ownership to an unknown member returns 404.
#[tokio::test]
async fn ownership_cannot_go_to_an_unknown_member() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_user_store: Arc::new(org_user_store_with([stored_caller(
            OrgRole::Owner,
            "Correct-Horse-Battery-9",
        )])),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&org_path(&format!(
            "/users/{}/transfer-ownership",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
