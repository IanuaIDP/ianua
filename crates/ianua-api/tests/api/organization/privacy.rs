//! Members' privacy: consent decisions and their history, and erasure.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::organization::{org_user_store_with, stored_caller};
use ianua_app::test_support::test_org_caller;
use ianua_domain::domains::organization::members::membership::OrgRole;
use serde_json::{Value, json};
use uuid::Uuid;

/// The test organization's address for the member `member`, followed by
/// `rest`.
fn member_path(member: Uuid, rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/users/{member}{rest}")
}

/// The test caller's own member id.
fn own_id() -> Uuid {
    *test_org_caller().member().as_uuid()
}

/// A server whose test caller is stored as the organization's owner.
fn with_the_caller_stored() -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        org_user_store: Arc::new(org_user_store_with([stored_caller(
            OrgRole::Owner,
            "Correct-Horse-Battery-9",
        )])),
        ..adapters()
    }))
    .unwrap()
}

/// Giving consent on another member's behalf returns 403.
#[tokio::test]
async fn consent_for_someone_else_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&member_path(Uuid::now_v7(), "/consent"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"consent_type": "Marketing", "version": "tos-2026-01", "granted": true}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A member who never decided anything reads an empty history.
#[tokio::test]
async fn a_member_reads_their_own_empty_consent_history() {
    let response = with_the_caller_stored()
        .get(&member_path(own_id(), "/consents"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let history: Value = response.json();
    assert_eq!(history, json!([]));
}

/// Requesting erasure for an unknown organization member returns 404.
#[tokio::test]
async fn erasing_an_unknown_member_is_not_found() {
    let response = with_the_caller_stored()
        .post(&member_path(Uuid::now_v7(), "/erasure"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
