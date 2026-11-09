//! A member's second factor: status, confirming, answering and turning it
//! off.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::json;

/// The test organization's second-factor address, followed by `rest`.
fn mfa_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/mfa{rest}")
}

/// A member without a second factor reads that it is off, in the shape the
/// dashboard reads.
#[tokio::test]
async fn a_member_without_a_factor_reads_it_is_off() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&mfa_path("/status"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_json(&json!({"enabled": false, "method": null}));
}

/// A code is what verification is about: a body without one is refused.
#[tokio::test]
async fn verifying_without_a_code_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&mfa_path("/verify"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A waiting sign-in named by something that is not a session id is
/// refused.
#[tokio::test]
async fn confirming_with_a_malformed_session_id_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&mfa_path("/confirm"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"code": "123456", "session_id": "not-a-uuid"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Turning off a factor the member never set up finds nothing to turn off.
#[tokio::test]
async fn turning_off_a_factor_never_set_up_is_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .delete(&mfa_path(""))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"code": "123456"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A signed-out session receives 401 when reading MFA status.
#[tokio::test]
async fn a_session_the_app_no_longer_honours_is_unauthenticated() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&mfa_path("/status"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An empty organization recovery code returns 422.
#[tokio::test]
async fn an_empty_recovery_code_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&mfa_path("/recovery"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"code": ""}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Regenerating organization recovery codes without password proof returns 422.
#[tokio::test]
async fn new_recovery_codes_need_the_password_again() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&mfa_path("/recovery-codes"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
