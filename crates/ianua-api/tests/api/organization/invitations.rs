//! The invitation and address-confirmation endpoints, signed in and
//! public.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::json;

/// The test organization's address, followed by `rest`.
fn org_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// An invitation to an address that is not one is refused.
#[tokio::test]
async fn inviting_a_malformed_address_is_refused() {
    let response = server()
        .post(&org_path("/users"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"email": "nope", "display_name": "Bea"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Inviting without organization authority returns 403.
#[tokio::test]
async fn inviting_without_the_right_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&org_path("/users"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"email": "bea@acme.test", "display_name": "Bea"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Someone who cannot sign in asks for another verification link without
/// a session. The answer is the same whether or not the address is known.
#[tokio::test]
async fn asking_for_another_verification_link_answers_alike() {
    let response = server()
        .post("/api/v1/users/send-verification")
        .json(&json!({"email": "nobody@acme.test"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// The organization's own resend page answers alike too.
#[tokio::test]
async fn the_organization_resend_page_answers_alike() {
    let response = server()
        .post(&org_path("/users/send-verification"))
        .json(&json!({"email": "nobody@acme.test"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// A verification request for something that is not an address is
/// refused.
#[tokio::test]
async fn a_verification_request_for_a_malformed_address_is_refused() {
    let response = server()
        .post("/api/v1/users/send-verification")
        .json(&json!({"email": "nope"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A public page of an organization that does not exist is not found.
#[tokio::test]
async fn an_unknown_organization_has_no_invitation_page() {
    let response = server()
        .post("/api/v1/organizations/nobody/users/invitation-status")
        .json(&json!({"token": "anything"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Resending an unknown invitation link returns 404.
#[tokio::test]
async fn an_unknown_invitation_link_is_not_renewed() {
    let response = server()
        .post(&org_path("/users/invitation-resend"))
        .json(&json!({"token": "a-link-nobody-sent"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
