//! A member's passkeys: listing, renaming, adding and signing in with one.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, Refusal};
use serde_json::{Value, json};

/// The test organization's passkey address, followed by `rest`.
fn passkey_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/passkeys{rest}")
}

/// A member without passkeys sees an empty list, in the shape the
/// dashboard reads.
#[tokio::test]
async fn a_member_lists_their_passkeys() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&passkey_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_json(&json!({"passkeys": []}));
}

/// A passkey the member does not hold reads as absent.
#[tokio::test]
async fn renaming_an_unknown_passkey_is_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .patch(&passkey_path(&format!("/{}", uuid::Uuid::now_v7())))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"name": "Laptop"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An attestation that is not base64url is refused before any ceremony is
/// read.
#[tokio::test]
async fn an_attestation_that_is_not_base64url_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&passkey_path("/register/confirm"))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "ceremony_id": uuid::Uuid::now_v7(),
            "response": "not base64url!",
            "passkey_name": "Laptop",
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The flat login page begins a passkey sign-in from any address: an
/// unknown one gets a challenge of the same shape.
#[tokio::test]
async fn a_passkey_sign_in_begins_from_an_address() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/passkey/login")
        .json(&json!({"email": "nobody@acme.test"}))
        .await;

    response.assert_status_ok();
    let challenge: Value = response.json();
    assert!(challenge["ceremony_id"].is_string());
    assert!(challenge["challenge"].is_string());
}

/// A discoverable sign-in begins with no address at all.
#[tokio::test]
async fn a_discoverable_passkey_sign_in_begins() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server.post("/api/v1/passkey/login/discover").await;

    response.assert_status_ok();
}

/// Something that is not an address is refused.
#[tokio::test]
async fn a_passkey_sign_in_from_a_malformed_address_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/passkey/login")
        .json(&json!({"email": "not an address"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A signed-out session receives 401 when listing organization passkeys.
#[tokio::test]
async fn a_session_the_app_no_longer_honours_is_unauthenticated() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&passkey_path(""))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}
