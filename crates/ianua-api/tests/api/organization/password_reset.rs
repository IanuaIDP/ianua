//! A member's password reset, from the signed-out side.

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{adapters, router};
use serde_json::json;

/// Asking for a link answers alike whether or not the address has an
/// account.
#[tokio::test]
async fn asking_for_a_link_answers_alike_for_an_unknown_address() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/password/reset-request")
        .json(&json!({"email": "nobody@acme.test"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// Something that is not an address is refused.
#[tokio::test]
async fn asking_with_a_malformed_address_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/password/reset-request")
        .json(&json!({"email": "not an address"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A link nobody was sent is invalid, and carries no password policy.
#[tokio::test]
async fn an_unknown_link_reads_as_invalid() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/password/reset-status")
        .json(&json!({"token": "fake_refresh_0"}))
        .await;

    response.assert_json(&json!({"status": "Invalid"}));
}

/// A link nobody was sent cannot be replaced.
#[tokio::test]
async fn replacing_an_unknown_link_is_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/password/reset-resend")
        .json(&json!({"token": "fake_refresh_0"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Completing a reset on a link nobody was sent is not found.
#[tokio::test]
async fn completing_a_reset_on_an_unknown_link_is_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post("/api/v1/password/reset-confirm")
        .json(&json!({"token": "fake_refresh_0", "password": "A-new-passw0rd!"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
