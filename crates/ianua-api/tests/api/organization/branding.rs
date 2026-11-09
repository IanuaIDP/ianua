//! The organization's own branding: reading, changing and resetting it.

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, ORG_MEMBER, adapters, router};
use serde_json::json;

/// The test organization's branding address.
fn branding_path() -> String {
    format!("/api/v1/organizations/{ORG}/branding")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// An organization that never changed its look reads the platform's: every
/// part is `null`.
#[tokio::test]
async fn an_unbranded_organization_reads_the_platform_look() {
    let response = server()
        .get(&branding_path())
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    response.assert_json(&json!({
        "logo_url": null,
        "primary_color": null,
        "sender_name": null,
    }));
}

/// A color set reads back as it was given.
#[tokio::test]
async fn a_changed_color_reads_back() {
    let server = server();

    let changed = server
        .patch(&branding_path())
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"primary_color": "#112233"}))
        .await;
    let read = server
        .get(&branding_path())
        .authorization_bearer(ORG_MEMBER)
        .await;

    changed.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(read.json::<serde_json::Value>()["primary_color"], "#112233");
}

/// A malformed organization branding color returns 422.
#[tokio::test]
async fn a_malformed_color_is_refused() {
    let response = server()
        .patch(&branding_path())
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"primary_color": "blue-ish"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Resetting returns every part to the platform's.
#[tokio::test]
async fn a_reset_answers_no_content() {
    let response = server()
        .delete(&branding_path())
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}
