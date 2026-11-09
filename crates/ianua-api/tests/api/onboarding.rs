//! The onboarding endpoints: whether signups are taken, asking for an
//! organization, confirming it from the link, and a member founding
//! another.

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, adapters, router};
use serde_json::{Value, json};

/// Another organization for a member to found, with the password of their
/// account there.
fn another_organization() -> Value {
    json!({
        "company_name": "Initech",
        "tenant_name": "Production",
        "password": "Correct-Horse-Battery-9",
    })
}

/// Creating another organization without a bearer credential returns 401.
#[tokio::test]
async fn founding_another_organization_needs_a_member() {
    let response = server()
        .post("/api/v1/organizations")
        .json(&another_organization())
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// An operator key receives 403 when used to create an organization.
#[tokio::test]
async fn an_operator_cannot_found_another_organization() {
    let response = server()
        .post("/api/v1/organizations")
        .authorization_bearer(OPERATOR)
        .json(&another_organization())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A public signup for this company, with Dana as its first admin at this
/// address.
fn signup_of(company: &str, email: &str) -> Value {
    json!({
        "company_name": company,
        "tenant_name": "Production",
        "admin_email": email,
        "admin_display_name": "Dana Founder",
        "admin_password": "Correct-Horse-Battery-9",
    })
}

/// The hosted service takes signups, and says so.
#[tokio::test]
async fn the_sign_in_page_learns_signups_are_open() {
    let response = server().get("/api/v1/signup").await;

    response.assert_json(&json!({"open": true}));
}

/// Dana signs up: nothing is made yet, and the answer tells her to check
/// her inbox for the link that founds her organization.
#[tokio::test]
async fn a_sign_up_waits_for_its_link() {
    let response = server()
        .post("/api/v1/signup")
        .json(&signup_of("Globex", "dana@globex.test"))
        .await;

    response.assert_status(StatusCode::ACCEPTED);
    response.assert_json(&json!({"status": "check_inbox"}));
}

/// An unknown sign-up link returns 404.
#[tokio::test]
async fn a_guessed_sign_up_link_founds_nothing() {
    let response = server()
        .post("/api/v1/signup/confirm")
        .json(&json!({"token": "guess"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An address that is not one is refused before anything is made.
#[tokio::test]
async fn an_invalid_address_is_refused() {
    let response = server()
        .post("/api/v1/signup")
        .json(&signup_of("Globex", "not an address"))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Signing up with an existing organization's slug returns 409.
#[tokio::test]
async fn a_taken_organization_slug_is_a_conflict() {
    let response = server()
        .post("/api/v1/signup")
        .json(&signup_of("Acme", "dana@acme.test"))
        .await;

    response.assert_status(StatusCode::CONFLICT);
}
