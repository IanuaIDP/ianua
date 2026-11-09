//! The authentication endpoints: what a sign-in page is told, what a
//! signed-in person reads of their own factors and devices, and how bodies
//! that are not well formed and app refusals are answered.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::authentication::{
    FakeMfaEnrollmentStore, FakeResetRequestStore, RecordingCodeSender,
};
use ianua_app::test_support::identity::{FakeUserStore, hash_of_link, stored_user};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::authentication::mfa::enrollment::EnrolledFactor;
use ianua_domain::domains::authentication::recovery::reset::{
    CreateResetParams, PasswordResetRequest, ResetInitiator,
};
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::types::{Lifetime, UserId};
use serde_json::{Value, json};

/// The test tenant's authentication address, followed by `rest`.
fn auth_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/auth{rest}")
}

/// A server over the default fake adapters.
fn server() -> TestServer {
    TestServer::new(router(adapters())).unwrap()
}

/// A server over these adapters.
fn server_over(adapters: Adapters) -> TestServer {
    TestServer::new(router(adapters)).unwrap()
}

/// A sign-in page asks what to offer besides a password, before anyone is
/// signed in, and is told in the shape it reads: two switches and a list of
/// identity providers.
#[tokio::test]
async fn a_sign_in_page_is_told_what_to_offer() {
    let response = server().get(&auth_path("/sign-in-options")).await;

    response.assert_status_ok();
    let options: Value = response.json();
    assert!(options["magic_link"].is_boolean());
    assert!(options["passkey"].is_boolean());
    assert!(options["connections"].is_array());
}

/// A tenant nobody has is not found, before any sign-in step runs.
#[tokio::test]
async fn an_unknown_tenant_is_not_found_before_anyone_signs_in() {
    let response = server()
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/nowhere/auth/sign-in-options"
        ))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A magic-link request with a malformed email address returns 422.
#[tokio::test]
async fn a_malformed_address_is_refused_before_a_link_is_mailed() {
    let response = server()
        .post(&auth_path("/magic-link"))
        .json(&json!({"email": "not an address"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Bob forgot his password, but the form cannot tell whether an address
/// has an account: an unknown one is answered like any other.
#[tokio::test]
async fn a_password_reset_answers_alike_for_an_unknown_address() {
    let response = server()
        .post(&auth_path("/password/reset-request"))
        .json(&json!({"email": "nobody@example.com"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// The reset link Ann's reset email carries.
const RESET_LINK: &str = "fake_refresh_0";

/// Adapters where Ann, whose factor mails her codes, holds a pending reset
/// link, and codes sent go to `sender`.
fn ann_resetting(sender: &Arc<RecordingCodeSender>) -> Adapters {
    let ann = UserId::new();
    let reset = PasswordResetRequest::create(
        &stored_user(ann, "ann@acme.test", UserStatus::Active),
        CreateResetParams {
            initiator: ResetInitiator::User,
            token_hash: hash_of_link(RESET_LINK),
            lifetime: Lifetime::seconds(3600).unwrap(),
        },
    )
    .unwrap();
    Adapters {
        reset_request_store: Arc::new(FakeResetRequestStore::with_request(&reset)),
        user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
        mfa_enrollment_store: Arc::new(FakeMfaEnrollmentStore::active_with_factor(
            ann,
            EnrolledFactor::EmailCode,
        )),
        factor_code_sender: sender.clone(),
        ..adapters()
    }
}

/// Ann forgot her password and her factor mails her codes. From her reset
/// link she asks for the code the reset needs, and it is mailed to her.
#[tokio::test]
async fn a_reset_link_sends_the_code_the_reset_asks_for() {
    let sender = Arc::new(RecordingCodeSender::default());
    let server = server_over(ann_resetting(&sender));

    let response = server
        .post(&auth_path("/password/reset-code"))
        .json(&json!({"token": RESET_LINK}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(sender.messages()[0].to, "ann@acme.test");
}

/// An unknown reset link receives 204 without sending a code.
#[tokio::test]
async fn an_unknown_reset_link_sends_no_code_and_answers_the_same() {
    let sender = Arc::new(RecordingCodeSender::default());
    let server = server_over(ann_resetting(&sender));

    let response = server
        .post(&auth_path("/password/reset-code"))
        .json(&json!({"token": "fake_refresh_9"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert!(sender.messages().is_empty());
}

/// A second reset-code request receives 429, leaving exactly one code sent.
#[tokio::test]
async fn a_second_reset_code_moments_later_is_refused() {
    let sender = Arc::new(RecordingCodeSender::default());
    let server = server_over(ann_resetting(&sender));
    let first = server
        .post(&auth_path("/password/reset-code"))
        .json(&json!({"token": RESET_LINK}))
        .await;
    first.assert_status(StatusCode::NO_CONTENT);

    let again = server
        .post(&auth_path("/password/reset-code"))
        .json(&json!({"token": RESET_LINK}))
        .await;

    again.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(sender.messages().len(), 1);
}

/// A usernameless passkey sign-in begins with a ceremony and a challenge
/// for the browser.
#[tokio::test]
async fn a_discoverable_passkey_sign_in_begins_with_a_challenge() {
    let response = server().post(&auth_path("/passkey/login/discover")).await;

    response.assert_status_ok();
    let challenge: Value = response.json();
    assert!(challenge["ceremony_id"].is_string());
    assert!(challenge["challenge"].is_string());
}

/// Ann has no second factor: her status says so, in the same shape as the
/// organization plane's.
#[tokio::test]
async fn the_mfa_status_of_someone_without_a_factor_is_off() {
    let response = server()
        .get(&auth_path("/mfa/status"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({"enabled": false, "method": null}));
}

/// Ann lists her trusted devices and has none yet.
#[tokio::test]
async fn a_person_without_trusted_devices_lists_none() {
    let response = server()
        .get(&auth_path("/device/trust"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({"devices": []}));
}

/// Ann, signed in and holding no second factor, asks what she may set up.
/// She is told the kinds offered, that she holds none, and owes nothing.
#[tokio::test]
async fn my_factor_options_say_what_i_hold_and_owe() {
    let response = server()
        .get(&auth_path("/mfa/options"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let options: Value = response.json();
    assert!(options["offered"].is_array());
    assert_eq!(options["held"]["state"], "none");
    assert_eq!(options["mfa_required"], false);
}

/// Requesting a code without an enrolled code factor returns 404.
#[tokio::test]
async fn a_code_for_no_factor_is_not_found() {
    let response = server()
        .post(&auth_path("/mfa/send-code"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// SMS enrollment without a phone number returns 422.
#[tokio::test]
async fn texted_codes_without_a_number_are_refused() {
    let response = server()
        .post(&auth_path("/mfa/enroll/code"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"method": "sms_code"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Regenerating recovery codes with an empty proof returns 422.
#[tokio::test]
async fn fresh_recovery_codes_need_a_proof() {
    let response = server()
        .post(&auth_path("/recovery-codes/regenerate"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing passkeys without a bearer credential returns 401.
#[tokio::test]
async fn listing_passkeys_needs_someone_signed_in() {
    let response = server().get(&auth_path("/passkeys")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// Denied tenant authority returns 403 from the passkey endpoint.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = server_over(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    });

    let response = server
        .get(&auth_path("/passkeys"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A break-glass request missing its grant returns 422.
#[tokio::test]
async fn a_break_glass_grant_of_nothing_is_refused() {
    let response = server()
        .post(&auth_path("/break-glass"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "user_id": uuid::Uuid::now_v7(),
            "reason": "incident 42",
            "duration_seconds": 600
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// MFA verification with a malformed session identifier returns 422.
#[tokio::test]
async fn a_code_for_a_malformed_session_is_refused() {
    let response = server()
        .post(&auth_path("/mfa/verify"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"session_id": "not-a-session", "code": "123456"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Confirming an authenticator for a different session than the bearer
/// identifies returns 403.
#[tokio::test]
async fn confirming_names_only_the_sign_in_of_the_bearer() {
    let response = server()
        .post(&auth_path("/mfa/enroll/confirm"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"code": "123456", "session_id": uuid::Uuid::now_v7()}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A bearer cannot request an MFA code for another session; the response is 403.
#[tokio::test]
async fn a_code_is_sent_only_for_the_sign_in_of_the_bearer() {
    let response = server()
        .post(&auth_path("/mfa/send-code"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"session_id": uuid::Uuid::now_v7()}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Signing out without a bearer credential returns 401.
#[tokio::test]
async fn signing_out_without_a_session_is_unauthenticated() {
    let response = server().post(&auth_path("/logout")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// The link that starts a single sign-on through connection `id`, with
/// the dashboard's `state`.
fn sso_begin(id: uuid::Uuid, state: &str) -> String {
    format!(
        "/api/v1/organizations/{ORG}/tenants/{TENANT}/federation/connections/{id}/login?state={state}"
    )
}

/// Starting single sign-on without dashboard state returns 422.
#[tokio::test]
async fn a_single_sign_on_without_the_dashboards_state_is_refused() {
    let response = server()
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/federation/connections/{}/login",
            uuid::Uuid::now_v7()
        ))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A dashboard value too short to be unguessable is refused.
#[tokio::test]
async fn a_short_dashboard_state_is_refused() {
    let response = server()
        .get(&sso_begin(uuid::Uuid::now_v7(), "short"))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// With a proper value the request goes on to the app, which looks for the
/// connection.
#[tokio::test]
async fn a_single_sign_on_with_the_dashboards_state_reaches_the_connection() {
    let state = "a-random-value-the-dashboard-keeps-0123456789";

    let response = server().get(&sso_begin(uuid::Uuid::now_v7(), state)).await;

    response.assert_status(StatusCode::NOT_FOUND);
}
