//! Password sign-in under a flood: the challenge a device nobody trusted
//! is asked for while a tenant's or the platform's failures are high, the
//! busy answer when no password check can start, and the threshold in the
//! sign-in settings.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use ianua_api::test_support::{ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::ports::authentication::FailureScope;
use ianua_app::test_support::authentication::{
    BusyHashPermits, FakeChallengeIssuer, FakeChallengeVerifier, FakeSignInFailureBudget,
};
use ianua_app::test_support::test_ctx;
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::authentication::risk_engine::pressure::DEFAULT_FAILURE_THRESHOLD;
use serde_json::{Value, json};

const SOLVED: &str = "solved-puzzle-0042";

/// The test tenant's password sign-in address.
fn tenant_login() -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/login")
}

/// The fakes with `scope` already at the default threshold of failures,
/// and a proof-of-work provider passing [`SOLVED`] once.
fn flooded(scope: FailureScope) -> Adapters {
    let failures = u64::from(DEFAULT_FAILURE_THRESHOLD);
    Adapters {
        sign_in_failure_budget: Arc::new(FakeSignInFailureBudget::over(scope, failures)),
        challenge_verifier: Some(Arc::new(FakeChallengeVerifier::accepting(SOLVED))),
        ..adapters()
    }
}

/// The test tenant's count of failures, at its threshold.
fn tenant_flooded() -> Adapters {
    flooded(FailureScope::Tenant(test_ctx().tenant_id()))
}

/// A server over `adapters`.
fn server(adapters: Adapters) -> TestServer {
    TestServer::new(router(adapters)).unwrap()
}

/// Signs in to the test tenant as `email`, sending `proof` as the
/// challenge proof when there is one.
async fn sign_in(server: &TestServer, email: &str, proof: Option<&str>) -> TestResponse {
    let body = json!({
        "email": email,
        "password": "correct horse battery staple",
        "challenge_proof": proof,
    });
    server.post(&tenant_login()).json(&body).await
}

/// A sign-in under tenant pressure returns 401 and names the required
/// proof-of-work challenge.
#[tokio::test]
async fn a_sign_in_under_pressure_is_told_which_challenge_to_solve() {
    let server = server(tenant_flooded());

    let response = sign_in(&server, "ann@acme.test", None).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["error"], "challenge_required");
    assert_eq!(body["challenge"], "proof_of_work");
}

/// Two email addresses receive identical challenge statuses and bodies
/// while the tenant is under pressure.
#[tokio::test]
async fn the_challenge_answers_alike_for_every_address() {
    let server = server(tenant_flooded());

    let first = sign_in(&server, "ann@acme.test", None).await;
    let second = sign_in(&server, "nobody@acme.test", None).await;

    assert_eq!(first.status_code(), second.status_code());
    assert_eq!(first.json::<Value>(), second.json::<Value>());
}

/// Ann solves the challenge and sends its proof. She gets past it, on to
/// the password, where her address is unknown to this tenant.
#[tokio::test]
async fn a_passed_challenge_reaches_the_password() {
    let server = server(tenant_flooded());

    let response = sign_in(&server, "ann@acme.test", Some(SOLVED)).await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Without a challenge provider, a pressured sign-in returns challenge_required
/// with status 401 and no challenge field.
#[tokio::test]
async fn with_no_provider_the_answer_names_no_challenge() {
    let server = server(Adapters {
        challenge_verifier: None,
        ..tenant_flooded()
    });

    let response = sign_in(&server, "ann@acme.test", Some(SOLVED)).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["error"], "challenge_required");
    assert!(body.get("challenge").is_none());
}

/// An empty proof is refused before anything is checked.
#[tokio::test]
async fn a_malformed_proof_is_refused() {
    let server = server(tenant_flooded());

    let response = sign_in(&server, "ann@acme.test", Some("")).await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Every password check the node may run is running. The sign-in is told
/// `429` with a short `Retry-After`, so the page tries again in a moment.
#[tokio::test]
async fn a_busy_node_answers_too_many_requests_with_retry_after() {
    let server = server(Adapters {
        password_hash_permits: Arc::new(BusyHashPermits),
        ..adapters()
    });

    let response = sign_in(&server, "ann@acme.test", None).await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after"), "1");
}

/// Organization sign-in under global pressure returns 401 with a
/// proof-of-work challenge.
#[tokio::test]
async fn an_organization_sign_in_under_pressure_is_challenged() {
    let server = server(flooded(FailureScope::UnnamedOrganizations));

    let response = server
        .post("/api/v1/login")
        .json(&json!({"email": "nobody@acme.test", "password": "whatever"}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["error"], "challenge_required");
    assert_eq!(body["challenge"], "proof_of_work");
}

/// A tenant's sign-in settings name the failures that put its sign-in
/// under pressure: the default when it never set its own.
#[tokio::test]
async fn the_tenant_sign_in_settings_name_the_challenge_threshold() {
    let response = server(adapters())
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/auth-config"
        ))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let config: Value = response.json();
    assert_eq!(config["challenge_threshold"], DEFAULT_FAILURE_THRESHOLD);
}

/// An organization's sign-in settings name their challenge threshold too.
#[tokio::test]
async fn the_organization_sign_in_settings_name_the_challenge_threshold() {
    let response = server(adapters())
        .get(&format!("/api/v1/organizations/{ORG}/auth-config"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    response.assert_status_ok();
    let config: Value = response.json();
    assert_eq!(config["challenge_threshold"], DEFAULT_FAILURE_THRESHOLD);
}

/// A browser asked for a puzzle asks for one, and is set it.
#[tokio::test]
async fn a_browser_is_set_a_puzzle() {
    let server = TestServer::new(router(Adapters {
        challenge_issuer: Some(Arc::new(FakeChallengeIssuer)),
        ..adapters()
    }))
    .unwrap();

    let response = server.post("/api/v1/sign-in/puzzle").await;

    response.assert_status_ok();
    let puzzle: Value = response.json();
    assert_eq!(puzzle["challenge"], "puzzle");
    assert_eq!(puzzle["difficulty_bits"], 8);
}

/// A deployment whose challenge is Turnstile sets no puzzle of its own.
#[tokio::test]
async fn a_deployment_setting_no_puzzle_answers_not_found() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server.post("/api/v1/sign-in/puzzle").await;

    response.assert_status(StatusCode::NOT_FOUND);
}
