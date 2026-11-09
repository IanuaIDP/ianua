//! The operator endpoints: operator accounts, an operator's own keys,
//! impersonation grants and dead jobs and their retry, and what each
//! answers.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeOperatorAuthorities, Refusal};
use ianua_app::test_support::operator::{FakeOperatorStore, stored_operator, test_operator_id};
use ianua_app::test_support::scheduling::FakeJobQueue;
use ianua_domain::domains::operator::status::OperatorStatus;
use ianua_domain::domains::scheduling::job::{NextAttempt, ScheduledJob};
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::types::{JobId, OperatorId, UntrustedText};
use serde_json::{Value, json};

/// A server whose platform holds the test operator and Bob, another
/// operator.
fn with_two_operators() -> (TestServer, OperatorId) {
    let bob = OperatorId::new();
    let store = FakeOperatorStore::holding([
        stored_operator(
            test_operator_id(),
            "ops@example.test",
            OperatorStatus::Active,
        ),
        stored_operator(bob, "bob@example.test", OperatorStatus::Active),
    ]);
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        operator_store: Arc::new(store),
        ..adapters()
    }))
    .unwrap();
    (server, bob)
}

/// The test operator's own address, followed by `rest`.
fn own(rest: &str) -> String {
    format!("/api/v1/operators/{}{rest}", test_operator_id().as_uuid())
}

/// The operator listing is a page of accounts, each with its address,
/// status by name and creation time.
#[tokio::test]
async fn an_operator_lists_the_operators() {
    let (server, _) = with_two_operators();

    let response = server
        .get("/api/v1/operators")
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(2));
    let entry = &page["items"][0];
    assert!(entry["id"].is_string());
    assert!(entry["email"].is_string());
    assert_eq!(entry["status"], "Active");
    assert!(entry.get("created_at").is_some());
}

/// A new operator is created and their id answered.
#[tokio::test]
async fn an_operator_creates_another() {
    let (server, _) = with_two_operators();

    let response = server
        .post("/api/v1/operators")
        .authorization_bearer(OPERATOR)
        .json(&json!({"email": "carol@example.test", "password": "correct horse battery"}))
        .await;

    response.assert_status(StatusCode::CREATED);
    assert!(response.json::<Value>()["id"].is_string());
}

/// An address that is not one is refused before anything is stored.
#[tokio::test]
async fn an_invalid_address_is_refused() {
    let (server, _) = with_two_operators();

    let response = server
        .post("/api/v1/operators")
        .authorization_bearer(OPERATOR)
        .json(&json!({"email": "not an address", "password": "correct horse battery"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An operator that does not exist is not found.
#[tokio::test]
async fn an_unknown_operator_is_not_found() {
    let (server, _) = with_two_operators();

    let response = server
        .get(&format!("/api/v1/operators/{}", uuid::Uuid::now_v7()))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// An operator disables Bob; the answer is empty.
#[tokio::test]
async fn an_operator_disables_another() {
    let (server, bob) = with_two_operators();

    let response = server
        .post(&format!("/api/v1/operators/{}/disable", bob.as_uuid()))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// An operator asks to move Bob's address; the links go out and the
/// answer is empty.
#[tokio::test]
async fn an_operator_asks_to_move_anothers_address() {
    let (server, bob) = with_two_operators();

    let response = server
        .post(&format!("/api/v1/operators/{}/email", bob.as_uuid()))
        .authorization_bearer(OPERATOR)
        .json(&json!({"new_email": "robert@example.test", "org_slug": "acme"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// An operator makes a key of their own: the raw key is shown once, with
/// the prefix it is found by later.
#[tokio::test]
async fn an_operator_makes_a_key_of_their_own() {
    let (server, _) = with_two_operators();

    let response = server
        .post(&own("/keys"))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created: Value = response.json();
    assert!(created["raw_key"].is_string());
    assert!(created["key_prefix"].is_string());
}

/// Creating a key for another operator returns 404.
#[tokio::test]
async fn another_operators_keys_are_not_found() {
    let (server, bob) = with_two_operators();

    let response = server
        .post(&format!("/api/v1/operators/{}/keys", bob.as_uuid()))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Revoking every key says how many went.
#[tokio::test]
async fn revoking_every_key_says_how_many_went() {
    let (server, _) = with_two_operators();

    let response = server
        .post(&own("/keys/revoke-all"))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_json(&json!({"revoked": 0}));
}

/// A grant naming a tenant that is not an id is refused.
#[tokio::test]
async fn a_grant_with_a_malformed_tenant_is_refused() {
    let (server, _) = with_two_operators();

    let response = server
        .post(&own("/grants"))
        .authorization_bearer(OPERATOR)
        .json(&json!({
            "tenant_id": "nope",
            "user_id": uuid::Uuid::now_v7(),
            "reason": "Support ticket",
            "expires_at": "2099-01-01T00:00:00Z",
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Denied operator authority returns 403 from the operator list.
#[tokio::test]
async fn an_operator_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get("/api/v1/operators")
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A mail job that bounced on its only try, its payload naming Ann.
fn dead_mail() -> ScheduledJob {
    let mut job = ScheduledJob::new(
        JobType::new("mail.deliver").unwrap(),
        r#"{"to":"ann@acme.test"}"#.to_owned(),
        clock::now(),
        NonZeroU32::MIN,
    );
    job.mark_running().unwrap();
    job.mark_failed(UntrustedText::record("bounced"), NextAttempt::AsScheduled)
        .unwrap();
    job
}

/// A server whose queue holds one dead mail job.
fn with_a_dead_job() -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        job_queue: Arc::new(FakeJobQueue::with_jobs(vec![dead_mail()])),
        ..adapters()
    }))
    .unwrap()
}

/// Olga lists the dead jobs. She reads the bounced mail job, how often it
/// ran and why it failed, but never its payload naming Ann.
#[tokio::test]
async fn an_operator_lists_the_dead_jobs_without_their_payloads() {
    let server = with_a_dead_job();

    let response = server
        .get("/api/v1/operators/dead-jobs")
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let entry = &page["items"][0];
    assert_eq!(entry["job_type"], "mail.deliver");
    assert_eq!(entry["attempts"], 1);
    assert_eq!(entry["reason"], "bounced");
    assert!(entry["tenant_id"].is_null());
    assert!(entry.get("payload").is_none());
    assert!(!response.text().contains("ann@acme.test"));
}

/// A tenant credential receives 403 when listing platform dead jobs.
#[tokio::test]
async fn a_tenant_user_cannot_list_dead_jobs() {
    let server = with_a_dead_job();

    let response = server
        .get("/api/v1/operators/dead-jobs")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Denied operator authority returns 403 from the dead-job list.
#[tokio::test]
async fn an_operator_the_app_refuses_cannot_list_dead_jobs() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        job_queue: Arc::new(FakeJobQueue::with_jobs(vec![dead_mail()])),
        operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get("/api/v1/operators/dead-jobs")
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A server whose queue holds `job`, and the path retrying it.
fn holding(job: ScheduledJob) -> (TestServer, String) {
    let path = format!("/api/v1/operators/dead-jobs/{}/retry", job.id());
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        job_queue: Arc::new(FakeJobQueue::with_jobs(vec![job])),
        ..adapters()
    }))
    .unwrap();
    (server, path)
}

/// Olga retries the bounced mail: it answers no content and the mail
/// leaves the dead jobs. Retrying it again is a conflict.
#[tokio::test]
async fn an_operator_retries_a_dead_job_once() {
    let (server, retry) = holding(dead_mail());

    let first = server.post(&retry).authorization_bearer(OPERATOR).await;
    let again = server.post(&retry).authorization_bearer(OPERATOR).await;

    first.assert_status(StatusCode::NO_CONTENT);
    again.assert_status(StatusCode::CONFLICT);
    let listed: Value = server
        .get("/api/v1/operators/dead-jobs")
        .authorization_bearer(OPERATOR)
        .await
        .json();
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(0));
}

/// A job the queue does not hold is not found.
#[tokio::test]
async fn retrying_an_unknown_job_is_not_found() {
    let (server, _) = holding(dead_mail());

    let response = server
        .post(&format!(
            "/api/v1/operators/dead-jobs/{}/retry",
            JobId::new()
        ))
        .authorization_bearer(OPERATOR)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A tenant credential receives 403 when retrying a dead job, and the job
/// stays dead.
#[tokio::test]
async fn a_tenant_user_cannot_retry_a_dead_job() {
    let (server, retry) = holding(dead_mail());

    let response = server.post(&retry).authorization_bearer(TENANT_USER).await;

    response.assert_status(StatusCode::FORBIDDEN);
    let listed: Value = server
        .get("/api/v1/operators/dead-jobs")
        .authorization_bearer(OPERATOR)
        .await
        .json();
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));
}

/// A tenant credential receives 403 from the operator list.
#[tokio::test]
async fn a_tenant_user_cannot_reach_the_operators() {
    let (server, _) = with_two_operators();

    let response = server
        .get("/api/v1/operators")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
