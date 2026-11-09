//! The signal stream endpoints: a tenant's receivers of security signals,
//! their deliveries, a receiver confirming its endpoint, and the endpoints
//! a receiver calls with its stream's key.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::signals::{
    FakeSignalStreamStore, TEST_CHALLENGE, TEST_RECEIVER_KEY, test_stream,
};
use ianua_app::test_support::test_ctx;
use ianua_domain::domains::signals::delivery::{SignalDelivery, SignalDeliveryAttempt};
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{
    DeliveryMethod, SignalStreamRow, StreamStatus, StreamVerificationStatus,
};
use ianua_domain::domains::signals::subjects::StreamSubjects;
use ianua_domain::types::{DeliveryOutcome, SignalDeliveryId, SignalId, SignalStreamId};
use serde_json::{Value, json};

/// The test tenant's signal stream address, followed by `rest`.
fn streams_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/streams{rest}")
}

/// A server whose test tenant holds one stream in `status`, its endpoint
/// verified or waiting on the test challenge.
fn holding(
    status: StreamStatus,
    verification: StreamVerificationStatus,
) -> (TestServer, Arc<FakeSignalStreamStore>, SignalStreamId) {
    holding_row(test_stream(status, verification))
}

/// A server whose test tenant holds the stream `row`.
fn holding_row(row: SignalStreamRow) -> (TestServer, Arc<FakeSignalStreamStore>, SignalStreamId) {
    let id = row.id;
    let store = Arc::new(FakeSignalStreamStore::holding(test_ctx().tenant_id(), row));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        signal_stream_store: store.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, store, id)
}

/// Ann registers a push stream for revoked sessions. It is listed, active,
/// with its endpoint waiting to confirm itself.
#[tokio::test]
async fn a_registered_stream_waits_on_its_endpoint() {
    let server = TestServer::new(router(adapters())).unwrap();

    let created = server
        .post(&streams_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "endpoint": "https://payroll.example.com/sse",
            "delivery_method": "Push",
            "signal_types": ["SessionRevoked"],
        }))
        .await;
    created.assert_status(StatusCode::CREATED);

    let page: Value = server
        .get(&streams_path(""))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let stream = &page["items"][0];
    assert_registered_push_stream(stream, &created.json::<Value>());
}

/// Checks the registered stream's state and that its key is shown only at creation.
fn assert_registered_push_stream(stream: &Value, created: &Value) {
    assert_eq!(stream["id"], created["id"]);
    assert_eq!(stream["endpoint"], "https://payroll.example.com/sse");
    assert_eq!(stream["verification"], "Pending");
    assert_eq!(stream["delivery_method"], "Push");
    assert_eq!(stream["signal_types"], json!(["SessionRevoked"]));
    assert_eq!(stream["status"], "Active");
    assert!(
        !created["receiver_key"].as_str().unwrap().is_empty(),
        "the receiver's key is handed out at registration"
    );
    assert!(
        stream.get("receiver_key").is_none(),
        "the key is shown once"
    );
}

/// The stream's receiver stops hearing about a user, signed in with its
/// stream's key.
#[tokio::test]
async fn the_receiver_removes_a_subject_with_its_key() {
    let (server, store, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);

    let response = server
        .post(&streams_path(&format!("/{}/subjects/remove", id.as_uuid())))
        .authorization_bearer(TEST_RECEIVER_KEY)
        .json(&json!({"subject": {"format": "opaque", "id": uuid::Uuid::now_v7()}}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert!(matches!(
        store.stored(&id).subjects(),
        StreamSubjects::AllExcept(removed) if removed.len() == 1
    ));
}

/// A guessed receiver key returns 401 when adding a stream subject.
#[tokio::test]
async fn a_key_that_is_not_the_streams_is_refused() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);

    let response = server
        .post(&streams_path(&format!("/{}/subjects/add", id.as_uuid())))
        .authorization_bearer("receiver-key-guessed")
        .json(&json!({"subject": {"format": "opaque", "id": uuid::Uuid::now_v7()}}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// Requesting stream verification without a receiver key returns 401.
#[tokio::test]
async fn a_receiver_call_without_a_key_is_unauthenticated() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);

    let response = server
        .post(&streams_path(&format!("/{}/verify", id.as_uuid())))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// The receiver asks its stream for a verification event, carrying back a
/// state of its own.
#[tokio::test]
async fn the_receiver_asks_for_a_verification_event() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);

    let response = server
        .post(&streams_path(&format!("/{}/verify", id.as_uuid())))
        .authorization_bearer(TEST_RECEIVER_KEY)
        .json(&json!({"state": "check-42"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

/// The receiver of a poll stream polls it with its key: nothing waits, and
/// the answer says so in RFC 8936's words.
#[tokio::test]
async fn a_poll_stream_hands_its_receiver_what_waits() {
    let row = SignalStreamRow {
        delivery_method: DeliveryMethod::Poll,
        ..test_stream(StreamStatus::Active, StreamVerificationStatus::Verified)
    };
    let (server, _, id) = holding_row(row);

    let response = server
        .post(&streams_path(&format!("/{}/poll", id.as_uuid())))
        .authorization_bearer(TEST_RECEIVER_KEY)
        .json(&json!({"maxEvents": 10, "ack": []}))
        .await;

    response.assert_status_ok();
    let answer: Value = response.json();
    assert_eq!(answer["sets"], json!({}));
    assert_eq!(answer["moreAvailable"], false);
}

/// Polling a push stream returns 409.
#[tokio::test]
async fn a_push_stream_is_not_polled() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);

    let response = server
        .post(&streams_path(&format!("/{}/poll", id.as_uuid())))
        .authorization_bearer(TEST_RECEIVER_KEY)
        .await;

    response.assert_status(StatusCode::CONFLICT);
}

/// A stream's status reads in the Shared Signals framework's words.
#[tokio::test]
async fn a_paused_stream_reads_as_paused() {
    let (server, _, id) = holding(StreamStatus::Paused, StreamVerificationStatus::Verified);

    let response = server
        .get(&streams_path(&format!("/{}/status", id.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["status"], "paused");
}

/// Anyone reads the transmitter's configuration, which names push and poll
/// delivery and the tenant's keys.
#[tokio::test]
async fn the_transmitter_configuration_is_public() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&format!(
            "/api/v1/organizations/{ORG}/tenants/{TENANT}/.well-known/ssf-configuration"
        ))
        .await;

    response.assert_status_ok();
    let configuration: Value = response.json();
    assert_eq!(configuration["spec_version"], "1_0");
    assert_eq!(
        configuration["delivery_methods_supported"],
        json!(["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"])
    );
    assert!(
        configuration["jwks_uri"]
            .as_str()
            .unwrap()
            .ends_with("/.well-known/jwks.json")
    );
}

/// Registering a push stream with a localhost endpoint returns 422.
#[tokio::test]
async fn an_internal_endpoint_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&streams_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "endpoint": "https://localhost/sse",
            "delivery_method": "Push",
            "signal_types": ["SessionRevoked"],
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The receiver echoes the challenge it was sent, and the stream reads as
/// verified from then on.
#[tokio::test]
async fn the_echoed_challenge_verifies_the_endpoint() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Pending);

    server
        .post(&streams_path(&format!("/{}/confirm", id.as_uuid())))
        .json(&json!({"challenge": TEST_CHALLENGE}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let stream: Value = server
        .get(&streams_path(&format!("/{}", id.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(stream["verification"], "Verified");
}

/// Confirming a stream with an incorrect challenge returns 403.
#[tokio::test]
async fn a_wrong_echo_is_forbidden() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Pending);

    let response = server
        .post(&streams_path(&format!("/{}/confirm", id.as_uuid())))
        .json(&json!({"challenge": "a-guess-at-the-challenge-00000000000000"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A paused stream resumes, and a disabled one is deleted for good.
#[tokio::test]
async fn a_stream_is_walked_through_its_life() {
    let (server, store, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);
    let stream = |rest: &str| streams_path(&format!("/{}{rest}", id.as_uuid()));

    for step in ["/pause", "/resume", "/disable"] {
        server
            .post(&stream(step))
            .authorization_bearer(TENANT_USER)
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }
    server
        .delete(&stream(""))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(store.count(), 0);
}

/// Resuming a stream that is not paused is a move it cannot make.
#[tokio::test]
async fn resuming_an_active_stream_is_refused() {
    let (server, _, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);

    let response = server
        .post(&streams_path(&format!("/{}/resume", id.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A stream's deliveries list how each push ended and what the receiver
/// answered.
#[tokio::test]
async fn deliveries_list_how_each_push_ended() {
    let (server, store, id) = holding(StreamStatus::Active, StreamVerificationStatus::Verified);
    store.attempts.lock().unwrap().push((
        test_ctx().tenant_id(),
        SignalDeliveryAttempt {
            id: SignalDeliveryId::new(),
            stream_id: id,
            signal_id: SignalId::new(),
            signal_type: SecuritySignalType::SessionRevoked,
            delivery: SignalDelivery::Pushed(DeliveryOutcome::Answered { code: 503 }),
            duration_ms: 40,
            attempt_number: 0,
            attempted_at: time::OffsetDateTime::now_utc(),
        },
    ));

    let response = server
        .get(&streams_path(&format!("/{}/deliveries", id.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let attempt = &response.json::<Value>()["items"][0];
    assert_eq!(attempt["status"], "Failed");
    assert_eq!(attempt["response_status"], 503);
    assert_eq!(attempt["signal_type"], "SessionRevoked");
}

/// What a receiver's confirm call to `org`/`tenant` answers on `server`,
/// for a stream id nobody was given.
async fn confirm_status(server: &TestServer, org: &str, tenant: &str) -> StatusCode {
    server
        .post(&format!(
            "/api/v1/organizations/{org}/tenants/{tenant}/streams/{}/confirm",
            uuid::Uuid::now_v7()
        ))
        .json(&json!({"challenge": TEST_CHALLENGE}))
        .await
        .status_code()
}

/// What a receiver's keyed call to `org`/`tenant` answers on `server`, for
/// a stream id nobody was given.
async fn keyed_status(server: &TestServer, org: &str, tenant: &str) -> StatusCode {
    server
        .post(&format!(
            "/api/v1/organizations/{org}/tenants/{tenant}/streams/{}/subjects/remove",
            uuid::Uuid::now_v7()
        ))
        .authorization_bearer(TEST_RECEIVER_KEY)
        .json(&json!({"subject": {"format": "opaque", "id": uuid::Uuid::now_v7()}}))
        .await
        .status_code()
}

/// A server whose test tenant was suspended.
fn suspended() -> TestServer {
    TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_store: ianua_app::test_support::tenant::tenant_store_in_status(
            ianua_domain::domains::tenant::status::TenantStatus::Suspended,
        ),
        ..adapters()
    }))
    .unwrap()
}

/// Receiver confirmation and keyed subject calls all return 401 for
/// unknown tenants, suspended tenants and active tenants without the stream.
#[tokio::test]
async fn receiver_routes_answer_alike_for_unknown_closed_and_open_tenants() {
    let open = TestServer::new(router(adapters())).unwrap();
    let closed = suspended();

    let answers = [
        confirm_status(&open, ORG, "nobody-here").await,
        confirm_status(&closed, ORG, TENANT).await,
        confirm_status(&open, ORG, TENANT).await,
        keyed_status(&open, ORG, "nobody-here").await,
        keyed_status(&closed, ORG, TENANT).await,
        keyed_status(&open, ORG, TENANT).await,
    ];

    assert!(
        answers
            .iter()
            .all(|status| *status == StatusCode::UNAUTHORIZED),
        "{answers:?}"
    );
}

/// Listing signal streams without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&streams_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
