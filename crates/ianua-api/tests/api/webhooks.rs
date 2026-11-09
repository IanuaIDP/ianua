//! The webhook endpoints: a tenant's subscriptions, their signing secrets
//! and delivery history, in the shape the dashboard reads.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::webhooks::{
    FakeWebhookStore, ShutWebhookSendThrottle, test_attempt, test_message, test_subscription,
};
use ianua_app::test_support::{RejectingLimitEnforcer, test_ctx};
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use serde_json::{Value, json};

/// The test tenant's webhook address, followed by `rest`.
fn webhooks_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/webhooks{rest}")
}

/// A server whose test tenant holds `subscription`.
fn holding(
    subscription: &WebhookSubscription<ResolvedTenant>,
) -> (TestServer, Arc<FakeWebhookStore>) {
    let store = Arc::new(FakeWebhookStore::holding(
        test_ctx().tenant_id(),
        subscription,
    ));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        webhook_store: store.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, store)
}

/// A subscription body sending user sign-ups to one URL.
fn new_subscription() -> Value {
    json!({
        "url": "https://hooks.example.com/ianua",
        "event_types": [{"Identity": "UserRegistered"}],
        "description": "user sign-ups",
    })
}

/// Ann subscribes a URL to user registrations. She gets the signing secret
/// once, and the listing shows the subscription without it.
#[tokio::test]
async fn a_created_subscription_hands_out_its_secret_once() {
    let server = TestServer::new(router(adapters())).unwrap();

    let created = server
        .post(&webhooks_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&new_subscription())
        .await;
    created.assert_status(StatusCode::CREATED);
    let answer: Value = created.json();
    assert!(!answer["signing_secret"].as_str().unwrap().is_empty());

    let listed = server
        .get(&webhooks_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    listed.assert_status_ok();
    let page: Value = listed.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let entry = &page["items"][0];
    assert_eq!(entry["id"], answer["id"]);
    assert_eq!(entry["url"], "https://hooks.example.com/ianua");
    assert_eq!(
        entry["event_types"],
        json!([{"Identity": "UserRegistered"}])
    );
    assert_eq!(entry["status"], "Active");
    assert_eq!(entry["description"], "user sign-ups");
    assert!(
        entry.get("signing_secret").is_none(),
        "the secret is shown once"
    );
}

/// Creating a webhook with a localhost URL returns 422.
#[tokio::test]
async fn an_internal_url_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();
    let mut body = new_subscription();
    body["url"] = json!("https://localhost/hook");

    let response = server
        .post(&webhooks_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A plan refusal returns 403 and leaves the webhook store empty.
#[tokio::test]
async fn a_subscription_past_the_plan_limit_is_refused() {
    let store = Arc::new(FakeWebhookStore::empty());
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        webhook_store: store.clone(),
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&webhooks_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&new_subscription())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(store.count(), 0);
}

/// Rotating the secret hands out a new one.
#[tokio::test]
async fn rotating_the_secret_hands_out_a_new_one() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, _) = holding(&subscription);

    let response = server
        .post(&webhooks_path(&format!(
            "/{}/rotate-secret",
            subscription.id().as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert!(
        !response.json::<Value>()["signing_secret"]
            .as_str()
            .unwrap()
            .is_empty()
    );
}

/// A paused subscription resumes, and is deleted once paused again.
#[tokio::test]
async fn a_subscription_is_walked_through_its_life() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, store) = holding(&subscription);
    let at = |rest: &str| webhooks_path(&format!("/{}{rest}", subscription.id().as_uuid()));

    for step in ["/pause", "/resume", "/pause"] {
        server
            .post(&at(step))
            .authorization_bearer(TENANT_USER)
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }
    server
        .delete(&at(""))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(store.count(), 0);
}

/// Deleting an active webhook subscription returns 409.
#[tokio::test]
async fn an_active_subscription_is_not_deleted() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, _) = holding(&subscription);

    let response = server
        .delete(&webhooks_path(&format!("/{}", subscription.id().as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::CONFLICT);
}

/// The deliveries list how each try ended and what the receiver answered.
#[tokio::test]
async fn deliveries_list_how_each_try_ended() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, store) = holding(&subscription);
    let message = test_message(*subscription.id());
    let attempt = test_attempt(&message, 200);
    let message_id = *message.id.as_uuid();
    store.sent(test_ctx().tenant_id(), message, attempt);

    let response = server
        .get(&webhooks_path(&format!(
            "/{}/deliveries",
            subscription.id().as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let attempt = &response.json::<Value>()["items"][0];
    assert_eq!(attempt["status"], "Success");
    assert_eq!(attempt["response_status"], 200);
    assert_eq!(attempt["message_id"], json!(message_id));
    assert_eq!(attempt["event_type"], json!({"Identity": "UserRegistered"}));
}

/// Ann changes where a webhook delivers and clears its description. The
/// answer is the subscription as it now stands.
#[tokio::test]
async fn an_update_changes_only_what_it_names() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, _) = holding(&subscription);

    let response = server
        .patch(&webhooks_path(&format!("/{}", subscription.id().as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"url": "https://hooks.example.com/v2", "retry": "Patient"}))
        .await;

    response.assert_status_ok();
    let answer: Value = response.json();
    assert_eq!(answer["url"], "https://hooks.example.com/v2");
    assert_eq!(answer["retry"], "Patient");
    assert_eq!(
        answer["event_types"],
        json!([{"Identity": "UserRegistered"}])
    );
}

/// Changing a webhook URL to localhost returns 422.
#[tokio::test]
async fn an_update_to_an_internal_url_is_refused() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, _) = holding(&subscription);

    let response = server
        .patch(&webhooks_path(&format!("/{}", subscription.id().as_uuid())))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"url": "https://localhost/hook"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A rotation that keeps the old secret signing for an hour hands out the
/// new one, and the subscription now signs with both.
#[tokio::test]
async fn a_rotation_with_an_overlap_keeps_the_old_secret_signing() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, store) = holding(&subscription);

    let response = server
        .post(&webhooks_path(&format!(
            "/{}/rotate-secret",
            subscription.id().as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"overlap_seconds": 3600}))
        .await;

    response.assert_status_ok();
    let stored = store
        .stored(test_ctx().tenant_id(), subscription.id())
        .unwrap();
    assert_eq!(stored.signing_secrets().len(), 2);
}

/// A thirty-day signing-secret overlap exceeds the limit and returns 422.
#[tokio::test]
async fn a_rotation_overlap_past_seven_days_is_refused() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, _) = holding(&subscription);

    let response = server
        .post(&webhooks_path(&format!(
            "/{}/rotate-secret",
            subscription.id().as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"overlap_seconds": 30 * 86_400}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The event catalog lists what a webhook may receive, never the record of
/// a webhook's own delivery.
#[tokio::test]
async fn the_event_catalog_leaves_out_webhook_deliveries() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&webhooks_path("/event-types"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let entries: Vec<Value> = response.json();
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|entry| entry["name"] != "webhooks.delivery_attempted")
    );
}

/// Ann sends her webhook a test event. The attempt comes back and is kept
/// in the history.
#[tokio::test]
async fn a_test_event_is_sent_and_kept() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, store) = holding(&subscription);

    let response = server
        .post(&webhooks_path(&format!(
            "/{}/test",
            subscription.id().as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"event_type": {"Identity": "UserRegistered"}}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["status"], "Success");
    assert_eq!(store.attempts_in(test_ctx().tenant_id()).len(), 1);
}

/// A closed send throttle makes the webhook test-event request return 429.
#[tokio::test]
async fn a_test_event_sent_too_soon_is_held_back() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let store = Arc::new(FakeWebhookStore::holding(
        test_ctx().tenant_id(),
        &subscription,
    ));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        webhook_store: store,
        webhook_send_throttle: Arc::new(ShutWebhookSendThrottle),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&webhooks_path(&format!(
            "/{}/test",
            subscription.id().as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"event_type": {"Identity": "UserRegistered"}}))
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// Resending an unknown webhook delivery attempt returns 404.
#[tokio::test]
async fn a_resend_of_an_unknown_attempt_is_not_found() {
    let subscription = test_subscription(
        "https://hooks.example.com/ianua",
        WebhookSubscriptionStatus::Active,
    );
    let (server, _) = holding(&subscription);

    let response = server
        .post(&webhooks_path(&format!(
            "/{}/deliveries/{}/resend",
            subscription.id().as_uuid(),
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Listing webhooks without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&webhooks_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
