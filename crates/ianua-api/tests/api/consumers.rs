//! The consumer endpoints: a tenant's machine identities, in the shape the
//! dashboard reads.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::RejectingLimitEnforcer;
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::consumers::{
    FakeConsumerStore, billing_sync, billing_sync_overlapping, consumers_of_test_tenant,
    disabled_billing_sync,
};
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::isolation::scope::ResolvedTenant;
use serde_json::{Value, json};

/// The test tenant's consumer address, followed by `rest`.
fn consumers_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/consumers{rest}")
}

/// A server whose test tenant holds `consumer`.
fn holding(consumer: Consumer<ResolvedTenant>) -> (TestServer, Arc<FakeConsumerStore>, String) {
    let id = consumer.id().as_uuid().to_string();
    let store = consumers_of_test_tenant(consumer);
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        consumer_store: store.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, store, id)
}

/// A request to register a consumer with an API key the platform makes.
fn new_key() -> Value {
    json!({
        "name": "payment-processor",
        "credential_kind": "api_key",
    })
}

/// Ann registers a consumer with an API key. The answer carries the key the
/// platform made, once; the consumer is kept and listed with only the key's
/// prefix showing, cleared for internal data by default.
#[tokio::test]
async fn a_created_consumer_is_listed_with_its_hint() {
    let server = TestServer::new(router(adapters())).unwrap();

    let created = server
        .post(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&new_key())
        .await;
    created.assert_status(StatusCode::CREATED);
    let answer: Value = created.json();
    let id = answer["id"].as_str().unwrap().to_owned();
    assert_eq!(answer["api_key"], "sk_live_minted1.minted-digest-1");

    let listed = server
        .get(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    listed.assert_status_ok();
    let page: Value = listed.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let entry = &page["items"][0];
    assert_eq!(entry["id"], id);
    assert_eq!(entry["name"], "payment-processor");
    assert_eq!(entry["credential_hint"], "sk_live_minted1");
    assert_eq!(entry["status"], "Active");
    assert_eq!(entry["clearance"], "Internal");
    assert!(entry["created_by"].as_str().unwrap().contains(':'));
    assert!(
        !entry.to_string().contains("minted-digest-1"),
        "neither the key nor its digest is answered again"
    );
}

/// A consumer signing in with a client certificate is answered no key.
#[tokio::test]
async fn a_certificate_consumer_is_answered_no_key() {
    let server = TestServer::new(router(adapters())).unwrap();

    let created = server
        .post(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "edge-device",
            "credential_kind": "client_cert",
            "fingerprint": format!("sha256:{}", "ab".repeat(32)),
        }))
        .await;

    created.assert_status(StatusCode::CREATED);
    assert!(created.json::<Value>()["api_key"].is_null());
}

/// A consumer reads back by its id.
#[tokio::test]
async fn a_consumer_reads_back_by_id() {
    let (server, _, id) = holding(billing_sync());

    let response = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["name"], "billing-sync");
}

/// Renaming keeps the consumer as it was otherwise.
#[tokio::test]
async fn renaming_a_consumer_changes_only_its_name() {
    let (server, _, id) = holding(billing_sync());

    server
        .patch(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "invoice-sync"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let consumer: Value = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(consumer["name"], "invoice-sync");
    assert_eq!(consumer["status"], "Active");
}

/// Raising a consumer's clearance answers the consumer as saved.
#[tokio::test]
async fn changing_the_clearance_answers_the_consumer() {
    let (server, _, id) = holding(billing_sync());

    let response = server
        .put(&consumers_path(&format!("/{id}/clearance")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"clearance": "Confidential"}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["clearance"], "Confidential");
}

/// Disabling, enabling and deleting walk the consumer through its life.
#[tokio::test]
async fn a_disabled_consumer_is_enabled_again() {
    let (server, _, id) = holding(disabled_billing_sync());

    server
        .post(&consumers_path(&format!("/{id}/enable")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let consumer: Value = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(consumer["status"], "Active");
}

/// A disabled consumer is deleted for good.
#[tokio::test]
async fn a_disabled_consumer_is_deleted() {
    let (server, store, id) = holding(disabled_billing_sync());

    server
        .delete(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(store.count(), 0);
}

/// Deleting an active consumer returns 403 and retains it in the store.
#[tokio::test]
async fn an_active_consumer_is_not_deleted() {
    let (server, store, id) = holding(billing_sync());

    let response = server
        .delete(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(store.count(), 1);
}

/// A credential kind the API does not know is refused, not stored.
#[tokio::test]
async fn an_unknown_credential_kind_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "x", "credential_kind": "password", "password": "hunter2"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Client-supplied key material does not determine the created consumer's
/// credential hint; reading it returns the minted prefix.
#[tokio::test]
async fn a_key_the_client_names_is_not_kept() {
    let server = TestServer::new(router(adapters())).unwrap();
    let mut body = new_key();
    body["key_prefix"] = json!("sk_live_mallory");
    body["key_hash"] = json!("a-digest-mallory-made");

    let created = server
        .post(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;

    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].as_str().unwrap().to_owned();
    let consumer: Value = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(consumer["credential_hint"], "sk_live_minted1");
}

/// A plan refusal returns 403 and leaves the consumer store empty.
#[tokio::test]
async fn a_consumer_past_the_plan_limit_is_refused() {
    let store = Arc::new(FakeConsumerStore::empty());
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        consumer_store: store.clone(),
        limit_enforcer: Arc::new(RejectingLimitEnforcer),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .post(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&new_key())
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(store.count(), 0);
}

/// Listing consumers without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A consumer created with an expiry and a daily quota reads back with
/// both; one created without either never expires and has no quota.
#[tokio::test]
async fn a_consumer_created_with_expiry_and_quota_reads_back_with_them() {
    let server = TestServer::new(router(adapters())).unwrap();
    let mut body = new_key();
    body["expires_at"] = json!("2999-01-01T00:00:00Z");
    body["quota"] = json!({"requests": 10_000, "per": "day"});

    let created = server
        .post(&consumers_path(""))
        .authorization_bearer(TENANT_USER)
        .json(&body)
        .await;
    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].as_str().unwrap().to_owned();

    let consumer: Value = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert!(!consumer["credential_expires_at"].is_null());
    assert_eq!(consumer["quota"], json!({"requests": 10_000, "per": "day"}));
    assert!(consumer["previous_credential"].is_null());
}

/// Setting a consumer quota to zero returns 422.
#[tokio::test]
async fn a_quota_of_zero_is_refused() {
    let (server, _, id) = holding(billing_sync());

    let response = server
        .put(&consumers_path(&format!("/{id}/quota")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"quota": {"requests": 0, "per": "hour"}}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Changing the quota answers the consumer with its new allowance, and
/// `null` takes the allowance away again.
#[tokio::test]
async fn a_quota_is_set_and_removed() {
    let (server, _, id) = holding(billing_sync());

    let limited = server
        .put(&consumers_path(&format!("/{id}/quota")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"quota": {"requests": 60, "per": "minute"}}))
        .await;
    limited.assert_status_ok();
    assert_eq!(limited.json::<Value>()["quota"]["per"], "minute");

    let unlimited = server
        .put(&consumers_path(&format!("/{id}/quota")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"quota": null}))
        .await;
    unlimited.assert_status_ok();
    assert!(unlimited.json::<Value>()["quota"].is_null());
}

/// A rotation to a new API key answers the key the platform made, once,
/// and with an overlap keeps the old key working beside it, shown by its
/// hint only.
#[tokio::test]
async fn a_rotation_with_an_overlap_shows_the_old_credential() {
    let (server, _, id) = holding(billing_sync());

    let rotated = server
        .post(&consumers_path(&format!("/{id}/rotate")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "credential_kind": "api_key",
            "overlap_seconds": 3600,
        }))
        .await;

    rotated.assert_status_ok();
    assert_eq!(
        rotated.json::<Value>()["api_key"],
        "sk_live_minted1.minted-digest-1"
    );
    let consumer: Value = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(consumer["credential_hint"], "sk_live_minted1");
    assert!(!consumer["previous_credential"]["until"].is_null());
    assert!(!consumer.to_string().contains("minted-digest-1"));
}

/// An eight-day credential overlap exceeds the supported duration and returns 422.
#[tokio::test]
async fn an_overlap_longer_than_a_week_is_refused() {
    let (server, _, id) = holding(billing_sync());

    let response = server
        .post(&consumers_path(&format!("/{id}/rotate")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "credential_kind": "api_key",
            "overlap_seconds": 8 * 86_400,
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ending the overlap stops the old credential now; the consumer shows
/// none kept.
#[tokio::test]
async fn ending_the_overlap_retires_the_old_credential() {
    let (server, _, id) = holding(billing_sync_overlapping());

    server
        .post(&consumers_path(&format!("/{id}/end-overlap")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let consumer: Value = server
        .get(&consumers_path(&format!("/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert!(consumer["previous_credential"].is_null());
}

/// An expiry is set on the current credential, and `null` makes it last
/// for good again.
#[tokio::test]
async fn a_credential_expiry_is_set_and_cleared() {
    let (server, _, id) = holding(billing_sync());

    let expiring = server
        .put(&consumers_path(&format!("/{id}/expiry")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"expires_at": "2999-06-01T00:00:00Z"}))
        .await;
    expiring.assert_status_ok();
    assert!(!expiring.json::<Value>()["credential_expires_at"].is_null());

    let lasting = server
        .put(&consumers_path(&format!("/{id}/expiry")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"expires_at": null}))
        .await;
    lasting.assert_status_ok();
    assert!(lasting.json::<Value>()["credential_expires_at"].is_null());
}

/// A description is given and then cleared with `null`.
#[tokio::test]
async fn a_description_is_set_and_cleared() {
    let (server, _, id) = holding(billing_sync());
    let description = consumers_path(&format!("/{id}/description"));
    let read = consumers_path(&format!("/{id}"));

    server
        .put(&description)
        .authorization_bearer(TENANT_USER)
        .json(&json!({"description": "Nightly invoice export"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let described: Value = server
        .get(&read)
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(described["description"], "Nightly invoice export");

    server
        .put(&description)
        .authorization_bearer(TENANT_USER)
        .json(&json!({"description": null}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let cleared: Value = server
        .get(&read)
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert!(cleared["description"].is_null());
}
