//! The notification endpoints: what each inbox answers, and in what shape.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{OPERATOR, ORG, ORG_MEMBER, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
use ianua_app::test_support::notification_delivery::TEST_DESTINATION_SECRET;
use ianua_app::test_support::notifications::{
    FakeTenantNotificationStore, test_ctx_user, user_registered,
};
use ianua_app::test_support::test_ctx;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use serde_json::{Value, json};

/// The path under the test tenant's notifications.
fn tenant_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/notifications{rest}")
}

/// A server whose test tenant user has one unread notification that a
/// user registered.
fn with_one_unread() -> (TestServer, Arc<FakeTenantNotificationStore>) {
    let inbox = Arc::new(FakeTenantNotificationStore::empty());
    inbox.notifications.lock().unwrap().push((
        (test_ctx().tenant_id(), test_ctx_user()),
        user_registered(NotificationSeverity::Warning),
    ));
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_notification_store: inbox.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, inbox)
}

/// Ann lists her inbox and sees the notification, in the shape the
/// dashboard reads: the event as `{context: event}`, the category,
/// severity and read flag by name, inside a page.
#[tokio::test]
async fn a_tenant_user_lists_their_inbox() {
    let (server, _) = with_one_unread();

    let response = server
        .get(&tenant_path(""))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let entry = &page["items"][0];
    assert_eq!(entry["event_type"], json!({"Identity": "UserRegistered"}));
    assert_eq!(entry["category"], "Identity");
    assert_eq!(entry["severity"], "Warning");
    assert_eq!(entry["title"], "Something happened");
    assert_eq!(entry["read"], false);
    assert!(entry.get("body").is_none(), "an empty body is left out");
}

/// The badge counts what is unread.
#[tokio::test]
async fn the_unread_count_counts_the_unread() {
    let (server, _) = with_one_unread();

    let response = server
        .get(&tenant_path("/unread-count"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({"count": 1}));
}

/// Ann opens the notification: it is read, and the badge drops to zero.
#[tokio::test]
async fn marking_a_notification_read_takes_it_off_the_count() {
    let (server, inbox) = with_one_unread();
    let id = inbox.notifications.lock().unwrap()[0].1.id();

    server
        .post(&tenant_path(&format!("/{}/read", id.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .get(&tenant_path("/unread-count"))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_json(&json!({"count": 0}));
}

/// A notification that is not in Ann's inbox is not found.
#[tokio::test]
async fn marking_someone_elses_notification_is_not_found() {
    let (server, _) = with_one_unread();

    let response = server
        .post(&tenant_path(&format!("/{}/read", uuid::Uuid::now_v7())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Marking everything read says how many changed.
#[tokio::test]
async fn marking_all_read_says_how_many_changed() {
    let (server, _) = with_one_unread();

    let response = server
        .post(&tenant_path("/read-all"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_json(&json!({"marked": 1}));
}

/// Ann switches identity notifications to email too. The answer is her
/// whole set, with that one changed.
#[tokio::test]
async fn a_tenant_user_changes_a_delivery_channel() {
    let (server, _) = with_one_unread();

    let response = server
        .patch(&tenant_path("/preferences"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"preferences": [{"category": "Identity", "channel": "InAppAndEmail"}]}))
        .await;

    response.assert_status_ok();
    let set: Vec<Value> = response.json();
    let identity = set
        .iter()
        .find(|entry| entry["category"] == "Identity")
        .unwrap();
    assert_eq!(identity["channel"], "InAppAndEmail");
    assert!(set.len() > 1, "every category is listed");
}

/// A channel the API does not know is refused, not stored.
#[tokio::test]
async fn an_unknown_channel_is_refused() {
    let (server, _) = with_one_unread();

    let response = server
        .patch(&tenant_path("/preferences"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"preferences": [{"category": "Identity", "channel": "Pigeon"}]}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A signed-out tenant session receives 401 when reading notification preferences.
#[tokio::test]
async fn a_session_the_app_no_longer_honours_is_unauthenticated() {
    let server = TestServer::new(router(ianua_assembly::deps::Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&tenant_path("/preferences"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// The operator's inbox and the organization's answer in the same shape.
#[tokio::test]
async fn the_operator_and_member_inboxes_answer_pages() {
    let server = TestServer::new(router(adapters())).unwrap();

    let operator = server
        .get("/api/v1/notifications")
        .authorization_bearer(OPERATOR)
        .await;
    let member = server
        .get(&format!("/api/v1/organizations/{ORG}/notifications"))
        .authorization_bearer(ORG_MEMBER)
        .await;

    operator.assert_status_ok();
    member.assert_status_ok();
    assert_eq!(
        operator.json::<Value>()["items"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        member.json::<Value>()["items"].as_array().map(Vec::len),
        Some(0)
    );
}

/// A member's own preferences, under their organization.
fn member_preferences() -> String {
    format!("/api/v1/organizations/{ORG}/notifications/preferences")
}

/// Bob turns off identity notifications for himself and reads it back.
#[tokio::test]
async fn a_member_changes_their_own_preferences() {
    let server = TestServer::new(router(adapters())).unwrap();

    server
        .patch(&member_preferences())
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({"preferences": [{"category": "Identity", "channel": "Disabled"}]}))
        .await
        .assert_status_ok();

    let chosen: Value = server
        .get(&member_preferences())
        .authorization_bearer(ORG_MEMBER)
        .await
        .json();
    let identity = chosen
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["category"] == "Identity")
        .unwrap();
    assert_eq!(identity["channel"], "Disabled");
}

/// Olga turns on email for critical crypto notifications and reads it
/// back.
#[tokio::test]
async fn an_operator_changes_their_own_preferences() {
    let server = TestServer::new(router(adapters())).unwrap();

    server
        .patch("/api/v1/notifications/preferences")
        .authorization_bearer(OPERATOR)
        .json(&json!({"preferences": [{"category": "Crypto", "channel": "InAppAndEmail"}]}))
        .await
        .assert_status_ok();

    let chosen: Value = server
        .get("/api/v1/notifications/preferences")
        .authorization_bearer(OPERATOR)
        .await
        .json();
    let crypto = chosen
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["category"] == "Crypto")
        .unwrap();
    assert_eq!(crypto["channel"], "InAppAndEmail");
}

/// A tenant credential receives 403 from the operator notification preferences.
#[tokio::test]
async fn a_tenant_user_reads_no_operator_preferences() {
    let response = TestServer::new(router(adapters()))
        .unwrap()
        .get("/api/v1/notifications/preferences")
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The organization's destinations, followed by `rest`.
fn destinations(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/notifications/destinations{rest}")
}

/// Bob adds a webhook destination: its signing secret is shown this once,
/// and the list shows neither it nor the address.
#[tokio::test]
async fn a_webhook_destination_shows_its_secret_once() {
    let server = TestServer::new(router(adapters())).unwrap();

    let added = server
        .post(&destinations(""))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "name": "Security webhook",
            "target": {"kind": "webhook", "url": "https://alerts.example.com/hook"},
            "categories": ["Authentication"],
            "minimum_severity": "Warning",
        }))
        .await;

    added.assert_status(StatusCode::CREATED);
    assert_eq!(
        added.json::<Value>()["signing_secret"],
        TEST_DESTINATION_SECRET
    );
    let listed = server
        .get(&destinations(""))
        .authorization_bearer(ORG_MEMBER)
        .await;
    let text = listed.text();
    assert!(text.contains("\"kind\":\"webhook\""));
    assert!(!text.contains(TEST_DESTINATION_SECRET));
    assert!(!text.contains("alerts.example.com"));
}

/// A Slack destination on a foreign host returns 422.
#[tokio::test]
async fn a_slack_destination_off_slacks_host_is_refused() {
    let response = TestServer::new(router(adapters()))
        .unwrap()
        .post(&destinations(""))
        .authorization_bearer(ORG_MEMBER)
        .json(&json!({
            "name": "Fake Slack",
            "target": {"kind": "slack", "url": "https://hooks.evil.example/services/x"},
            "categories": ["Authentication"],
            "minimum_severity": "Info",
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Adding a notification destination without organization authority returns 403.
#[tokio::test]
async fn a_member_the_app_refuses_adds_no_destination() {
    let response = TestServer::new(router(ianua_assembly::deps::Adapters {
        org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap()
    .post(&destinations(""))
    .authorization_bearer(ORG_MEMBER)
    .json(&json!({
        "name": "Security webhook",
        "target": {"kind": "webhook", "url": "https://alerts.example.com/hook"},
        "categories": ["Authentication"],
        "minimum_severity": "Warning",
    }))
    .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
