//! The messaging endpoints: topics, subscriptions, schemas, publishing,
//! pulling and the live topic stream, in the shape the dashboard reads.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, router};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::consumers::{billing_sync, consumers_of_test_tenant};
use ianua_app::test_support::messaging::{
    FakeMessageConsumer, FakeMessagePublisher, FakeTopicStore, Settlement, archived_topic,
    paused_topic, pending_message, topic_classed, topic_named, topics_of_test_tenant,
};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::message_type::MessageType;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::isolation::scope::ResolvedTenant;
use serde_json::{Value, json};

/// The test tenant's messaging address, followed by `rest`.
fn messaging_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}/messaging{rest}")
}

/// A server whose test tenant holds `topic`.
fn holding(topic: Topic<ResolvedTenant>) -> (TestServer, Arc<FakeTopicStore>, String) {
    let id = topic.id().as_uuid().to_string();
    let store = topics_of_test_tenant(topic);
    let server = TestServer::new(router(Adapters {
        topic_store: store.clone(),
        ..adapters()
    }))
    .unwrap();
    (server, store, id)
}

/// Ann creates a topic. It is listed in the shape the topic browser reads.
#[tokio::test]
async fn a_created_topic_is_listed() {
    let server = TestServer::new(router(adapters())).unwrap();

    let created = server
        .post(&messaging_path("/topics"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "Orders",
            "topic_name": "orders.created",
            "retention": {"Duration": 3600},
        }))
        .await;
    created.assert_status(StatusCode::CREATED);

    let page: Value = server
        .get(&messaging_path("/topics"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    let topic = &page["items"][0];
    assert_eq!(topic["id"], created.json::<Value>()["id"]);
    assert_eq!(topic["topic_name"], "orders.created");
    assert_eq!(topic["retention"], json!({"Duration": 3600}));
    assert_eq!(topic["status"], "Active");
    assert_eq!(topic["data_class"], "Internal");
    assert!(topic["schema"].is_null());
    assert!(topic["created_by"].is_string());
}

/// A retention that would drop every message as it arrives is refused.
#[tokio::test]
async fn a_zero_retention_is_refused() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .post(&messaging_path("/topics"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "Orders",
            "topic_name": "orders.created",
            "retention": {"Duration": 0},
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A topic is paused, resumed, archived and then deleted.
#[tokio::test]
async fn a_topic_is_walked_through_its_life() {
    let (server, store, id) = holding(topic_named("orders"));

    for step in ["/pause", "/resume", "/archive"] {
        server
            .post(&messaging_path(&format!("/topics/{id}{step}")))
            .authorization_bearer(TENANT_USER)
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }
    server
        .delete(&messaging_path(&format!("/topics/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(store.count(), 0);
}

/// Deleting an active topic returns 409 and retains the topic in the store.
#[tokio::test]
async fn an_active_topic_is_not_deleted() {
    let (server, store, id) = holding(topic_named("orders"));

    let response = server
        .delete(&messaging_path(&format!("/topics/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::CONFLICT);
    assert_eq!(store.count(), 1);
}

/// Raising a topic's class and changing its retention and schema each
/// take hold.
#[tokio::test]
async fn a_topics_settings_are_changed() {
    let (server, _, id) = holding(topic_named("orders"));

    server
        .put(&messaging_path(&format!("/topics/{id}/data-class")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"data_class": "Confidential"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .put(&messaging_path(&format!("/topics/{id}/retention")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"retention": {"MessageCount": 500}}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .put(&messaging_path(&format!("/topics/{id}/schema")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"schema": "{\"type\":\"object\"}"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let topic: Value = server
        .get(&messaging_path(&format!("/topics/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(topic["data_class"], "Confidential");
    assert_eq!(topic["retention"], json!({"MessageCount": 500}));
    assert_eq!(topic["schema"], "{\"type\":\"object\"}");
}

/// Lowering a confidential topic to public classification returns 403.
#[tokio::test]
async fn lowering_a_topics_class_is_forbidden() {
    let (server, _, id) = holding(topic_classed("orders", DataClassLevel::Confidential));

    let response = server
        .put(&messaging_path(&format!("/topics/{id}/data-class")))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"data_class": "Public"}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A message published to an active topic reaches the bus.
#[tokio::test]
async fn a_published_message_reaches_the_bus() {
    let publisher = Arc::new(FakeMessagePublisher::empty());
    let server = TestServer::new(router(Adapters {
        topic_store: topics_of_test_tenant(topic_named("orders")),
        message_publisher: publisher.clone(),
        ..adapters()
    }))
    .unwrap();

    server
        .post(&messaging_path("/topics/orders/publish"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"payload": "aGk=", "headers": [{"key": "kind", "value": "test"}]}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(publisher.count(), 1);
}

/// A message published with a type reaches the bus as that type.
#[tokio::test]
async fn a_message_reaches_the_bus_with_its_type() {
    let publisher = Arc::new(FakeMessagePublisher::empty());
    let server = TestServer::new(router(Adapters {
        topic_store: topics_of_test_tenant(topic_named("orders")),
        message_publisher: publisher.clone(),
        ..adapters()
    }))
    .unwrap();

    server
        .post(&messaging_path("/topics/orders/publish"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"payload": "aGk=", "message_type": "order.refund.requested"}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let published = publisher.published();
    let message_type = published[0].message_type.as_ref().map(MessageType::as_str);
    assert_eq!(message_type, Some("order.refund.requested"));
}

/// A wildcard message type returns 422 without publishing a message.
#[tokio::test]
async fn a_malformed_message_type_is_refused() {
    let publisher = Arc::new(FakeMessagePublisher::empty());
    let server = TestServer::new(router(Adapters {
        topic_store: topics_of_test_tenant(topic_named("orders")),
        message_publisher: publisher.clone(),
        ..adapters()
    }))
    .unwrap();

    server
        .post(&messaging_path("/topics/orders/publish"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"payload": "aGk=", "message_type": "order.*"}))
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);

    assert_eq!(publisher.count(), 0);
}

/// A payload that is not base64 is refused before the app is asked.
#[tokio::test]
async fn a_payload_that_is_not_base64_is_refused() {
    let (server, _, _) = holding(topic_named("orders"));

    let response = server
        .post(&messaging_path("/topics/orders/publish"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"payload": "not base64!"}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A server whose test tenant holds the topic `orders` and the service
/// billing-sync, on a bus where `bus` has messages waiting. Returns the
/// service's id.
fn with_billing_sync(bus: Arc<FakeMessageConsumer>) -> (TestServer, String) {
    let consumer = billing_sync();
    let consumer_id = consumer.id().as_uuid().to_string();
    let server = TestServer::new(router(Adapters {
        topic_store: topics_of_test_tenant(topic_named("orders")),
        consumer_store: consumers_of_test_tenant(consumer),
        message_consumer: bus.clone(),
        dead_letters: bus,
        ..adapters()
    }))
    .unwrap();
    (server, consumer_id)
}

/// Subscribes billing-sync to `orders` through `server`, delivered as
/// `body` adds, and gives back the answer.
async fn subscribe(server: &TestServer, consumer_id: &str, body: Value) -> Value {
    let mut request = json!({"topic_name": "orders", "consumer_id": consumer_id});
    for (key, value) in body.as_object().unwrap() {
        request[key] = value.clone();
    }
    let created = server
        .post(&messaging_path("/subscriptions"))
        .authorization_bearer(TENANT_USER)
        .json(&request)
        .await;
    created.assert_status(StatusCode::CREATED);
    created.json()
}

/// Ann subscribes billing-sync to a topic, pulls what waits there with
/// each payload base64-encoded and a receipt, and acknowledges it.
#[tokio::test]
async fn a_subscribed_service_pulls_and_acknowledges_its_messages() {
    let bus = Arc::new(FakeMessageConsumer::holding(vec![pending_message(
        "r-1", 1,
    )]));
    let (server, consumer_id) = with_billing_sync(bus.clone());
    let created = subscribe(&server, &consumer_id, json!({"delivery_mode": "Pull"})).await;
    assert!(
        created.get("signing_secret").is_none(),
        "a pull subscription signs nothing"
    );
    let id = created["id"].as_str().unwrap().to_owned();

    let pulled = server
        .get(&messaging_path(&format!("/subscriptions/{id}/messages")))
        .authorization_bearer(TENANT_USER)
        .await;
    pulled.assert_status_ok();
    assert_eq!(
        pulled.json::<Value>(),
        json!([{
            "payload": "b3JkZXIgNw==",
            "headers": [],
            "message_type": null,
            "receipt": "r-1",
            "delivered": 1
        }])
    );

    acknowledge(&server, &id, "r-1").await;
    assert!(matches!(
        bus.settled().as_slice(),
        [(_, Settlement::Acknowledged)]
    ));
}

/// Acknowledges the receipt through the subscription and checks the HTTP result.
async fn acknowledge(server: &TestServer, id: &str, receipt: &str) {
    server
        .post(&messaging_path(&format!(
            "/subscriptions/{id}/messages/ack"
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"receipt": receipt}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

/// A push subscription hands out its signing secret once, and a rotation
/// that keeps the old secret signing for an hour hands out the new one.
#[tokio::test]
async fn a_push_subscription_hands_out_its_secret_and_rotates_it() {
    let (server, consumer_id) = with_billing_sync(Arc::new(FakeMessageConsumer::empty()));
    let created = subscribe(
        &server,
        &consumer_id,
        json!({"delivery_mode": "Push", "push_endpoint": "https://hooks.acme.com/orders"}),
    )
    .await;
    assert!(!created["signing_secret"].as_str().unwrap().is_empty());
    let id = created["id"].as_str().unwrap();

    let rotated = server
        .post(&messaging_path(&format!(
            "/subscriptions/{id}/rotate-push-secret"
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"overlap_seconds": 3600}))
        .await;

    rotated.assert_status_ok();
    assert_ne!(
        rotated.json::<Value>()["signing_secret"],
        created["signing_secret"]
    );
}

/// Creating a push subscription without an endpoint returns 422.
#[tokio::test]
async fn a_push_subscription_without_an_endpoint_is_refused() {
    let (server, consumer_id) = with_billing_sync(Arc::new(FakeMessageConsumer::empty()));

    let response = server
        .post(&messaging_path("/subscriptions"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "topic_name": "orders",
            "consumer_id": consumer_id,
            "delivery_mode": "Push",
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A subscription with nothing set aside lists no dead letters, and a
/// replay of one it never held finds nothing.
#[tokio::test]
async fn a_dead_letter_never_set_aside_is_not_replayed() {
    let (server, consumer_id) = with_billing_sync(Arc::new(FakeMessageConsumer::empty()));
    let created = subscribe(&server, &consumer_id, json!({"delivery_mode": "Pull"})).await;
    let id = created["id"].as_str().unwrap();

    let listed: Value = server
        .get(&messaging_path(&format!(
            "/subscriptions/{id}/dead-letters"
        )))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(0));

    server
        .post(&messaging_path(&format!(
            "/subscriptions/{id}/dead-letters/7/replay"
        )))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

/// Ann subscribes billing-sync to a topic, and the listing shows how it is
/// delivered.
#[tokio::test]
async fn a_subscribed_service_is_listed() {
    let consumer = billing_sync();
    let consumer_id = consumer.id().as_uuid().to_string();
    let server = TestServer::new(router(Adapters {
        topic_store: topics_of_test_tenant(topic_named("orders")),
        consumer_store: consumers_of_test_tenant(consumer),
        ..adapters()
    }))
    .unwrap();

    let created = server
        .post(&messaging_path("/subscriptions"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "topic_name": "orders",
            "consumer_id": consumer_id,
            "delivery_mode": "Pull",
        }))
        .await;
    created.assert_status(StatusCode::CREATED);

    let listed: Value = server
        .get(&messaging_path("/subscriptions?topic_name=orders"))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    let entry = &listed["items"][0];
    assert_eq!(entry["consumer_id"], consumer_id);
    assert_eq!(entry["delivery_mode"], "Pull");
    assert!(entry["push_endpoint"].is_null());
    assert_eq!(entry["ack_deadline_seconds"], 30);
    assert_eq!(entry["max_deliveries"], 5);
}

/// Listing subscriptions names a topic or a service; naming neither is
/// refused.
#[tokio::test]
async fn listing_subscriptions_needs_a_topic_or_a_service() {
    let server = TestServer::new(router(adapters())).unwrap();

    let response = server
        .get(&messaging_path("/subscriptions"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// A schema is registered with its first version, read back, and deleted.
#[tokio::test]
async fn a_schema_is_registered_read_and_deleted() {
    let server = TestServer::new(router(adapters())).unwrap();

    let created = server
        .post(&messaging_path("/schemas"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "Order Created",
            "schema_name": "order-created",
            "format": "JsonSchema",
            "compatibility": "None",
            "definition": "{\"type\":\"object\"}",
        }))
        .await;
    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].as_str().unwrap().to_owned();

    let schema: Value = server
        .get(&messaging_path(&format!("/schemas/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .json();
    assert_eq!(schema["format"], "JsonSchema");
    assert_eq!(schema["versions"][0]["version"], 1);

    server
        .delete(&messaging_path(&format!("/schemas/{id}")))
        .authorization_bearer(TENANT_USER)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

/// The app admits Ann to an active topic's live messages, so only the
/// missing WebSocket handshake stands between her and the stream.
#[tokio::test]
async fn an_admitted_stream_waits_only_on_the_handshake() {
    let (server, _, _) = holding(topic_named("orders"));

    let response = server
        .get(&messaging_path("/topics/orders/stream"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
}

/// Opening a paused topic's stream returns 403.
#[tokio::test]
async fn a_paused_topic_cannot_be_streamed() {
    let (server, _, _) = holding(paused_topic("orders"));

    let response = server
        .get(&messaging_path("/topics/orders/stream"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Publishing to an archived topic returns 403.
#[tokio::test]
async fn an_archived_topic_takes_no_message() {
    let (server, _, _) = holding(archived_topic("orders"));

    let response = server
        .post(&messaging_path("/topics/orders/publish"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"payload": "aGk="}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Listing topics without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = TestServer::new(router(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    }))
    .unwrap();

    let response = server
        .get(&messaging_path("/topics"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}
