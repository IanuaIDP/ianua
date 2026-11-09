//! A topic's settings and its end. Tess changes how long the orders topic
//! keeps its messages, gives it a schema, takes it back and raises its
//! data class, which can only rise; a service not cleared for the new
//! class cannot subscribe any more. An archived topic takes no more
//! changes. A topic in use cannot be deleted; once paused it goes, its
//! subscriptions with it, and a new topic of that name begins with
//! nothing the old one kept.

use ianua_scenarios::api::messaging;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::messaging::{
    DataClassChange, PullSubscription, Retention, RetentionChange, SchemaChange,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::bus::{made_topic, published, pulled_by, refused_to_the_cast, service};
use crate::support::person;

/// The routing key of the topic.
const ORDERS: &str = "orders.created";

/// The record a changed retention leaves.
const RETENTION_CHANGED: &str = "messaging.topic_retention_changed";

/// The record a changed schema leaves.
const SCHEMA_CHANGED: &str = "messaging.topic_schema_changed";

/// The record a raised data class leaves.
const CLASS_RAISED: &str = "messaging.topic_data_class_raised";

/// The record an archived topic leaves.
const ARCHIVED: &str = "messaging.topic_archived";

/// The record a deleted topic leaves.
const DELETED: &str = "messaging.topic_deleted";

/// The schema Tess gives the orders topic.
const ORDER_SCHEMA: &str = r#"{"type":"object","required":["id"]}"#;

/// A retention of `count` messages.
fn keeping(count: u64) -> RetentionChange {
    RetentionChange {
        retention: Retention::MessageCount(count),
    }
}

/// A raise to `class`.
fn raising_to(class: &str) -> DataClassChange {
    DataClassChange {
        data_class: class.to_owned(),
    }
}

/// Tess finds the orders topic in the tenant's list, then changes its
/// retention to the last thousand messages, gives it a schema and clears
/// it, and raises its class to Restricted, each read back and on record.
/// A retention of zero is no retention. Lowering the class is refused, so
/// the class stays where it is.
#[tokio::test]
async fn tess_changes_a_topics_settings_and_its_class_only_rises() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let topic_id = made_topic(&world, ORDERS).await;
    let seen = world.trail().ids().await;

    let listed = messaging::topics(world.tenant()).send(tess).await.ok();
    let found = listed
        .items
        .iter()
        .find(|topic| topic.id == topic_id)
        .expect("the topic is among the tenant's");
    assert_eq!(found.topic_name, ORDERS);
    assert_eq!(found.data_class.as_deref(), Some("Internal"));

    messaging::change_retention(world.tenant(), &topic_id, &keeping(1000))
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, RETENTION_CHANGED).await;
    let kept = messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(kept.retention, Some(json!({"MessageCount": 1000})));
    let zero = RetentionChange {
        retention: Retention::Duration(0),
    };
    messaging::change_retention(world.tenant(), &topic_id, &zero)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "invalid_body");

    let schema = SchemaChange {
        schema: Some(ORDER_SCHEMA.to_owned()),
    };
    messaging::change_schema(world.tenant(), &topic_id, &schema)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, SCHEMA_CHANGED).await;
    let schemed = messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(schemed.schema.as_deref(), Some(ORDER_SCHEMA));
    messaging::change_schema(world.tenant(), &topic_id, &SchemaChange { schema: None })
        .send(tess)
        .await
        .ok();
    let cleared = messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(cleared.schema, None, "the schema was taken back");

    messaging::raise_data_class(world.tenant(), &topic_id, &raising_to("Restricted"))
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, CLASS_RAISED).await;
    messaging::raise_data_class(world.tenant(), &topic_id, &raising_to("Public"))
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let raised = messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(raised.data_class.as_deref(), Some("Restricted"));

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess raises the orders topic to Restricted. The courier's service,
/// cleared for internal data as every service starts, is refused a new
/// subscription: a raised class shuts out whoever is not cleared for it.
#[tokio::test]
async fn raising_a_topics_class_shuts_out_services_cleared_below_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let topic_id = made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;

    messaging::raise_data_class(world.tenant(), &topic_id, &raising_to("Restricted"))
        .send(tess)
        .await
        .ok();

    let subscription = PullSubscription {
        topic_name: ORDERS.to_owned(),
        consumer_id: courier,
        delivery_mode: "Pull".to_owned(),
        max_deliveries: 5,
    };
    messaging::subscribe(world.tenant(), &subscription)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess archives the orders topic, on record. From then on neither its
/// retention, its schema nor its class can change: an archived topic is
/// read-only, and the status stays Archived.
#[tokio::test]
async fn an_archived_topic_takes_no_more_changes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let topic_id = made_topic(&world, ORDERS).await;
    let seen = world.trail().ids().await;

    messaging::archive_topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, ARCHIVED).await;

    messaging::change_retention(world.tenant(), &topic_id, &keeping(10))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    messaging::change_schema(world.tenant(), &topic_id, &SchemaChange { schema: None })
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    messaging::raise_data_class(world.tenant(), &topic_id, &raising_to("Restricted"))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let archived = messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(archived.status, "Archived");
    assert_eq!(archived.data_class.as_deref(), Some("Internal"));

    stack.stop().await.expect("the stack stops cleanly");
}

/// The courier's service is subscribed to the orders topic and a message
/// waits for it. While the topic is active it cannot be deleted. Tess
/// pauses and deletes it, on record: the courier's subscription goes with
/// it, its pull finds nothing, and the name is free. Publishing to the
/// old name finds no topic. Tess makes a topic of that name again and
/// subscribes a new service: it starts with nothing of what the old topic
/// kept.
#[tokio::test]
async fn deleting_a_topic_ends_its_subscriptions_and_its_kept_messages() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let topic_id = made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let subscription_id = pulled_by(&world, ORDERS, &courier).await;
    published(&world, ORDERS, "order 3001").await;
    let seen = world.trail().ids().await;

    messaging::delete_topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    messaging::pause_topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    messaging::delete_topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, DELETED).await;

    messaging::pull(world.tenant(), &subscription_id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let orphaned = messaging::subscriptions_to(world.tenant(), ORDERS)
        .send(tess)
        .await
        .ok();
    assert!(orphaned.items.is_empty(), "no subscriber is left");

    made_topic(&world, ORDERS).await;
    let newcomer = service(&world, "Newcomer service").await;
    let fresh_subscription = pulled_by(&world, ORDERS, &newcomer).await;
    let waiting = messaging::pull(world.tenant(), &fresh_subscription)
        .send(tess)
        .await
        .ok();
    assert!(waiting.is_empty(), "nothing of the old topic came back");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in cannot list topics or change or delete one, and Sam finds no such
/// topic from his own tenant. The topic keeps its settings and nothing is
/// on record.
#[tokio::test]
async fn nobody_without_the_right_changes_a_topic() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    let topic_id = made_topic(&world, ORDERS).await;
    let seen = world.trail().ids().await;

    for call in [
        messaging::topics(world.tenant()).call(),
        messaging::change_retention(world.tenant(), &topic_id, &keeping(10)).call(),
        messaging::change_schema(world.tenant(), &topic_id, &SchemaChange { schema: None }).call(),
        messaging::raise_data_class(world.tenant(), &topic_id, &raising_to("Public")).call(),
        messaging::delete_topic(world.tenant(), &topic_id).call(),
    ] {
        refused_to_the_cast(&world, &uma, "managing the orders topic", call).await;
    }

    for call in [
        messaging::topic(world.twin(), &topic_id).call(),
        messaging::delete_topic(world.twin(), &topic_id).call(),
    ] {
        Matrix::new("reaching Acme's topic from the other tenant", call)
            .refused(world.stranger().client(), Status::NOT_FOUND, "not_found")
            .run()
            .await;
    }

    let topic = messaging::topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(topic.status, "Active");
    assert_eq!(topic.data_class.as_deref(), Some("Internal"));
    world.trail().nothing_after(&seen, RETENTION_CHANGED).await;
    world.trail().nothing_after(&seen, DELETED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
