//! A topic that really forgets. Tess keeps the orders topic's messages for
//! a few seconds: an order read just inside the limit is handed out, and
//! one just outside it is neither read nor posted, to a service that was
//! away as to one that was not. A limit on the number of messages keeps
//! only the newest, and lengthening a limit brings nothing back.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::api::messaging;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::messaging::{Pulled, PushSubscription, Retention, RetentionChange};
use ianua_scenarios::world::World;

use crate::bus::{made_topic, published, pulled_by, service, set_aside};

/// The routing key of the topic.
const ORDERS: &str = "orders.created";

/// An address that can never answer: its suffix is reserved so no such
/// name exists.
const NOWHERE: &str = "https://courier.acme.invalid/orders";

/// The topic's short limit, in seconds: long enough for a read right
/// after a publish to be well inside it.
const LIMIT: u32 = 8;

/// Tess keeps the topic's messages for `retention`.
async fn set_limit(world: &World<'_>, topic_id: &str, retention: Retention) {
    let change = RetentionChange { retention };
    messaging::change_retention(world.tenant(), topic_id, &change)
        .send(world.admin().client())
        .await
        .ok();
}

/// Waits past the topic's limit, the service neither reading nor told.
async fn limit_passed() {
    tokio::time::sleep(Duration::from_secs(u64::from(LIMIT) + 1)).await;
}

/// What a pull of `subscription_id` hands out now, as the orders' text.
async fn pulled_orders(world: &World<'_>, subscription_id: &str) -> Vec<String> {
    let messages: Vec<Pulled> = messaging::pull(world.tenant(), subscription_id)
        .send(world.admin().client())
        .await
        .ok();
    messages.iter().map(|one| text_of(&one.payload)).collect()
}

/// `payload`, the base64 of a message, as text.
fn text_of(payload: &str) -> String {
    let bytes = STANDARD.decode(payload).expect("the payload is base64");
    String::from_utf8(bytes).expect("the payload is text")
}

/// Tess keeps the orders topic's messages for eight seconds. The courier's
/// service reads order 7001 straight away. Order 7002 is published and the
/// service is away past the limit; when it comes back it is handed order
/// 7003, published just now, and never order 7002.
#[tokio::test]
async fn an_order_past_the_limit_is_not_read_by_a_service_that_was_away() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let topic_id = made_topic(&world, ORDERS).await;
    set_limit(&world, &topic_id, Retention::Duration(LIMIT)).await;
    let courier = service(&world, "Courier service").await;
    let subscription_id = pulled_by(&world, ORDERS, &courier).await;

    published(&world, ORDERS, "order 7001").await;
    let inside = pulled_orders(&world, &subscription_id).await;
    assert_eq!(inside, ["order 7001"], "read inside the limit");

    published(&world, ORDERS, "order 7002").await;
    limit_passed().await;
    published(&world, ORDERS, "order 7003").await;

    let outside = pulled_orders(&world, &subscription_id).await;
    assert!(
        !outside.iter().any(|order| order == "order 7002"),
        "the order past the limit stays unread: {outside:?}"
    );
    assert!(
        outside.iter().any(|order| order == "order 7003"),
        "the fresh order is handed out: {outside:?}"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The courier's address cannot take a post, and each order gets one try.
/// Tess pauses the subscription, publishes order 7101, and waits past the
/// limit. She resumes and publishes order 7102. The worker posts the fresh
/// order, whose post fails and is set aside. Order 7101, past the limit,
/// is not posted and so is never set aside.
#[tokio::test]
async fn an_order_past_the_limit_is_not_posted() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let topic_id = made_topic(&world, ORDERS).await;
    set_limit(&world, &topic_id, Retention::Duration(LIMIT)).await;
    let courier = service(&world, "Courier service").await;
    let pushed = PushSubscription {
        topic_name: ORDERS.to_owned(),
        consumer_id: courier,
        delivery_mode: "Push".to_owned(),
        push_endpoint: Some(NOWHERE.to_owned()),
        max_deliveries: 1,
    };
    let subscription = messaging::subscribe_push(world.tenant(), &pushed)
        .send(tess)
        .await
        .ok();
    messaging::pause_subscription(world.tenant(), &subscription.id)
        .send(tess)
        .await
        .ok();

    published(&world, ORDERS, "order 7101").await;
    limit_passed().await;
    messaging::resume_subscription(world.tenant(), &subscription.id)
        .send(tess)
        .await
        .ok();
    published(&world, ORDERS, "order 7102").await;

    let fresh = set_aside(&world, &subscription.id, "order 7102").await;
    assert_eq!(fresh.delivered, 1, "the fresh order was posted once");
    let letters = messaging::dead_letters(world.tenant(), &subscription.id)
        .send(tess)
        .await
        .ok();
    assert!(
        letters
            .items
            .iter()
            .all(|letter| text_of(&letter.payload) != "order 7101"),
        "the order past the limit was never posted"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess keeps only the last two orders. Three are published before the
/// service reads; it is handed the two newest and never the first.
#[tokio::test]
async fn a_count_limit_hands_out_only_the_newest_orders() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let topic_id = made_topic(&world, ORDERS).await;
    set_limit(&world, &topic_id, Retention::MessageCount(2)).await;
    let courier = service(&world, "Courier service").await;
    let subscription_id = pulled_by(&world, ORDERS, &courier).await;

    published(&world, ORDERS, "order 7201").await;
    published(&world, ORDERS, "order 7202").await;
    published(&world, ORDERS, "order 7203").await;

    let orders = pulled_orders(&world, &subscription_id).await;
    assert_eq!(orders, ["order 7202", "order 7203"]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Order 7301 passes the short limit unread. Tess lengthens the limit to
/// an hour: the order stays gone, and a later order is still handed out.
#[tokio::test]
async fn lengthening_a_limit_brings_nothing_back() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let topic_id = made_topic(&world, ORDERS).await;
    set_limit(&world, &topic_id, Retention::Duration(LIMIT)).await;
    let courier = service(&world, "Courier service").await;
    let subscription_id = pulled_by(&world, ORDERS, &courier).await;

    published(&world, ORDERS, "order 7301").await;
    limit_passed().await;
    set_limit(&world, &topic_id, Retention::Duration(3600)).await;
    published(&world, ORDERS, "order 7302").await;

    let orders = pulled_orders(&world, &subscription_id).await;
    assert_eq!(orders, ["order 7302"]);

    stack.stop().await.expect("the stack stops cleanly");
}
