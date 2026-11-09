//! A company's own services talking through the tenant's message bus.
//! Tess makes a topic for new orders and subscribes the courier's
//! service to it; an order published is pulled, handled and gone. An
//! order the service cannot handle comes round again, is set aside once
//! its deliveries run out, and is replayed. A paused subscription hands
//! out nothing and a paused topic takes nothing. Uma, Max, Sam and nobody
//! signed in publish or pull nothing.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::api::{consumers, messaging};
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::consumers::NewConsumer;
use ianua_scenarios::wire::messaging::{
    PlainTopic, Publication, PullSubscription, Pulled, Receipt, Retention,
};
use ianua_scenarios::world::World;

use crate::support::person;

/// The routing key of the topic.
const ORDERS: &str = "orders.created";

/// The record a published message leaves, with its size only.
const PUBLISHED: &str = "messaging.message_published";

/// The record a replayed dead letter leaves.
const REPLAYED: &str = "messaging.dead_letter_replayed";

/// The records the topic and subscription steps leave.
const SET_UP: [&str; 6] = [
    "messaging.topic_created",
    "messaging.subscription_created",
    "messaging.subscription_paused",
    "messaging.subscription_resumed",
    "messaging.topic_paused",
    "messaging.topic_resumed",
];

/// The orders topic and the courier's subscription to it.
struct Bus {
    topic_id: String,
    subscription_id: String,
}

/// Tess makes the orders topic and the courier's service, and subscribes
/// the service to pull it, setting each message aside after `deliveries`.
async fn orders_bus(world: &World<'_>, deliveries: u32) -> Bus {
    let tess = world.admin().client();
    let topic = PlainTopic {
        name: "New orders".to_owned(),
        topic_name: ORDERS.to_owned(),
        retention: Retention::Duration(3600),
    };
    let topic_id = messaging::create_topic(world.tenant(), &topic)
        .send(tess)
        .await
        .ok()
        .id;
    let courier = NewConsumer {
        name: "Courier service".to_owned(),
        description: None,
        credential_kind: "api_key".to_owned(),
    };
    let consumer_id = consumers::create(world.tenant(), &courier)
        .send(tess)
        .await
        .ok()
        .id;
    let subscription = PullSubscription {
        topic_name: ORDERS.to_owned(),
        consumer_id,
        delivery_mode: "Pull".to_owned(),
        max_deliveries: deliveries,
    };
    let subscription_id = messaging::subscribe(world.tenant(), &subscription)
        .send(tess)
        .await
        .ok()
        .id;
    Bus {
        topic_id,
        subscription_id,
    }
}

/// Tess publishes `order` to the orders topic.
async fn publish(world: &World<'_>, order: &str) {
    let message = Publication {
        payload: STANDARD.encode(order),
    };
    messaging::publish(world.tenant(), ORDERS, &message)
        .send(world.admin().client())
        .await
        .ok();
}

/// The message carrying `order`, once a pull of `bus` hands it out.
async fn pulled(world: &World<'_>, bus: &Bus, order: &str) -> Pulled {
    let expected = STANDARD.encode(order);
    let what = format!("the order {order} to be pulled");
    eventually(&what, || {
        let expected = expected.clone();
        async move {
            let messages = messaging::pull(world.tenant(), &bus.subscription_id)
                .send(world.admin().client())
                .await
                .ok();
            messages
                .into_iter()
                .find(|message| message.payload == expected)
        }
    })
    .await
}

/// The receipt of `message`.
fn receipt_of(message: &Pulled) -> Receipt {
    Receipt {
        receipt: message.receipt.clone(),
    }
}

/// Tess publishes an order, on record with its size only. The courier's
/// service pulls it, handled for the first time, and acknowledges it: the
/// next pull is empty, and the receipt settles nothing a second time.
/// Tess pauses the subscription: a pull is refused until she resumes it,
/// and the order published meanwhile waits and is pulled after. She
/// pauses the topic: publishing is refused until she resumes it. Every
/// step is on record.
#[tokio::test]
async fn the_courier_s_service_pulls_each_order_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;
    let bus = orders_bus(&world, 5).await;

    publish(&world, "order 1001").await;
    let first = pulled(&world, &bus, "order 1001").await;
    assert_eq!(first.delivered, 1, "handed out for the first time");
    messaging::ack(world.tenant(), &bus.subscription_id, &receipt_of(&first))
        .send(tess)
        .await
        .ok();
    let after = messaging::pull(world.tenant(), &bus.subscription_id)
        .send(tess)
        .await
        .ok();
    assert!(after.is_empty(), "an acknowledged order is gone");
    messaging::ack(world.tenant(), &bus.subscription_id, &receipt_of(&first))
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let published = world.trail().recorded_after(&seen, PUBLISHED).await;
    assert!(
        !published.details.to_string().contains("order 1001"),
        "the record holds the size, never the order"
    );

    messaging::pause_subscription(world.tenant(), &bus.subscription_id)
        .send(tess)
        .await
        .ok();
    publish(&world, "order 1002").await;
    messaging::pull(world.tenant(), &bus.subscription_id)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    messaging::resume_subscription(world.tenant(), &bus.subscription_id)
        .send(tess)
        .await
        .ok();
    pulled(&world, &bus, "order 1002").await;

    messaging::pause_topic(world.tenant(), &bus.topic_id)
        .send(tess)
        .await
        .ok();
    let paused = messaging::topic(world.tenant(), &bus.topic_id)
        .send(tess)
        .await
        .ok();
    assert_eq!(paused.status, "Paused");
    let refused = Publication {
        payload: STANDARD.encode("order 1003"),
    };
    messaging::publish(world.tenant(), ORDERS, &refused)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    messaging::resume_topic(world.tenant(), &bus.topic_id)
        .send(tess)
        .await
        .ok();
    publish(&world, "order 1004").await;

    for event_type in SET_UP {
        world.trail().recorded_after(&seen, event_type).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// The courier's service may try each order twice. It refuses an order:
/// the order comes round again at once. Refused a second time, it is set
/// aside as a dead letter and no longer handed out. Tess finds it among
/// the dead letters and replays it, on record: it is pulled again, with a
/// fresh count, and gone from the dead letters.
#[tokio::test]
async fn an_order_the_service_cannot_handle_is_set_aside_and_replayed() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let bus = orders_bus(&world, 2).await;
    let seen = world.trail().ids().await;

    publish(&world, "order 2001").await;
    let first = pulled(&world, &bus, "order 2001").await;
    let fate = messaging::nack(world.tenant(), &bus.subscription_id, &receipt_of(&first))
        .send(tess)
        .await
        .ok();
    assert_eq!(fate.fate, "Redeliver");
    let second = pulled(&world, &bus, "order 2001").await;
    assert_eq!(second.delivered, 2, "the second try");
    let fate = messaging::nack(world.tenant(), &bus.subscription_id, &receipt_of(&second))
        .send(tess)
        .await
        .ok();
    assert_eq!(fate.fate, "DeadLetter");

    let set_aside = messaging::dead_letters(world.tenant(), &bus.subscription_id)
        .send(tess)
        .await
        .ok();
    let dead = set_aside
        .items
        .iter()
        .find(|letter| letter.payload == STANDARD.encode("order 2001"))
        .expect("the order is among the dead letters");
    assert_eq!(dead.delivered, 2);
    let dead_id = dead.id;
    messaging::replay(world.tenant(), &bus.subscription_id, dead_id)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, REPLAYED).await;
    let replayed = pulled(&world, &bus, "order 2001").await;
    assert_eq!(replayed.delivered, 1, "a replay starts the count afresh");
    let remaining = messaging::dead_letters(world.tenant(), &bus.subscription_id)
        .send(tess)
        .await
        .ok();
    assert!(remaining.items.iter().all(|letter| letter.id != dead_id));

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in may not publish to the orders topic, pull the courier's messages,
/// or pause either. Nothing is published or recorded, and the topic stays
/// active.
#[tokio::test]
async fn nobody_without_the_right_publishes_or_pulls_orders() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let bus = orders_bus(&world, 5).await;
    let seen: HashSet<String> = world.trail().ids().await;
    let forged = Publication {
        payload: STANDARD.encode("order 9999"),
    };

    for request in [
        messaging::publish(world.tenant(), ORDERS, &forged).call(),
        messaging::pull(world.tenant(), &bus.subscription_id).call(),
        messaging::pause_topic(world.tenant(), &bus.topic_id).call(),
        messaging::pause_subscription(world.tenant(), &bus.subscription_id).call(),
    ] {
        Matrix::new("using the orders bus", request)
            .refused(uma.client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    let topic = messaging::topic(world.tenant(), &bus.topic_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(topic.status, "Active");
    let waiting = messaging::pull(world.tenant(), &bus.subscription_id)
        .send(world.admin().client())
        .await
        .ok();
    assert!(waiting.is_empty(), "nothing was published");
    world.trail().nothing_after(&seen, PUBLISHED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
