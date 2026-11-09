//! Who reads a topic. Tess finds the courier's subscription by its topic
//! and by its service, and deletes it: it stops pulling, and what is
//! published later waits for nobody. A second subscription of the same
//! service to the same topic is a conflict. A list naming neither topic
//! nor service is refused, and nobody without the right lists or deletes
//! one.

use ianua_scenarios::api::messaging;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::messaging::PullSubscription;
use ianua_scenarios::world::World;

use crate::bus::{made_topic, published, pulled_by, refused_to_the_cast, service};
use crate::support::person;

/// The routing key of the topic.
const ORDERS: &str = "orders.created";

/// The record a deleted subscription leaves.
const DELETED: &str = "messaging.subscription_deleted";

/// Tess finds the courier's subscription under its topic and under its
/// service, the same one both ways. Subscribing the same service again is
/// a conflict. She deletes the subscription, on record: the courier can
/// no longer pull, the list is empty, and an order published now is
/// published to nobody. A list naming neither topic nor service says so.
#[tokio::test]
async fn tess_lists_and_deletes_a_services_subscription() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let subscription_id = pulled_by(&world, ORDERS, &courier).await;
    let seen = world.trail().ids().await;

    let by_topic = messaging::subscriptions_to(world.tenant(), ORDERS)
        .send(tess)
        .await
        .ok();
    assert_eq!(by_topic.items.len(), 1, "the courier reads the topic");
    assert_eq!(by_topic.items[0].id, subscription_id);
    assert_eq!(by_topic.items[0].delivery_mode, "Pull");
    assert_eq!(by_topic.items[0].status, "Active");
    assert_eq!(by_topic.items[0].push_endpoint, None);
    let by_service = messaging::subscriptions_of(world.tenant(), &courier)
        .send(tess)
        .await
        .ok();
    assert_eq!(by_service.items.len(), 1, "the courier reads one topic");
    assert_eq!(by_service.items[0].topic_name, ORDERS);
    assert_eq!(by_service.items[0].consumer_id, courier);

    let twice = PullSubscription {
        topic_name: ORDERS.to_owned(),
        consumer_id: courier.clone(),
        delivery_mode: "Pull".to_owned(),
        max_deliveries: 5,
    };
    messaging::subscribe(world.tenant(), &twice)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");

    messaging::delete_subscription(world.tenant(), &subscription_id)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, DELETED).await;
    messaging::pull(world.tenant(), &subscription_id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let remaining = messaging::subscriptions_to(world.tenant(), ORDERS)
        .send(tess)
        .await
        .ok();
    assert!(remaining.items.is_empty(), "the subscription is gone");
    published(&world, ORDERS, "order 4001").await;

    messaging::all_subscriptions(world.tenant())
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in cannot list the courier's subscription or delete it, and Sam finds
/// no such subscription from his own tenant. The courier goes on pulling
/// and nothing is on record.
#[tokio::test]
async fn nobody_without_the_right_lists_or_deletes_a_subscription() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let subscription_id = pulled_by(&world, ORDERS, &courier).await;
    let seen = world.trail().ids().await;

    for call in [
        messaging::subscriptions_to(world.tenant(), ORDERS).call(),
        messaging::subscriptions_of(world.tenant(), &courier).call(),
        messaging::delete_subscription(world.tenant(), &subscription_id).call(),
    ] {
        refused_to_the_cast(&world, &uma, "managing the courier's subscription", call).await;
    }

    Matrix::new(
        "reaching Acme's subscription from the other tenant",
        messaging::delete_subscription(world.twin(), &subscription_id).call(),
    )
    .refused(world.stranger().client(), Status::NOT_FOUND, "not_found")
    .run()
    .await;

    messaging::pull(world.tenant(), &subscription_id)
        .send(tess)
        .await
        .ok();
    world.trail().nothing_after(&seen, DELETED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
