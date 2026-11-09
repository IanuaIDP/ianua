//! A service told of each order instead of asking. Tess subscribes the
//! courier's service to the orders topic at its HTTPS address and is shown
//! the secret its posts are signed with, once. It never appears again: not
//! in the list, not in the audit record of a rotation. When the address
//! cannot take a post, the order is set aside for Tess to look at. No
//! address inside the deployment can be named, and nobody without the
//! right rotates the secret.
//!
//! A post reaching a working receiver and the signature it verifies are
//! proved here too, against a stand-in for the courier's service the
//! deployment trusts (`OUTBOUND_DELIVERY_CA_FILE`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::api::{Request, messaging};
use ianua_scenarios::expect::{Matrix, eventually, no_secret_leaked, standard_webhook_signed_by};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, OutsideReceiver, Received};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::messaging::{PushSecretRotation, PushSubscription};
use ianua_scenarios::world::World;

use crate::bus::{made_topic, published, pulled_by, refused_to_the_cast, service, set_aside};
use crate::support::person;

/// The routing key of the topic.
const ORDERS: &str = "orders.created";

/// An address that can never answer: the `.invalid` suffix is reserved so
/// that no such name exists.
const NOWHERE: &str = "https://courier.acme.invalid/orders";

/// The record a new subscription leaves.
const CREATED: &str = "messaging.subscription_created";

/// The record a rotated signing secret leaves.
const ROTATED: &str = "messaging.subscription_secret_rotated";

/// One week and a second: the longest overlap, passed by one.
const OVER_A_WEEK: i64 = 7 * 24 * 60 * 60 + 1;

/// A push subscription of `consumer_id` to the orders topic at `address`,
/// given `tries` posts.
fn pushed_to(consumer_id: &str, address: &str, tries: u32) -> PushSubscription {
    PushSubscription {
        topic_name: ORDERS.to_owned(),
        consumer_id: consumer_id.to_owned(),
        delivery_mode: "Push".to_owned(),
        push_endpoint: Some(address.to_owned()),
        max_deliveries: tries,
    }
}

/// Tess subscribes the courier's service to be pushed, and sees the
/// signing secret this once: the subscription as listed names the address
/// and carries no secret. She rotates it with an hour's overlap and again
/// with none; each rotation gives a new secret, on record without any of
/// them.
#[tokio::test]
async fn a_push_subscription_shows_its_secret_once_and_rotates_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let seen = world.trail().ids().await;

    let subscribed = messaging::subscribe_push(world.tenant(), &pushed_to(&courier, NOWHERE, 5))
        .send(tess)
        .await
        .ok();
    assert!(
        !subscribed.signing_secret.is_empty(),
        "the secret is shown when the subscription is made"
    );
    world.trail().recorded_after(&seen, CREATED).await;

    let listed = messaging::subscriptions_to(world.tenant(), ORDERS)
        .send(tess)
        .await
        .ok();
    assert_eq!(listed.items[0].delivery_mode, "Push");
    assert_eq!(listed.items[0].push_endpoint.as_deref(), Some(NOWHERE));
    let asked_again = messaging::subscriptions_to(world.tenant(), ORDERS).call();
    let body = Request::text(asked_again).send_text(tess).await.ok();
    no_secret_leaked(&body, &[subscribed.signing_secret.as_str()]);

    let overlapping = PushSecretRotation {
        overlap_seconds: Some(3600),
    };
    let rotated = messaging::rotate_push_secret(world.tenant(), &subscribed.id, &overlapping)
        .send(tess)
        .await
        .ok();
    assert_ne!(
        rotated.signing_secret, subscribed.signing_secret,
        "the secret is a new one"
    );
    let entry = world.trail().recorded_after(&seen, ROTATED).await;
    no_secret_leaked(
        &entry.details.to_string(),
        &[
            subscribed.signing_secret.as_str(),
            rotated.signing_secret.as_str(),
        ],
    );
    let at_once = PushSecretRotation {
        overlap_seconds: None,
    };
    let again = messaging::rotate_push_secret(world.tenant(), &subscribed.id, &at_once)
        .send(tess)
        .await
        .ok();
    assert_ne!(
        again.signing_secret, rotated.signing_secret,
        "a second rotation gives another secret"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The courier's address cannot take a post, and the subscription gives
/// each order one try. Tess publishes an order: the worker posts it, the
/// post fails, and the order is set aside as a dead letter holding what
/// was published, for Tess to find.
#[tokio::test]
async fn an_order_the_address_cannot_take_is_set_aside() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let subscribed = messaging::subscribe_push(world.tenant(), &pushed_to(&courier, NOWHERE, 1))
        .send(tess)
        .await
        .ok();

    published(&world, ORDERS, "order 5001").await;

    let letter = set_aside(&world, &subscribed.id, "order 5001").await;
    assert_eq!(letter.delivered, 1, "it was posted once");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, holding Tess's rights, tries to have the platform post into
/// its own network: at the loopback address, at the cloud's metadata
/// address, at a name only the deployment resolves, and in the clear. All
/// are refused before anything is made, as is a pulled subscription that
/// names an address and a pushed one that names none. Nothing is on
/// record.
#[tokio::test]
async fn no_push_address_may_reach_inside_the_deployment() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let seen = world.trail().ids().await;

    for address in [
        "https://localhost/orders",
        "https://127.0.0.1/orders",
        "https://169.254.169.254/latest/meta-data",
        "https://billing.svc.cluster.local/orders",
        "http://courier.example.com/orders",
    ] {
        messaging::subscribe_push(world.tenant(), &pushed_to(&courier, address, 5))
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }

    let pulled_with_address = PushSubscription {
        delivery_mode: "Pull".to_owned(),
        ..pushed_to(&courier, NOWHERE, 5)
    };
    messaging::subscribe_push(world.tenant(), &pulled_with_address)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let pushed_without_address = PushSubscription {
        push_endpoint: None,
        ..pushed_to(&courier, NOWHERE, 5)
    };
    messaging::subscribe_push(world.tenant(), &pushed_without_address)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    world.trail().nothing_after(&seen, CREATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The path the courier's service takes orders at.
const COURIER_INBOX: &str = "/orders";

/// The `count`-th post to `server`, once it has arrived, counting from one.
async fn post_number(server: &OutsideReceiver, count: usize) -> Received {
    let what = format!("post number {count} at the courier's service");
    let mut posts = eventually(&what, || async move {
        let posts = server.received_at("POST", COURIER_INBOX);
        (posts.len() >= count).then_some(posts)
    })
    .await;
    posts.remove(count - 1)
}

/// The courier's real service takes pushes. Tess subscribes it and
/// publishes an order: the post carries the order in the shape a pulled
/// message has, signed with the secret she was shown. She rotates with an
/// overlap and publishes again: the post verifies under both secrets. She
/// rotates at once and publishes a third: it verifies under the newest
/// secret alone, so the old ones stop working the moment the rotation
/// takes effect.
#[tokio::test]
async fn a_push_is_signed_and_a_rotated_secret_stops_signing() {
    let server = OutsideReceiver::start(
        "courier.acme.example",
        [(COURIER_INBOX, Canned::json(&serde_json::json!({})))],
    )
    .await;
    let stack = Stack::start(
        Profile::standard().with("OUTBOUND_DELIVERY_CA_FILE", server.authority_file()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let address = server.url_on(&stack, COURIER_INBOX);
    let subscribed = messaging::subscribe_push(world.tenant(), &pushed_to(&courier, &address, 5))
        .send(tess)
        .await
        .ok();

    published(&world, ORDERS, "order 5001").await;
    let first = post_number(&server, 1).await;
    assert_eq!(
        first.json()["payload"],
        STANDARD.encode("order 5001"),
        "the post is the order, as a pulled message carries it"
    );
    assert!(standard_webhook_signed_by(
        &first,
        &subscribed.signing_secret
    ));

    let overlapping = PushSecretRotation {
        overlap_seconds: Some(3600),
    };
    let rotated = messaging::rotate_push_secret(world.tenant(), &subscribed.id, &overlapping)
        .send(tess)
        .await
        .ok();
    published(&world, ORDERS, "order 5002").await;
    let second = post_number(&server, 2).await;
    assert!(
        standard_webhook_signed_by(&second, &subscribed.signing_secret),
        "within the overlap the old secret still signs"
    );
    assert!(
        standard_webhook_signed_by(&second, &rotated.signing_secret),
        "and so does the new one"
    );

    let at_once = PushSecretRotation {
        overlap_seconds: None,
    };
    let newest = messaging::rotate_push_secret(world.tenant(), &subscribed.id, &at_once)
        .send(tess)
        .await
        .ok();
    published(&world, ORDERS, "order 5003").await;
    let third = post_number(&server, 3).await;
    assert!(standard_webhook_signed_by(&third, &newest.signing_secret));
    assert!(
        !standard_webhook_signed_by(&third, &subscribed.signing_secret),
        "the first secret signs nothing now"
    );
    assert!(
        !standard_webhook_signed_by(&third, &rotated.signing_secret),
        "nor the one rotated away at once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Rotating a pulled subscription is a conflict: it signs nothing. An
/// overlap longer than a week is refused. Uma, Max, Sam and nobody signed
/// in rotate nothing, and Sam finds no such subscription from his own
/// tenant. No rotation is on record.
#[tokio::test]
async fn only_a_push_subscription_rotates_and_only_with_the_right() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    made_topic(&world, ORDERS).await;
    let courier = service(&world, "Courier service").await;
    let subscribed = messaging::subscribe_push(world.tenant(), &pushed_to(&courier, NOWHERE, 5))
        .send(tess)
        .await
        .ok();
    let puller = service(&world, "Pulling service").await;
    let pulled = pulled_by(&world, ORDERS, &puller).await;
    let seen = world.trail().ids().await;
    let rotation = PushSecretRotation {
        overlap_seconds: None,
    };

    messaging::rotate_push_secret(world.tenant(), &pulled, &rotation)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    let too_long = PushSecretRotation {
        overlap_seconds: Some(OVER_A_WEEK),
    };
    messaging::rotate_push_secret(world.tenant(), &subscribed.id, &too_long)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    refused_to_the_cast(
        &world,
        &uma,
        "rotating the courier's push secret",
        messaging::rotate_push_secret(world.tenant(), &subscribed.id, &rotation).call(),
    )
    .await;
    Matrix::new(
        "rotating Acme's push secret from the other tenant",
        messaging::rotate_push_secret(world.twin(), &subscribed.id, &rotation).call(),
    )
    .refused(world.stranger().client(), Status::NOT_FOUND, "not_found")
    .run()
    .await;

    world.trail().nothing_after(&seen, ROTATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
