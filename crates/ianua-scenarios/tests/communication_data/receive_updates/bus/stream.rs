//! Watching a topic live. Tess opens the orders topic's stream and sees an
//! order the moment it is published. The stream hands over what pulling
//! would, so it takes what pulling takes: it is refused to anyone without
//! the right, for a topic that does not exist, and for one that is paused.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::api::messaging;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::bus::{made_topic, published};
use crate::support::person;

/// The routing key of the topic.
const ORDERS: &str = "orders.created";

/// How long the stream is read for once it has gone quiet.
const QUIET: Duration = Duration::from_secs(3);

/// Tess opens the orders topic's live stream and publishes an order: it
/// arrives on the stream, its bytes in base64, in a frame naming the
/// topic. She leaves by closing the stream.
#[tokio::test]
async fn tess_sees_an_order_on_the_live_stream_as_it_is_published() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    made_topic(&world, ORDERS).await;
    let path = messaging::topic_stream(world.tenant(), ORDERS);
    let mut stream = world.admin().client().open_socket(&path).await.open();

    published(&world, ORDERS, "order 6001").await;

    let frames = stream.texts_until_quiet(QUIET).await;
    let expected = STANDARD.encode("order 6001");
    assert!(
        frames
            .iter()
            .any(|frame| frame.contains(&expected) && frame.contains(ORDERS)),
        "the order arrived on the stream: {frames:?}"
    );
    stream.close().await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Nobody signed in is asked to sign in. Uma, an ordinary user of the
/// tenant, Max, a member with no administrator's rights, and Sam from the
/// other company are refused. Tess is refused a topic that does not exist,
/// and refused the orders topic while it is paused; once she resumes it
/// the stream opens.
#[tokio::test]
async fn a_stream_is_refused_without_the_right_or_while_the_topic_is_paused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    let topic_id = made_topic(&world, ORDERS).await;
    let path = messaging::topic_stream(world.tenant(), ORDERS);

    world
        .anonymous()
        .client()
        .open_socket(&path)
        .await
        .refusal()
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    for client in [
        uma.client(),
        world.member().client(),
        world.stranger().client(),
    ] {
        client
            .open_socket(&path)
            .await
            .refusal()
            .refused(Status::FORBIDDEN, "forbidden");
    }

    let missing = messaging::topic_stream(world.tenant(), "orders.cancelled");
    tess.open_socket(&missing)
        .await
        .refusal()
        .refused(Status::NOT_FOUND, "not_found");

    messaging::pause_topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    tess.open_socket(&path)
        .await
        .refusal()
        .refused(Status::FORBIDDEN, "forbidden");
    messaging::resume_topic(world.tenant(), &topic_id)
        .send(tess)
        .await
        .ok();
    tess.open_socket(&path).await.open().close().await;

    stack.stop().await.expect("the stack stops cleanly");
}
