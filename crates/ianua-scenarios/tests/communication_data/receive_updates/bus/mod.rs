//! The rest of a tenant's message bus: the topics, the services that
//! read them, and who may change either. Holds what these scenarios
//! share: a topic Tess makes, the service she subscribes to it, a message
//! she publishes, and the cast's refusals of a step that needs a
//! messaging right.
//!
//! - `retention`: a topic's limit, by age or by count: inside it an order
//!   is read, outside it neither read nor posted, and a longer limit
//!   brings nothing back.
//! - `schemas`: Tess registers an order-created schema, adds a compatible
//!   version and deletes it; a breaking version, a definition that is not
//!   JSON and a second schema of that name are refused.
//! - `topics`: a topic's retention, schema and data class, which only
//!   rises and shuts out services cleared below it; an archived topic is
//!   read-only, and deleting a topic ends its subscriptions.
//! - `subscriptions`: the courier's subscription found by topic and by
//!   service, and deleted; a second one is a conflict.
//! - `push`: the signing secret shown once and rotated, a push that fails
//!   set aside, and no address inside the deployment.
//! - `channels`: Tess opens and closes a channel between two agents;
//!   a channel outside the sender's area is refused.
//! - `stream`: Tess watches the orders topic live over a WebSocket; a
//!   stream is refused to anyone who may not read that topic, and to
//!   everyone while it is paused.

mod channels;
mod push;
mod retention;
mod schemas;
mod stream;
mod subscriptions;
mod topics;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{consumers, messaging};
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::consumers::NewConsumer;
use ianua_scenarios::wire::messaging::{
    DeadLetter, PlainTopic, Publication, PullSubscription, Retention,
};
use ianua_scenarios::world::World;

/// Tess makes a topic named `topic_name`, keeping messages for an hour.
///
/// # Panics
///
/// When the topic is refused.
pub(crate) async fn made_topic(world: &World<'_>, topic_name: &str) -> String {
    let topic = PlainTopic {
        name: format!("Topic {topic_name}"),
        topic_name: topic_name.to_owned(),
        retention: Retention::Duration(3600),
    };
    messaging::create_topic(world.tenant(), &topic)
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// Tess makes a service called `name`, signing in with a key the platform
/// makes.
///
/// # Panics
///
/// When the service is refused.
pub(crate) async fn service(world: &World<'_>, name: &str) -> String {
    let courier = NewConsumer {
        name: name.to_owned(),
        description: None,
        credential_kind: "api_key".to_owned(),
    };
    consumers::create(world.tenant(), &courier)
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// Tess subscribes `consumer_id` to pull `topic_name`.
///
/// # Panics
///
/// When the subscription is refused.
pub(crate) async fn pulled_by(world: &World<'_>, topic_name: &str, consumer_id: &str) -> String {
    let subscription = PullSubscription {
        topic_name: topic_name.to_owned(),
        consumer_id: consumer_id.to_owned(),
        delivery_mode: "Pull".to_owned(),
        max_deliveries: 5,
    };
    messaging::subscribe(world.tenant(), &subscription)
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// Tess publishes `text` to `topic_name`.
///
/// # Panics
///
/// When the message is refused.
pub(crate) async fn published(world: &World<'_>, topic_name: &str, text: &str) {
    let message = Publication {
        payload: STANDARD.encode(text),
    };
    messaging::publish(world.tenant(), topic_name, &message)
        .send(world.admin().client())
        .await
        .ok();
}

/// The dead letter carrying `order`, once `subscription_id` has set one
/// aside.
///
/// # Panics
///
/// When none is set aside within the patience of `eventually`.
pub(crate) async fn set_aside(world: &World<'_>, subscription_id: &str, order: &str) -> DeadLetter {
    let expected = STANDARD.encode(order);
    eventually("the order to be set aside", || {
        let expected = expected.clone();
        async move {
            let letters = messaging::dead_letters(world.tenant(), subscription_id)
                .send(world.admin().client())
                .await
                .ok();
            letters
                .items
                .into_iter()
                .find(|letter| letter.payload == expected)
        }
    })
    .await
}

/// `call` refused to Uma, an ordinary user of the tenant, Max, a member
/// with no administrator's rights, Sam, from the other company, and nobody
/// signed in.
///
/// # Panics
///
/// When any of them is not refused as told.
pub(crate) async fn refused_to_the_cast(world: &World<'_>, uma: &Person, what: &str, call: Call) {
    Matrix::new(what, call)
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
