//! A tenant's message bus as its services use it: topics made, read,
//! paused, resumed, archived, changed and deleted; event schemas and their
//! versions; pull and push subscriptions and their signing secrets;
//! messages published, pulled, acknowledged and refused; dead letters read
//! and replayed; and channels between agents.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::messaging::{
    Channel, DataClassChange, DeadLetter, EventSchema, NewChannel, NewSchema, NewSchemaVersion,
    PlainTopic, Publication, PullSubscription, Pulled, PushSecretRotation, PushSubscribed,
    PushSubscription, Receipt, Refused, RetentionChange, RotatedPushSecret, SchemaChange,
    SchemaEvolved, SchemaMade, Subscription, SubscriptionMade, Topic, TopicMade,
};

/// `POST …/messaging/topics`.
#[must_use]
pub fn create_topic(tenant: &TenantPath, topic: &PlainTopic) -> Request<TopicMade> {
    Request::of(Call::post(tenant.at("/messaging/topics")).json(topic))
}

/// `GET …/messaging/topics/{id}`.
#[must_use]
pub fn topic(tenant: &TenantPath, topic_id: &str) -> Request<Topic> {
    Request::of(Call::get(
        tenant.at(&format!("/messaging/topics/{topic_id}")),
    ))
}

/// `POST …/messaging/topics/{id}/pause`: publishing is refused until it
/// resumes.
#[must_use]
pub fn pause_topic(tenant: &TenantPath, topic_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_id}/pause"));
    Request::of(Call::post(path))
}

/// `POST …/messaging/topics/{id}/resume`.
#[must_use]
pub fn resume_topic(tenant: &TenantPath, topic_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_id}/resume"));
    Request::of(Call::post(path))
}

/// `POST …/messaging/topics/{id}/archive`.
#[must_use]
pub fn archive_topic(tenant: &TenantPath, topic_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_id}/archive"));
    Request::of(Call::post(path))
}

/// `GET …/messaging/topics`.
#[must_use]
pub fn topics(tenant: &TenantPath) -> Request<Page<Topic>> {
    Request::of(Call::get(tenant.at("/messaging/topics")))
}

/// `DELETE …/messaging/topics/{id}`: only a paused or archived one, with
/// every subscription to it.
#[must_use]
pub fn delete_topic(tenant: &TenantPath, topic_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/messaging/topics/{topic_id}")),
    ))
}

/// `PUT …/messaging/topics/{id}/retention`.
#[must_use]
pub fn change_retention(
    tenant: &TenantPath,
    topic_id: &str,
    change: &RetentionChange,
) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_id}/retention"));
    Request::of(Call::put(path).json(change))
}

/// `PUT …/messaging/topics/{id}/schema`.
#[must_use]
pub fn change_schema(tenant: &TenantPath, topic_id: &str, change: &SchemaChange) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_id}/schema"));
    Request::of(Call::put(path).json(change))
}

/// `PUT …/messaging/topics/{id}/data-class`: only ever upward.
#[must_use]
pub fn raise_data_class(
    tenant: &TenantPath,
    topic_id: &str,
    change: &DataClassChange,
) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_id}/data-class"));
    Request::of(Call::put(path).json(change))
}

/// `POST …/messaging/schemas`.
#[must_use]
pub fn register_schema(tenant: &TenantPath, schema: &NewSchema) -> Request<SchemaMade> {
    Request::of(Call::post(tenant.at("/messaging/schemas")).json(schema))
}

/// `GET …/messaging/schemas`.
#[must_use]
pub fn schemas(tenant: &TenantPath) -> Request<Page<EventSchema>> {
    Request::of(Call::get(tenant.at("/messaging/schemas")))
}

/// `GET …/messaging/schemas/{id}`.
#[must_use]
pub fn schema(tenant: &TenantPath, schema_id: &str) -> Request<EventSchema> {
    Request::of(Call::get(
        tenant.at(&format!("/messaging/schemas/{schema_id}")),
    ))
}

/// `POST …/messaging/schemas/{id}/versions`.
#[must_use]
pub fn evolve_schema(
    tenant: &TenantPath,
    schema_id: &str,
    version: &NewSchemaVersion,
) -> Request<SchemaEvolved> {
    let path = tenant.at(&format!("/messaging/schemas/{schema_id}/versions"));
    Request::of(Call::post(path).json(version))
}

/// `DELETE …/messaging/schemas/{id}`.
#[must_use]
pub fn delete_schema(tenant: &TenantPath, schema_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/messaging/schemas/{schema_id}")),
    ))
}

/// `POST …/messaging/subscriptions`, for a push subscription: answered
/// with its signing secret, shown this once.
#[must_use]
pub fn subscribe_push(
    tenant: &TenantPath,
    subscription: &PushSubscription,
) -> Request<PushSubscribed> {
    Request::of(Call::post(tenant.at("/messaging/subscriptions")).json(subscription))
}

/// `GET …/messaging/subscriptions?topic_name=…`.
#[must_use]
pub fn subscriptions_to(tenant: &TenantPath, topic_name: &str) -> Request<Page<Subscription>> {
    let path = tenant.at(&format!("/messaging/subscriptions?topic_name={topic_name}"));
    Request::of(Call::get(path))
}

/// `GET …/messaging/subscriptions?consumer_id=…`.
#[must_use]
pub fn subscriptions_of(tenant: &TenantPath, consumer_id: &str) -> Request<Page<Subscription>> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions?consumer_id={consumer_id}"
    ));
    Request::of(Call::get(path))
}

/// `GET …/messaging/subscriptions`, naming neither a topic nor a service.
#[must_use]
pub fn all_subscriptions(tenant: &TenantPath) -> Request<Page<Subscription>> {
    Request::of(Call::get(tenant.at("/messaging/subscriptions")))
}

/// `DELETE …/messaging/subscriptions/{id}`.
#[must_use]
pub fn delete_subscription(tenant: &TenantPath, subscription_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/messaging/subscriptions/{subscription_id}"));
    Request::of(Call::delete(path))
}

/// `POST …/messaging/subscriptions/{id}/rotate-push-secret`.
#[must_use]
pub fn rotate_push_secret(
    tenant: &TenantPath,
    subscription_id: &str,
    rotation: &PushSecretRotation,
) -> Request<RotatedPushSecret> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/rotate-push-secret"
    ));
    Request::of(Call::post(path).json(rotation))
}

/// `POST …/messaging/channels`.
#[must_use]
pub fn open_channel(tenant: &TenantPath, channel: &NewChannel) -> Request<Channel> {
    Request::of(Call::post(tenant.at("/messaging/channels")).json(channel))
}

/// `GET …/messaging/channels`.
#[must_use]
pub fn channels(tenant: &TenantPath) -> Request<Page<Channel>> {
    Request::of(Call::get(tenant.at("/messaging/channels")))
}

/// `POST …/messaging/channels/{id}/close`.
#[must_use]
pub fn close_channel(tenant: &TenantPath, channel_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/messaging/channels/{channel_id}/close"));
    Request::of(Call::post(path))
}

/// `GET …/messaging/topics/{name}/stream`: where a person watches a topic
/// live over a WebSocket.
#[must_use]
pub fn topic_stream(tenant: &TenantPath, topic_name: &str) -> String {
    tenant.at(&format!("/messaging/topics/{topic_name}/stream"))
}

/// `POST …/messaging/subscriptions`.
#[must_use]
pub fn subscribe(
    tenant: &TenantPath,
    subscription: &PullSubscription,
) -> Request<SubscriptionMade> {
    Request::of(Call::post(tenant.at("/messaging/subscriptions")).json(subscription))
}

/// `POST …/messaging/subscriptions/{id}/pause`.
#[must_use]
pub fn pause_subscription(tenant: &TenantPath, subscription_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/messaging/subscriptions/{subscription_id}/pause"));
    Request::of(Call::post(path))
}

/// `POST …/messaging/subscriptions/{id}/resume`.
#[must_use]
pub fn resume_subscription(tenant: &TenantPath, subscription_id: &str) -> Request<()> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/resume"
    ));
    Request::of(Call::post(path))
}

/// `POST …/messaging/topics/{name}/publish`.
#[must_use]
pub fn publish(tenant: &TenantPath, topic_name: &str, message: &Publication) -> Request<()> {
    let path = tenant.at(&format!("/messaging/topics/{topic_name}/publish"));
    Request::of(Call::post(path).json(message))
}

/// `GET …/messaging/subscriptions/{id}/messages`: the waiting messages.
#[must_use]
pub fn pull(tenant: &TenantPath, subscription_id: &str) -> Request<Vec<Pulled>> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/messages"
    ));
    Request::of(Call::get(path))
}

/// `POST …/messaging/subscriptions/{id}/messages/ack`.
#[must_use]
pub fn ack(tenant: &TenantPath, subscription_id: &str, receipt: &Receipt) -> Request<()> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/messages/ack"
    ));
    Request::of(Call::post(path).json(receipt))
}

/// `POST …/messaging/subscriptions/{id}/messages/nack`.
#[must_use]
pub fn nack(tenant: &TenantPath, subscription_id: &str, receipt: &Receipt) -> Request<Refused> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/messages/nack"
    ));
    Request::of(Call::post(path).json(receipt))
}

/// `GET …/messaging/subscriptions/{id}/dead-letters`.
#[must_use]
pub fn dead_letters(tenant: &TenantPath, subscription_id: &str) -> Request<Page<DeadLetter>> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/dead-letters"
    ));
    Request::of(Call::get(path))
}

/// `POST …/messaging/subscriptions/{id}/dead-letters/{dead}/replay`.
#[must_use]
pub fn replay(tenant: &TenantPath, subscription_id: &str, dead_letter_id: u64) -> Request<()> {
    let path = tenant.at(&format!(
        "/messaging/subscriptions/{subscription_id}/dead-letters/{dead_letter_id}/replay"
    ));
    Request::of(Call::post(path))
}
