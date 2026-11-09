//! A tenant's message bus as its services use it: topics, pull
//! subscriptions, messages published, pulled, acknowledged or refused,
//! and the dead letters set aside.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::wire::agents::messaging::Retention;

/// `POST …/messaging/topics`: a topic with no schema.
#[derive(Debug, Clone, Serialize)]
pub struct PlainTopic {
    /// The name people see.
    pub name: String,
    /// The routing key services publish to, such as `orders.created`.
    pub topic_name: String,
    /// How long it keeps its messages.
    pub retention: Retention,
}

/// The topic just made.
#[derive(Debug, Clone, Deserialize)]
pub struct TopicMade {
    /// Handle used to manage it.
    pub id: String,
}

/// A topic as `GET …/messaging/topics/{id}` answers it.
#[derive(Debug, Clone, Deserialize)]
pub struct Topic {
    /// Handle used to manage it.
    pub id: String,
    /// The routing key.
    pub topic_name: String,
    /// `Active`, `Paused` or `Archived`.
    pub status: String,
    /// The JSON schema agent messages on it must match, if it has one.
    #[serde(default)]
    pub schema: Option<String>,
    /// How long it keeps its messages, as the API writes it, such as
    /// `{"Duration": 3600}`.
    #[serde(default)]
    pub retention: Option<Value>,
    /// The most sensitive data it may carry, such as `Internal`.
    #[serde(default)]
    pub data_class: Option<String>,
}

/// `PUT …/messaging/topics/{id}/retention`.
#[derive(Debug, Clone, Serialize)]
pub struct RetentionChange {
    /// How long it keeps its messages from now on.
    pub retention: Retention,
}

/// `PUT …/messaging/topics/{id}/schema`: a schema, or `None` to clear it.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaChange {
    /// The JSON schema as text, or `None` for none.
    pub schema: Option<String>,
}

/// `PUT …/messaging/topics/{id}/data-class`.
#[derive(Debug, Clone, Serialize)]
pub struct DataClassChange {
    /// `Public`, `Internal`, `Confidential` or `Restricted`.
    pub data_class: String,
}

/// `POST …/messaging/subscriptions`: a service posted a topic's messages.
#[derive(Debug, Clone, Serialize)]
pub struct PushSubscription {
    /// The topic's routing key.
    pub topic_name: String,
    /// The consumer, the service subscribing.
    pub consumer_id: String,
    /// `Push`, or `Pull` to try a push address on a pulled subscription.
    pub delivery_mode: String,
    /// Where each message is posted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_endpoint: Option<String>,
    /// How often a message is posted before it is set aside.
    pub max_deliveries: u32,
}

/// The push subscription just made. Holds its secret, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct PushSubscribed {
    /// Handle used to manage it.
    pub id: String,
    /// What each push is signed with, shown this once.
    pub signing_secret: String,
}

/// A subscription as a list answers it. Carries no signing secret.
#[derive(Debug, Clone, Deserialize)]
pub struct Subscription {
    /// Handle used to manage it.
    pub id: String,
    /// The topic subscribed to.
    pub topic_name: String,
    /// The consumer subscribed.
    pub consumer_id: String,
    /// `Pull` or `Push`.
    pub delivery_mode: String,
    /// Where a push subscription posts, or `None` for a pulled one.
    #[serde(default)]
    pub push_endpoint: Option<String>,
    /// `Active` or `Paused`.
    pub status: String,
}

/// `POST …/subscriptions/{id}/rotate-push-secret`: how long the old secret
/// keeps signing beside the new one, or not at all.
#[derive(Debug, Clone, Serialize)]
pub struct PushSecretRotation {
    /// Seconds of overlap, at most seven days; left out, the old stops at
    /// once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_seconds: Option<i64>,
}

/// The new secret a rotation made. Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct RotatedPushSecret {
    /// The new secret, shown this once.
    pub signing_secret: String,
}

/// `POST …/messaging/schemas`: an event schema with its first version.
#[derive(Debug, Clone, Serialize)]
pub struct NewSchema {
    /// The name people see, such as `Order created`.
    pub name: String,
    /// What it is called in code, such as `order-created`.
    pub schema_name: String,
    /// `JsonSchema`, `Avro` or `Protobuf`.
    pub format: String,
    /// `None`, `Backward`, `Forward` or `Full`.
    pub compatibility: String,
    /// The first version's definition, as text.
    pub definition: String,
}

/// The schema just registered.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaMade {
    /// Handle used to manage it.
    pub id: String,
}

/// `POST …/messaging/schemas/{id}/versions`.
#[derive(Debug, Clone, Serialize)]
pub struct NewSchemaVersion {
    /// The new version's definition, as text.
    pub definition: String,
}

/// The version just added.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaEvolved {
    /// Its number, one past the last.
    pub version: u32,
}

/// An event schema with every version.
#[derive(Debug, Clone, Deserialize)]
pub struct EventSchema {
    /// Handle used to manage it.
    pub id: String,
    /// What it is called in code.
    pub schema_name: String,
    /// Every version, oldest first.
    pub versions: Vec<EventSchemaVersion>,
}

/// What one version of a schema declares, numbered from one.
#[derive(Debug, Clone, Deserialize)]
pub struct EventSchemaVersion {
    /// Its number.
    pub version: u32,
    /// Its definition, as registered.
    pub definition: String,
}

/// `POST …/messaging/channels`: the area of one agent another may read.
#[derive(Debug, Clone, Serialize)]
pub struct NewChannel {
    /// The agent whose area the messages come from.
    pub sender_agent_id: String,
    /// The agent that may read them.
    pub receiver_agent_id: String,
    /// The topics in the sender's area the receiver may read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<String>,
    /// One object both agents may hold rights on, such as `doc:42`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// The most sensitive data that may travel through it.
    pub max_class: String,
    /// How long it stays open, in seconds, 60 to 2,592,000.
    pub lifetime_seconds: u32,
}

/// A channel between two agents.
#[derive(Debug, Clone, Deserialize)]
pub struct Channel {
    /// Handle used to close it.
    pub id: String,
    /// The agent whose area the messages come from.
    pub sender_agent_id: String,
    /// The agent that may read them.
    pub receiver_agent_id: String,
    /// `topics` or `resource`.
    pub scope_kind: String,
    /// The topic pattern or resource reference.
    pub scope: String,
    /// When a person closed it, if one did, in RFC 3339.
    #[serde(default)]
    pub closed_at: Option<String>,
    /// Whether it carries messages right now.
    pub open: bool,
}

/// `POST …/messaging/subscriptions`: a service pulling a topic's messages.
#[derive(Debug, Clone, Serialize)]
pub struct PullSubscription {
    /// The topic's routing key.
    pub topic_name: String,
    /// The consumer, the service subscribing.
    pub consumer_id: String,
    /// Always `Pull` here.
    pub delivery_mode: String,
    /// How often a message is handed out before it is set aside.
    pub max_deliveries: u32,
}

/// The subscription just made.
#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionMade {
    /// Handle used to pull and manage it.
    pub id: String,
}

/// `POST …/messaging/topics/{name}/publish`: one message.
#[derive(Debug, Clone, Serialize)]
pub struct Publication {
    /// The message's bytes, base64-encoded.
    pub payload: String,
}

/// One message a pull handed out. Holds its receipt, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct Pulled {
    /// The message's bytes, base64-encoded.
    pub payload: String,
    /// What settles it, once, by `ack` or `nack`.
    pub receipt: String,
    /// How often it was handed out, this time included.
    pub delivered: u32,
}

/// `POST …/messages/ack` or `…/nack`: the receipt of a pulled message.
#[derive(Clone, Serialize)]
pub struct Receipt {
    /// The receipt the pull gave.
    pub receipt: String,
}

/// What became of a refused message.
#[derive(Debug, Clone, Deserialize)]
pub struct Refused {
    /// `Redeliver` or `DeadLetter`.
    pub fate: String,
}

/// A message set aside once its deliveries ran out.
#[derive(Debug, Clone, Deserialize)]
pub struct DeadLetter {
    /// Handle used to replay it.
    pub id: u64,
    /// Its bytes, base64-encoded.
    pub payload: String,
    /// How often it was handed out.
    pub delivered: u32,
}
