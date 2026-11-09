//! Events raised by topics, subscriptions, schemas and published messages.

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::messaging::topic::RetentionPolicy;
use crate::domains::messaging::topic_name::TopicName;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::MessagingEvent;
use crate::types::{EventLabel, EventSchemaId, Label, MessageSubscriptionId, TopicId};

/// The reference kind for a messaging topic.
///
/// A topic is not the message schema published to it. So it has its own
/// kind instead of [`RefKind::SCHEMA`].
const TOPIC: RefKind = RefKind::new("topic");

/// The reference kind for a service's subscription to a topic.
///
/// It is not [`RefKind::SUBSCRIPTION`], which names a billing plan
/// subscription.
const TOPIC_SUBSCRIPTION: RefKind = RefKind::new("topic_subscription");

/// A topic was created.
#[derive(Debug)]
pub struct TopicCreated {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// When it was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicCreated => MessagingEvent::TopicCreated,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name)
    }
}

/// A topic was deleted, together with every subscription to it.
#[derive(Debug)]
pub struct TopicDeleted {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name, so the record stays readable once it is gone.
    pub(crate) topic_name: TopicName,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicDeleted => MessagingEvent::TopicDeleted,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name)
    }
}

/// A subscription was created.
#[derive(Debug)]
pub struct SubscriptionCreated {
    /// The subscription's unique ID.
    pub(crate) subscription_id: MessageSubscriptionId,
    /// A readable name for the subscription: its consumer group, or else the
    /// topic it consumes. It is copied when the event is written, so the
    /// audit entry stays readable after the subscription is removed.
    pub(crate) subscription_label: EventLabel,
    /// The topic subscribed to.
    pub(crate) topic_name: TopicName,
    /// When it was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SubscriptionCreated => MessagingEvent::SubscriptionCreated,
    fn payload(&self) -> EventData {
        subscription_payload(self.subscription_id, &self.subscription_label, &self.topic_name)
    }
}

/// A topic was paused: it refuses new messages until it is resumed.
#[derive(Debug)]
pub struct TopicPaused {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// When it was paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicPaused => MessagingEvent::TopicPaused,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name)
    }
}

/// A paused topic was resumed and accepts messages again.
#[derive(Debug)]
pub struct TopicResumed {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// When it was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicResumed => MessagingEvent::TopicResumed,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name)
    }
}

/// A topic was archived: read-only for good, with no new publishes or
/// subscriptions.
#[derive(Debug)]
pub struct TopicArchived {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// When it was archived.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicArchived => MessagingEvent::TopicArchived,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name)
    }
}

/// A topic's message schema was replaced or cleared. The record names the
/// topic, never the schema itself, which can be large.
#[derive(Debug)]
pub struct TopicSchemaChanged {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// When the schema changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicSchemaChanged => MessagingEvent::TopicSchemaChanged,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name)
    }
}

/// A topic's retention policy was replaced. A shorter one drops messages
/// subscribers have not read, so the record keeps both policies.
#[derive(Debug)]
pub struct TopicRetentionChanged {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// The policy before the change.
    pub(crate) previous: RetentionPolicy,
    /// The policy now in force.
    pub(crate) current: RetentionPolicy,
    /// When the policy changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicRetentionChanged => MessagingEvent::TopicRetentionChanged,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name).change(
            "retention",
            retention_text(self.previous),
            retention_text(self.current),
        )
    }
}

/// A topic's data class was raised. Subscribers cleared below the new class
/// stop hearing it, so the record keeps both classes.
#[derive(Debug)]
pub struct TopicDataClassRaised {
    /// The topic's unique ID.
    pub(crate) topic_id: TopicId,
    /// The topic's machine name.
    pub(crate) topic_name: TopicName,
    /// The class before it was raised.
    pub(crate) previous: DataClassLevel,
    /// The class now declared.
    pub(crate) current: DataClassLevel,
    /// When the class was raised.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TopicDataClassRaised => MessagingEvent::TopicDataClassRaised,
    fn payload(&self) -> EventData {
        topic_payload(self.topic_id, &self.topic_name).change(
            "data_class",
            self.previous.as_str().to_owned(),
            self.current.as_str().to_owned(),
        )
    }
}

/// A service's subscription to a topic was deleted.
#[derive(Debug)]
pub struct SubscriptionDeleted {
    /// The subscription's unique ID.
    pub(crate) subscription_id: MessageSubscriptionId,
    /// A readable name for the subscription: its consumer group, or else the
    /// topic it consumed. It keeps the audit entry readable after the
    /// subscription is gone.
    pub(crate) subscription_label: EventLabel,
    /// The topic it consumed.
    pub(crate) topic_name: TopicName,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SubscriptionDeleted => MessagingEvent::SubscriptionDeleted,
    fn payload(&self) -> EventData {
        subscription_payload(self.subscription_id, &self.subscription_label, &self.topic_name)
    }
}

/// A subscription was paused: its messages wait and are not delivered.
#[derive(Debug)]
pub struct SubscriptionPaused {
    /// The subscription's unique ID.
    pub(crate) subscription_id: MessageSubscriptionId,
    /// A readable name for the subscription: its consumer group, or else the
    /// topic it consumes.
    pub(crate) subscription_label: EventLabel,
    /// The topic it consumes.
    pub(crate) topic_name: TopicName,
    /// When it was paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SubscriptionPaused => MessagingEvent::SubscriptionPaused,
    fn payload(&self) -> EventData {
        subscription_payload(self.subscription_id, &self.subscription_label, &self.topic_name)
    }
}

/// A paused subscription was resumed and is delivered to again.
#[derive(Debug)]
pub struct SubscriptionResumed {
    /// The subscription's unique ID.
    pub(crate) subscription_id: MessageSubscriptionId,
    /// A readable name for the subscription: its consumer group, or else the
    /// topic it consumes.
    pub(crate) subscription_label: EventLabel,
    /// The topic it consumes.
    pub(crate) topic_name: TopicName,
    /// When it was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SubscriptionResumed => MessagingEvent::SubscriptionResumed,
    fn payload(&self) -> EventData {
        subscription_payload(self.subscription_id, &self.subscription_label, &self.topic_name)
    }
}

/// A push subscription's signing secret was replaced. Pushes are signed
/// with the new one from now on, and with the old one beside it until its
/// overlap ends.
#[derive(Debug)]
pub struct SubscriptionSecretRotated {
    /// The subscription's unique ID.
    pub(crate) subscription_id: MessageSubscriptionId,
    /// A readable name for the subscription: its consumer group, or else the
    /// topic it consumes.
    pub(crate) subscription_label: EventLabel,
    /// The topic it consumes.
    pub(crate) topic_name: TopicName,
    /// When the old secret stops signing: the rotation itself when it
    /// stopped at once.
    pub(crate) old_secret_ends_at: OffsetDateTime,
    /// When the secret was replaced.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SubscriptionSecretRotated => MessagingEvent::SubscriptionSecretRotated,
    fn payload(&self) -> EventData {
        subscription_payload(self.subscription_id, &self.subscription_label, &self.topic_name)
            .field("expires_at", self.old_secret_ends_at.to_string())
    }
}

/// A message a subscription set aside as a dead letter was put back in
/// front of its service.
#[derive(Debug)]
pub struct DeadLetterReplayed {
    /// The subscription that set it aside.
    pub(crate) subscription_id: MessageSubscriptionId,
    /// A readable name for the subscription: its consumer group, or else the
    /// topic it consumes.
    pub(crate) subscription_label: EventLabel,
    /// The topic it consumes.
    pub(crate) topic_name: TopicName,
    /// When it was replayed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeadLetterReplayed => MessagingEvent::DeadLetterReplayed,
    fn payload(&self) -> EventData {
        subscription_payload(self.subscription_id, &self.subscription_label, &self.topic_name)
    }
}

/// An event schema was registered with its first version.
#[derive(Debug)]
pub struct SchemaRegistered {
    /// The schema's unique ID.
    pub(crate) schema_id: EventSchemaId,
    /// The schema's machine name.
    pub(crate) schema_name: Label,
    /// When it was registered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SchemaRegistered => MessagingEvent::SchemaRegistered,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "schema",
            schema_reference(self.schema_id, self.schema_name.as_str()),
        )
    }
}

/// An event schema gained a new version.
#[derive(Debug)]
pub struct SchemaEvolved {
    /// The schema's unique ID.
    pub(crate) schema_id: EventSchemaId,
    /// The schema's machine name.
    pub(crate) schema_label: EventLabel,
    /// The version that was current before.
    pub(crate) previous_version: u32,
    /// The version just added.
    pub(crate) new_version: u32,
    /// When it was evolved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SchemaEvolved => MessagingEvent::SchemaEvolved,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "schema",
                schema_reference(self.schema_id, self.schema_label.as_str()),
            )
            .change(
                "version",
                self.previous_version.to_string(),
                self.new_version.to_string(),
            )
    }
}

/// An event schema was deleted, with every version it held.
#[derive(Debug)]
pub struct SchemaDeleted {
    /// The schema's unique ID.
    pub(crate) schema_id: EventSchemaId,
    /// The schema's machine name, so the record stays readable once it is
    /// gone.
    pub(crate) schema_label: EventLabel,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SchemaDeleted => MessagingEvent::SchemaDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "schema",
            schema_reference(self.schema_id, self.schema_label.as_str()),
        )
    }
}

/// A message was published to a topic.
#[derive(Debug)]
pub struct MessagePublished {
    /// The destination that accepted the message payload.
    pub(crate) topic_name: TopicName,
    /// Message payload size in bytes.
    pub(crate) payload_size: usize,
    /// When it was published.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MessagePublished => MessagingEvent::MessagePublished,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("topic_name", self.topic_name.as_str().to_owned())
            .field("payload_size", self.payload_size.to_string())
    }
}

/// The payload every topic event shares: the topic by id and by the name
/// publishers use.
fn topic_payload(topic_id: TopicId, topic_name: &TopicName) -> EventData {
    EventData::new()
        .reference(
            "topic",
            Reference::new(TOPIC, topic_id.to_string(), topic_name.as_str().to_owned()),
        )
        .field("topic_name", topic_name.as_str().to_owned())
}

/// A schema as every schema event links it: by id, labelled with its
/// machine name.
fn schema_reference(schema_id: EventSchemaId, label: &str) -> Reference {
    Reference::new(RefKind::SCHEMA, schema_id.to_string(), label)
}

/// The payload every subscription event shares: the subscription and the
/// topic it consumes.
fn subscription_payload(
    subscription_id: MessageSubscriptionId,
    label: &EventLabel,
    topic_name: &TopicName,
) -> EventData {
    EventData::new()
        .reference(
            "subscription",
            Reference::new(
                TOPIC_SUBSCRIPTION,
                subscription_id.to_string(),
                label.as_str(),
            ),
        )
        .field("topic_name", topic_name.as_str().to_owned())
}

/// A retention policy as the audit trail shows it.
fn retention_text(policy: RetentionPolicy) -> String {
    match policy {
        RetentionPolicy::Duration(seconds) => format!("{seconds}s"),
        RetentionPolicy::MessageCount(count) => format!("{count} messages"),
        RetentionPolicy::Unlimited => "unlimited".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// A tenant creates the topic `orders.created`. The record links the
    /// topic by its id and shows the name publishers use, so a reader can
    /// find it either way.
    #[test]
    fn creating_a_topic_names_it_by_id_and_by_name() {
        let topic_id = TopicId::new();

        let event = TopicCreated {
            topic_id,
            topic_name: TopicName::new("orders.created").unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "topic"),
            (TOPIC, topic_id.to_string(), "orders.created".to_owned())
        );
        assert_eq!(text(&payload, "topic_name"), "orders.created");
    }

    /// A service subscribes to `orders.created` under the group
    /// `billing-export`. The record links it with the topic subscription
    /// kind, so it is never mistaken for a billing plan subscription.
    #[test]
    fn creating_a_subscription_names_it_and_the_topic_it_consumes() {
        let subscription_id = MessageSubscriptionId::new();

        let event = SubscriptionCreated {
            subscription_id,
            subscription_label: EventLabel::of("billing-export"),
            topic_name: TopicName::new("orders.created").unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "subscription"),
            (
                TOPIC_SUBSCRIPTION,
                subscription_id.to_string(),
                "billing-export".to_owned()
            )
        );
        assert_eq!(text(&payload, "topic_name"), "orders.created");
    }

    /// A service publishes 512 bytes to `orders.created`. The record holds
    /// the topic and the size, and never the message itself.
    #[test]
    fn publishing_records_the_topic_and_the_size_of_what_was_sent() {
        let event = MessagePublished {
            topic_name: TopicName::new("orders.created").unwrap(),
            payload_size: 512,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(text(&payload, "topic_name"), "orders.created");
        assert_eq!(text(&payload, "payload_size"), "512");
    }

    /// An admin pauses `orders.created` ahead of deleting it. The record
    /// names the topic the way its creation did.
    #[test]
    fn pausing_a_topic_names_it_by_id_and_by_name() {
        let topic_id = TopicId::new();

        let event = TopicPaused {
            topic_id,
            topic_name: TopicName::new("orders.created").unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "topic"),
            (TOPIC, topic_id.to_string(), "orders.created".to_owned())
        );
        assert_eq!(text(&payload, "topic_name"), "orders.created");
    }

    /// An admin shortens `orders.created` from keeping everything to an
    /// hour. The record keeps both policies, since the shorter one drops
    /// messages no subscriber has read.
    #[test]
    fn a_retention_change_records_both_policies() {
        let event = TopicRetentionChanged {
            topic_id: TopicId::new(),
            topic_name: TopicName::new("orders.created").unwrap(),
            previous: RetentionPolicy::Unlimited,
            current: RetentionPolicy::Duration(NonZeroU32::new(3600).unwrap()),
            occurred_at: now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("retention") else {
            panic!("retention is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("unlimited"), Some("3600s"))
        );
    }

    /// An admin raises `orders.created` from internal to confidential. The
    /// record keeps both classes, since subscribers cleared below the new
    /// one stop hearing it.
    #[test]
    fn raising_a_data_class_records_both_classes() {
        let event = TopicDataClassRaised {
            topic_id: TopicId::new(),
            topic_name: TopicName::new("orders.created").unwrap(),
            previous: DataClassLevel::Internal,
            current: DataClassLevel::Confidential,
            occurred_at: now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("data_class") else {
            panic!("data_class is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (
                Some(DataClassLevel::Internal.as_str()),
                Some(DataClassLevel::Confidential.as_str())
            )
        );
    }

    /// Ann deletes the schema `order-created`. The record links it by id
    /// and keeps its name, so it reads the same once the schema is gone.
    #[test]
    fn deleting_a_schema_names_it_by_id_and_by_name() {
        let schema_id = EventSchemaId::new();

        let event = SchemaDeleted {
            schema_id,
            schema_label: EventLabel::of("order-created"),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "schema"),
            (
                RefKind::SCHEMA,
                schema_id.to_string(),
                "order-created".to_owned()
            )
        );
    }
}
