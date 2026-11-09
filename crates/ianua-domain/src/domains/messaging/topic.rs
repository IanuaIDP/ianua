//! Topics, the named message channels of one tenant.
//!
//! Services publish messages to topics and subscribe to receive them. A
//! topic may have a JSON schema, which agent messages through the relay
//! are checked against. A service's own publish is not.

use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroU64};

use time::OffsetDateTime;

use crate::domains::authorization::permission::MessagingAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::messaging::control::{
    CreatedBy, MessagingControl, MessagingCreator, MessagingReader,
};
use crate::domains::messaging::events::{
    MessagePublished, TopicArchived, TopicCreated, TopicDataClassRaised, TopicDeleted, TopicPaused,
    TopicResumed, TopicRetentionChanged, TopicSchemaChanged,
};
use crate::domains::messaging::schema::SchemaDefinition;
use crate::domains::messaging::topic_name::TopicName;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{Label, Setting, TopicId};

/// Message retention policy for a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RetentionPolicy {
    /// Messages expire after this many seconds. Never zero, which would
    /// drop every message as it arrives.
    Duration(NonZeroU32),
    /// Keep the last N messages per topic. Never zero, for the same reason.
    MessageCount(NonZeroU64),
    /// Keep messages until someone purges them.
    Unlimited,
}

impl RetentionPolicy {
    /// Whether a message published at `published_at` is past this rule's
    /// age at `now`, so no reader may have it. At exactly the limit it is
    /// past. A count limit has no age: the bus checks it by how many came
    /// after.
    #[must_use]
    pub fn has_aged_out(self, published_at: OffsetDateTime, now: OffsetDateTime) -> bool {
        match self {
            Self::Duration(seconds) => {
                crate::shared::clock::between(published_at, now)
                    >= time::Duration::seconds(i64::from(seconds.get()))
            }
            Self::MessageCount(_) | Self::Unlimited => false,
        }
    }
}

/// Topic lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TopicStatus {
    /// Accepting publishes and delivering to subscribers.
    Active,
    /// New messages are refused. Subscriptions are kept.
    Paused,
    /// Read-only. No new publishes or subscriptions.
    Archived,
}

impl TopicStatus {
    /// Moves to `to`.
    ///
    /// Active and paused move between each other. Either can be archived.
    /// An archived topic stays archived.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Active, Self::Paused | Self::Archived)
                    | (Self::Paused, Self::Active | Self::Archived)
            )
        })
    }
}

/// What a new topic is created from.
pub struct CreateTopicParams {
    /// Human-readable display name.
    pub name: Label,
    /// Machine-readable topic name, used in the NATS subject.
    pub topic_name: TopicName,
    /// Optional description.
    pub description: Option<Label>,
    /// Optional JSON schema that agent messages through the relay are
    /// checked against.
    pub schema: Setting<SchemaDefinition>,
    /// Message retention policy.
    pub retention: RetentionPolicy,
    /// The most sensitive data the topic may carry. It is chosen here
    /// because it can later only rise.
    pub data_class: DataClassLevel,
}

/// A topic as storage holds it.
pub struct TopicRow {
    /// Unique identifier.
    pub id: TopicId,
    /// Human-readable display name.
    pub name: Label,
    /// Machine-readable topic name.
    pub topic_name: TopicName,
    /// Optional description.
    pub description: Option<Label>,
    /// Optional JSON schema.
    pub schema: Setting<SchemaDefinition>,
    /// Message retention policy.
    pub retention: RetentionPolicy,
    /// Current status.
    pub status: TopicStatus,
    /// Who created this topic.
    pub created_by: CreatedBy,
    /// The most sensitive data the topic may carry.
    pub data_class: DataClassLevel,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last modified.
    pub updated_at: OffsetDateTime,
}

/// A messaging topic of one tenant.
///
/// Messages are routed by topic. Services publish to a topic name, and
/// every subscribed service receives the message. The NATS subject holds
/// the tenant, `ianua.msg.{tenant_id}.{topic_name}`, so one tenant cannot
/// reach another's topics.
#[derive(Debug)]
pub struct Topic<T: TenantScope> {
    id: TopicId,
    name: Label,
    topic_name: TopicName,
    description: Option<Label>,
    schema: Setting<SchemaDefinition>,
    retention: RetentionPolicy,
    status: TopicStatus,
    created_by: CreatedBy,
    data_class: DataClassLevel,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Topic<T> {
    /// Creates a new active topic, recording the person or consumer
    /// `creator` names as its creator. Raises `messaging.topic_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person, or the consumer's
    ///   roles, do not give the right to create in messaging.
    pub fn create(
        params: CreateTopicParams,
        creator: MessagingCreator<'_>,
    ) -> Result<Self, DomainError> {
        let created_by = creator.ensure_may_create()?;
        let now = crate::shared::clock::now();
        let mut topic = Self {
            id: TopicId::new(),
            name: params.name,
            topic_name: params.topic_name,
            description: params.description,
            schema: params.schema,
            retention: params.retention,
            status: TopicStatus::Active,
            created_by,
            data_class: params.data_class,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        topic.raised.raise(TopicCreated {
            topic_id: topic.id,
            topic_name: topic.topic_name.clone(),
            occurred_at: now,
        });
        Ok(topic)
    }

    /// Rebuilds a topic from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the topic changed
    ///   before it was created.
    pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            topic_name: row.topic_name,
            description: row.description,
            schema: row.schema,
            retention: row.retention,
            status: row.status,
            created_by: row.created_by,
            data_class: row.data_class,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &TopicRow) -> Result<(), DomainError> {
        RowCheck::of("topic")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &TopicId {
        &self.id
    }

    /// Human-readable display name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Machine-readable topic name, used in the NATS subject.
    #[must_use]
    pub fn topic_name(&self) -> &TopicName {
        &self.topic_name
    }

    /// Optional description.
    #[must_use]
    pub fn description(&self) -> Option<&Label> {
        self.description.as_ref()
    }

    /// Optional JSON schema that agent messages through the relay are
    /// checked against.
    #[must_use]
    pub fn schema(&self) -> Option<&SchemaDefinition> {
        self.schema.value()
    }

    /// Message retention policy.
    #[must_use]
    pub fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> TopicStatus {
        self.status
    }

    /// Whether this topic is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == TopicStatus::Active
    }

    /// Who created this topic.
    #[must_use]
    pub fn created_by(&self) -> &CreatedBy {
        &self.created_by
    }

    /// The most sensitive data this topic may carry.
    ///
    /// An agent may publish to it, or read from it, only if this is at least
    /// as high as the most sensitive data the agent has touched. Doing so
    /// raises the agent to this class.
    #[must_use]
    pub fn data_class(&self) -> DataClassLevel {
        self.data_class
    }

    /// Whether a service may start a new subscription to this topic. An
    /// archived topic takes none. A paused one does, and its messages wait.
    #[must_use]
    pub fn accepts_subscriptions(&self) -> bool {
        self.status != TopicStatus::Archived
    }

    /// Takes a new message of `payload_size` bytes, if the topic takes them
    /// now. Only an active topic does. A paused one holds its flow, and an
    /// archived one is read-only for good. Raises
    /// `messaging.message_published`, naming the size and never the
    /// message. Nothing about the topic changes, so the events are taken
    /// once the message is on the bus, without a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] while the topic is paused or archived.
    pub fn accept_publish(&mut self, payload_size: usize) -> Result<(), DomainError> {
        if !self.is_active() {
            return Err(DomainError::forbidden(message!(
                "messaging-a-paused-or-archived-topic-takes",
                "a paused or archived topic takes no new messages"
            )));
        }
        self.raised.raise(MessagePublished {
            topic_name: self.topic_name.clone(),
            payload_size,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses handing `reader` this topic's messages when the topic's
    /// class is above what the reader is cleared for.
    ///
    /// A subscription is checked against the class when it is made, but
    /// the class can rise afterwards, and raising it shuts out subscribers
    /// cleared below it. "billing-sync", cleared for internal data,
    /// subscribed to `payroll.events` while it was internal. Fay has raised
    /// it to restricted since. Without this check, billing-sync goes on
    /// pulling salaries.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the topic's class is above the
    ///   reader's clearance.
    pub fn ensure_readable_by(&self, reader: MessagingReader<'_>) -> Result<(), DomainError> {
        if self.data_class <= reader.clearance() {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "messaging-the-topic-carries-data-the-reader",
            "the topic carries data the reader is not cleared for"
        )))
    }

    /// Whether agents may exchange messages on this topic.
    ///
    /// Only an active topic with a schema qualifies. Free text can hide a
    /// secret signal between agents. A schema limits what a message can
    /// carry, and a tighter schema leaves less room.
    #[must_use]
    pub fn accepts_agent_messages(&self) -> bool {
        self.is_active() && !self.schema.is_unset()
    }

    /// Pauses the topic. New messages are refused. It stops every message
    /// flowing, so this needs the full messaging right. Raises
    /// `messaging.topic_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] unless the topic is active.
    pub fn pause(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Manage)?;
        self.move_to(TopicStatus::Paused)?;
        self.raised.raise(TopicPaused {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Resumes the topic. Messages are accepted again. Raises
    /// `messaging.topic_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] unless the topic is paused.
    pub fn resume(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Manage)?;
        self.move_to(TopicStatus::Active)?;
        self.raised.raise(TopicResumed {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Archives the topic. It becomes read-only, with no new publishes or
    /// subscriptions, for good. That is how a topic is retired, so this
    /// needs the delete right. Raises `messaging.topic_archived`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete topics.
    /// - [`DomainError::InvalidTransition`] when it is already archived.
    pub fn archive(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Delete)?;
        self.move_to(TopicStatus::Archived)?;
        self.raised.raise(TopicArchived {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Replaces the JSON schema. It decides what messages may carry, so
    /// this needs the full messaging right. Raises
    /// `messaging.topic_schema_changed`, which names the topic and never
    /// the schema, which can be large.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] when the topic is archived,
    ///   which makes it read-only.
    pub fn change_schema(
        &mut self,
        schema: Setting<SchemaDefinition>,
        control: &MessagingControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_writable(control)?;
        self.schema = schema;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(TopicSchemaChanged {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    fn move_to(&mut self, to: TopicStatus) -> Result<(), DomainError> {
        self.status = self.status.try_transition(to)?;
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }

    /// Replaces the retention policy. A shorter one drops messages
    /// subscribers have not read yet, so this needs the full messaging
    /// right. Raises `messaging.topic_retention_changed` with the policy
    /// before and after.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] when the topic is archived,
    ///   which makes it read-only.
    pub fn change_retention(
        &mut self,
        retention: RetentionPolicy,
        control: &MessagingControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_writable(control)?;
        let previous = std::mem::replace(&mut self.retention, retention);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(TopicRetentionChanged {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            previous,
            current: retention,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Declares the most sensitive data this topic may carry.
    ///
    /// The class only ever rises. The topic may already hold restricted
    /// messages, and an agent that reads it is raised only to the topic's
    /// class. If the topic were lowered to public, an agent could read those
    /// restricted messages and still count as public. Less sensitive traffic
    /// goes to a new topic. Raising the class shuts out subscribers cleared
    /// below it, so this needs the full messaging right. Raises
    /// `messaging.topic_data_class_raised` with the class before and after.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::InvalidTransition`] when the topic is archived.
    /// - [`DomainError::Forbidden`] when `data_class` is below the current
    ///   one.
    pub fn raise_data_class(
        &mut self,
        data_class: DataClassLevel,
        control: &MessagingControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_writable(control)?;
        if data_class < self.data_class {
            return Err(DomainError::forbidden(message!(
                "messaging-a-topic-s-data-class-can",
                "a topic's data class can only be raised"
            )));
        }
        let previous = std::mem::replace(&mut self.data_class, data_class);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(TopicDataClassRaised {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            previous,
            current: data_class,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this topic, with every subscription to it, once the person
    /// may delete in messaging and it no longer takes messages. Raises
    /// `messaging.topic_deleted`, taken once the topic is removed from
    /// storage.
    ///
    /// Sam may publish to topics. Without this check, he deletes
    /// `payments.settled` and every service subscribed to it stops hearing
    /// of payments. A topic still active is paused or archived first, so
    /// none is deleted while services publish to it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete in
    ///   messaging.
    /// - [`DomainError::Conflict`] while the topic is active.
    pub fn delete(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Delete)?;
        if self.is_active() {
            return Err(DomainError::conflict(message!(
                "messaging-an-active-topic-is-paused-or",
                "an active topic is paused or archived before it is deleted"
            )));
        }
        self.raised.raise(TopicDeleted {
            topic_id: self.id,
            topic_name: self.topic_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses a change to how the topic works unless the person manages
    /// messaging, and any change to an archived topic, which is read-only.
    fn ensure_writable(&self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Manage)?;
        if self.status == TopicStatus::Archived {
            return Err(DomainError::invalid_transition(message!(
                "messaging-an-archived-topic-is-read-only",
                "an archived topic is read-only"
            )));
        }
        Ok(())
    }
}

impl<T: TenantScope> Raises for Topic<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Topic<T> {
    type Id = TopicId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{DataAccessAction, SystemPermission};
    use crate::domains::consumers::fixtures::service_cleared;
    use crate::domains::messaging::control::MessagingCreator::{Consumer, Person};
    use crate::domains::messaging::fixtures::{
        creating_service, holding, messaging_admin, messaging_viewer, publishing_service,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    const ONE_DAY: RetentionPolicy = RetentionPolicy::Duration(NonZeroU32::new(86_400).unwrap());

    /// A message a day old is past a day's limit, as it is at the very
    /// instant the day ends; one a second younger is not.
    #[test]
    fn a_message_ages_out_at_exactly_its_limit() {
        let now = crate::shared::clock::now();
        let a_day = time::Duration::days(1);

        assert!(ONE_DAY.has_aged_out(now - a_day, now));
        assert!(!ONE_DAY.has_aged_out(now - a_day + time::Duration::seconds(1), now));
    }

    /// A count limit and no limit at all have no age: however old, a
    /// message is not past either.
    #[test]
    fn only_a_duration_ages_a_message_out() {
        let now = crate::shared::clock::now();
        let long_ago = now - time::Duration::days(365);
        let count = RetentionPolicy::MessageCount(NonZeroU64::new(2).unwrap());

        assert!(!count.has_aged_out(long_ago, now));
        assert!(!RetentionPolicy::Unlimited.has_aged_out(long_ago, now));
    }

    fn order_events() -> CreateTopicParams {
        CreateTopicParams {
            name: label("Order Events"),
            topic_name: TopicName::new("orders.created").unwrap(),
            description: Some(label("Emitted when a new order is placed")),
            schema: Setting::Unset,
            retention: ONE_DAY,
            data_class: DataClassLevel::Internal,
        }
    }

    fn test_topic() -> Topic<ResolvedTenant> {
        Topic::create(order_events(), Consumer(&creating_service())).unwrap()
    }

    /// A service with publishing permission alone cannot create a topic.
    #[test]
    fn a_service_without_the_create_right_makes_no_topic() {
        let result =
            Topic::<ResolvedTenant>::create(order_events(), Consumer(&publishing_service()));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A service creates `orders.created` with a one-day retention. The new
    /// topic is active and keeps its names and retention.
    #[test]
    fn create_produces_active_topic() {
        let topic = test_topic();
        assert!(topic.is_active());
        assert_eq!(topic.name().as_str(), "Order Events");
        assert_eq!(topic.topic_name().as_str(), "orders.created");
        assert_eq!(topic.retention(), ONE_DAY);
    }

    /// Stored retention policies reject zero duration and zero message
    /// count, while a one-day duration deserializes successfully.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_zero_retention_does_not_load() {
        for stored in [r#"{"Duration":0}"#, r#"{"MessageCount":0}"#] {
            assert!(serde_json::from_str::<RetentionPolicy>(stored).is_err());
        }
        assert_eq!(
            serde_json::from_str::<RetentionPolicy>(r#"{"Duration":86400}"#).unwrap(),
            ONE_DAY
        );
    }

    /// An active topic is paused and then resumed. It reports paused in
    /// between and active again after.
    #[test]
    fn pause_and_resume() {
        let mut topic = test_topic();
        topic.pause(&messaging_admin()).unwrap();
        assert_eq!(topic.status(), TopicStatus::Paused);
        assert!(!topic.is_active());

        topic.resume(&messaging_admin()).unwrap();
        assert!(topic.is_active());
    }

    /// A viewer's pause is forbidden and leaves the topic active.
    #[test]
    fn a_viewer_cannot_pause_a_topic() {
        let mut topic = test_topic();

        let result = topic.pause(&messaging_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(topic.is_active());
    }

    /// A viewer cannot resume a topic paused by an administrator. The topic
    /// stays paused.
    #[test]
    fn a_viewer_cannot_resume_a_topic() {
        let mut topic = test_topic();
        topic.pause(&messaging_admin()).unwrap();

        let result = topic.resume(&messaging_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(topic.status(), TopicStatus::Paused);
    }

    /// Creating permission alone cannot archive a topic. The refusal leaves
    /// it active.
    #[test]
    fn archiving_a_topic_needs_the_delete_right() {
        let mut topic = test_topic();
        let creator = holding(&[SystemPermission::Messaging(MessagingAction::Create)]);

        let result = topic.archive(&creator);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(topic.is_active());
    }

    /// Someone who may delete topics, and manage nothing else, archives
    /// `orders.created`. It is archived.
    #[test]
    fn the_delete_right_archives_a_topic() {
        let mut topic = test_topic();
        let deleter = holding(&[SystemPermission::Messaging(MessagingAction::Delete)]);

        topic.archive(&deleter).unwrap();

        assert_eq!(topic.status(), TopicStatus::Archived);
    }

    /// A topic is archived. Resuming, pausing, archiving again and changing
    /// its schema are all refused, and it stays archived.
    #[test]
    fn archive_is_terminal() {
        let mut topic = test_topic();
        let admin = messaging_admin();
        topic.archive(&admin).unwrap();

        assert!(topic.resume(&admin).is_err());
        assert!(topic.pause(&admin).is_err());
        assert!(topic.archive(&admin).is_err());
        assert!(topic.change_schema(Setting::Unset, &admin).is_err());
        assert_eq!(topic.status(), TopicStatus::Archived);
    }

    /// Resuming a topic that is already active is refused as a wrong move.
    #[test]
    fn an_active_topic_cannot_be_resumed() {
        assert!(test_topic().resume(&messaging_admin()).is_err());
    }

    /// A publisher cannot clear a topic's schema. The refusal leaves a
    /// schema attached.
    #[test]
    fn a_publisher_cannot_change_a_topics_schema() {
        let mut topic = test_topic();
        let schema = SchemaDefinition::new(r#"{"type":"object"}"#).unwrap();
        topic
            .change_schema(Setting::Set(schema), &messaging_admin())
            .unwrap();
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        let result = topic.change_schema(Setting::Unset, &publisher);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(topic.schema().is_some());
    }

    /// A viewer cannot shorten retention to one second. The topic retains
    /// its one-day policy.
    #[test]
    fn a_viewer_cannot_change_a_topics_retention() {
        let mut topic = test_topic();

        let one_second = RetentionPolicy::Duration(NonZeroU32::MIN);

        let result = topic.change_retention(one_second, &messaging_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(topic.retention(), ONE_DAY);
    }

    /// A viewer cannot raise a topic to restricted. Its class remains internal.
    #[test]
    fn a_viewer_cannot_raise_a_topics_class() {
        let mut topic = test_topic();

        let result = topic.raise_data_class(DataClassLevel::Restricted, &messaging_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(topic.data_class(), DataClassLevel::Internal);
    }

    /// A topic with no schema is given `{"type":"object"}`. It then reports
    /// that schema, and its last change time does not go back.
    #[test]
    fn a_changed_schema_takes_effect() {
        let mut topic = test_topic();
        let before = topic.updated_at();
        topic
            .change_schema(
                Setting::Set(SchemaDefinition::new(r#"{"type":"object"}"#).unwrap()),
                &messaging_admin(),
            )
            .unwrap();
        assert_eq!(
            topic.schema().map(SchemaDefinition::as_str),
            Some(r#"{"type":"object"}"#)
        );
        assert!(topic.updated_at() >= before);
    }

    /// A topic created as internal reports internal. Raising it to
    /// restricted is allowed and takes effect.
    #[test]
    fn a_topic_carries_the_class_it_was_created_with_and_can_be_raised() {
        let mut topic = test_topic();
        assert_eq!(topic.data_class(), DataClassLevel::Internal);

        topic
            .raise_data_class(DataClassLevel::Restricted, &messaging_admin())
            .unwrap();

        assert_eq!(topic.data_class(), DataClassLevel::Restricted);
    }

    /// An active topic takes messages. Once paused, and once archived, it
    /// refuses them.
    #[test]
    fn only_an_active_topic_takes_new_messages() {
        let mut topic = test_topic();
        let admin = messaging_admin();
        assert!(topic.accept_publish(512).is_ok());

        topic.pause(&admin).unwrap();
        let paused = topic.accept_publish(512);
        topic.resume(&admin).unwrap();
        topic.archive(&admin).unwrap();
        let archived = topic.accept_publish(512);

        assert!(matches!(paused, Err(DomainError::Forbidden(_))));
        assert!(matches!(archived, Err(DomainError::Forbidden(_))));
    }

    /// "billing-sync", cleared for internal data, reads `orders.created`
    /// while it is internal. Fay raises the topic to restricted, and it is
    /// shut out.
    #[test]
    fn a_service_reads_a_topic_only_within_its_clearance() {
        let mut topic = test_topic();
        let service = service_cleared(&[], DataClassLevel::Internal);
        let before = topic.ensure_readable_by(MessagingReader::Consumer(&service));

        topic
            .raise_data_class(DataClassLevel::Restricted, &messaging_admin())
            .unwrap();
        let after = topic.ensure_readable_by(MessagingReader::Consumer(&service));

        assert!(before.is_ok());
        assert!(matches!(after, Err(DomainError::Forbidden(_))));
    }

    /// A confidential topic refuses a reader cleared only for internal data
    /// and admits one with confidential clearance.
    #[test]
    fn a_person_reads_a_topic_only_within_their_clearance() {
        let mut topic = test_topic();
        topic
            .raise_data_class(DataClassLevel::Confidential, &messaging_admin())
            .unwrap();
        let sam = holding(&[CONSUME]);
        let fay = holding(&[
            CONSUME,
            SystemPermission::Data(DataAccessAction::Confidential),
        ]);

        let by_sam = topic.ensure_readable_by(MessagingReader::Person(&sam));
        let by_fay = topic.ensure_readable_by(MessagingReader::Person(&fay));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_fay.is_ok());
    }

    /// Lowering a restricted topic to public is forbidden, and its class
    /// remains restricted.
    #[test]
    fn a_topic_class_cannot_be_lowered() {
        let mut topic = test_topic();
        let admin = messaging_admin();
        topic
            .raise_data_class(DataClassLevel::Restricted, &admin)
            .unwrap();

        let lowered = topic.raise_data_class(DataClassLevel::Public, &admin);

        assert!(matches!(lowered, Err(DomainError::Forbidden(_))));
        assert_eq!(topic.data_class(), DataClassLevel::Restricted);
    }

    /// A topic is archived. Changing its retention and raising its data
    /// class are both refused, since it is read-only.
    #[test]
    fn an_archived_topic_keeps_its_retention_and_class() {
        let mut topic = test_topic();
        let admin = messaging_admin();
        topic.archive(&admin).unwrap();

        assert!(
            topic
                .change_retention(RetentionPolicy::Unlimited, &admin)
                .is_err()
        );
        assert!(
            topic
                .raise_data_class(DataClassLevel::Restricted, &admin)
                .is_err()
        );
    }

    /// A topic with no schema takes no agent messages. Once it has a schema
    /// it does, and once it is paused it stops again.
    #[test]
    fn only_an_active_topic_with_a_schema_takes_agent_messages() {
        let mut topic = test_topic();
        let admin = messaging_admin();
        topic.change_schema(Setting::Unset, &admin).unwrap();
        assert!(!topic.accepts_agent_messages(), "free text is not accepted");

        topic
            .change_schema(
                Setting::Set(SchemaDefinition::new(r#"{"type":"object"}"#).unwrap()),
                &admin,
            )
            .unwrap();
        assert!(topic.accepts_agent_messages());

        topic.pause(&admin).unwrap();
        assert!(!topic.accepts_agent_messages());
    }

    /// A topic with a one-day retention is set to keep messages without
    /// limit. It then reports the new retention.
    #[test]
    fn a_changed_retention_takes_effect() {
        let mut topic = test_topic();
        topic
            .change_retention(RetentionPolicy::Unlimited, &messaging_admin())
            .unwrap();
        assert_eq!(topic.retention(), RetentionPolicy::Unlimited);
    }

    /// A topic is created with no description. It is accepted and reports
    /// none.
    #[test]
    fn a_topic_may_have_no_description() {
        let params = CreateTopicParams {
            name: label("Simple"),
            topic_name: TopicName::new("simple").unwrap(),
            description: None,
            schema: Setting::Unset,
            retention: RetentionPolicy::MessageCount(NonZeroU64::new(1000).unwrap()),
            data_class: DataClassLevel::Internal,
        };

        let topic = Topic::<ResolvedTenant>::create(params, Consumer(&creating_service())).unwrap();

        assert!(topic.description().is_none());
    }

    /// A service creates a topic with a description. The topic gets a fresh
    /// id, records that service as its creator and keeps the description.
    #[test]
    fn a_topic_carries_its_id_owner_and_description() {
        let owner = creating_service();

        let topic = Topic::<ResolvedTenant>::create(order_events(), Consumer(&owner)).unwrap();

        assert!(!topic.id().as_uuid().is_nil());
        assert_eq!(Aggregate::id(&topic), topic.id());
        assert_eq!(topic.created_by(), &CreatedBy::Consumer(*owner.id()));
        assert_eq!(
            topic.description().map(Label::as_str),
            Some("Emitted when a new order is placed")
        );
    }

    /// Ann may create in messaging and makes `orders.created` herself. The
    /// topic records her as its creator. Sam, who may only view messaging,
    /// makes none.
    #[test]
    fn a_person_with_the_create_right_makes_a_topic() {
        let ann = holding(&[SystemPermission::Messaging(MessagingAction::Create)]);

        let topic = Topic::<ResolvedTenant>::create(order_events(), Person(&ann)).unwrap();
        let by_viewer =
            Topic::<ResolvedTenant>::create(order_events(), Person(&messaging_viewer()));

        assert_eq!(topic.created_by(), &CreatedBy::Person(ann.by().clone()));
        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
    }

    /// A publisher cannot delete a topic, and an administrator cannot delete
    /// it while active. Deletion succeeds after the administrator archives it.
    #[test]
    fn deleting_a_topic_needs_the_right_and_a_stopped_topic() {
        let mut topic = test_topic();
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        let by_publisher = topic.delete(&publisher);
        let while_active = topic.delete(&messaging_admin());
        topic.archive(&messaging_admin()).unwrap();

        assert!(matches!(by_publisher, Err(DomainError::Forbidden(_))));
        assert!(matches!(while_active, Err(DomainError::Conflict(_))));
        assert!(topic.delete(&messaging_admin()).is_ok());
    }

    /// A topic and what it raised since it was made, the creation taken
    /// out first.
    fn fresh_topic() -> Topic<ResolvedTenant> {
        let mut topic = test_topic();
        raised_names(&mut topic);
        topic
    }

    /// A service creates `orders.created`. The creation is raised for the
    /// audit trail.
    #[test]
    fn creating_raises_messaging_topic_created() {
        let mut topic = test_topic();

        assert_eq!(raised_names(&mut topic), ["messaging.topic_created"]);
    }

    /// `orders.created` is read back from storage. Loading it is no change,
    /// so it has raised nothing.
    #[test]
    fn a_topic_read_back_from_storage_has_raised_nothing() {
        let now = crate::shared::clock::now();
        let row = TopicRow {
            id: TopicId::new(),
            name: label("Order Events"),
            topic_name: TopicName::new("orders.created").unwrap(),
            description: None,
            schema: Setting::Unset,
            retention: ONE_DAY,
            status: TopicStatus::Active,
            created_by: CreatedBy::Consumer(*creating_service().id()),
            data_class: DataClassLevel::Internal,
            created_at: now,
            updated_at: now,
        };

        let mut stored = Topic::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// Ann pauses `orders.created`, then resumes it. Each move is raised,
    /// in order.
    #[test]
    fn pausing_and_resuming_raise_messaging_topic_paused_and_resumed() {
        let mut topic = fresh_topic();

        topic.pause(&messaging_admin()).unwrap();
        topic.resume(&messaging_admin()).unwrap();

        assert_eq!(
            raised_names(&mut topic),
            ["messaging.topic_paused", "messaging.topic_resumed"]
        );
    }

    /// Ann archives `orders.created`. The archive is raised.
    #[test]
    fn archiving_raises_messaging_topic_archived() {
        let mut topic = fresh_topic();

        topic.archive(&messaging_admin()).unwrap();

        assert_eq!(raised_names(&mut topic), ["messaging.topic_archived"]);
    }

    /// Ann clears the schema of `orders.created`. The change is raised.
    #[test]
    fn changing_the_schema_raises_messaging_topic_schema_changed() {
        let mut topic = fresh_topic();

        topic
            .change_schema(Setting::Unset, &messaging_admin())
            .unwrap();

        assert_eq!(raised_names(&mut topic), ["messaging.topic_schema_changed"]);
    }

    /// Ann shortens `orders.created` from a day to an hour. The change is
    /// raised with both policies, the one replaced first.
    #[test]
    fn changing_the_retention_raises_both_policies() {
        let mut topic = fresh_topic();
        let one_hour = RetentionPolicy::Duration(NonZeroU32::new(3600).unwrap());

        topic
            .change_retention(one_hour, &messaging_admin())
            .unwrap();

        let events = raised(&mut topic);
        assert_eq!(
            events[0].event_type().to_string(),
            "messaging.topic_retention_changed"
        );
        assert_eq!(
            change(&events[0], "retention"),
            ("86400s".to_owned(), "3600s".to_owned())
        );
    }

    /// Fay raises `orders.created` from internal to restricted. The change
    /// is raised with both classes.
    #[test]
    fn raising_the_class_raises_both_classes() {
        let mut topic = fresh_topic();

        topic
            .raise_data_class(DataClassLevel::Restricted, &messaging_admin())
            .unwrap();

        let events = raised(&mut topic);
        assert_eq!(
            events[0].event_type().to_string(),
            "messaging.topic_data_class_raised"
        );
        assert_eq!(
            change(&events[0], "data_class"),
            (
                DataClassLevel::Internal.as_str().to_owned(),
                DataClassLevel::Restricted.as_str().to_owned()
            )
        );
    }

    /// Ann deletes `orders.created` once it is archived. The deletion is
    /// raised.
    #[test]
    fn deleting_raises_messaging_topic_deleted() {
        let mut topic = fresh_topic();
        topic.archive(&messaging_admin()).unwrap();
        raised_names(&mut topic);

        topic.delete(&messaging_admin()).unwrap();

        assert_eq!(raised_names(&mut topic), ["messaging.topic_deleted"]);
    }

    /// A service publishes 512 bytes to `orders.created`. The publish is
    /// raised with its size.
    #[test]
    fn a_publish_raises_messaging_message_published() {
        let mut topic = fresh_topic();

        topic.accept_publish(512).unwrap();

        let events = raised(&mut topic);
        assert_eq!(
            events[0].event_type().to_string(),
            "messaging.message_published"
        );
        assert_eq!(
            events[0].payload().value("payload_size"),
            Some(&FieldValue::Text("512".to_owned()))
        );
    }

    /// A viewer's pause, publishing to a paused topic and a publisher's delete
    /// all fail. The refused publish and delete raise no events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut topic = fresh_topic();
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        let paused_by_viewer = topic.pause(&messaging_viewer());
        topic.pause(&messaging_admin()).unwrap();
        raised_names(&mut topic);
        let published = topic.accept_publish(512);
        let deleted = topic.delete(&publisher);

        assert!(paused_by_viewer.is_err());
        assert!(published.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut topic).is_empty());
    }

    fn change(event: &DomainEvent, key: &str) -> (String, String) {
        match event.payload().value(key) {
            Some(FieldValue::Change(change)) => (
                change.from().unwrap().to_owned(),
                change.to().unwrap().to_owned(),
            ),
            other => panic!("{key} is not a change: {other:?}"),
        }
    }
}
