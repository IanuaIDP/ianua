//! Publishing and consuming messages.

use async_trait::async_trait;
use ianua_domain::domains::messaging::message_type::{MessageFilter, MessageType};
use ianua_domain::domains::messaging::schema::SchemaDefinition;
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Seconds, TenantId};
use time::OffsetDateTime;

/// Dyn-safe port for publishing messages to the tenant messaging bus.
///
/// The adapter keeps each message on the bus under a subject scoped to its
/// tenant, its topic and its type, so a subscription's filter is applied by
/// the bus itself.
#[async_trait]
pub trait MessagePublisher: Send + Sync {
    /// Publishes a message to a topic within a tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the message could not be published.
    async fn publish(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        message: &OutgoingMessage<'_>,
    ) -> Result<(), DomainError>;
}

/// A message on its way to a topic.
#[derive(Debug, Clone, Copy)]
pub struct OutgoingMessage<'a> {
    /// The raw payload bytes.
    pub payload: &'a [u8],
    /// Headers attached to the message.
    pub headers: &'a [(String, String)],
    /// What kind of message it is, which subscriptions filter on. A message
    /// without one reaches only the subscriptions that filter on nothing.
    pub message_type: Option<&'a MessageType>,
}

/// The bus's name for one message: the same on every delivery of it, so a
/// receiver that was sent it twice can drop the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKey(String);

impl MessageKey {
    /// The key as the bus wrote it.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The key as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A single message received from a topic.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// The bus's name for it, the same on every delivery.
    pub key: MessageKey,
    /// The raw payload bytes.
    pub payload: Vec<u8>,
    /// Headers attached to the message.
    pub headers: Vec<(String, String)>,
    /// What kind of message it is, as it was published.
    pub message_type: Option<MessageType>,
    /// When the bus took it, which the topic's age limit counts from. A
    /// replayed dead letter counts from its replay.
    pub published_at: OffsetDateTime,
}

/// The bus's handle on one delivery of one message, which the service hands
/// back to acknowledge or refuse it.
///
/// The bus makes it and is the only one that reads it. The adapter makes it
/// so it cannot be forged or altered, and refuses one made for another
/// consumer, so a service settles only what was delivered to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt(String);

impl DeliveryReceipt {
    /// The receipt as the bus wrote it, or as the service handed it back.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The receipt as text, for the bus and the service.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A message handed out and waiting for its acknowledgement.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    /// The message itself.
    pub message: ReceivedMessage,
    /// The handle that acknowledges or refuses this delivery.
    pub receipt: DeliveryReceipt,
    /// How many times the bus has delivered it, this delivery included.
    pub delivered: u32,
}

/// A delivery still waiting for its acknowledgement, as the bus counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenDelivery {
    /// How many times the bus has delivered the message, the open delivery
    /// included.
    pub delivered: u32,
}

/// When the bus counts a message as taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledgement {
    /// As soon as it is fetched. For a reader's own cursor, which nobody
    /// redelivers to.
    OnFetch,
    /// Once the service acknowledges it. Not acknowledged within `deadline`,
    /// it is delivered again.
    Explicit {
        /// How long a delivered message waits for its acknowledgement.
        deadline: Seconds,
    },
}

/// The consumer a subscription reads through.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerSpec<'a> {
    /// Its name, derived from the subscription so creating it is idempotent,
    /// or from the subscription's consumer group, so every subscription of
    /// the group reads through one consumer and shares its messages.
    pub name: &'a str,
    /// The message types it reads, if it reads only some.
    pub filter: Option<&'a MessageFilter>,
    /// When a message counts as taken.
    pub acknowledgement: Acknowledgement,
}

/// Whose messages are read, by which consumer, and how much the topic
/// still keeps.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerRead<'a> {
    /// The topic the messages were published on.
    pub topic_name: &'a TopicName,
    /// The durable consumer reading, one per subscription or group.
    pub consumer_name: &'a str,
    /// The topic's retention as it stands now.
    pub retention: RetentionPolicy,
}

/// Dyn-safe port for consuming messages from the tenant messaging bus.
///
/// The adapter keeps one durable bus consumer per name: one per
/// subscription, or one per consumer group on a topic.
/// A subscription's consumer hands messages out with [`Self::fetch_pending`]
/// and waits for them to be settled; a reader's own cursor takes them with
/// [`Self::pull_messages`]. The bus counts deliveries; when a message is set
/// aside is the domain's rule (`AckPolicy::fate_after`), which the use cases
/// apply, so the adapter sets no delivery limit of its own.
///
/// Both ways of reading take the topic's retention as it stands now, and
/// the adapter hands out nothing the retention no longer keeps, to a
/// reader that was away as to any other. Dead letters are kept apart and
/// are not held to it.
#[async_trait]
pub trait MessageConsumer: Send + Sync {
    /// Ensures a bus consumer exists for this subscription.
    ///
    /// Called when a subscription is created. The consumer name is derived
    /// from the subscription ID for idempotent creation.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the consumer cannot be created.
    async fn ensure_consumer(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer: &ConsumerSpec<'_>,
    ) -> Result<(), DomainError>;

    /// Takes a batch of messages from a consumer that acknowledges on
    /// fetch.
    ///
    /// Returns up to `max_messages` messages that `retention` still keeps.
    /// Returns an empty vec if none are available (non-blocking).
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the pull fails.
    async fn pull_messages(
        &self,
        tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        max_messages: usize,
    ) -> Result<Vec<ReceivedMessage>, DomainError>;

    /// Hands out up to `max_messages` that `retention` still keeps from a
    /// consumer that waits for acknowledgements, each with its receipt and
    /// delivery count. Nothing is acknowledged by handing it out.
    /// Non-blocking: empty when nothing waits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the fetch fails.
    async fn fetch_pending(
        &self,
        tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        max_messages: usize,
    ) -> Result<Vec<PendingMessage>, DomainError>;

    /// Removes the topic's messages that `retention` no longer keeps, for
    /// every reader of the topic. Done before a topic's rule is changed, so
    /// a longer limit never brings back what the old one had dropped. Safe
    /// to repeat: removing what is gone changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus refuses.
    async fn remove_lapsed(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        retention: RetentionPolicy,
    ) -> Result<(), DomainError>;

    /// The delivery `receipt` names, while it still waits for its
    /// acknowledgement on `consumer_name`. `None` when it was settled, its
    /// deadline passed, or the receipt is not one this consumer was given.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus cannot be read.
    async fn open_delivery(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<Option<OpenDelivery>, DomainError>;

    /// Acknowledges the delivery `receipt` names: the message is taken and
    /// not delivered again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus refuses.
    async fn acknowledge(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError>;

    /// Refuses the delivery `receipt` names, so the message is delivered
    /// again at once rather than when its deadline passes.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus refuses.
    async fn redeliver(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError>;

    /// Sets the message `receipt` names aside as a dead letter of
    /// `consumer_name`, kept for [`DeadLetters`](crate::ports::messaging::DeadLetters), and
    /// never delivers it again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus refuses.
    async fn dead_letter(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError>;

    /// Removes the bus consumer for a subscription, with its dead
    /// letters.
    ///
    /// Called when a subscription is deleted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the consumer cannot be removed.
    async fn delete_consumer(
        &self,
        tenant_id: &TenantId,
        topic_name: &TopicName,
        consumer_name: &str,
    ) -> Result<(), DomainError>;
}

/// Driven port: holds an agent message to its topic's declared shape.
///
/// Returns the payload in canonical form, with keys sorted and insignificant
/// whitespace removed, so the only thing that travels is what the schema
/// allows, and nothing rides in the layout of the bytes.
pub trait MessageShape: Send + Sync {
    /// Checks `payload` against the JSON Schema `schema` and returns its
    /// canonical form.
    ///
    /// Never fetches anything: a schema that points at a remote or file
    /// reference does not compile.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the payload is not JSON or does not
    ///   match the schema.
    /// - [`DomainError::Infrastructure`] when the stored schema itself does not
    ///   compile.
    fn conform(&self, schema: &SchemaDefinition, payload: &[u8]) -> Result<Vec<u8>, DomainError>;
}
