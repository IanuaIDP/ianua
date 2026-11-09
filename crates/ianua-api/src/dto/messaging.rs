//! Messaging bodies: topics, subscriptions and their push secrets, event
//! schemas, the messages published, pulled and settled, and dead letters.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::error::AppError;
use ianua_app::ports::messaging::{DeadLetter, DeadLetterId, DeliveryReceipt, PendingMessage};
use ianua_app::use_cases::messaging::broker::{
    AckMessageRequest, NackMessageRequest, PublishMessageRequest, ReplayDeadLetterRequest,
};
use ianua_app::use_cases::messaging::schemas::{EvolveRequest, RegisterRequest};
use ianua_app::use_cases::messaging::subscriptions::{
    CreatedDelivery, CreatedSubscription, DeliveryChoice, RotatePushSecretRequest,
    SubscriptionFilter,
};
use ianua_app::use_cases::messaging::topics::{
    ChangeRetentionRequest, ChangeSchemaRequest, RaiseDataClassRequest,
};
use ianua_app::use_cases::messaging::{subscriptions, topics};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::control::CreatedBy;
use ianua_domain::domains::messaging::delivery::{AckPolicy, MessageFate, SubscriptionDelivery};
use ianua_domain::domains::messaging::message_type::{MessageFilter, MessageType};
use ianua_domain::domains::messaging::schema::{
    CompatibilityMode, EventSchema, SchemaDefinition, SchemaFormat,
};
use ianua_domain::domains::messaging::subscription::{
    ConsumerGroup, DeliveryMode, Subscription, SubscriptionStatus,
};
use ianua_domain::domains::messaging::topic::{RetentionPolicy, Topic, TopicStatus};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ConsumerId, EventSchemaId, Label, MessageSubscriptionId, PrincipalRef, PublicHttpsUrl, Seconds,
    Setting, TopicId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::time::rotation_overlap;

/// The most messages one pull returns.
const MAX_PULLED: usize = 100;

/// Request body for creating a topic.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateTopicBody {
    /// Human-readable display name.
    pub name: String,
    /// Machine-readable topic name (such as `"orders.created"`), which the
    /// publish and stream endpoints address the topic by.
    pub topic_name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional JSON schema documenting the messages.
    pub schema: Option<String>,
    /// How long messages are kept: `{"Duration": seconds}`,
    /// `{"MessageCount": n}` or `"Unlimited"`. Never zero.
    #[schema(value_type = Object)]
    pub retention: RetentionPolicy,
    /// The most sensitive data the topic may carry; `Internal` when left
    /// out.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: Option<DataClassLevel>,
}

impl TryFrom<CreateTopicBody> for topics::CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateTopicBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            topic_name: TopicName::new(body.topic_name).map_err(ApiError::validation)?,
            description: body
                .description
                .map(|text| Label::new("description", text))
                .transpose()
                .map_err(ApiError::validation)?,
            schema: schema_setting(body.schema)?,
            retention: body.retention,
            data_class: body.data_class.unwrap_or(DataClassLevel::Internal),
        })
    }
}

/// A schema a body sets, or unset when it names none.
fn schema_setting(schema: Option<String>) -> Result<Setting<SchemaDefinition>, ApiError> {
    let definition = schema
        .map(SchemaDefinition::new)
        .transpose()
        .map_err(ApiError::validation)?;
    Ok(Setting::from_stored(definition))
}

/// Request body for replacing or clearing a topic's schema.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeTopicSchemaBody {
    /// The JSON schema agent messages through the relay are checked against
    /// from now on, or `null` for none. A service's own publish is not.
    pub schema: Option<String>,
}

impl ChangeTopicSchemaBody {
    /// The schema change for `topic_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the schema is blank or too large.
    pub(crate) fn change_of(self, topic_id: TopicId) -> Result<ChangeSchemaRequest, ApiError> {
        Ok(ChangeSchemaRequest {
            topic_id,
            schema: schema_setting(self.schema)?,
        })
    }
}

/// Request body for replacing a topic's retention policy.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeTopicRetentionBody {
    /// How long messages are kept from now on: `{"Duration": seconds}`,
    /// `{"MessageCount": n}` or `"Unlimited"`. Never zero.
    #[schema(value_type = Object)]
    pub retention: RetentionPolicy,
}

impl ChangeTopicRetentionBody {
    /// The retention change for `topic_id`.
    #[must_use]
    pub(crate) fn change_of(self, topic_id: TopicId) -> ChangeRetentionRequest {
        ChangeRetentionRequest {
            topic_id,
            retention: self.retention,
        }
    }
}

/// Request body for raising a topic's data class.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RaiseTopicDataClassBody {
    /// The most sensitive data the topic may carry from now on: `Public`,
    /// `Internal`, `Confidential` or `Restricted`. Never below the current
    /// class.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
}

impl RaiseTopicDataClassBody {
    /// The data class change for `topic_id`.
    #[must_use]
    pub(crate) fn change_of(self, topic_id: TopicId) -> RaiseDataClassRequest {
        RaiseDataClassRequest {
            topic_id,
            data_class: self.data_class,
        }
    }
}

/// Request body for publishing a message.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PublishMessageBody {
    /// The message payload, base64-encoded so any bytes travel over JSON.
    pub payload: String,
    /// Optional headers delivered with the message.
    #[serde(default)]
    pub headers: Vec<HeaderPair>,
    /// What kind of message it is, such as `order.refund.requested`.
    /// Subscriptions with a filter get only the types under it; a message
    /// without a type reaches only the subscriptions that filter on nothing.
    #[serde(default)]
    pub message_type: Option<String>,
}

impl PublishMessageBody {
    /// The publication of this message to `topic_name`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the payload is not base64 or the type is
    /// malformed.
    pub(crate) fn publication_to(
        self,
        topic_name: TopicName,
    ) -> Result<PublishMessageRequest, ApiError> {
        let payload = STANDARD.decode(&self.payload).map_err(|e| {
            ApiError::validation(message!(
                "api-invalid-base64-payload",
                format!("invalid base64 payload: {e}")
            ))
        })?;
        let message_type = self
            .message_type
            .map(MessageType::new)
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(PublishMessageRequest {
            topic_name,
            payload,
            headers: self
                .headers
                .into_iter()
                .map(|header| (header.key, header.value))
                .collect(),
            message_type,
        })
    }
}

/// A header delivered with a message.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct HeaderPair {
    /// Header key.
    pub key: String,
    /// Header value.
    pub value: String,
}

/// Request body for subscribing a service to a topic.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateSubscriptionBody {
    /// The topic to subscribe to, by its topic name.
    pub topic_name: String,
    /// The subscribing service, one of the tenant's consumers.
    pub consumer_id: Uuid,
    /// Consumer group name: services in one group share the messages.
    pub consumer_group: Option<String>,
    /// How messages are delivered: `Push` or `Pull`.
    #[schema(schema_with = crate::dto::schemas::delivery_mode)]
    pub delivery_mode: DeliveryMode,
    /// Where a `Push` subscription posts its messages: HTTPS on the public
    /// internet. Required for `Push`, refused for `Pull`.
    pub push_endpoint: Option<String>,
    /// How long, in seconds, a delivered message waits for its
    /// acknowledgement before it is delivered again: 5 to 600, 30 when
    /// left out.
    pub ack_deadline_seconds: Option<u32>,
    /// How many deliveries a message gets before it is set aside as a dead
    /// letter: 1 to 100, 5 when left out.
    pub max_deliveries: Option<u32>,
    /// Optional filter: the leading segments a message's type must start
    /// with, such as `order.refund`. Messages without a type do not pass.
    /// Subscriptions in one consumer group must filter alike.
    pub filter: Option<String>,
}

impl TryFrom<CreateSubscriptionBody> for subscriptions::CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateSubscriptionBody) -> Result<Self, Self::Error> {
        let consumer_group = body
            .consumer_group
            .map(ConsumerGroup::new)
            .transpose()
            .map_err(ApiError::validation)?;
        let filter = body
            .filter
            .map(MessageFilter::new)
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(Self {
            topic_name: TopicName::new(body.topic_name).map_err(ApiError::validation)?,
            subscriber: ConsumerId::from_uuid(body.consumer_id),
            consumer_group: Setting::from_stored(consumer_group),
            delivery: delivery_choice(body.delivery_mode, body.push_endpoint)?,
            ack_policy: ack_policy(body.ack_deadline_seconds, body.max_deliveries)?,
            filter: Setting::from_stored(filter),
        })
    }
}

/// How a new subscription delivers: pulled, or pushed to `endpoint`.
fn delivery_choice(
    mode: DeliveryMode,
    endpoint: Option<String>,
) -> Result<DeliveryChoice, ApiError> {
    match (mode, endpoint) {
        (DeliveryMode::Pull, None) => Ok(DeliveryChoice::Pull),
        (DeliveryMode::Push, Some(url)) => Ok(DeliveryChoice::Push(
            PublicHttpsUrl::new(url).map_err(ApiError::validation)?,
        )),
        (DeliveryMode::Pull, Some(_)) => Err(ApiError::validation(message!(
            "api-a-pull-subscription-has-no-push",
            "a pull subscription has no push_endpoint"
        ))),
        (DeliveryMode::Push, None) => Err(ApiError::validation(message!(
            "api-a-push-subscription-needs-a-push",
            "a push subscription needs a push_endpoint"
        ))),
    }
}

/// The acknowledgement policy a body asks for, each part left out taken
/// from the standard one.
fn ack_policy(deadline: Option<u32>, deliveries: Option<u32>) -> Result<AckPolicy, ApiError> {
    let standard = AckPolicy::standard();
    AckPolicy::new(
        deadline.map_or(standard.ack_deadline(), Seconds::new),
        deliveries.unwrap_or(standard.max_deliveries()),
    )
    .map_err(AppError::from_domain)
    .map_err(ApiError::from)
}

/// Query parameters for listing subscriptions: exactly one of a topic or a
/// service.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SubscriptionFilterParams {
    /// The subscriptions to this topic, by topic name.
    pub topic_name: Option<String>,
    /// The subscriptions of this service.
    pub consumer_id: Option<Uuid>,
}

impl SubscriptionFilterParams {
    /// Whose subscriptions are listed: the topic's when one is named, else
    /// the service's.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when neither is named, or the topic name is not a
    /// valid one.
    pub(crate) fn filter(self) -> Result<SubscriptionFilter, ApiError> {
        if let Some(name) = self.topic_name {
            let topic = TopicName::new(name).map_err(ApiError::validation)?;
            return Ok(SubscriptionFilter::ByTopic(topic));
        }
        let Some(service) = self.consumer_id else {
            return Err(ApiError::validation(message!(
                "api-either-topic-name-or-consumer-id",
                "either topic_name or consumer_id filter is required"
            )));
        };
        Ok(SubscriptionFilter::ByService(ConsumerId::from_uuid(
            service,
        )))
    }
}

/// Query parameters for pulling messages.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PullMessagesParams {
    /// Most messages to return (default 10, at most 100).
    #[serde(default = "default_max_messages")]
    pub max_messages: usize,
}

impl PullMessagesParams {
    /// How many messages to pull: the number asked for, at most 100.
    #[must_use]
    pub(crate) fn max(&self) -> usize {
        self.max_messages.min(MAX_PULLED)
    }
}

/// How many messages a pull returns when it names no number.
fn default_max_messages() -> usize {
    10
}

/// Request body for registering an event schema.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegisterSchemaBody {
    /// Human-readable name (such as `"Order Created"`).
    pub name: String,
    /// Machine-readable identifier (such as `"order-created"`).
    pub schema_name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Schema format: `JsonSchema`, `Avro` or `Protobuf`.
    #[schema(schema_with = crate::dto::schemas::schema_format)]
    pub format: SchemaFormat,
    /// How a new version must relate to the one before it: `None`,
    /// `Backward`, `Forward` or `Full`.
    #[schema(schema_with = crate::dto::schemas::compatibility_mode)]
    pub compatibility: CompatibilityMode,
    /// The first version's definition.
    pub definition: String,
}

impl TryFrom<RegisterSchemaBody> for RegisterRequest {
    type Error = ApiError;

    fn try_from(body: RegisterSchemaBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            schema_name: Label::new("schema_name", body.schema_name)
                .map_err(ApiError::validation)?,
            description: body
                .description
                .map(|text| Label::new("description", text))
                .transpose()
                .map_err(ApiError::validation)?,
            format: body.format,
            compatibility: body.compatibility,
            definition: SchemaDefinition::new(body.definition).map_err(ApiError::validation)?,
        })
    }
}

/// Request body for adding a schema version.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct EvolveSchemaBody {
    /// The new version's definition.
    pub definition: String,
}

impl EvolveSchemaBody {
    /// The next version of `schema_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the definition is blank or too large.
    pub(crate) fn version_of(self, schema_id: EventSchemaId) -> Result<EvolveRequest, ApiError> {
        Ok(EvolveRequest {
            schema_id,
            definition: SchemaDefinition::new(self.definition).map_err(ApiError::validation)?,
        })
    }
}

/// A message destination's names, retention settings and lifecycle status.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TopicResponse {
    /// Unique topic ID.
    pub id: Uuid,
    /// Human-readable display name.
    pub name: String,
    /// Machine-readable topic name.
    pub topic_name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional JSON schema.
    pub schema: Option<String>,
    /// Retention policy.
    #[schema(value_type = Object)]
    pub retention: RetentionPolicy,
    /// `Active`, `Paused` or `Archived`.
    #[schema(schema_with = crate::dto::schemas::topic_status)]
    pub status: TopicStatus,
    /// The account or consumer that created it.
    pub created_by: Uuid,
    /// The most sensitive data the topic may carry.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
    /// When created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Topic<ResolvedTenant>> for TopicResponse {
    fn from(topic: Topic<ResolvedTenant>) -> Self {
        Self {
            id: *topic.id().as_uuid(),
            name: topic.name().as_str().to_owned(),
            topic_name: topic.topic_name().as_str().to_owned(),
            description: topic.description().map(|d| d.as_str().to_owned()),
            schema: topic.schema().map(|s| s.as_str().to_owned()),
            retention: topic.retention(),
            status: topic.status(),
            created_by: creator_id(topic.created_by()),
            data_class: topic.data_class(),
            created_at: topic.created_at(),
            updated_at: topic.updated_at(),
        }
    }
}

/// The id of whoever created a topic or schema: the account a person used,
/// or the consumer.
fn creator_id(created_by: &CreatedBy) -> Uuid {
    match created_by {
        CreatedBy::Person(person) => PrincipalRef::from(person.account()).id(),
        CreatedBy::Consumer(id) => *id.as_uuid(),
    }
}

/// Identifies a newly created topic.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateTopicResponse {
    /// The new topic's ID.
    pub id: Uuid,
}

/// A consumer's delivery settings for messages from one topic.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SubscriptionResponse {
    /// Unique subscription ID.
    pub id: Uuid,
    /// The topic subscribed to.
    pub topic_name: String,
    /// The subscribing service.
    pub consumer_id: Uuid,
    /// Consumer group name.
    pub consumer_group: Option<String>,
    /// How messages are delivered.
    #[schema(schema_with = crate::dto::schemas::delivery_mode)]
    pub delivery_mode: DeliveryMode,
    /// Where a `Push` subscription posts its messages; `null` for `Pull`.
    pub push_endpoint: Option<String>,
    /// How long, in seconds, a delivered message waits for its
    /// acknowledgement.
    pub ack_deadline_seconds: u32,
    /// How many deliveries a message gets before it is set aside.
    pub max_deliveries: u32,
    /// Optional filter.
    pub filter: Option<String>,
    /// `Active` or `Paused`.
    #[schema(schema_with = crate::dto::schemas::subscription_status)]
    pub status: SubscriptionStatus,
    /// When created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<Subscription<ResolvedTenant>> for SubscriptionResponse {
    fn from(subscription: Subscription<ResolvedTenant>) -> Self {
        Self {
            id: *subscription.id().as_uuid(),
            topic_name: subscription.topic_name().as_str().to_owned(),
            consumer_id: *subscription.consumer_id().as_uuid(),
            consumer_group: subscription
                .consumer_group()
                .map(|group| group.as_str().to_owned()),
            delivery_mode: subscription.delivery_mode(),
            push_endpoint: push_endpoint(subscription.delivery()),
            ack_deadline_seconds: subscription.ack_policy().ack_deadline().get(),
            max_deliveries: subscription.ack_policy().max_deliveries(),
            filter: subscription.filter().map(|f| f.as_str().to_owned()),
            status: subscription.status(),
            created_at: subscription.created_at(),
        }
    }
}

/// Where `delivery` posts, when it is pushed.
fn push_endpoint(delivery: &SubscriptionDelivery) -> Option<String> {
    match delivery {
        SubscriptionDelivery::Pull => None,
        SubscriptionDelivery::Push(endpoint) => Some(endpoint.url().as_str().to_owned()),
    }
}

/// Identifies a newly created subscription, with a push subscription's
/// signing secret.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateSubscriptionResponse {
    /// The new subscription's ID.
    pub id: Uuid,
    /// The secret a `Push` subscription signs its posts with, for the
    /// service to check them. It is shown this once; left out for `Pull`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret: Option<String>,
}

impl From<CreatedSubscription> for CreateSubscriptionResponse {
    fn from(created: CreatedSubscription) -> Self {
        Self {
            id: *created.subscription_id.as_uuid(),
            signing_secret: match created.delivery {
                CreatedDelivery::Pull => None,
                CreatedDelivery::Push { signing_secret } => {
                    Some(signing_secret.expose().to_owned())
                }
            },
        }
    }
}

/// Request body for rotating a push subscription's signing secret.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotatePushSecretBody {
    /// How long, in seconds, the old secret keeps signing beside the new
    /// one, at most seven days, while the service moves over. Left out, the
    /// old secret stops at once, as after a leak.
    pub overlap_seconds: Option<i64>,
}

impl RotatePushSecretBody {
    /// The rotation of `subscription_id`'s push secret `body` asks for:
    /// with no body, the old secret stops at once.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the overlap is not a positive number of seconds.
    pub(crate) fn rotation_of(
        subscription_id: MessageSubscriptionId,
        body: Option<Self>,
    ) -> Result<RotatePushSecretRequest, ApiError> {
        Ok(RotatePushSecretRequest {
            subscription_id,
            overlap: rotation_overlap(body.and_then(|body| body.overlap_seconds))?,
        })
    }
}

/// Answer to rotating a push secret.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RotatePushSecretResponse {
    /// The new signing secret. It is shown this once.
    pub signing_secret: String,
}

impl From<Secret> for RotatePushSecretResponse {
    fn from(secret: Secret) -> Self {
        Self {
            signing_secret: secret.expose().to_owned(),
        }
    }
}

/// A message pulled from a subscription, waiting for its acknowledgement.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MessageResponse {
    /// The payload, base64-encoded.
    pub payload: String,
    /// The message's headers.
    pub headers: Vec<HeaderPair>,
    /// What kind of message it is, when it was published with a type.
    pub message_type: Option<String>,
    /// The handle that acknowledges or refuses this delivery. Hand it back
    /// to `ack` or `nack`; unacknowledged within the subscription's
    /// deadline, the message is delivered again.
    pub receipt: String,
    /// How many times the message has been delivered, this time included.
    pub delivered: u32,
}

impl From<PendingMessage> for MessageResponse {
    fn from(pending: PendingMessage) -> Self {
        Self {
            payload: STANDARD.encode(&pending.message.payload),
            headers: header_pairs(pending.message.headers),
            message_type: type_text(pending.message.message_type),
            receipt: pending.receipt.as_str().to_owned(),
            delivered: pending.delivered,
        }
    }
}

/// `message_type` as the answer carries it.
fn type_text(message_type: Option<MessageType>) -> Option<String> {
    message_type.map(|message_type| message_type.as_str().to_owned())
}

/// `headers` as the answer carries them.
fn header_pairs(headers: Vec<(String, String)>) -> Vec<HeaderPair> {
    headers
        .into_iter()
        .map(|(key, value)| HeaderPair { key, value })
        .collect()
}

/// Request body handing back a delivery's receipt, to acknowledge or
/// refuse it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReceiptBody {
    /// The receipt the pull handed out with the message.
    pub receipt: String,
}

impl ReceiptBody {
    /// Acknowledging this delivery of `subscription_id`.
    #[must_use]
    pub(crate) fn ack_of(self, subscription_id: MessageSubscriptionId) -> AckMessageRequest {
        AckMessageRequest {
            subscription_id,
            receipt: DeliveryReceipt::new(self.receipt),
        }
    }

    /// Refusing this delivery of `subscription_id`.
    #[must_use]
    pub(crate) fn nack_of(self, subscription_id: MessageSubscriptionId) -> NackMessageRequest {
        NackMessageRequest {
            subscription_id,
            receipt: DeliveryReceipt::new(self.receipt),
        }
    }
}

/// What became of a refused message.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct NackResponse {
    /// `Redeliver` when it is delivered again, `DeadLetter` when its
    /// deliveries ran out and it was set aside.
    pub fate: &'static str,
}

impl From<MessageFate> for NackResponse {
    fn from(fate: MessageFate) -> Self {
        Self {
            fate: match fate {
                MessageFate::Redeliver => "Redeliver",
                MessageFate::DeadLetter => "DeadLetter",
            },
        }
    }
}

/// A message set aside after its deliveries ran out.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeadLetterResponse {
    /// The dead letter's id, which a replay names.
    pub id: u64,
    /// The payload, base64-encoded.
    pub payload: String,
    /// The message's headers.
    pub headers: Vec<HeaderPair>,
    /// What kind of message it is, when it was published with a type.
    pub message_type: Option<String>,
    /// How many times it was delivered before it was set aside.
    pub delivered: u32,
    /// When it was set aside.
    #[serde(with = "time::serde::rfc3339")]
    pub set_aside_at: OffsetDateTime,
}

impl From<DeadLetter> for DeadLetterResponse {
    fn from(letter: DeadLetter) -> Self {
        Self {
            id: letter.id.get(),
            payload: STANDARD.encode(&letter.message.payload),
            headers: header_pairs(letter.message.headers),
            message_type: type_text(letter.message.message_type),
            delivered: letter.delivered,
            set_aside_at: letter.set_aside_at,
        }
    }
}

/// Replaying dead letter `dead_letter_id` of `subscription_id`.
#[must_use]
pub(crate) fn replay_of(
    subscription_id: MessageSubscriptionId,
    dead_letter_id: u64,
) -> ReplayDeadLetterRequest {
    ReplayDeadLetterRequest {
        subscription_id,
        dead_letter_id: DeadLetterId::new(dead_letter_id),
    }
}

/// Identifies a newly registered schema.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RegisterSchemaResponse {
    /// The new schema's ID.
    pub id: Uuid,
}

/// Answer to adding a schema version.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EvolveSchemaResponse {
    /// The new version number.
    pub version: u32,
}

/// An event schema with every version.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SchemaResponse {
    /// Unique schema ID.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Machine-readable identifier.
    pub schema_name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Schema format.
    #[schema(schema_with = crate::dto::schemas::schema_format)]
    pub format: SchemaFormat,
    /// Compatibility mode.
    #[schema(schema_with = crate::dto::schemas::compatibility_mode)]
    pub compatibility: CompatibilityMode,
    /// Every version, oldest first.
    pub versions: Vec<SchemaVersionResponse>,
    /// The account or consumer that registered it.
    pub created_by: Uuid,
    /// When created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// A registered message definition identified by its revision number.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SchemaVersionResponse {
    /// Version number.
    pub version: u32,
    /// Schema definition.
    pub definition: String,
    /// When registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<EventSchema<ResolvedTenant>> for SchemaResponse {
    fn from(schema: EventSchema<ResolvedTenant>) -> Self {
        Self {
            id: *schema.id().as_uuid(),
            name: schema.name().as_str().to_owned(),
            schema_name: schema.schema_name().as_str().to_owned(),
            description: schema.description().map(|d| d.as_str().to_owned()),
            format: schema.format(),
            compatibility: schema.compatibility(),
            versions: schema
                .versions()
                .iter()
                .map(|v| SchemaVersionResponse {
                    version: v.version,
                    definition: v.definition.as_str().to_owned(),
                    created_at: v.created_at,
                })
                .collect(),
            created_by: creator_id(schema.created_by()),
            created_at: schema.created_at(),
            updated_at: schema.updated_at(),
        }
    }
}
