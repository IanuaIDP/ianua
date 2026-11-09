//! Channel bodies: what a person opens between two agents, and the messages
//! the relay carries through them.

use ianua_app::error::AppError;
use ianua_app::use_cases::messaging::channels::agent_relay::RelayedMessage;
use ianua_app::use_cases::messaging::channels::{
    OpenRequest, RelayPublishRequest, RelayReadRequest,
};
use ianua_domain::domains::agents::authority::capability::{ResourceRef, TopicPattern};
use ianua_domain::domains::agents::channels::channel::{AgentChannel, ChannelScope};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, Seconds};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// How many messages a read returns when it names no number.
const DEFAULT_MAX_MESSAGES: usize = 10;

/// Request body for opening a channel between two agents. Names exactly
/// one of `topics` or `resource`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OpenChannelBody {
    /// The agent whose area the messages come from.
    pub sender_agent_id: Uuid,
    /// The agent that may read them.
    pub receiver_agent_id: Uuid,
    /// The topics in the sender's area the receiver may read, such as
    /// `agents.<sender id>.tasks` or `agents.<sender id>.>`.
    #[serde(default)]
    pub topics: Option<String>,
    /// One object both agents may hold rights on, such as `doc:42`.
    #[serde(default)]
    pub resource: Option<String>,
    /// The most sensitive data that may travel through the channel.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_class: DataClassLevel,
    /// How long the channel stays open, in seconds (60 to 2,592,000).
    pub lifetime_seconds: u32,
}

impl TryFrom<OpenChannelBody> for OpenRequest {
    type Error = ApiError;

    fn try_from(body: OpenChannelBody) -> Result<Self, Self::Error> {
        let scope = match (body.topics, body.resource) {
            (Some(topics), None) => {
                ChannelScope::Topics(TopicPattern::new(topics).map_err(ApiError::validation)?)
            }
            (None, Some(resource)) => {
                ChannelScope::Resource(ResourceRef::new(resource).map_err(ApiError::validation)?)
            }
            _ => {
                return Err(ApiError::validation(message!(
                    "api-a-channel-names-exactly-one-of",
                    "a channel names exactly one of topics or resource"
                )));
            }
        };
        Ok(Self {
            sender: AgentId::from_uuid(body.sender_agent_id),
            receiver: AgentId::from_uuid(body.receiver_agent_id),
            scope,
            max_class: body.max_class,
            lifetime_seconds: Seconds::new(body.lifetime_seconds),
        })
    }
}

/// A channel between two agents.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ChannelResponse {
    /// Unique channel ID.
    pub id: Uuid,
    /// The agent whose area the messages come from.
    pub sender_agent_id: Uuid,
    /// The agent that may read them.
    pub receiver_agent_id: Uuid,
    /// What the channel carries: `topics` or `resource`.
    pub scope_kind: String,
    /// The topic pattern or resource reference.
    pub scope: String,
    /// The most sensitive data that may travel.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_class: DataClassLevel,
    /// The person who opened it.
    pub opened_by: OwnerDto,
    /// When it was opened.
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
    /// When it closes by itself.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// When a person closed it, if they did.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub closed_at: Option<OffsetDateTime>,
    /// Whether it carries messages right now.
    pub open: bool,
}

impl From<AgentChannel<ResolvedTenant>> for ChannelResponse {
    fn from(channel: AgentChannel<ResolvedTenant>) -> Self {
        Self {
            id: *channel.id().as_uuid(),
            sender_agent_id: *channel.sender().as_uuid(),
            receiver_agent_id: *channel.receiver().as_uuid(),
            scope_kind: channel.scope().kind().to_owned(),
            scope: channel.scope().as_str().to_owned(),
            max_class: channel.max_class(),
            opened_by: OwnerDto::from_principal(channel.opened_by()),
            opened_at: channel.opened_at(),
            expires_at: channel.expires_at(),
            closed_at: channel.closed_at(),
            open: channel.is_open(clock::now()),
        }
    }
}

/// The message an agent publishes through the relay, as it sent it.
pub(crate) struct RelayMessage<'a> {
    /// The agent's task token.
    pub credential: Secret,
    /// The topic it publishes to.
    pub topic: TopicName,
    /// The request body, verbatim.
    pub payload: &'a [u8],
}

impl From<RelayMessage<'_>> for RelayPublishRequest {
    fn from(message: RelayMessage<'_>) -> Self {
        Self {
            credential: message.credential,
            topic: message.topic,
            payload: message.payload.to_vec(),
        }
    }
}

/// Query parameters for reading through the relay.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RelayReadParams {
    /// Maximum number of messages to return (default 10, at most 100).
    #[serde(default = "default_max_messages")]
    pub max_messages: usize,
}

/// How many messages a relay read returns when it does not say.
fn default_max_messages() -> usize {
    DEFAULT_MAX_MESSAGES
}

impl RelayReadParams {
    /// The read of `topic` the agent holding `credential` asks for.
    #[must_use]
    pub(crate) fn read(&self, credential: Secret, topic: TopicName) -> RelayReadRequest {
        RelayReadRequest {
            credential,
            topic,
            max_messages: self.max_messages,
        }
    }
}

/// A message the relay delivered, with the authorship ianua vouches for.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RelayedMessageResponse {
    /// The message, in the canonical form the relay forwarded.
    #[schema(value_type = Object)]
    pub message: serde_json::Value,
    /// The agent that sent it.
    pub sender_agent_id: Uuid,
    /// The delegation the sender acted under.
    pub delegation_id: Uuid,
    /// Whom the sender acted for; empty for an autonomous agent.
    pub on_behalf_of: Vec<OwnerDto>,
}

impl RelayedMessageResponse {
    /// Every message in `relayed`.
    ///
    /// # Errors
    ///
    /// - An internal error when a message the relay forwarded is not JSON:
    ///   the relay forwards only JSON, so one that is not was not its.
    pub(crate) fn all_of(relayed: Vec<RelayedMessage>) -> Result<Vec<Self>, ApiError> {
        relayed.into_iter().map(Self::try_from).collect()
    }
}

impl TryFrom<RelayedMessage> for RelayedMessageResponse {
    type Error = ApiError;

    fn try_from(relayed: RelayedMessage) -> Result<Self, Self::Error> {
        let provenance = &relayed.provenance;
        Ok(Self {
            message: serde_json::from_slice(&relayed.payload).map_err(AppError::internal)?,
            sender_agent_id: *provenance.sender().as_uuid(),
            delegation_id: *provenance.delegation_id().as_uuid(),
            on_behalf_of: provenance
                .on_behalf_of()
                .iter()
                .map(OwnerDto::from_principal)
                .collect(),
        })
    }
}
