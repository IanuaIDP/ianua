//! Loading the topic, subscription, schema or channel a caller names, which
//! the messaging use cases start with.

use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::domains::messaging::schema::EventSchema;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{AgentChannelId, AgentId, EventSchemaId, MessageSubscriptionId, TopicId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::AgentStore;
use crate::ports::messaging::{AgentChannelStore, SchemaStore, SubscriptionStore, TopicStore};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;

/// The tenant's topic with `topic_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such topic.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_topic(
    store: &dyn TopicStore,
    tenant: &ScopedTenant,
    topic_id: &TopicId,
) -> Result<Topic<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, topic_id)
        .await
        .or_internal()?
        .or_not_found(message!("messaging-topic-not-found-2", "topic not found"))
}

/// The tenant's topic named `topic_name`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no topic by that name.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_named_topic(
    store: &dyn TopicStore,
    tenant: &ScopedTenant,
    topic_name: &TopicName,
) -> Result<Topic<ResolvedTenant>, AppError> {
    store
        .find_by_name(tenant, topic_name)
        .await
        .or_internal()?
        .ok_or_else(|| {
            AppError::NotFound(message!(
                "messaging-topic-not-found",
                format!("topic '{topic_name}' not found")
            ))
        })
}

/// The tenant's subscription with `subscription_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such subscription.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_subscription(
    store: &dyn SubscriptionStore,
    tenant: &ScopedTenant,
    subscription_id: &MessageSubscriptionId,
) -> Result<Subscription<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, subscription_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "messaging-subscription-not-found",
            "subscription not found"
        ))
}

/// The tenant's event schema with `schema_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such schema.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_schema(
    store: &dyn SchemaStore,
    tenant: &ScopedTenant,
    schema_id: &EventSchemaId,
) -> Result<EventSchema<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, schema_id)
        .await
        .or_internal()?
        .or_not_found(message!("messaging-schema-not-found", "schema not found"))
}

/// The tenant's channel with `channel_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such channel.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_channel(
    store: &dyn AgentChannelStore,
    tenant: &ScopedTenant,
    channel_id: &AgentChannelId,
) -> Result<AgentChannel<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, channel_id)
        .await
        .or_internal()?
        .or_not_found(message!("messaging-channel-not-found", "channel not found"))
}

/// Where a channel and its sending agent are read from.
pub(super) struct ChannelStores<'a> {
    /// Where channels are kept.
    pub(super) channels: &'a dyn AgentChannelStore,
    /// Where the sending agent is kept.
    pub(super) agents: &'a dyn AgentStore,
}

/// A channel the person acting may close, with its sending agent.
pub(super) struct ClosableChannel {
    /// The communication path the authorized caller may shut down.
    pub(super) channel: AgentChannel<ResolvedTenant>,
    /// The agent whose area the channel reads from.
    pub(super) sender: AgentIdentity<ResolvedTenant>,
}

/// The tenant's channel with `channel_id`, with its sending agent, read as
/// missing unless the person `control` names may close it. Someone with no
/// say over it is answered as for a channel that does not exist, so an id
/// cannot be used to find out which channels are open.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such channel or sending
///   agent, or the person may not close the channel.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_channel(
    stores: ChannelStores<'_>,
    tenant: &ScopedTenant,
    channel_id: &AgentChannelId,
    control: &AgentControl<'_>,
) -> Result<ClosableChannel, AppError> {
    let channel = existing_channel(stores.channels, tenant, channel_id).await?;
    let sender = existing_agent(stores.agents, tenant, channel.sender()).await?;
    channel
        .ensure_closable_by(control, sender.owner())
        .map_err(|_| {
            AppError::NotFound(message!("messaging-channel-not-found", "channel not found"))
        })?;
    Ok(ClosableChannel { channel, sender })
}

/// The tenant's agent `agent_id` that messages are to come from, read as
/// missing unless the person `control` names owns it or may update agents.
/// Someone with no say over it is answered as for an agent that does not
/// exist, so an id cannot be used to find out which agents there are.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such agent, or the person
///   has no say over it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_sender(
    store: &dyn AgentStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    control: &AgentControl<'_>,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    let sender = existing_agent(store, tenant, agent_id).await?;
    control
        .ensure_may(sender.owner(), AgentAction::Update)
        .map_err(|_| AppError::NotFound(message!("app-agent-not-found", "agent not found")))?;
    Ok(sender)
}
