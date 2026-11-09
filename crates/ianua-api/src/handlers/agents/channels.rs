//! Agent channel handlers: how a person lets one agent read another's area,
//! and the relay agents publish and read through with their task token.
//!
//! Agents hold no broker credentials. They publish and read at the relay
//! with their task token as the bearer credential, and the relay checks,
//! reshapes, signs and records every message.

use axum::body::Bytes;
use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::channels::{
    ChannelResponse, OpenChannelBody, RelayMessage, RelayReadParams, RelayedMessageResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::AgentRelayCaller;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::agents::{AgentTopicPath, ChannelPath};
use crate::extractors::query::Query;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/channels",
    tag = "Messaging",
    request_body = OpenChannelBody,
    responses(
        (status = 201, description = "Opened", body = ChannelResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "An agent was not found", body = ErrorBody),
        (status = 409, description = "An agent is not active", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Open a channel between two agents
///
/// Grants either one-way reads of `topics` in the sender's
/// `agents.<sender id>.…` area, or shared rights on one `resource` that
/// either agent may write. Agents exchange data only through these channels.
/// Sets the highest data sensitivity and a lifetime of one minute to 30 days.
/// Returns `422` for both or neither channel kinds, topics outside the
/// sender's area, or identical agents. Requires the sender's owner or
/// `Agents(Delegate)` because sharing output grants authority.
/// Records `messaging.channel_opened`.
pub(crate) async fn open_channel(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<OpenChannelBody>,
) -> Result<Created<ChannelResponse>, ApiError> {
    let channel = agents
        .channels
        .open
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(ChannelResponse::from(channel)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/channels",
    tag = "Messaging",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ChannelResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List channels between agents
///
/// Every channel people opened in the tenant, open and closed, newest
/// first. `open` says whether it carries messages right now. Requires
/// `Agents(View)`.
pub(crate) async fn list_channels(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ChannelResponse>>, ApiError> {
    let page = agents
        .channels
        .list
        .execute(&tenant.caller, pagination)
        .await?;
    Ok(Json(PageResponse::from_page(page, ChannelResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/channels/{id}/close",
    tag = "Messaging",
    responses(
        (status = 204, description = "Closed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already closed", body = ErrorBody)
    )
)]
/// Close a channel between two agents
///
/// The next read through the channel is refused. A closed channel stays on
/// record and cannot be reopened; open a new one instead. Records
/// `messaging.channel_closed`. Requires the person who opened it, the sending
/// agent's owner, or `Agents(Delegate)`.
pub(crate) async fn close_channel(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ChannelPath>,
) -> Result<NoContent, ApiError> {
    agents
        .channels
        .close
        .execute(&tenant.caller, &tenant.auditor, path.channel())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/messages/{topic}",
    tag = "Agents",
    request_body(content = Object, description = "The message: JSON matching the topic's schema"),
    responses(
        (status = 204, description = "Relayed"),
        (status = 401, description = "No valid task token for this tenant", body = ErrorBody),
        (status = 403, description = "The relay refused the message", body = ErrorBody),
        (status = 404, description = "Topic not found", body = ErrorBody),
        (status = 422, description = "The message does not match the topic's schema", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Publish an agent message through the relay
///
/// The agent presents its task token as the bearer credential and sends
/// the message as the request body. The relay forwards it only when the
/// token is live and issued for this tenant, the agent is in good
/// standing, its delegation covers the topic for publishing, the topic
/// carries agent messages and declares a schema, the message is JSON of at
/// most 64 KiB that matches the schema, and the topic is cleared at least
/// as high as the data the agent has touched. The relay forwards the
/// message in canonical form and signs its provenance. Every decision is
/// recorded (`agents.message_authorized` or `agents.message_denied`). Rate
/// limited per address.
pub(crate) async fn publish_agent_message(
    State(agents): State<AgentState>,
    relay: AgentRelayCaller,
    Path(path): Path<AgentTopicPath>,
    body: Bytes,
) -> Result<NoContent, ApiError> {
    let message = RelayMessage {
        credential: relay.credential,
        topic: path.topic()?,
        payload: &body,
    };
    agents
        .channels
        .relay_publish
        .execute(&relay.tenant, &relay.auditor, message.into())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/messages/{topic}",
    tag = "Agents",
    params(RelayReadParams),
    responses(
        (status = 200, description = "The next messages on the topic", body = Vec<RelayedMessageResponse>),
        (status = 401, description = "No valid task token for this tenant", body = ErrorBody),
        (status = 403, description = "The relay refused the read", body = ErrorBody),
        (status = 404, description = "Topic not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Read agent messages through the relay
///
/// The agent presents its task token as the bearer credential. The relay
/// returns up to `max_messages` (at most 100) of the next messages on the
/// topic, each with the sender, its delegation and whom it acted for, as
/// verified from the signed provenance. A message whose provenance does
/// not verify is dropped and recorded, never returned. Reading another
/// agent's area needs an open channel, and raises the reader's data mark
/// to the topic's class. Rate limited per address.
pub(crate) async fn read_agent_messages(
    State(agents): State<AgentState>,
    relay: AgentRelayCaller,
    Path(path): Path<AgentTopicPath>,
    Query(params): Query<RelayReadParams>,
) -> Result<Json<Vec<RelayedMessageResponse>>, ApiError> {
    let relayed = agents
        .channels
        .relay_read
        .execute(
            &relay.tenant,
            &relay.auditor,
            params.read(relay.credential, path.topic()?),
        )
        .await?;
    Ok(Json(RelayedMessageResponse::all_of(relayed)?))
}
