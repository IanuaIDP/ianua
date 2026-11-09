//! Agent ownership handlers: an owner offering an agent to another person,
//! that person accepting or declining it, and someone allowed to manage
//! agents taking one over.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::lifecycle::{AgentResponse, OfferAgentBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::AgentPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/offer",
    tag = "Agents",
    request_body = OfferAgentBody,
    responses(
        (status = 200, description = "Offered", body = AgentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the recipient may not own an agent", body = ErrorBody),
        (status = 404, description = "Agent or user not found", body = ErrorBody),
        (status = 409, description = "The recipient owns the agent already", body = ErrorBody)
    )
)]
/// Offer an agent to another person
///
/// The owner names the tenant user who is to look after the agent from now
/// on, such as before moving teams. Nothing moves until they accept, signed
/// in themselves; the offer lapses after a week. Whether they may own an
/// agent is worked out from what the tenant's records say they hold. A new
/// offer replaces one standing. Answers the agent with the standing offer.
/// Records `agents.agent_ownership_offered`. Requires the agent's owner or
/// `Agents(Manage)`.
pub(crate) async fn offer_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<OfferAgentBody>,
) -> Result<Json<AgentResponse>, ApiError> {
    let agent = agents
        .ownership
        .offer
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent()),
        )
        .await?;
    Ok(Json(AgentResponse::from(agent)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/offer",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 409, description = "No offer stands", body = ErrorBody)
    )
)]
/// Withdraw or decline an agent offer
///
/// Ends a standing offer unaccepted: the owner withdraws it, or the person
/// it was made to declines it. The agent stays with its owner. Records
/// `agents.agent_ownership_offer_withdrawn`. Requires the owner, the
/// recipient or `Agents(Manage)`.
pub(crate) async fn withdraw_agent_offer(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<NoContent, ApiError> {
    agents
        .ownership
        .withdraw
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/accept",
    tag = "Agents",
    responses(
        (status = 200, description = "Accepted: the caller owns it", body = AgentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Offered to someone else, or the caller may not own an agent", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 409, description = "Not on offer: none was made, or it lapsed", body = ErrorBody)
    )
)]
/// Accept an agent offered to me
///
/// The person an agent was offered to becomes its owner. What they hold is
/// read from their own sign-in, so a right lost since the offer no longer
/// counts. The agent keeps its status, keys and delegations; a delegation
/// the old owner granted still names them. Records
/// `agents.agent_ownership_transferred`, naming both owners.
pub(crate) async fn accept_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<AgentResponse>, ApiError> {
    let agent = agents
        .ownership
        .accept
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(Json(AgentResponse::from(agent)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/take-over",
    tag = "Agents",
    responses(
        (status = 200, description = "Taken over: the caller owns it", body = AgentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the caller may not own an agent", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 409, description = "The caller owns it already", body = ErrorBody)
    )
)]
/// Take over an agent
///
/// Makes the caller the agent's owner, for an agent whose owner left or
/// moved to other work, so it never stays with nobody looking after it.
/// The agent keeps its status, keys and delegations; a delegation the old
/// owner granted still names them. Records
/// `agents.agent_ownership_transferred`, naming both owners. Requires
/// `Agents(Manage)`, and the right to create agents.
pub(crate) async fn take_over_agent(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<AgentResponse>, ApiError> {
    let agent = agents
        .ownership
        .take_over
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(Json(AgentResponse::from(agent)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/agent-offers",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<AgentResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the agents offered to me
///
/// Returns the agents waiting for the caller to accept or decline them,
/// each with when its offer lapses. Lapsed offers are left out. Every
/// person may read their own.
pub(crate) async fn list_my_agent_offers(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<AgentResponse>>, ApiError> {
    let offered = agents
        .ownership
        .list_offers
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(offered.into_iter().map(AgentResponse::from).collect()))
}
