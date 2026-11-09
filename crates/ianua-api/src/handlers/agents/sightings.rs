//! Sighting handlers: the agents seen at work that nobody registered, and
//! a person registering or dismissing one.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::sightings::{RegisterSightingBody, SightingQueryParams, SightingResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::SightingPath;
use crate::extractors::query::Query;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/sightings",
    tag = "Agents",
    params(SightingQueryParams),
    responses(
        (status = 200, description = "Success", body = Vec<SightingResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Unknown filter", body = ErrorBody)
    )
)]
/// List unregistered agents seen at work
///
/// Returns the callers the gateway, the OAuth server or a cloud scan saw
/// acting like agents with no agent behind them: a person's key used by a
/// script, a client nobody tied to an agent, a workload holding
/// credentials. Each says where it was seen, what tells it apart, what it
/// called itself, and how often and when it was seen. `?shown=all` adds
/// those already registered or dismissed. A sighting grants nothing.
/// Requires `Agents(View)`.
pub(crate) async fn list_sightings(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Query(query): Query<SightingQueryParams>,
) -> Result<Json<Vec<SightingResponse>>, ApiError> {
    let sightings = agents
        .sightings
        .list
        .execute(&tenant.caller, query.shown()?)
        .await?;
    Ok(Json(sightings.iter().map(SightingResponse::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/sightings/{id}/register",
    tag = "Agents",
    request_body = RegisterSightingBody,
    responses(
        (status = 200, description = "Registered", body = SightingResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Sighting or agent not found", body = ErrorBody),
        (status = 422, description = "Registered already", body = ErrorBody)
    )
)]
/// Register a sighting as an agent
///
/// Records that a sighted caller is one of the tenant's agents, created for
/// it or already there, which puts it under delegations like any agent.
/// Records `agents.agent_sighting_registered`. Requires `Agents(Manage)`.
pub(crate) async fn register_sighting(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<SightingPath>,
    Json(body): Json<RegisterSightingBody>,
) -> Result<Json<SightingResponse>, ApiError> {
    let sighting = agents
        .sightings
        .register
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.sighting()),
        )
        .await?;
    Ok(Json(SightingResponse::from(&sighting)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/sightings/{id}/dismiss",
    tag = "Agents",
    responses(
        (status = 200, description = "Dismissed", body = SightingResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Sighting not found", body = ErrorBody),
        (status = 422, description = "Dealt with already", body = ErrorBody)
    )
)]
/// Dismiss a sighting
///
/// Records that a sighted caller is no agent at all, dropping it from the
/// unreviewed list. What it does is still allowed or refused by the usual
/// rules. Records `agents.agent_sighting_dismissed`. Requires
/// `Agents(Manage)`.
pub(crate) async fn dismiss_sighting(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<SightingPath>,
) -> Result<Json<SightingResponse>, ApiError> {
    let sighting = agents
        .sightings
        .dismiss
        .execute(&tenant.caller, &tenant.auditor, path.sighting())
        .await?;
    Ok(Json(SightingResponse::from(&sighting)))
}
