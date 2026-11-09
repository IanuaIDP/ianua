//! Agent access handlers: dry runs of whether an agent may take an action,
//! make a request, or exercise a relation on an object.

use axum::extract::{Path, State};
use ianua_app::use_case::Query as _;
use ianua_assembly::agents::AgentState;

use crate::dto::agents::access::{
    AuthorizeCheckBody, AuthorizeCheckResponse, AuthorizeResourceBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::AgentPath;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/authorize-check",
    tag = "Agents",
    request_body = AuthorizeCheckBody,
    responses(
        (status = 200, description = "Success", body = AuthorizeCheckResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Dry-run authorization check
///
/// Reports whether the agent's live delegations grant an `action`, or,
/// given a `method` and `path` instead, whether the agent would be let
/// through for that request: the request is resolved against the tenant's
/// routes to find the governing policy, then checked the way the proxy
/// would. Nothing happens: no token is issued and no request is forwarded.
/// Answers `allow` or `deny` with a reason. `404` if the agent does not
/// exist, `422` when neither or both forms are given or the permission is
/// unknown. Requires the agent's owner or `Agents(View)`.
pub(crate) async fn authorize_check(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<AuthorizeCheckBody>,
) -> Result<Json<AuthorizeCheckResponse>, ApiError> {
    let outcome = agents
        .access
        .authorize
        .execute(&tenant.caller, body.into_request(path.agent())?)
        .await?;
    Ok(Json(AuthorizeCheckResponse::from(outcome)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/authorize-resource",
    tag = "Agents",
    request_body = AuthorizeResourceBody,
    responses(
        (status = 200, description = "Success", body = AuthorizeCheckResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Dry-run resource-scoped authorization check
///
/// Reports whether the agent may exercise a `relation` on a `resource`,
/// with nothing happening. Deny by default: the agent needs a delegated
/// resource capability over the object, and either an exact match or a
/// relationship the graph confirms. `404` if the agent does not exist.
/// Requires the agent's owner or `Agents(View)`.
pub(crate) async fn authorize_resource(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<AuthorizeResourceBody>,
) -> Result<Json<AuthorizeCheckResponse>, ApiError> {
    let outcome = agents
        .access
        .authorize_resource
        .execute(&tenant.caller, body.into_request(path.agent())?)
        .await?;
    Ok(Json(AuthorizeCheckResponse::from(outcome)))
}
