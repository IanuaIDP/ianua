//! Agent tool handlers: the APIs agents may call.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::tools::{
    RegisterToolBody, RegisterToolResponse, ToolResponse, UpdateToolStatusBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::ToolPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/tools",
    tag = "Agents",
    request_body = RegisterToolBody,
    responses(
        (status = 201, description = "Registered", body = RegisterToolResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Route not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Plan limit reached", body = ErrorBody)
    )
)]
/// Register a tool
///
/// Adds an API agents may call: a model-facing name, description and input
/// schema bound to an HTTP endpoint on one of the tenant's routes. The tool
/// takes its action class and data class from that route, so the
/// orchestration loop offers only the tools inside a run's purpose, and a
/// run that has read data of a higher class than the tool's is refused it.
/// The person registering it may use it from then on. Records
/// `agents.tool_registered`. Requires `Agents(Manage)`.
pub(crate) async fn register_tool(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<RegisterToolBody>,
) -> Result<Created<RegisterToolResponse>, ApiError> {
    let id = agents
        .tools
        .register
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(RegisterToolResponse::from(id)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/tools",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<ToolResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List tools
///
/// Returns this tenant's registered tools: name, endpoint, input schema,
/// route, and the action class and data class each carries. Requires
/// `Agents(View)`.
pub(crate) async fn list_tools(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<ToolResponse>>, ApiError> {
    let tools = agents.tools.list.execute(&tenant.caller, ()).await?;
    Ok(Json(tools.into_iter().map(ToolResponse::from).collect()))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/tools/{id}",
    tag = "Agents",
    request_body = RegisterToolBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Tool or route not found", body = ErrorBody),
        (status = 422, description = "Validation error, or the route does not serve the call", body = ErrorBody)
    )
)]
/// Edit a tool
///
/// Replaces a tool's whole definition, in the shape it was registered
/// with: its name, description, input schema, method, path and the route
/// that serves it. The tool takes its action class and data class from the
/// route again, so a tool moved to a riskier route waits for approval like
/// any call of that class. Its status is unchanged. Records
/// `agents.tool_edited`. Requires `Agents(Manage)`.
pub(crate) async fn edit_tool(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ToolPath>,
    Json(body): Json<RegisterToolBody>,
) -> Result<NoContent, ApiError> {
    agents
        .tools
        .edit
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_edit(path.tool())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/tools/{id}",
    tag = "Agents",
    request_body = UpdateToolStatusBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Enable or disable a tool
///
/// Sets a tool's status. A disabled tool is kept but no longer offered to
/// agents. Records `agents.tool_status_changed`. Requires `Agents(Update)`.
pub(crate) async fn update_tool_status(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ToolPath>,
    Json(body): Json<UpdateToolStatusBody>,
) -> Result<NoContent, ApiError> {
    agents
        .tools
        .update_status
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.tool())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/tools/{id}",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Still active", body = ErrorBody)
    )
)]
/// Delete a tool
///
/// Removes a tool for good. The tool must be disabled first. Records
/// `agents.tool_deleted`. Requires `Agents(Delete)`.
pub(crate) async fn delete_tool(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ToolPath>,
) -> Result<NoContent, ApiError> {
    agents
        .tools
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.tool())
        .await?;
    Ok(NoContent)
}
