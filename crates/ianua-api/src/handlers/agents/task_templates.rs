//! Task template handlers: one person proposes what a kind of agent task
//! may do, a different person approves it, and delegations are granted
//! inside it.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::task_templates::{DecideRequest, TemplateDecision};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::task_templates::{ProposeTaskTemplateBody, TaskTemplateResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::TaskTemplatePath;
use crate::response::Created;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/task-templates",
    tag = "Agents",
    request_body = ProposeTaskTemplateBody,
    responses(
        (status = 201, description = "Proposed", body = TaskTemplateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "The template allows nothing", body = ErrorBody)
    )
)]
/// Propose a task template
///
/// Writes down what one kind of agent task needs: the most it may be
/// granted, the kinds of action it may take, the paths, the most sensitive
/// data, the budget and the longest lifetime. Nothing can be granted under
/// it until a different person approves it. Records
/// `agents.task_template_proposed`. Requires `Agents(Delegate)`.
pub(crate) async fn propose_task_template(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<ProposeTaskTemplateBody>,
) -> Result<Created<TaskTemplateResponse>, ApiError> {
    let template = agents
        .task_templates
        .propose
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(TaskTemplateResponse::from(&template)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/task-templates",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<TaskTemplateResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List task templates
///
/// Every template in the tenant, newest first, retired ones included.
/// Requires `Agents(View)`.
pub(crate) async fn list_task_templates(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<TaskTemplateResponse>>, ApiError> {
    let templates = agents
        .task_templates
        .list
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        templates.iter().map(TaskTemplateResponse::from).collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/task-templates/{id}",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = TaskTemplateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a task template
///
/// One template, with its ceiling, its limits, and who proposed and
/// approved it. Requires `Agents(View)`.
pub(crate) async fn get_task_template(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<TaskTemplatePath>,
) -> Result<Json<TaskTemplateResponse>, ApiError> {
    let template = agents
        .task_templates
        .get
        .execute(&tenant.caller, path.template())
        .await?;
    Ok(Json(TaskTemplateResponse::from(&template)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/task-templates/{id}/approve",
    tag = "Agents",
    responses(
        (status = 200, description = "Approved", body = TaskTemplateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "The proposer cannot approve, or it is not awaiting approval", body = ErrorBody)
    )
)]
/// Approve a task template
///
/// Must be a different person than proposed it. Delegations can be granted
/// under it from now on. Records `agents.task_template_approved`. Requires
/// `Agents(Delegate)`.
pub(crate) async fn approve_task_template(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<TaskTemplatePath>,
) -> Result<Json<TaskTemplateResponse>, ApiError> {
    let template = agents
        .task_templates
        .decide
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DecideRequest {
                template_id: path.template(),
                decision: TemplateDecision::Approve,
            },
        )
        .await?;
    Ok(Json(TaskTemplateResponse::from(&template)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/task-templates/{id}/retire",
    tag = "Agents",
    responses(
        (status = 200, description = "Retired", body = TaskTemplateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already retired", body = ErrorBody)
    )
)]
/// Retire a task template
///
/// No new delegation can be granted under it. Delegations already granted
/// keep their own expiry; revoke them to end them sooner. Records
/// `agents.task_template_retired`. Requires `Agents(Delegate)`.
pub(crate) async fn retire_task_template(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<TaskTemplatePath>,
) -> Result<Json<TaskTemplateResponse>, ApiError> {
    let template = agents
        .task_templates
        .decide
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DecideRequest {
                template_id: path.template(),
                decision: TemplateDecision::Retire,
            },
        )
        .await?;
    Ok(Json(TaskTemplateResponse::from(&template)))
}
