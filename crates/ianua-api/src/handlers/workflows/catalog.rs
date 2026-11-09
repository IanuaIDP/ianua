//! Integration catalog handlers: what a workflow's builder may use.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::catalog::apps::AppResponse;
use crate::dto::workflows::catalog::data::DataResponse;
use crate::dto::workflows::catalog::{
    ChoicesResponse, EventResponse, IntegrationResponse, ListChoicesBody, OperationResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::OperationInputPath;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/integrations",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<IntegrationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List the integrations a workflow may use
///
/// Returns every integration installed in this deployment, each with the
/// `key` its operations and accounts name, its `title`, a `description` of
/// what it lets a workflow do, and the name of its `icon`, such as `github`
/// or `slack`. An icon name is lowercase letters, digits and dashes; the
/// dashboard draws the icon for it and a plain one for a name it does not
/// know. `connecting` says how an account is connected to it: `sign_in`
/// at its service through `.../accounts/connections`, where the deployment
/// registered an app with that service, or `credential` handed to
/// `.../accounts`; `sign_in_asks_for` names what signing in asks for
/// besides the account's name, such as `organization` for Azure DevOps. What each integration offers is listed by
/// `.../operations`, and the events that may start a workflow by
/// `.../events`. Read-only. Requires the right to view workflows.
pub(crate) async fn list_integrations(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<IntegrationResponse>>, ApiError> {
    let integrations = workflows
        .list_integrations
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        integrations.iter().map(IntegrationResponse::from).collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/operations",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<OperationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List the operations a workflow may use
///
/// Returns every operation the installed integrations offer, each with its
/// `title` and a `description` of what it does, its inputs with what each
/// means, the `outputs` it gives back at their paths in the step's output
/// (such as `json.number` for the number of an issue GitHub opened),
/// whether it acts through an account, the most sensitive data it may be
/// handed, and the kind of action it takes as the tenant counts it: a risk
/// the tenant raised shows here, never only what the integration declared.
/// An action step's `effect` and `ceiling` are checked against this when
/// its workflow is published; the titles and descriptions only explain.
/// Read-only. Requires the right to view workflows.
pub(crate) async fn list_operations(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<OperationResponse>>, ApiError> {
    let operations = workflows
        .list_operations
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        operations
            .into_iter()
            .map(OperationResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/events",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<EventResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List the service events a workflow may start on
///
/// Returns every event the installed integrations' services send that may
/// start a workflow, each with its `title`, a `description` of when it
/// happens, the `filters` a trigger may set to narrow which of these
/// events start it, and the `outputs` it gives the workflow at their paths
/// in the trigger's output. A `service` trigger names one of these with
/// the account it registers through; publishing registers it at the
/// service. Read-only. Requires the right to view workflows.
pub(crate) async fn list_events(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<EventResponse>>, ApiError> {
    let events = workflows.list_events.execute(&tenant.caller, ()).await?;
    Ok(Json(events.into_iter().map(EventResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/apps",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<AppResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List the apps a workflow may call
///
/// Returns every active route the tenant opened to workflows, in the order
/// the gateway tries them, each with the `id` a Protected apps step names
/// in its `route` input, its `name`, the `path_pattern` a step's `path`
/// must fit, the `methods` it answers and the `hosts` it answers on. Each
/// call is still decided by the route's own policy for the person the run
/// acts for. Read-only. Requires the right to view workflows.
pub(crate) async fn list_apps(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<AppResponse>>, ApiError> {
    let apps = workflows.list_apps.execute(&tenant.caller, ()).await?;
    Ok(Json(apps.into_iter().map(AppResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/data",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<DataResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List the systems a workflow may reach
///
/// Returns every active stream route the tenant opened to workflows, by
/// name, each with the `id` a Protected data step names in its `route`
/// input and its `name`. Each connection is still decided by the stream
/// route's own access for the person the run acts for, and the login kept
/// for it is never shown. Read-only. Requires the right to view workflows.
pub(crate) async fn list_data(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<DataResponse>>, ApiError> {
    let data = workflows.list_data.execute(&tenant.caller, ()).await?;
    Ok(Json(data.into_iter().map(DataResponse::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/operations/{integration}/{operation}/inputs/{input}/choices",
    tag = "Workflows",
    request_body = ListChoicesBody,
    responses(
        (status = 200, description = "Success", body = ChoicesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such picker, or the account is not the caller's to use", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Fill a picker in a step's form
///
/// Lists the options a `picker` or `multi_picker` input offers now, such
/// as the repositories an account can reach or the labels of the chosen
/// one, read live through the integration's own read operation and the
/// account in `account_id`. Only the account's owner, or someone who may
/// manage accounts, fills a picker through it. The read never changes
/// anything at the service: an operation that is not declared as a read is
/// refused before any call. When the service gives no list,
/// `unavailable` says what it said and the builder types the value
/// instead. Requires the right to update workflows.
pub(crate) async fn list_choices(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<OperationInputPath>,
    Json(body): Json<ListChoicesBody>,
) -> Result<Json<ChoicesResponse>, ApiError> {
    let choices = workflows
        .list_choices
        .execute(&tenant.caller, &tenant.auditor, body.request(&path)?)
        .await?;
    Ok(Json(ChoicesResponse::from(choices)))
}
