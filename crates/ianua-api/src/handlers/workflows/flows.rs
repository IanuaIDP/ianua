//! Agent flow handlers: stages of agent runs a person makes and starts at
//! once, read back with where each run stands, stopped and deleted.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::workflows::flows::CreateRequest;
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::flows::{CreateFlowBody, FlowResponse, started_flow};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::workflows::FlowPath;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/flows",
    tag = "Workflows",
    request_body = CreateFlowBody,
    responses(
        (status = 201, description = "Made and started", body = FlowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's workflow limit is reached", body = ErrorBody),
        (status = 422, description = "The stages do not make a flow", body = ErrorBody)
    )
)]
/// Make and start an agent flow
///
/// Lays out `stages` of agent runs (the runs of each stage start together,
/// once every run of the stage before has answered, and are handed those
/// answers) and starts the flow at once, acting for the caller, with
/// `input` (an empty object when left out) of `exposure` (default
/// `internal`). Each run names its agent, model provider, goal, purpose,
/// tools, approval classes and step cap (`max_steps`, 10 when left out).
/// Answers the flow with every run pending. Records
/// `workflows.flow_created` and the run's start. A flow counts against the
/// plan's workflows, and making one needs the rights to create and to run
/// workflows.
///
/// `422` for a stage without runs, a run an agent step does not allow, or
/// too many steps.
pub(crate) async fn create_flow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<CreateFlowBody>,
) -> Result<Created<FlowResponse>, ApiError> {
    let request = CreateRequest::try_from(body)?;
    let started = workflows
        .create_flow
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(started_flow(&started)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/flows",
    tag = "Workflows",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<FlowResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List agent flows
///
/// Returns one page of the tenant's agent flows, newest first, each with
/// where it stands, as reading the flow shows it: its `status`, the first
/// stage with a run still going (`current_stage`, from 0), and each run's
/// `status`, agent run, answer and error. Data above the caller's
/// clearance is withheld. A flow whose run was never kept is listed as laid
/// out, without `status` or `current_stage`. Read-only. Requires the right
/// to view workflows.
pub(crate) async fn list_flows(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<FlowResponse>>, ApiError> {
    let page = workflows
        .list_flows
        .execute(&tenant.caller, pagination)
        .await?;
    Ok(Json(PageResponse::from_page(page, FlowResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/flows/{flow_id}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = FlowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such flow", body = ErrorBody)
    )
)]
/// Get an agent flow
///
/// Returns one flow and where it stands: its `status` (`Running`,
/// `Completed`, `Failed` or `Canceled`; a run that ran out of time failed),
/// the first stage with a run still going (`current_stage`, from 0), and
/// each run's `status` (`Pending`, `Dispatched`, `Completed` or `Failed`),
/// agent run, answer and error. Data above the caller's clearance is
/// withheld: a withheld run shows only its status and how sensitive its
/// data is. Read-only. Requires the right to view workflows.
pub(crate) async fn get_flow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<FlowPath>,
) -> Result<Json<FlowResponse>, ApiError> {
    let progress = workflows
        .get_flow
        .execute(&tenant.caller, path.flow())
        .await?;
    Ok(Json(FlowResponse::from(progress)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/flows/{flow_id}/cancel",
    tag = "Workflows",
    responses(
        (status = 200, description = "Stopped", body = FlowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such flow", body = ErrorBody),
        (status = 409, description = "It ran out of time", body = ErrorBody),
        (status = 422, description = "It already ended", body = ErrorBody)
    )
)]
/// Cancel an agent flow
///
/// Stops the flow's run and every agent run it leaves going, and answers
/// the flow as reading it would, its `status` now `Canceled`. A maker who
/// may not view workflows is answered the flow as laid out with its
/// `status` alone. `409` when it ran out of time, which leaves it timed
/// out; `422` when it already ended. Records the run's end. Its maker may
/// always stop it; anyone else needs full control of workflows.
pub(crate) async fn cancel_flow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<FlowPath>,
) -> Result<Json<FlowResponse>, ApiError> {
    let stopped = workflows
        .cancel_flow
        .execute(&tenant.caller, &tenant.auditor, path.flow())
        .await?;
    Ok(Json(FlowResponse::from(stopped)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/flows/{flow_id}",
    tag = "Workflows",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such flow", body = ErrorBody),
        (status = 409, description = "Its run is still going", body = ErrorBody)
    )
)]
/// Delete an agent flow
///
/// Deletes a flow whose run has ended, with that run (`409` while it is
/// still going). Records `workflows.flow_deleted`. Its maker may always
/// delete it; anyone else needs the right to delete workflows.
pub(crate) async fn delete_flow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<FlowPath>,
) -> Result<NoContent, ApiError> {
    workflows
        .delete_flow
        .execute(&tenant.caller, &tenant.auditor, path.flow())
        .await?;
    Ok(NoContent)
}
