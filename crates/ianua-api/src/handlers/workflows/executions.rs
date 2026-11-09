//! Workflow execution handlers: starting a workflow by hand or through its
//! webhook, following its executions, stopping one, starting a failed one
//! again, and deciding its approval steps.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::workflows::executions::{DenyStepRequest, ShowApprovalRequest};
use ianua_assembly::workflows::WorkflowState;
use serde_json::Value;

use crate::dto::workflows::executions::{
    ApprovalDataResponse, ApproveStepBody, ExecutionDecidedResponse, ExecutionResponse,
    RunKindParams, StartExecutionBody, StartTestBody, WebhookCallParams, WebhookStartResponse,
    all_execution_listing, execution_listing, pass_listing,
};
use crate::dto::workflows::loop_approvals::{ApproveItemsBody, ItemsPageResponse, items_listing};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::PageQuery;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::workflows::{ApprovalPath, ExecutionPath, WorkflowPath};
use crate::extractors::public_tenant::PublicTenant;
use crate::extractors::query::Query;
use crate::extractors::workflows::WebhookCall;
use crate::response::{Accepted, Created, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/triggers/{trigger_id}",
    tag = "Workflows",
    params(
        WebhookCallParams,
        ("ianua-trigger-secret" = String, Header, description = "The secret issued for the webhook")
    ),
    request_body(content = String, description = "The data the execution starts with: any JSON value", content_type = "application/json"),
    responses(
        (status = 202, description = "Started, or refused for the publisher", body = WebhookStartResponse),
        (status = 401, description = "No such webhook, a wrong or missing secret, or nothing in service", body = ErrorBody),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "The data or the class is not valid", body = ErrorBody)
    )
)]
/// Call a workflow's webhook
///
/// Starts the version in service of the workflow whose webhook secret
/// `trigger_id` names, acting for its publisher, with the request's JSON
/// body as its data and `exposure` (default `internal`) as the most
/// sensitive class in it. The secret travels in the `Ianua-Trigger-Secret`
/// header; it is checked against the digest kept for it, and is never
/// logged or answered. Answers `202` with `status` `started` and the
/// `execution_id`, or `refused` with the `reason` the publisher may not
/// have it start now (also recorded), or `chain_too_long`.
///
/// `401` for every call that is not admitted, alike: an unknown webhook, a
/// wrong or missing secret, no version in service, or one someone other
/// than the secret's issuer published. Needs no session.
pub(crate) async fn call_webhook(
    State(workflows): State<WorkflowState>,
    tenant: PublicTenant,
    WebhookCall {
        path,
        presented,
        params,
    }: WebhookCall,
    Json(input): Json<Value>,
) -> Result<Accepted<WebhookStartResponse>, ApiError> {
    let request = params.start(path.trigger(), presented, &input)?;
    let started = workflows
        .start_on_webhook
        .execute(&tenant.tenant, &tenant.auditor, request)
        .await?;
    Ok(Accepted(WebhookStartResponse::from(started)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions",
    tag = "Workflows",
    params(RunKindParams, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ExecutionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Not a kind of run", body = ErrorBody)
    )
)]
/// List executions across workflows
///
/// Returns one page of the tenant's executions of every designed workflow,
/// newest first, each as the execution endpoint shows it, with data above
/// the caller's clearance withheld. Agent flows are listed as flows. Real
/// runs by default; `kind=tests` lists tests of drafts instead, so a test
/// never shows among real runs. Read-only. Requires the right to view
/// workflows.
pub(crate) async fn list_all_executions(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Query(params): Query<RunKindParams>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ExecutionResponse>>, ApiError> {
    let page = workflows
        .list_all_executions
        .execute(
            &tenant.caller,
            all_execution_listing(params.kind()?, pagination),
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, ExecutionResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/rerun",
    tag = "Workflows",
    responses(
        (status = 201, description = "Started again", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or not the person it acted for", body = ErrorBody),
        (status = 404, description = "No such execution", body = ErrorBody),
        (status = 409, description = "It did not fail, or its version is no longer in service", body = ErrorBody)
    )
)]
/// Re-run a failed execution
///
/// Starts a failed or timed-out execution again from its trigger, every
/// step running again, as a new execution acting for the caller. Answers
/// the new `execution_id` and `status`. Records its start. Only the person
/// the failed run acted for may, with the right to run workflows.
pub(crate) async fn rerun_execution(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ExecutionPath>,
) -> Result<Created<ExecutionDecidedResponse>, ApiError> {
    let execution = workflows
        .rerun_execution
        .execute(&tenant.caller, &tenant.auditor, path.execution())
        .await?;
    Ok(Created(ExecutionDecidedResponse::started(&execution)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/retry",
    tag = "Workflows",
    responses(
        (status = 201, description = "Started again", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or not the person it acted for", body = ErrorBody),
        (status = 404, description = "No such execution", body = ErrorBody),
        (status = 409, description = "It did not fail, or its version is no longer in service", body = ErrorBody)
    )
)]
/// Retry a failed execution from its failed steps
///
/// Starts a failed or timed-out execution again from the steps that did
/// not finish, keeping what the finished ones produced, as a new execution
/// acting for the caller. Answers the new `execution_id` and `status`.
/// Records its start. Only the person the failed run acted for may, with
/// the right to run workflows.
pub(crate) async fn retry_execution(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ExecutionPath>,
) -> Result<Created<ExecutionDecidedResponse>, ApiError> {
    let execution = workflows
        .retry_execution
        .execute(&tenant.caller, &tenant.auditor, path.execution())
        .await?;
    Ok(Created(ExecutionDecidedResponse::started(&execution)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/executions",
    tag = "Workflows",
    request_body = StartExecutionBody,
    responses(
        (status = 201, description = "Started", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No version of the workflow is published", body = ErrorBody),
        (status = 422, description = "Validation error, or the workflow does not start by hand", body = ErrorBody)
    )
)]
/// Start a workflow
///
/// Starts the published version of a workflow that starts by hand, acting
/// for the caller, with `input` as its data and `exposure` the most
/// sensitive class in it, such as `internal`. Answers the new execution's
/// `execution_id` and `status`; read it through the execution endpoint.
/// `404` when no version is published. Records
/// `workflows.execution_started`. Requires the right to run workflows.
pub(crate) async fn start_execution(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    Json(body): Json<StartExecutionBody>,
) -> Result<Created<ExecutionDecidedResponse>, ApiError> {
    let execution = workflows
        .start_by_hand
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.workflow())?,
        )
        .await?;
    Ok(Created(ExecutionDecidedResponse::started(&execution)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/tests",
    tag = "Workflows",
    request_body = StartTestBody,
    responses(
        (status = 201, description = "Started", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 409, description = "Its latest version is archived", body = ErrorBody),
        (status = 422, description = "Validation error, or a step reads one that cannot come before it", body = ErrorBody)
    )
)]
/// Test a workflow
///
/// Runs the workflow's latest version, its draft or the one in service, on
/// `input` as example data, acting for the caller. Nothing outside changes:
/// every step that writes, sends, deletes or is undeclared, every agent
/// run, approval and wait, and code that may reach the network answers at
/// once with a stand-in whose output says `stood_in` and what it
/// `would_use`. Reads, conditions, transforms and code with no network run
/// for real. A test is listed apart from real runs (`kind=tests`), may not
/// be started again, and tells nobody when it fails. Records
/// `workflows.execution_started` with mode `test`. Requires the rights to
/// update and to run workflows.
pub(crate) async fn start_test(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    Json(body): Json<StartTestBody>,
) -> Result<Created<ExecutionDecidedResponse>, ApiError> {
    let execution = workflows
        .start_test
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.workflow())?,
        )
        .await?;
    Ok(Created(ExecutionDecidedResponse::started(&execution)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/executions",
    tag = "Workflows",
    params(RunKindParams, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ExecutionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Not a kind of run", body = ErrorBody)
    )
)]
/// List a workflow's executions
///
/// Returns the executions of every version of the workflow, newest first,
/// paginated. Each shows where it and its steps stand; data above the
/// caller's clearance is withheld, and a withheld step shows only its
/// `phase` and `exposure`. Real runs by default; `kind=tests` lists its
/// tests instead. Requires the right to view workflows.
pub(crate) async fn list_executions(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    PageQuery {
        query: params,
        page: pagination,
    }: PageQuery<RunKindParams>,
) -> Result<Json<PageResponse<ExecutionResponse>>, ApiError> {
    let page = workflows
        .list_executions
        .execute(
            &tenant.caller,
            execution_listing(path.workflow(), params.kind()?, pagination),
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, ExecutionResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/passes",
    tag = "Workflows",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ExecutionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List an execution's passes
///
/// Returns the passes the execution's loop steps started, newest first,
/// paginated. Each pass is an execution of the loop's own steps for one
/// item, and its `pass` names the loop step and the item. Data above the
/// caller's clearance is withheld. An execution without loops has none.
/// Requires the right to view workflows.
pub(crate) async fn list_passes(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ExecutionPath>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ExecutionResponse>>, ApiError> {
    let page = workflows
        .list_passes
        .execute(&tenant.caller, pass_listing(path.execution(), pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, ExecutionResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = ExecutionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such execution", body = ErrorBody)
    )
)]
/// Get an execution
///
/// Returns one execution: its `status`, the data it started with and where
/// each step stands. Data above the caller's clearance is withheld.
/// Requires the right to view workflows.
pub(crate) async fn get_execution(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ExecutionPath>,
) -> Result<Json<ExecutionResponse>, ApiError> {
    let execution = workflows
        .get_execution
        .execute(&tenant.caller, path.execution())
        .await?;
    Ok(Json(ExecutionResponse::from(execution)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/cancel",
    tag = "Workflows",
    responses(
        (status = 200, description = "Stopped", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such execution", body = ErrorBody),
        (status = 409, description = "It ran out of time", body = ErrorBody),
        (status = 422, description = "It already ended", body = ErrorBody)
    )
)]
/// Cancel an execution
///
/// Stops a running execution and the agent runs it started. Answers only
/// its `execution_id` and `status`. `409` when it ran out of time, which
/// leaves it timed out; `422` when it already ended. Records
/// `workflows.execution_ended`. Requires being the person it acts for, or
/// full control of workflows.
pub(crate) async fn cancel_execution(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ExecutionPath>,
) -> Result<Json<ExecutionDecidedResponse>, ApiError> {
    let decided = workflows
        .cancel_execution
        .execute(&tenant.caller, &tenant.auditor, path.execution())
        .await?;
    Ok(Json(ExecutionDecidedResponse::from(decided)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/approvals/{step}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = ApprovalDataResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such execution or step", body = ErrorBody),
        (status = 409, description = "The execution ran out of time", body = ErrorBody),
        (status = 422, description = "The step is not waiting for approval", body = ErrorBody)
    )
)]
/// Show an approval
///
/// Returns the data an approval step lets through, as `shown`, for the
/// caller to decide on. Approving counts only for exactly this data, so it
/// is sent back as it came. `422` when the step is not waiting for
/// approval. Requires the right to approve workflow steps and clearance
/// for the data.
pub(crate) async fn show_approval(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ApprovalPath>,
) -> Result<Json<ApprovalDataResponse>, ApiError> {
    let request = ShowApprovalRequest {
        execution_id: path.execution(),
        step: path.step()?,
    };
    let shown = workflows
        .show_approval
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(ApprovalDataResponse::from(shown)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/approvals/{step}/approve",
    tag = "Workflows",
    request_body = ApproveStepBody,
    responses(
        (status = 200, description = "Approved", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a second factor is needed", body = ErrorBody),
        (status = 404, description = "No such execution or step", body = ErrorBody),
        (status = 409, description = "The data is not what the step lets through, or the execution ran out of time", body = ErrorBody),
        (status = 422, description = "The step is not waiting for approval, or its window closed", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Approve a step
///
/// Approves an approval step for exactly the data the caller was shown,
/// sent back as `shown`. A step before a high-risk action needs two
/// different people, each with a fresh second-factor `mfa_code`; the first
/// approval is recorded and the step keeps waiting. Neither the person the
/// execution acts for nor an author of a high-risk step may approve.
/// Answers only the execution's `execution_id` and `status`. Records
/// `workflows.approval_granted`. Requires the right to approve workflow
/// steps and clearance for the data.
pub(crate) async fn approve_step(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ApprovalPath>,
    Json(body): Json<ApproveStepBody>,
) -> Result<Json<ExecutionDecidedResponse>, ApiError> {
    let request = body.request(path.execution(), path.step()?)?;
    let decided = workflows
        .approve_step
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(ExecutionDecidedResponse::from(decided)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/approvals/{step}/items",
    tag = "Workflows",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = ItemsPageResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such execution or step", body = ErrorBody),
        (status = 409, description = "The execution ran out of time", body = ErrorBody),
        (status = 422, description = "The loop is not waiting for an approval of its items", body = ErrorBody)
    )
)]
/// List the items a loop asks to approve
///
/// Returns one page of the items a loop will act on, in the order its
/// passes take them, for a loop whose first step asks one approval for
/// every item. The items were fixed when the approval opened. Each page
/// served is kept as opened by the caller, and `shown` says how many of the
/// `total` items they have been shown so far. Requires the right to approve
/// workflow steps and clearance for the data.
pub(crate) async fn list_approval_items(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ApprovalPath>,
    Paging(pagination): Paging,
) -> Result<Json<ItemsPageResponse>, ApiError> {
    let request = items_listing(path.execution(), path.step()?, pagination);
    let page = workflows
        .show_items
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(ItemsPageResponse::from(page)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/approvals/{step}/items/approve",
    tag = "Workflows",
    request_body = ApproveItemsBody,
    responses(
        (status = 200, description = "Approved", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a second factor is needed", body = ErrorBody),
        (status = 404, description = "No such execution, or the loop asks nobody", body = ErrorBody),
        (status = 409, description = "Not every page was opened, the list changed, or the execution ran out of time", body = ErrorBody),
        (status = 422, description = "The window closed", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Approve every item of a loop
///
/// Approves every item a loop will act on. The yes counts only once every
/// item was on a page the caller opened through the items endpoint; before
/// that it is refused. A loop before a high-risk action needs two different
/// people, each with a fresh second-factor `mfa_code`; the first approval
/// is recorded and the loop keeps waiting. The approval that completes it
/// starts the passes. Records `workflows.approval_granted` with how many
/// items were shown and when the last was. Deny it through the step's
/// `deny` endpoint. Requires the right to approve workflow steps and
/// clearance for the data.
pub(crate) async fn approve_items(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ApprovalPath>,
    Json(body): Json<ApproveItemsBody>,
) -> Result<Json<ExecutionDecidedResponse>, ApiError> {
    let request = body.request(path.execution(), path.step()?);
    let decided = workflows
        .approve_items
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(ExecutionDecidedResponse::from(decided)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/executions/{execution_id}/approvals/{step}/deny",
    tag = "Workflows",
    responses(
        (status = 200, description = "Denied", body = ExecutionDecidedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such execution or step", body = ErrorBody),
        (status = 409, description = "The execution ran out of time", body = ErrorBody),
        (status = 422, description = "The step is not waiting for approval", body = ErrorBody)
    )
)]
/// Deny a step
///
/// Refuses an approval step, which fails the execution, or a loop's
/// approval of every item, which fails the loop before any pass runs.
/// Answers only its
/// `execution_id` and `status`. Records the step's failure and the
/// execution's end. Requires the right to approve workflow steps and
/// clearance for the data the step shows.
pub(crate) async fn deny_step(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ApprovalPath>,
) -> Result<Json<ExecutionDecidedResponse>, ApiError> {
    let request = DenyStepRequest {
        execution_id: path.execution(),
        step: path.step()?,
    };
    let decided = workflows
        .deny_step
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(ExecutionDecidedResponse::from(decided)))
}
