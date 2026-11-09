//! Workflow definition handlers: drafting, editing, publishing and
//! archiving the versions of a workflow.

use axum::extract::{Path, State};
use ianua_app::ports::workflows::WorkflowSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::workflows::definitions::{
    ArchiveWorkflowRequest, GetWorkflowRequest, StepDataRequest, WhichVersion,
};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::builder::{DraftBody, ProposalResponse, StepDataResponse};
use crate::dto::workflows::definitions::{
    CreateWorkflowBody, EditDraftBody, PublishWorkflowBody, WorkflowResponse, workflow_listing,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::workflows::{WorkflowPath, WorkflowVersionPath};
use crate::extractors::sort::SortQuery;
use crate::response::{Created, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows",
    tag = "Workflows",
    params(SortQuery<WorkflowSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<WorkflowResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List workflows
///
/// Returns the latest version of each of the tenant's workflows, sortable
/// and paginated. Each carries its `graph`, `trigger`, `status` (`draft`,
/// `published` or `archived`) and the `revision` a publisher hands back.
/// Requires the right to view workflows.
pub(crate) async fn list_workflows(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<WorkflowSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<WorkflowResponse>>, ApiError> {
    let page = workflows
        .list_workflows
        .execute(&tenant.caller, workflow_listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, WorkflowResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows",
    tag = "Workflows",
    request_body = CreateWorkflowBody,
    responses(
        (status = 201, description = "Drafted", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's workflow limit is reached", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a workflow
///
/// Drafts version 1 of a new workflow with a `name`, its `graph` of steps
/// and edges, the `trigger` that starts it and `run_limit_seconds`, how long
/// one execution may run (at most 31 days). Each step is named by `kind`:
/// `agent_run`, `action`, `condition`, `transform`, `approval` or `wait`.
/// An action step's `effect` and `ceiling` are checked against the
/// integration catalog when the workflow is published. Records
/// `workflows.workflow_created`. Requires the right to create workflows,
/// within the plan's workflow limit.
pub(crate) async fn create_workflow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<CreateWorkflowBody>,
) -> Result<Created<WorkflowResponse>, ApiError> {
    let workflow = workflows
        .create_workflow
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody)
    )
)]
/// Get a workflow
///
/// Returns the workflow's latest version, draft or not. Requires the right
/// to view workflows.
pub(crate) async fn get_workflow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Json<WorkflowResponse>, ApiError> {
    let request = GetWorkflowRequest {
        workflow_id: path.workflow(),
        version: WhichVersion::Latest,
    };
    let workflow = workflows
        .get_workflow
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/versions/{version}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow or version", body = ErrorBody)
    )
)]
/// Get a workflow version
///
/// Returns one version of the workflow by its number. Requires the right
/// to view workflows.
pub(crate) async fn get_workflow_version(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowVersionPath>,
) -> Result<Json<WorkflowResponse>, ApiError> {
    let request = GetWorkflowRequest {
        workflow_id: path.workflow(),
        version: WhichVersion::Number(path.version()),
    };
    let workflow = workflows
        .get_workflow
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/draft",
    tag = "Workflows",
    request_body = EditDraftBody,
    responses(
        (status = 200, description = "Edited", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 409, description = "The latest version is not a draft", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Edit a workflow's draft
///
/// Makes one change to the workflow's latest version, which must be a
/// draft, named by `edit`: `rename` (with `name`), `replace_steps` (with
/// `graph`), `change_trigger` (with `trigger`), `change_run_limit` (with
/// `run_limit_seconds`), `describe` (with `description`),
/// `change_failure_alert` (with `failure_alert`) or `arrange` (with
/// `layout`). Answers the draft as saved, with its new `revision`; moving
/// steps with `arrange` keeps the revision and records nothing. `409` when
/// the latest version is not a draft. Records `workflows.draft_renamed`,
/// `workflows.draft_steps_replaced`, `workflows.draft_trigger_changed`,
/// `workflows.draft_run_limit_changed`, `workflows.draft_described` or
/// `workflows.draft_failure_alert_changed`. Requires the right to update
/// workflows.
pub(crate) async fn edit_draft(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    Json(body): Json<EditDraftBody>,
) -> Result<Json<WorkflowResponse>, ApiError> {
    let workflow = workflows
        .edit_draft
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.workflow())?,
        )
        .await?;
    Ok(Json(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/draft",
    tag = "Workflows",
    responses(
        (status = 201, description = "Drafted", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 409, description = "The latest version is still a draft", body = ErrorBody)
    )
)]
/// Draft the next version
///
/// Drafts the version after the workflow's latest one, starting as a copy
/// of it. `409` when the latest version is still a draft. Records
/// `workflows.version_drafted`. Requires the right to create workflows.
pub(crate) async fn next_draft(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Created<WorkflowResponse>, ApiError> {
    let workflow = workflows
        .next_draft
        .execute(&tenant.caller, &tenant.auditor, path.workflow())
        .await?;
    Ok(Created(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/publish",
    tag = "Workflows",
    request_body = PublishWorkflowBody,
    responses(
        (status = 200, description = "Published", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 409, description = "The draft changed since it was reviewed, or another version was published", body = ErrorBody),
        (status = 422, description = "No draft, or an action no longer offered or fitting, or a high-risk action without an approval before it", body = ErrorBody)
    )
)]
/// Publish a workflow's draft
///
/// Publishes the draft as the version in service, archiving the one it
/// replaces. `revision` is the draft's revision as the publisher reviewed
/// it; `409` when the draft changed since. Every action step is checked
/// against what the integration catalog offers now, as the tenant's raised
/// risks treat it, and a high-risk action needs an approval step right
/// before it. Records `workflows.version_published`, and
/// `workflows.version_archived` for the version replaced. Requires the
/// right to update workflows, and to see the event it starts on.
pub(crate) async fn publish_workflow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    Json(body): Json<PublishWorkflowBody>,
) -> Result<Json<WorkflowResponse>, ApiError> {
    let workflow = workflows
        .publish_workflow
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.workflow()),
        )
        .await?;
    Ok(Json(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/versions/{version}/archive",
    tag = "Workflows",
    responses(
        (status = 200, description = "Archived", body = WorkflowResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such version", body = ErrorBody),
        (status = 422, description = "Already archived", body = ErrorBody)
    )
)]
/// Archive a workflow version
///
/// Archives one version for good: a published one stops starting. `422`
/// when it is already archived. Records `workflows.version_archived`.
/// Requires the right to delete workflows.
pub(crate) async fn archive_workflow(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowVersionPath>,
) -> Result<Json<WorkflowResponse>, ApiError> {
    let request = ArchiveWorkflowRequest {
        workflow_id: path.workflow(),
        version: path.version(),
    };
    let workflow = workflows
        .archive_workflow
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(WorkflowResponse::from(workflow)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/step-data",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<StepDataResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody)
    )
)]
/// Read what each step may read
///
/// Returns, for each step of the workflow's latest version, what it may
/// read: the trigger's data first, then each step that can come before it,
/// with every value at the full path a step's input names, such as
/// `trigger.issue.title`. A value marked `whole` is everything at its path,
/// whose shape only a run shows. Requires the right to view workflows.
pub(crate) async fn step_data(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Json<Vec<StepDataResponse>>, ApiError> {
    let request = StepDataRequest {
        workflow_id: path.workflow(),
        version: WhichVersion::Latest,
    };
    let steps = workflows.step_data.execute(&tenant.caller, request).await?;
    Ok(Json(
        steps.into_iter().map(StepDataResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/suggestions",
    tag = "Workflows",
    request_body = DraftBody,
    responses(
        (status = 200, description = "Proposed", body = ProposalResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such provider or workflow", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 502, description = "The model gave no answer to use", body = ErrorBody)
    )
)]
/// Suggest steps from words
///
/// Gives the person's `words` to the tenant's model provider and answers
/// the steps it proposes: a whole new workflow, or with `after` the steps
/// that follow one step of a draft. Every step is checked against what the
/// integrations offer now; one that fits nothing is left out with a note.
/// Nothing is saved or recorded: the builder places what it keeps and saves
/// it as a draft. Requires the right to update workflows.
pub(crate) async fn suggest_steps(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<DraftBody>,
) -> Result<Json<ProposalResponse>, ApiError> {
    let proposal = workflows
        .draft_steps
        .execute(&tenant.caller, body.try_into()?)
        .await?;
    Ok(Json(ProposalResponse::from(proposal)))
}
