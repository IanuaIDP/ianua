//! Evaluation handlers: saving and reading a workflow's sample cases,
//! starting an evaluation of its draft, and reading evaluations back.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::evaluations::{
    EvaluationResponse, EvaluationSetResponse, SaveEvaluationSetBody, evaluation_listing,
    evaluation_reading, evaluation_set_reading, evaluation_start,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::{WorkflowEvaluationPath, WorkflowPath};
use crate::response::Accepted;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/evaluation-set",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = EvaluationSetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No sample cases were saved for the workflow", body = ErrorBody)
    )
)]
/// Get a workflow's sample cases
///
/// Returns the cases its versions are evaluated against and whether
/// publishing waits on an evaluation. A case whose input is above the
/// caller's clearance shows only its `name` and `exposure`. Requires the
/// right to view workflows.
pub(crate) async fn get_evaluation_set(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Json<EvaluationSetResponse>, ApiError> {
    let set = workflows
        .evaluations
        .get_set
        .execute(&tenant.caller, evaluation_set_reading(path.workflow()))
        .await?;
    Ok(Json(EvaluationSetResponse::from(set)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/evaluation-set",
    tag = "Workflows",
    request_body = SaveEvaluationSetBody,
    responses(
        (status = 200, description = "Saved", body = EvaluationSetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 422, description = "Validation error: more than 50 cases, two of one name, too much data, a check that is not valid, or `must_pass` with no case", body = ErrorBody)
    )
)]
/// Save a workflow's sample cases
///
/// Replaces the cases its versions are evaluated against: each an input,
/// how sensitive it is, and up to ten checks of the results. A check reads
/// a path the way a step reads its input, such as `summarise.answer`, and
/// expects the value there to equal a value, contain a text, or match a
/// short pattern. `publish_gate` `must_pass` holds publishing back until
/// the draft's last evaluation passed every case; it is `off` unless set.
/// Records `workflows.evaluation_set_saved`. Requires the right to change
/// workflows.
pub(crate) async fn save_evaluation_set(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    Json(body): Json<SaveEvaluationSetBody>,
) -> Result<Json<EvaluationSetResponse>, ApiError> {
    let set = workflows
        .evaluations
        .save_set
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.workflow())?,
        )
        .await?;
    Ok(Json(EvaluationSetResponse::from(set)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/evaluations",
    tag = "Workflows",
    responses(
        (status = 202, description = "Started; a worker runs its cases", body = EvaluationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's evaluations running at once are reached", body = ErrorBody),
        (status = 404, description = "No such workflow, or no sample cases were saved for it", body = ErrorBody),
        (status = 409, description = "The latest version is archived", body = ErrorBody),
        (status = 422, description = "The workflow has no sample case", body = ErrorBody)
    )
)]
/// Evaluate a workflow
///
/// Tries the workflow's latest version, its draft before it is published,
/// against every saved case. Each case runs as a test run, so nothing
/// outside changes, at most five at a time. It answers at once with
/// `status` `running`; read the evaluation for each case's `outcome`:
/// `passed`, `failed` with what differed, or `not_run` with why. It ends
/// within an hour, `passed` only when every case passed. Records
/// `workflows.evaluation_started` and, at the end,
/// `workflows.evaluation_ended`. Requires the rights to change and run
/// workflows.
pub(crate) async fn start_evaluation(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Accepted<EvaluationResponse>, ApiError> {
    let evaluation = workflows
        .evaluations
        .start
        .execute(
            &tenant.caller,
            &tenant.auditor,
            evaluation_start(path.workflow()),
        )
        .await?;
    Ok(Accepted(EvaluationResponse::from(evaluation)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/evaluations",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<EvaluationResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List a workflow's evaluations
///
/// Returns its latest 20 evaluations, newest first; the first is the one
/// a publishing gate reads. What is above the caller's clearance is
/// withheld. Requires the right to view workflows.
pub(crate) async fn list_evaluations(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Json<Vec<EvaluationResponse>>, ApiError> {
    let evaluations = workflows
        .evaluations
        .list
        .execute(&tenant.caller, evaluation_listing(path.workflow()))
        .await?;
    Ok(Json(
        evaluations
            .into_iter()
            .map(EvaluationResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/evaluations/{evaluation_id}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = EvaluationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such evaluation of the workflow, or it was cleared", body = ErrorBody)
    )
)]
/// Get an evaluation
///
/// Returns what each case came to so far. A failed case whose run held
/// data above the caller's clearance shows that it failed and its run, but
/// not what differed. Ended evaluations are kept for 30 days. Requires the
/// right to view workflows.
pub(crate) async fn get_evaluation(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowEvaluationPath>,
) -> Result<Json<EvaluationResponse>, ApiError> {
    let evaluation = workflows
        .evaluations
        .get
        .execute(
            &tenant.caller,
            evaluation_reading(path.workflow(), path.evaluation()),
        )
        .await?;
    Ok(Json(EvaluationResponse::from(evaluation)))
}
