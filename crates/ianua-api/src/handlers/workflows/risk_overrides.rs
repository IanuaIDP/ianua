//! Raised operation risk handlers: the operations the tenant treats as
//! riskier than their integration declares.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::catalog::risk_overrides::{ChangeRiskBody, RaiseRiskBody, RiskResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::RiskPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/risks",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<RiskResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List raised risks
///
/// Returns every operation the tenant raised, oldest first: its
/// `integration`, `operation` and the `effect` it counts as. Requires the
/// right to view workflows.
pub(crate) async fn list_risks(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<RiskResponse>>, ApiError> {
    let risks = workflows.list_risks.execute(&tenant.caller, ()).await?;
    Ok(Json(risks.into_iter().map(RiskResponse::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/risks",
    tag = "Workflows",
    request_body = RaiseRiskBody,
    responses(
        (status = 201, description = "Raised", body = RiskResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "The operation is raised already", body = ErrorBody),
        (status = 422, description = "Validation error, or the effect raises nothing", body = ErrorBody)
    )
)]
/// Raise an operation's risk
///
/// Makes the tenant treat one `operation` of an `integration` as `effect`:
/// `undeclared` or a high-risk action class. From then on a workflow
/// calling it needs an approval step right before it. `409` when it is
/// raised already; change that one instead. `422` when the effect raises
/// nothing. Records `workflows.operation_risk_raised`. Requires the right
/// to change workflows.
pub(crate) async fn raise_risk(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<RaiseRiskBody>,
) -> Result<Created<RiskResponse>, ApiError> {
    let risk = workflows
        .raise_risk
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(RiskResponse::from(risk)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/risks/{risk_id}",
    tag = "Workflows",
    request_body = ChangeRiskBody,
    responses(
        (status = 200, description = "Changed", body = RiskResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such raised risk", body = ErrorBody),
        (status = 422, description = "Validation error, or the effect raises nothing", body = ErrorBody)
    )
)]
/// Change a raised risk
///
/// Sets what a raised operation counts as: `undeclared` or a high-risk
/// action class. `422` when the effect raises nothing. Records
/// `workflows.operation_risk_raised`. Requires the right to change
/// workflows.
pub(crate) async fn change_risk(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<RiskPath>,
    Json(body): Json<ChangeRiskBody>,
) -> Result<Json<RiskResponse>, ApiError> {
    let risk = workflows
        .change_risk
        .execute(&tenant.caller, &tenant.auditor, body.request(path.risk())?)
        .await?;
    Ok(Json(RiskResponse::from(risk)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/risks/{risk_id}",
    tag = "Workflows",
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such raised risk", body = ErrorBody)
    )
)]
/// Remove a raised risk
///
/// Lets the operation count as its integration declares again. Records
/// `workflows.operation_risk_override_removed`. Requires full control of
/// workflows.
pub(crate) async fn remove_risk(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<RiskPath>,
) -> Result<NoContent, ApiError> {
    workflows
        .remove_risk
        .execute(&tenant.caller, &tenant.auditor, path.risk())
        .await?;
    Ok(NoContent)
}
