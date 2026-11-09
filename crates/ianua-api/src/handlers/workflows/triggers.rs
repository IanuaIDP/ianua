//! Webhook secret handlers: issuing, rotating and revoking the secret a
//! workflow's webhook is called with.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::triggers::TriggerSecretResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::WorkflowPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/trigger-secret",
    tag = "Workflows",
    responses(
        (status = 201, description = "Issued", body = TriggerSecretResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 409, description = "Its webhook already has a secret", body = ErrorBody),
        (status = 422, description = "The workflow does not start on its webhook", body = ErrorBody)
    )
)]
/// Issue a workflow's webhook secret
///
/// Makes the secret the workflow's webhook is called with, for a workflow
/// whose trigger is its webhook. Answers the `trigger_id` the webhook's
/// address names (`POST .../workflows/triggers/{trigger_id}`) and the
/// `secret`, shown this once, which the caller sends in the
/// `Ianua-Trigger-Secret` header; only its digest is kept. A webhook that
/// already has a secret is rotated or revoked instead (`409`). Records
/// `workflows.trigger_secret_issued`. Requires the right to edit
/// workflows.
pub(crate) async fn issue_trigger_secret(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Created<TriggerSecretResponse>, ApiError> {
    let issued = workflows
        .issue_trigger_secret
        .execute(&tenant.caller, &tenant.auditor, path.workflow())
        .await?;
    Ok(Created(TriggerSecretResponse::from(issued)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/trigger-secret/rotate",
    tag = "Workflows",
    responses(
        (status = 200, description = "Rotated", body = TriggerSecretResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow, or its webhook has no secret", body = ErrorBody)
    )
)]
/// Rotate a workflow's webhook secret
///
/// Replaces the webhook's secret; the old one stops working at once.
/// Answers the new `trigger_id` and `secret`, shown this once. Records
/// `workflows.trigger_secret_rotated`. Requires the right to edit
/// workflows.
pub(crate) async fn rotate_trigger_secret(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<Json<TriggerSecretResponse>, ApiError> {
    let issued = workflows
        .rotate_trigger_secret
        .execute(&tenant.caller, &tenant.auditor, path.workflow())
        .await?;
    Ok(Json(TriggerSecretResponse::from(issued)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/{workflow_id}/trigger-secret",
    tag = "Workflows",
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow, or its webhook has no secret", body = ErrorBody)
    )
)]
/// Revoke a workflow's webhook secret
///
/// Deletes the webhook's secret, so no call starts the workflow until a
/// new one is issued. Records `workflows.trigger_secret_revoked`. Requires
/// the right to edit workflows.
pub(crate) async fn revoke_trigger_secret(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
) -> Result<NoContent, ApiError> {
    workflows
        .revoke_trigger_secret
        .execute(&tenant.caller, &tenant.auditor, path.workflow())
        .await?;
    Ok(NoContent)
}
