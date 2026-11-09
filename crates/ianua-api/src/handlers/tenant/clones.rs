//! Clone handlers: copying one tenant's setup into another tenant of the
//! same organization, and following the copy.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::tenant::TenantState;

use crate::dto::tenant::clones::{CloneStartedResponse, StartCloneBody, TenantCloneResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::paths::tenant::ClonePath;
use crate::extractors::tenant::Steward;
use crate::response::Accepted;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenant-clones",
    tag = "Tenants",
    request_body = StartCloneBody,
    responses(
        (status = 202, description = "Copying started", body = CloneStartedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "A tenant not found", body = ErrorBody),
        (status = 409, description = "Source closed, target unfillable or already being filled", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Copy a tenant's setup into another
///
/// Starts copying the named `parts` of one tenant's setup into another
/// tenant of the same organization, such as production's settings, roles
/// and routes into a fresh staging tenant. Users, sessions, signing keys
/// and secrets are never copied, and OAuth applications arrive without
/// their secrets. The copy runs in the background, part by part; follow it
/// with the id this answers.
///
/// Source and target the same tenant, no parts or a part named twice are
/// `422`. A closed source, a target that cannot be filled, or a target
/// another clone still fills is `409`. Records `tenant.clone_started` under
/// the target.
///
/// Requires a member who may make tenants in the organization, or an
/// operator.
pub(crate) async fn start_clone(
    State(tenant): State<TenantState>,
    steward: Steward,
    Json(body): Json<StartCloneBody>,
) -> Result<Accepted<CloneStartedResponse>, ApiError> {
    let id = tenant
        .clones
        .start
        .execute(&steward.caller, &steward.auditor, body.try_into()?)
        .await?;
    Ok(Accepted(CloneStartedResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenant-clones/{clone_id}",
    tag = "Tenants",
    responses(
        (status = 200, description = "The clone", body = TenantCloneResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Follow a copy of a tenant's setup
///
/// How far a clone has come: the parts it copies, those copied so far,
/// and whether it is `copying`, `completed` or `failed` (with why). A
/// member reads only clones into their own organization's tenants; any
/// other is `404`. Read-only.
///
/// Requires a member of the organization, or an operator.
pub(crate) async fn get_clone(
    State(tenant): State<TenantState>,
    steward: Steward,
    Path(path): Path<ClonePath>,
) -> Result<Json<TenantCloneResponse>, ApiError> {
    let clone = tenant
        .clones
        .get
        .execute(&steward.caller, path.clone_id())
        .await?;
    Ok(Json(TenantCloneResponse::from(&clone)))
}
