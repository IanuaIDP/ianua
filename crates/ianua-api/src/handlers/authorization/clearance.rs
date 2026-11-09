//! Clearance handlers: the rules that clear a tenant's people for
//! confidential or restricted data by an app permission they hold, read
//! and edited one rule at a time.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::clearance::{
    AddClearanceRuleBody, ChangeClearanceRuleBody, ClearanceRulesResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::authorization::ClearanceRulePath;
use crate::response::Created;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/clearance-rules",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = ClearanceRulesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the clearance rules
///
/// The tenant's rules clearing holders of an app permission for
/// confidential or restricted data; none when nobody wrote one.
///
/// Requires the right to view classification rules.
pub(crate) async fn get_clearance_rules(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<ClearanceRulesResponse>, ApiError> {
    let rules = authorization
        .clearance
        .get_rules
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(ClearanceRulesResponse::from(&rules)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/clearance-rules",
    tag = "Authorization",
    request_body = AddClearanceRuleBody,
    responses(
        (status = 201, description = "The rules with the new one", body = ClearanceRulesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "A rule already names the permission", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Add a clearance rule
///
/// From now on, holding `permission` clears for data up to `up_to`. Only
/// `Confidential` and `Restricted` are cleared by a rule (`422` for a
/// lower level), and nobody clears others above their own clearance
/// (`403`). Records `authorization.clearance_rule_added`.
///
/// Requires the right to change how data is classified.
pub(crate) async fn add_clearance_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<AddClearanceRuleBody>,
) -> Result<Created<ClearanceRulesResponse>, ApiError> {
    let rules = authorization
        .clearance
        .add_rule
        .execute(&tenant.caller, &tenant.auditor, body.into())
        .await?;
    Ok(Created(ClearanceRulesResponse::from(&rules)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/clearance-rules/{resource}/{action}",
    tag = "Authorization",
    request_body = ChangeClearanceRuleBody,
    responses(
        (status = 200, description = "The rules with the change", body = ClearanceRulesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No rule names the permission", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change a clearance rule
///
/// Changes the level holders of the `resource:action` permission are
/// cleared for. The caller must be cleared for both the level before and
/// the level after (`403`). Records `authorization.clearance_rule_changed`.
///
/// Requires the right to change how data is classified.
pub(crate) async fn change_clearance_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<ClearanceRulePath>,
    Json(body): Json<ChangeClearanceRuleBody>,
) -> Result<Json<ClearanceRulesResponse>, ApiError> {
    let rules = authorization
        .clearance
        .change_rule
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.permission()?),
        )
        .await?;
    Ok(Json(ClearanceRulesResponse::from(&rules)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/clearance-rules/{resource}/{action}",
    tag = "Authorization",
    responses(
        (status = 200, description = "The rules without it", body = ClearanceRulesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No rule names the permission", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove a clearance rule
///
/// Holding the `resource:action` permission no longer clears for anything.
/// The caller must be cleared for what the rule cleared for (`403`).
/// Records `authorization.clearance_rule_removed`.
///
/// Requires the right to change how data is classified.
pub(crate) async fn remove_clearance_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<ClearanceRulePath>,
) -> Result<Json<ClearanceRulesResponse>, ApiError> {
    let rules = authorization
        .clearance
        .remove_rule
        .execute(&tenant.caller, &tenant.auditor, path.permission()?)
        .await?;
    Ok(Json(ClearanceRulesResponse::from(&rules)))
}
