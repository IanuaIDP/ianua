//! Separation-of-duties handlers: the pairs of roles nobody in the tenant
//! holds together, checked whenever a role or a group is given.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::separation::{AddSeparationRuleBody, SeparationRuleResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::authorization::SeparationRulePath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/separation-rules",
    tag = "Authorization",
    request_body = AddSeparationRuleBody,
    responses(
        (status = 201, description = "Declared", body = SeparationRuleResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Declare a separation-of-duties rule
///
/// From now on nobody is given one of the two roles while holding the
/// other: straight, through a group, by an approved access request, or by
/// moving a group. `404` when either role does not exist; `422` when both
/// are one role. Records `authorization.separation_rule_added`.
///
/// Requires `Roles(Update)`.
pub(crate) async fn add_separation_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<AddSeparationRuleBody>,
) -> Result<Created<SeparationRuleResponse>, ApiError> {
    let rule = authorization
        .separation
        .add_rule
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(SeparationRuleResponse::from(&rule)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/separation-rules",
    tag = "Authorization",
    responses(
        (status = 200, description = "Every rule, oldest first", body = Vec<SeparationRuleResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List separation-of-duties rules
///
/// Every rule of the tenant, oldest first.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_separation_rules(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<SeparationRuleResponse>>, ApiError> {
    let rules = authorization
        .separation
        .list_rules
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        rules.iter().map(SeparationRuleResponse::from).collect(),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/separation-rules/{id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "Lifted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Lift a separation-of-duties rule
///
/// The two roles may be held together again. Holdings given while the
/// rule stood are not touched. Records
/// `authorization.separation_rule_removed`.
///
/// Requires `Roles(Update)`.
pub(crate) async fn remove_separation_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<SeparationRulePath>,
) -> Result<NoContent, ApiError> {
    authorization
        .separation
        .remove_rule
        .execute(&tenant.caller, &tenant.auditor, path.rule())
        .await?;
    Ok(NoContent)
}
