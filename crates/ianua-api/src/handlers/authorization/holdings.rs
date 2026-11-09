//! Holding handlers: who holds a role, and what one person, agent or app
//! holds and where it comes from.

use axum::extract::{Path, State};
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::authorization::holdings::ListRoleHoldersRequest;
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::holdings::{PrincipalAccessResponse, RoleHolderResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::{PrincipalPath, RolePath};
use crate::response::PageResponse;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles/{id}/holders",
    tag = "Authorization",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<RoleHolderResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List who holds a role
///
/// A page of the role's holders, with `after`/`limit`: first everyone
/// given the role straight (people, agents and apps, each once, `via`
/// `direct`), then the groups carrying it (`via` `group`): their members,
/// and the members of the groups under them, hold it too. A holding whose
/// end has passed is not shown. `404` for a role the tenant does not have.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_role_holders(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RolePath>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<RoleHolderResponse>>, ApiError> {
    let request = ListRoleHoldersRequest {
        role_id: path.role(),
        page: pagination,
    };
    let page = authorization
        .holdings
        .role_holders
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        RoleHolderResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/principals/{principal_kind}/{principal_id}/access",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = PrincipalAccessResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get what a principal holds
///
/// The roles a user, org user, agent or consumer holds now and where each
/// comes from: given straight (with its end, if it has one), or through a
/// group, with every group it is in. A principal the tenant does not know
/// holds nothing, and answers empty lists rather than `404`.
///
/// Requires `Roles(View)`.
pub(crate) async fn get_principal_access(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<PrincipalPath>,
) -> Result<Json<PrincipalAccessResponse>, ApiError> {
    let access = authorization
        .holdings
        .principal_access
        .execute(&tenant.caller, path.principal())
        .await?;
    Ok(Json(PrincipalAccessResponse::from(access)))
}
