//! Role handlers: a tenant's roles, who holds them, and the catalogue of
//! built-in permissions a role can carry.

use axum::extract::{Path, State};
use ianua_app::ports::authorization::RoleSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authorization::roles::ListRequest;
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::roles::{
    AssignRoleBody, CreateRoleBody, CreateRoleResponse, DeleteRoleBody, PermissionGroup,
    RoleResponse, UpdateRoleBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::{RoleAssignmentPath, RolePath};
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles",
    tag = "Authorization",
    request_body = CreateRoleBody,
    responses(
        (status = 201, description = "Created", body = CreateRoleResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Create a role
///
/// Creates a tenant role bundling **system** permissions (admin gates the identity provider
/// enforces, such as user and role management and audit; these follow an
/// `implies` ladder, so `ManageUsers` also covers `Users(View)`), and
/// **custom** permissions (the tenant's own `resource:action` pairs from its
/// permission catalogue, carried in tokens for its application to enforce).
/// Set `is_default` to give the role to every newly registered user.
///
/// **Delegation.** Only system permissions the caller already holds can be
/// granted: minting one they lack is `403`. A custom permission must name a
/// declared resource type and action (`422` otherwise). The name must be
/// unique within the tenant (`409`), and the tenant plan's role limit
/// applies (`403` when reached). Records `authorization.role_created`.
///
/// Requires `Roles(Create)`.
pub(crate) async fn create_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<CreateRoleBody>,
) -> Result<Created<CreateRoleResponse>, ApiError> {
    let id = authorization
        .roles
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(CreateRoleResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/permissions",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = Vec<PermissionGroup>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List available system permissions
///
/// Returns the fixed catalogue of system permissions the identity provider
/// recognizes, grouped by area: the same set a role can carry. This is a
/// static list read from no store, for building a permission picker in the
/// role editor. Each entry's `value` is what create and update requests
/// take.
///
/// Requires a caller acting in the tenant.
pub(crate) async fn list_permissions(_tenant: TenantCaller) -> Json<Vec<PermissionGroup>> {
    Json(PermissionGroup::catalogue())
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles",
    tag = "Authorization",
    params(SortQuery<RoleSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<RoleResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List roles
///
/// Paginated, sortable list of every role in the tenant, default and
/// custom alike. Each role carries its system and custom permissions and
/// how many users hold it. Use `?sort=` (such as `name` or `-created_at`)
/// and `after`/`limit`.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_roles(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<RoleSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<RoleResponse>>, ApiError> {
    let page = authorization
        .roles
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, RoleResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles/{id}",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = RoleResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get a role
///
/// Returns one role by id, with its system permissions, custom
/// permissions, whether it is a default role and how many users hold it.
/// `404` if the id does not exist in this tenant.
///
/// Requires `Roles(View)`.
pub(crate) async fn get_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RolePath>,
) -> Result<Json<RoleResponse>, ApiError> {
    let role = authorization
        .roles
        .get
        .execute(&tenant.caller, path.role())
        .await?;
    Ok(Json(RoleResponse::from(role)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles/{id}",
    tag = "Authorization",
    request_body = UpdateRoleBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Update a role
///
/// Renames a role, replaces its system or custom permissions, or changes
/// whether new users are given it. Every field is optional; an omitted one
/// is left alone, and a permission list sent replaces the role's whole set.
/// A request that changes nothing records nothing.
///
/// **Delegation.** Granting system permissions the caller does not hold is
/// `403`, and so is narrowing a role so far that nobody would be left to
/// administer the tenant. A rename onto an existing name is `409`; an
/// unknown role is `404`. Records `authorization.role_renamed`,
/// `authorization.permission_granted`, `authorization.permission_revoked`
/// and `authorization.role_default_assignment_changed` for what changed.
///
/// Requires `Roles(Update)`.
pub(crate) async fn update_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RolePath>,
    Json(body): Json<UpdateRoleBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .roles
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.role())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles/{id}",
    tag = "Authorization",
    request_body = DeleteRoleBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Delete a role
///
/// Permanently removes a role from the tenant. Supply `replacement_role_id`
/// to move every current holder onto that role first; the delete then
/// succeeds. Without a replacement the delete is **refused while anyone
/// still holds it** (`409`), and so is deleting a role a group still
/// carries. A replacement equal to the role being deleted is `422`; an
/// unknown role or replacement is `404`; a deletion that would leave nobody
/// to administer the tenant is `403`. Records `authorization.role_deleted`,
/// and `authorization.role_reassigned` when holders were moved.
///
/// Requires `Roles(Delete)`.
pub(crate) async fn delete_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RolePath>,
    body: Option<Json<DeleteRoleBody>>,
) -> Result<NoContent, ApiError> {
    authorization
        .roles
        .delete
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DeleteRoleBody::deleting(path.role(), body.map(|Json(body)| body)),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles/{id}/assignments",
    tag = "Authorization",
    request_body = AssignRoleBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Breaks a separation-of-duties rule", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Assign a role to a user
///
/// Gives a role to a user. `until` ends it at that time; left out, it is
/// held until it is taken away. Idempotent: giving a role the user already
/// holds is `204`, not an error, because the state asked for is already
/// true. An unknown user or role is `404`; a role the user may not hold
/// beside one they hold, under a separation-of-duties rule, is `409`.
/// Records `authorization.role_assigned`.
///
/// Requires `Users(Update)`: which roles a person holds is part of that
/// person's record. Holding it does not let a caller hand out authority
/// they lack: a role carrying permissions the caller does not hold is
/// refused with `403`.
pub(crate) async fn assign_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RolePath>,
    Json(body): Json<AssignRoleBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .roles
        .assign
        .execute(&tenant.caller, &tenant.auditor, body.request(path.role()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/roles/{id}/assignments/{user_id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Revoke a role from a user
///
/// Takes a role away from a user. Revoking a role the user does not hold
/// is `404` (not idempotent), and a revocation that would leave nobody to
/// administer the tenant is `403`. Records `authorization.role_revoked`.
///
/// Requires `Users(Update)`, the same right that gives one.
pub(crate) async fn revoke_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RoleAssignmentPath>,
) -> Result<NoContent, ApiError> {
    authorization
        .roles
        .revoke
        .execute(&tenant.caller, &tenant.auditor, path.revocation())
        .await?;
    Ok(NoContent)
}
