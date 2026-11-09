//! Group handlers: a tenant's groups, their place in the tree, their
//! members and the roles bound to them.

use axum::extract::{Path, State};
use ianua_app::ports::authorization::GroupSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authorization::groups::{ListMembersRequest, ListRequest};
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::groups::{
    AddGroupMemberBody, AssignGroupRoleBody, CreateGroupBody, CreateGroupResponse,
    GroupMemberResponse, GroupResponse, MoveGroupBody, RenameGroupBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::{GroupMemberPath, GroupPath, GroupRolePath};
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups",
    tag = "Authorization",
    request_body = CreateGroupBody,
    responses(
        (status = 201, description = "Created", body = CreateGroupResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Create a group
///
/// Mints a group for organizing users and assigning roles in bulk.
/// `parent_id` optionally nests it under an existing group, whose roles it
/// then inherits; an unknown parent is `404`, and nesting under a group
/// conferring more than the caller holds is `403`. The name must be unique
/// within the tenant (`409`), and the tenant plan's group limit applies
/// (`403` when reached). Records `authorization.group_created`.
///
/// Requires `Roles(Create)`.
pub(crate) async fn create_group(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<CreateGroupBody>,
) -> Result<Created<CreateGroupResponse>, ApiError> {
    let id = authorization
        .groups
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(CreateGroupResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups",
    tag = "Authorization",
    params(SortQuery<GroupSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<GroupResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List groups
///
/// Paginated, sortable list of every group in the tenant. Use `?sort=`
/// (such as `name` or `-created_at`) and `after`/`limit`.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_groups(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<GroupSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<GroupResponse>>, ApiError> {
    let page = authorization
        .groups
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, GroupResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = GroupResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get a group
///
/// Returns one group by id. `404` if the id does not exist in this tenant.
///
/// Requires `Roles(View)`.
pub(crate) async fn get_group(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
) -> Result<Json<GroupResponse>, ApiError> {
    let group = authorization
        .groups
        .get
        .execute(&tenant.caller, path.group())
        .await?;
    Ok(Json(GroupResponse::from(group)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}",
    tag = "Authorization",
    request_body = RenameGroupBody,
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
/// Rename a group
///
/// Gives a group a new name, unique within the tenant (`409` on a
/// collision). A group a directory keeps in sync is renamed only by the
/// directory (`403`). Records `authorization.group_renamed`.
///
/// Requires `Roles(Update)`.
pub(crate) async fn rename_group(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
    Json(body): Json<RenameGroupBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .rename
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.group())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}/parent",
    tag = "Authorization",
    request_body = MoveGroupBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Move a group in the tree
///
/// Puts a group under another one, whose roles it then inherits, or at the
/// top of the tree with `parent_id: null`. A move under the group itself or
/// one of its descendants is `422`; a move that hands its members more than
/// the caller holds, or that would leave nobody to administer the tenant,
/// is `403`. An unknown group or parent is `404`. Records
/// `authorization.group_moved`.
///
/// Requires `Roles(Update)`.
pub(crate) async fn move_group(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
    Json(body): Json<MoveGroupBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .move_group
        .execute(&tenant.caller, &tenant.auditor, body.request(path.group()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Delete a group
///
/// Removes a group. **Refused while it has child groups** (`409`): delete
/// or move them first. Members and role bindings on the group itself do
/// not block deletion, but a deletion that would leave nobody to
/// administer the tenant is `403`. An unknown group is `404`. Records
/// `authorization.group_deleted`.
///
/// Requires `Roles(Delete)`.
pub(crate) async fn delete_group(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.group())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}/members",
    tag = "Authorization",
    request_body = AddGroupMemberBody,
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
/// Add a principal to a group
///
/// Adds a principal as a member of a group, so the roles bound to the
/// group apply to it. The body names the kind as well as the id: a
/// consumer or an agent in a group holds the group's roles at the proxy
/// exactly as a person does. `until` ends the membership at that time;
/// left out, it lasts until the member is taken out.
///
/// An unknown id for the named kind is `404`; adding a principal that is
/// already a member, or one who would then hold both roles of a
/// separation-of-duties rule, is `409`. The caller must hold
/// everything the group and its ancestors confer, or the request is `403`.
/// Records `authorization.group_member_added`.
///
/// Requires `Roles(Assign)`.
pub(crate) async fn add_group_member(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
    Json(body): Json<AddGroupMemberBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .add_member
        .execute(&tenant.caller, &tenant.auditor, body.request(path.group()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}/members",
    tag = "Authorization",
    params(PaginationParams),
    responses(
        (status = 200, description = "The group's members", body = PageResponse<GroupMemberResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List a group's members
///
/// Every principal that holds the group's roles through belonging to it,
/// each with its kind and, where it could be resolved, its name, a page at
/// a time with `after`/`limit`, oldest membership first. Machine
/// identities are listed beside the people: membership is a grant, and a
/// grant nobody can enumerate is one nobody can review or revoke.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_group_members(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<GroupMemberResponse>>, ApiError> {
    let request = ListMembersRequest {
        group_id: path.group(),
        page: pagination,
    };
    let page = authorization
        .groups
        .list_members
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        GroupMemberResponse::from,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}/members/{principal_kind}/{principal_id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove a principal from a group
///
/// Ends a principal's group membership, whatever kind of principal it is.
/// The permissions the membership conferred end at once, including at the
/// proxy. Removing a principal that is not a member is `404` (not
/// idempotent); a removal that would leave nobody to administer the tenant
/// is `403`. Records `authorization.group_member_removed`.
///
/// Requires `Roles(Assign)`.
pub(crate) async fn remove_group_member(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupMemberPath>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .remove_member
        .execute(&tenant.caller, &tenant.auditor, path.removal())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}/roles",
    tag = "Authorization",
    request_body = AssignGroupRoleBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Assign a role to a group
///
/// Binds a role to a group so every member inherits it. Binding a role the
/// group already has is `409` (not idempotent); an unknown group or role
/// is `404`; a role carrying more than the caller holds is `403`. Records
/// `authorization.group_role_assigned`.
///
/// Requires `Roles(Assign)`.
pub(crate) async fn assign_group_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupPath>,
    Json(body): Json<AssignGroupRoleBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .assign_role
        .execute(&tenant.caller, &tenant.auditor, body.request(path.group()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/groups/{id}/roles/{role_id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove a role from a group
///
/// Unbinds a role from a group. Removing a role the group does not have is
/// `404` (not idempotent); a removal that would leave nobody to administer
/// the tenant is `403`. Records `authorization.group_role_unassigned`.
///
/// Requires `Roles(Assign)`.
pub(crate) async fn unassign_group_role(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<GroupRolePath>,
) -> Result<NoContent, ApiError> {
    authorization
        .groups
        .unassign_role
        .execute(&tenant.caller, &tenant.auditor, path.unassignment())
        .await?;
    Ok(NoContent)
}
