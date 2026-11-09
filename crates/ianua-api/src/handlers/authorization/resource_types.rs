//! Permission catalogue handlers: the kinds of thing a tenant's own
//! application protects, and the verbs each accepts.

use axum::extract::{Path, State};
use ianua_app::ports::authorization::ResourceTypeSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authorization::resource_types::ListRequest;
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::resource_types::{
    DeclareResourceTypeBody, DeclareResourceTypeResponse, ResourceTypeResponse,
    UpdateResourceTypeBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::ResourceTypePath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/resource-types",
    tag = "Authorization",
    request_body = DeclareResourceTypeBody,
    responses(
        (status = 201, description = "Created", body = DeclareResourceTypeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Declare a resource type
///
/// Adds a resource kind, such as `project`, with its actions and `data_class`
/// to the tenant's permission catalogue. Roles and routes select the same names;
/// each resource carries the class governing where its data may be sent.
///
/// **The ladder.** An action may confer others on the same resource, so
/// `admin` conferring `write` conferring `read` means granting admin grants
/// all three. The ladder must not loop, and may only name actions this
/// resource declares.
///
/// The key is unique within the tenant (`409` on collision) and cannot use
/// the reserved `idp` prefix; the tenant plan's resource-type limit applies
/// (`403` when reached). Records `authorization.resource_type_declared`.
///
/// Requires `Roles(Create)`.
pub(crate) async fn declare_resource_type(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<DeclareResourceTypeBody>,
) -> Result<Created<DeclareResourceTypeResponse>, ApiError> {
    let id = authorization
        .resource_types
        .declare
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(DeclareResourceTypeResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/resource-types",
    tag = "Authorization",
    params(SortQuery<ResourceTypeSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ResourceTypeResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List the permission catalogue
///
/// Returns every resource type this tenant has declared, with each
/// action's ladder already walked: `grants` on an action lists everything
/// holding it confers, so a client never expands the ladder itself and
/// cannot disagree with the proxy about what a grant means. This is what a
/// role editor and a route's permission picker read.
///
/// Requires `Roles(View)`.
pub(crate) async fn list_resource_types(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<ResourceTypeSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ResourceTypeResponse>>, ApiError> {
    let page = authorization
        .resource_types
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(ResourceTypeResponse::page(&page)?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/resource-types/{id}",
    tag = "Authorization",
    request_body = UpdateResourceTypeBody,
    responses(
        (status = 204, description = "Updated"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Update a resource type
///
/// Changes the display name, the description, the action ladder or the
/// data class. The ladder is replaced whole, not merged, and is checked the
/// same way it was on declaration: a loop or an action conferring something
/// undeclared is refused and the existing ladder is left alone. Narrowing
/// the ladder further than the caller could hand out is `403`.
///
/// The key cannot change: it is what every role and route already refers
/// to. Declare a new resource type and retire this one instead. Records
/// `authorization.resource_type_updated`.
///
/// Requires `Roles(Update)`.
pub(crate) async fn update_resource_type(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<ResourceTypePath>,
    Json(body): Json<UpdateResourceTypeBody>,
) -> Result<NoContent, ApiError> {
    authorization
        .resource_types
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.resource_type())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/resource-types/{id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Delete a resource type
///
/// Removes the declaration from the catalogue. Refused with `409` while
/// any role still grants a permission naming it: deleting under a live
/// grant would leave roles holding permissions nothing defines. Revoke
/// those permissions first. Records `authorization.resource_type_deleted`.
///
/// Requires `Roles(Delete)`.
pub(crate) async fn delete_resource_type(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<ResourceTypePath>,
) -> Result<NoContent, ApiError> {
    authorization
        .resource_types
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.resource_type())
        .await?;
    Ok(NoContent)
}
