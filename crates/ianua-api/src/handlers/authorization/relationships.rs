//! Relationship handlers: facts about single objects of the tenant's app,
//! read by the access check, written, listed and removed.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::authorization::relationships::ListRequest;
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::relationships::{RelationshipResponse, WriteRelationshipBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authorization::RelationshipQuery;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::authorization::RelationshipPath;
use crate::extractors::query::Query;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/relationships",
    tag = "Authorization",
    request_body = WriteRelationshipBody,
    responses(
        (status = 201, description = "Written", body = RelationshipResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Write a relationship
///
/// Records a fact about one object of the tenant's app: that a person,
/// agent, app or group holds a relation on it (`{"holds": {"relation",
/// "subject"}}`), or that it sits under a parent object whose relations
/// reach it (`{"under": {"resource_type", "key"}}`). The relation must be
/// one of the actions the object's declared resource type accepts, and an
/// object cannot sit under itself (`422`). Writing a fact already written
/// answers it as it was, with no new record. Records
/// `authorization.relationship_added`.
///
/// Requires `Roles(Assign)`, and holding what the relation brings.
pub(crate) async fn write_relationship(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<WriteRelationshipBody>,
) -> Result<Created<RelationshipResponse>, ApiError> {
    let relationship = authorization
        .relationships
        .write
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(RelationshipResponse::from(&relationship)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/relationships",
    tag = "Authorization",
    params(RelationshipQuery, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<RelationshipResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List relationships
///
/// One page of the tenant's relationships, newest first: every one, those
/// about one object (`object_type` and `object_key`), or those one subject
/// holds (`subject_kind` and `subject_id`).
///
/// Requires `Roles(View)`.
pub(crate) async fn list_relationships(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Query(query): Query<RelationshipQuery>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<RelationshipResponse>>, ApiError> {
    let page = authorization
        .relationships
        .list
        .execute(
            &tenant.caller,
            ListRequest {
                filter: query.filter()?,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(page, |relationship| {
        RelationshipResponse::from(&relationship)
    })))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/relationships/{id}",
    tag = "Authorization",
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove a relationship
///
/// Takes the fact away; checks stop reading it at once. Records
/// `authorization.relationship_removed`.
///
/// Requires `Roles(Assign)`, and having been able to give what the relation
/// brings.
pub(crate) async fn delete_relationship(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<RelationshipPath>,
) -> Result<NoContent, ApiError> {
    authorization
        .relationships
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.relationship())
        .await?;
    Ok(NoContent)
}
