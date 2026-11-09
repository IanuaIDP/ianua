//! Event schema handlers: the tenant's versioned message contracts.

use axum::extract::{Path, State};
use ianua_app::ports::messaging::EventSchemaSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::messaging::schemas::{ListRequest, RegisterRequest};
use ianua_assembly::messaging::MessagingState;

use crate::dto::messaging::{
    EvolveSchemaBody, EvolveSchemaResponse, RegisterSchemaBody, RegisterSchemaResponse,
    SchemaResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::messaging::TenantMessenger;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::messaging::SchemaPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/schemas",
    tag = "Messaging",
    request_body = RegisterSchemaBody,
    responses(
        (status = 201, description = "Created", body = RegisterSchemaResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Register an event schema
///
/// Registers a versioned message schema (first version `1`) for typed
/// validation and code generation. `format` is `JsonSchema`, `Avro` or
/// `Protobuf`; `compatibility` says how later versions must relate to the
/// one before (`None`, `Backward`, `Forward` or `Full`). The creator is the
/// person calling. Returns the schema's `id`. Records
/// `messaging.schema_registered`.
///
/// `409` if the schema name is taken, `422` for an invalid name or a
/// definition malformed for its format. Requires the right to create in
/// messaging.
pub(crate) async fn register_schema(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Json(body): Json<RegisterSchemaBody>,
) -> Result<Created<RegisterSchemaResponse>, ApiError> {
    let request = RegisterRequest::try_from(body)?;
    let id = messaging
        .register_schema
        .execute(&messenger.caller, &messenger.auditor, request)
        .await?;
    Ok(Created(RegisterSchemaResponse { id: *id.as_uuid() }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/schemas",
    tag = "Messaging",
    params(SortQuery<EventSchemaSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<SchemaResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List event schemas
///
/// Returns every event schema the tenant registered, sortable (see the
/// `sort` parameter) and paginated. Each entry carries its `format`, its
/// `compatibility` mode and every version, oldest first, with its number,
/// definition and registration time. The registry is a typed contract for
/// services and code generation. Read-only. Requires the right to view
/// messaging.
pub(crate) async fn list_schemas(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<EventSchemaSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<SchemaResponse>>, ApiError> {
    let request = ListRequest {
        sort,
        page: pagination,
    };
    let page = messaging
        .list_schemas
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(page, SchemaResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/schemas/{id}",
    tag = "Messaging",
    responses(
        (status = 200, description = "Success", body = SchemaResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get an event schema
///
/// Returns a single event schema by `id`, with its `format`,
/// `compatibility`, creator and every version, oldest first. The latest
/// version is the current definition; the history is kept for code
/// generation and consumer migrations. A schema never evolved still has its
/// version `1`. `404` if the tenant has no such schema. Read-only. Requires
/// the right to view messaging.
pub(crate) async fn get_schema(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SchemaPath>,
) -> Result<Json<SchemaResponse>, ApiError> {
    let schema = messaging
        .get_schema
        .execute(&tenant.caller, path.schema())
        .await?;
    Ok(Json(SchemaResponse::from(schema)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/schemas/{id}/versions",
    tag = "Messaging",
    request_body = EvolveSchemaBody,
    responses(
        (status = 200, description = "Success", body = EvolveSchemaResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Add a schema version
///
/// Appends a new `definition` as the schema's next version (2, 3 and on)
/// and returns its number. The definition must be well formed for the
/// schema's format, and is checked against its `compatibility` mode: for
/// JSON Schema, `Backward` and `Full` refuse dropping a required field,
/// `Forward` and `Full` refuse adding one; `None` and the other formats
/// skip the check. A schema holds at most 1000 versions of at most 64 KB
/// each. Records `messaging.schema_evolved`.
///
/// `404` if the schema does not exist, `422` if the definition is
/// malformed, incompatible or too large, or the schema is full. Requires
/// the right to manage messaging.
pub(crate) async fn evolve_schema(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SchemaPath>,
    Json(body): Json<EvolveSchemaBody>,
) -> Result<Json<EvolveSchemaResponse>, ApiError> {
    let version = messaging
        .evolve_schema
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.version_of(path.schema())?,
        )
        .await?;
    Ok(Json(EvolveSchemaResponse { version }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/schemas/{id}",
    tag = "Messaging",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Delete an event schema
///
/// Removes a schema and every version it holds. Topics keep their own
/// definitions, so no topic stops it. Records `messaging.schema_deleted`.
/// `404` if the tenant has no such schema. Requires the right to delete in
/// messaging.
pub(crate) async fn delete_schema(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<SchemaPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .delete_schema
        .execute(&tenant.caller, &tenant.auditor, path.schema())
        .await?;
    Ok(NoContent)
}
