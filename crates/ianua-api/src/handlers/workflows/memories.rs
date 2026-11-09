//! Memory handlers: making a memory, listing the tenant's memories,
//! deleting one after its name is typed, bringing one back, and reading
//! its texts page by page for a copy.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::workflows::memories;
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::memories::{
    CreateMemoryBody, DeleteMemoryBody, MemoryEntryPageResponse, MemoryResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::MemoryPath;
use crate::extractors::query::Query;
use crate::extractors::workflows::MemoryPageQuery;
use crate::response::Created;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/memories",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<MemoryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List memories
///
/// Returns the tenant's memories by name, those waiting to be deleted
/// among them, never their texts. A memory step's form lists them.
/// Requires the right to view workflows.
pub(crate) async fn list_memories(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<MemoryResponse>>, ApiError> {
    let memories = workflows.memories.list.execute(&tenant.caller, ()).await?;
    Ok(Json(
        memories.into_iter().map(MemoryResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/memories",
    tag = "Workflows",
    request_body = CreateMemoryBody,
    responses(
        (status = 201, description = "Made", body = MemoryResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, the plan's memory limit is reached, or the provider is not cleared for the memory's data", body = ErrorBody),
        (status = 404, description = "No such active provider", body = ErrorBody),
        (status = 422, description = "Validation error, no embedding server here, or a provider offering no embedding model", body = ErrorBody)
    )
)]
/// Make a memory
///
/// Makes an empty memory filled by the platform's own embedding server, or
/// by the embedding model of the tenant's provider `provider_id`. Its
/// embedding model is asked once for a vector, so the memory keeps the
/// length its vectors have. Records `workflows.memory_created`. Requires
/// the right to create workflows.
pub(crate) async fn create_memory(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<CreateMemoryBody>,
) -> Result<Created<MemoryResponse>, ApiError> {
    let memory = workflows
        .memories
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(MemoryResponse::from(memory)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/memories/{memory_id}/delete",
    tag = "Workflows",
    request_body = DeleteMemoryBody,
    responses(
        (status = 200, description = "Waiting to be deleted", body = MemoryResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such memory", body = ErrorBody),
        (status = 409, description = "Set to be deleted already", body = ErrorBody),
        (status = 422, description = "The name typed is not the memory's", body = ErrorBody)
    )
)]
/// Delete a memory
///
/// Sets the memory to be deleted once `name` matches its name exactly.
/// Nothing is kept in or found in it from then on; it and every text it
/// kept are deleted for good at `deleted_after`, unless brought back first.
/// Records `workflows.memory_deletion_requested`. Requires the right to
/// delete workflows.
pub(crate) async fn delete_memory(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<MemoryPath>,
    Json(body): Json<DeleteMemoryBody>,
) -> Result<Json<MemoryResponse>, ApiError> {
    let memory = workflows
        .memories
        .delete
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.memory()),
        )
        .await?;
    Ok(Json(MemoryResponse::from(memory)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/memories/{memory_id}/restore",
    tag = "Workflows",
    responses(
        (status = 200, description = "Brought back", body = MemoryResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such memory, or deleted for good", body = ErrorBody),
        (status = 409, description = "Not set to be deleted", body = ErrorBody)
    )
)]
/// Bring a memory back
///
/// Brings back a memory set to be deleted, with every text it kept, while
/// its waiting period lasts. Records `workflows.memory_restored`. Requires
/// the right to delete workflows.
pub(crate) async fn restore_memory(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<MemoryPath>,
) -> Result<Json<MemoryResponse>, ApiError> {
    let memory = workflows
        .memories
        .restore
        .execute(&tenant.caller, &tenant.auditor, path.memory())
        .await?;
    Ok(Json(MemoryResponse::from(memory)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/memories/{memory_id}/entries",
    tag = "Workflows",
    params(MemoryPageQuery),
    responses(
        (status = 200, description = "Success", body = MemoryEntryPageResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such memory, or deleted for good", body = ErrorBody)
    )
)]
/// Read a memory's texts
///
/// Returns up to 100 of the memory's texts, oldest first, each with how
/// sensitive it may be and when it was kept, never its vector; `next`
/// names where the following page starts, passed back as `from`. A memory
/// waiting to be deleted can still be read, so a copy can be kept before
/// it is gone. Requires the right to delete workflows.
pub(crate) async fn list_memory_entries(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<MemoryPath>,
    Query(query): Query<MemoryPageQuery>,
) -> Result<Json<MemoryEntryPageResponse>, ApiError> {
    let page = workflows
        .memories
        .export
        .execute(
            &tenant.caller,
            memories::ExportRequest {
                memory_id: path.memory(),
                start: query.start(),
            },
        )
        .await?;
    Ok(Json(MemoryEntryPageResponse::from(page)))
}
