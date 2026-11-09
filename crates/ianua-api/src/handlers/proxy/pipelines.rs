//! Pipeline handlers: a tenant's request pipelines.
//!
//! A tenant holds several so that a change to one does not have to be made in
//! place: editing a pipeline means disabling it, and a disabled pipeline
//! refuses every route that runs it.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::proxy::ProxyState;

use crate::dto::proxy::{
    CreatePipelineBody, CreatePipelineResponse, PipelineResponse, PipelineSummaryResponse,
    RenamePipelineBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::proxy::PipelinePath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines",
    tag = "Pipeline",
    request_body = CreatePipelineBody,
    responses(
        (status = 201, description = "Created", body = CreatePipelineResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "Another pipeline has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a proxy pipeline
///
/// Provisions a request-processing pipeline with the mandatory stages
/// (`Identity`, `Policy`) in `Draft` status: the starting point you then
/// extend, activate, and point routes at. The returned `id` is what a route's
/// `pipeline_id` names.
///
/// A tenant holds as many as it likes. That is the point: editing a pipeline
/// means disabling it, and a disabled pipeline refuses every route running it,
/// so a change is shipped by building the replacement alongside and moving
/// routes across rather than editing in place.
///
/// Returns `409` if the tenant already has a pipeline by this name. Records
/// `proxy.pipeline_created`. Requires `Pipeline(Manage)`.
pub(crate) async fn configure_pipeline(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Json(body): Json<CreatePipelineBody>,
) -> Result<Created<CreatePipelineResponse>, ApiError> {
    let id = proxy
        .configure_pipeline
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines",
    tag = "Pipeline",
    responses(
        (status = 200, description = "Success", body = Vec<PipelineSummaryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the tenant's pipelines
///
/// Every pipeline the tenant holds, oldest first, each with how many routes
/// run it. The count is what tells you whether one can be deleted: a pipeline
/// still naming routes is refused, and knowing that before you ask is the
/// difference between a disabled button and an error. Read-only. Requires
/// `Pipeline(View)`.
pub(crate) async fn list_pipelines(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<PipelineSummaryResponse>>, ApiError> {
    let pipelines = proxy.list_pipelines.execute(&tenant.caller, ()).await?;
    Ok(Json(
        pipelines
            .into_iter()
            .map(PipelineSummaryResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}",
    tag = "Pipeline",
    responses(
        (status = 200, description = "Success", body = PipelineResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody)
    )
)]
/// Get a pipeline
///
/// Returns one pipeline: its lifecycle `status` (`Draft`, `Active` or
/// `Disabled`) and the ordered `stages` (kind, position, `enabled`,
/// `mandatory`). Returns `404` if the tenant has no such pipeline.
/// Read-only. Requires `Pipeline(View)`.
pub(crate) async fn get_pipeline(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
) -> Result<Json<PipelineResponse>, ApiError> {
    let pipeline = proxy
        .get_pipeline
        .execute(&tenant.caller, path.pipeline())
        .await?;
    Ok(Json(PipelineResponse::from(pipeline)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}",
    tag = "Pipeline",
    request_body = RenamePipelineBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody),
        (status = 409, description = "Another pipeline has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Rename a pipeline
///
/// Gives the pipeline a new `name`, unique within the tenant. Routes name a
/// pipeline by id, so none of them changes; a gateway configuration document
/// names it by the new name from here on. Records `proxy.pipeline_renamed`.
/// Requires `Pipeline(Update)`.
pub(crate) async fn rename_pipeline(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
    Json(body): Json<RenamePipelineBody>,
) -> Result<NoContent, ApiError> {
    proxy
        .rename_pipeline
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.pipeline())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}",
    tag = "Pipeline",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody),
        (status = 409, description = "Routes still run it", body = ErrorBody)
    )
)]
/// Delete a pipeline
///
/// Refused with `409` while any route still names it. Dropping those routes,
/// or silently repointing them, would change what runs on live traffic without
/// anyone asking: move them first. Records `proxy.pipeline_deleted`.
/// Requires `Pipeline(Manage)`.
pub(crate) async fn delete_pipeline(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
) -> Result<NoContent, ApiError> {
    proxy
        .delete_pipeline
        .execute(&tenant.caller, &tenant.auditor, path.pipeline())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/activate",
    tag = "Pipeline",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody),
        (status = 422, description = "The pipeline is not in a state to activate", body = ErrorBody)
    )
)]
/// Activate a pipeline
///
/// Puts the pipeline live so its stages are enforced on the traffic of every
/// route running it. Stages cannot be added or removed while it is active:
/// disable it first.
///
/// **State.** `Draft -> Active`, or `Disabled -> Active`. Returns `404` if the
/// pipeline does not exist, or `422` if it is already `Active`. Records
/// `proxy.pipeline_activated`. Requires `Pipeline(Update)`.
pub(crate) async fn activate_pipeline(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
) -> Result<NoContent, ApiError> {
    proxy
        .activate_pipeline
        .execute(&tenant.caller, &tenant.auditor, path.pipeline())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/disable",
    tag = "Pipeline",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody),
        (status = 422, description = "The pipeline is not active", body = ErrorBody)
    )
)]
/// Disable a pipeline
///
/// Suspends enforcement: every route running the pipeline is refused (deny
/// by default), but its configuration is kept. Use this as an emergency kill
/// switch or to make stage changes.
///
/// **State.** `Active -> Disabled`. Returns `404` if the pipeline does not
/// exist, or `422` if it is not `Active`. Records `proxy.pipeline_disabled`.
/// Requires `Pipeline(Update)`.
pub(crate) async fn disable_pipeline(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
) -> Result<NoContent, ApiError> {
    proxy
        .disable_pipeline
        .execute(&tenant.caller, &tenant.auditor, path.pipeline())
        .await?;
    Ok(NoContent)
}
