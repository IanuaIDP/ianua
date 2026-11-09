//! Stage handlers: what a pipeline runs, in which order, and the canary
//! tokens and WASM modules stages are configured with.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::proxy::stages::{DisableRequest, EnableRequest, RemoveRequest};
use ianua_assembly::proxy::ProxyState;

use crate::dto::proxy::{
    AddStageBody, GeneratedCanaryTokenResponse, ReconfigureStageBody, ReorderStagesBody,
    UploadWasmModuleBody, WasmModuleResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::proxy::{PipelinePath, StagePath};
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/stages",
    tag = "Pipeline",
    request_body = AddStageBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the pipeline is active", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Add a pipeline stage
///
/// Appends a processing stage of the given `kind` (for example `Waf`,
/// `RateLimit`, `Redact`, or `Custom` WASM) to the **end** of the pipeline.
/// Move it with `PUT .../stages/order`, which takes the whole sequence.
///
/// Appending keeps the stage after Identity, so filtering cannot run before
/// the caller is identified. Changing its position requires the complete
/// stage order.
///
/// New stages are added enabled and non-mandatory. Stages can only be added
/// while the pipeline is `Draft` or `Disabled`, so a newly added stage starts
/// enforcing the moment the pipeline is next activated; use
/// `.../stages/{id}/disable` right after adding if you want it present but
/// inactive. `Identity` and `Policy` cannot be added: every pipeline already
/// runs them.
///
/// Returns `404` if the pipeline does not exist, or `403` if it is `Active`
/// (immutable while live). Records `proxy.stage_added`. Requires
/// `Pipeline(Update)`.
pub(crate) async fn add_stage(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
    Json(body): Json<AddStageBody>,
) -> Result<NoContent, ApiError> {
    proxy
        .stages
        .add
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.pipeline()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/stages/{id}",
    tag = "Pipeline",
    request_body = ReconfigureStageBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, the stage is mandatory, or the pipeline is active", body = ErrorBody),
        (status = 404, description = "No such pipeline or stage", body = ErrorBody),
        (status = 422, description = "The settings are for another kind of stage, or invalid", body = ErrorBody)
    )
)]
/// Change a pipeline stage's settings
///
/// Gives a stage new settings in place: send its `kind` with the new
/// configuration, such as a rate limit's new budget or a canary stage's
/// updated `tokens`. The stage keeps its `id`, its place in the order and
/// whether it is enabled; its kind cannot change (remove it and add another
/// for that). `Identity` and `Policy` take no settings here.
///
/// Settings can only change while the pipeline is `Draft` or `Disabled`.
/// Returns `404` if no pipeline or stage exists, `403` if the stage is
/// mandatory or the pipeline is `Active`, or `422` if the settings are for
/// another kind of stage or would leave it unable to do its job. Records
/// `proxy.stage_reconfigured`, naming the stage and its kind but never its
/// settings. Requires `Pipeline(Update)`.
pub(crate) async fn reconfigure_stage(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<StagePath>,
    Json(body): Json<ReconfigureStageBody>,
) -> Result<NoContent, ApiError> {
    proxy
        .stages
        .reconfigure
        .execute(&tenant.caller, &tenant.auditor, body.into_request(&path))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/stages/{id}",
    tag = "Pipeline",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, the stage is mandatory, or the pipeline is active", body = ErrorBody),
        (status = 404, description = "No such pipeline or stage", body = ErrorBody)
    )
)]
/// Remove a pipeline stage
///
/// Deletes a stage by `id`. As with add, stages can only be removed while the
/// pipeline is `Draft` or `Disabled`, and the mandatory stages never.
///
/// Returns `404` if no pipeline or stage exists, or `403` if the pipeline is
/// `Active`. Records `proxy.stage_removed`. Requires `Pipeline(Update)`.
pub(crate) async fn remove_stage(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<StagePath>,
) -> Result<NoContent, ApiError> {
    let request = RemoveRequest {
        pipeline_id: path.pipeline(),
        stage_id: path.stage(),
    };
    proxy
        .stages
        .remove
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/stages/{id}/enable",
    tag = "Pipeline",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the pipeline is active", body = ErrorBody),
        (status = 404, description = "No such pipeline or stage", body = ErrorBody)
    )
)]
/// Enable a pipeline stage
///
/// Turns a disabled, non-mandatory stage back on without
/// re-adding it (which would lose its configured position). Stages can only
/// be enabled while the pipeline is `Draft` or `Disabled`.
///
/// Returns `404` if no pipeline or stage exists, or `403` if the pipeline is
/// `Active`. Records `proxy.stage_enabled`. Requires `Pipeline(Update)`.
pub(crate) async fn enable_stage(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<StagePath>,
) -> Result<NoContent, ApiError> {
    let request = EnableRequest {
        pipeline_id: path.pipeline(),
        stage_id: path.stage(),
    };
    proxy
        .stages
        .enable
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/stages/{id}/disable",
    tag = "Pipeline",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, the stage is mandatory, or the pipeline is active", body = ErrorBody),
        (status = 404, description = "No such pipeline or stage", body = ErrorBody)
    )
)]
/// Disable a pipeline stage
///
/// Turns a non-mandatory stage off in place: it stays in the pipeline at its
/// configured position but stops being enforced, without the
/// remove-then-re-add round trip a delete would need. Mandatory stages
/// (`Identity`, `Policy`) cannot be disabled. Stages can only be disabled
/// while the pipeline is `Draft` or `Disabled`.
///
/// Returns `404` if no pipeline or stage exists, or `403` if the stage is
/// mandatory or the pipeline is `Active`. Records `proxy.stage_disabled`.
/// Requires `Pipeline(Update)`.
pub(crate) async fn disable_stage(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<StagePath>,
) -> Result<NoContent, ApiError> {
    let request = DisableRequest {
        pipeline_id: path.pipeline(),
        stage_id: path.stage(),
    };
    proxy
        .stages
        .disable
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/{pipeline_id}/stages/order",
    tag = "Pipeline",
    request_body = ReorderStagesBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the pipeline is active", body = ErrorBody),
        (status = 404, description = "No such pipeline", body = ErrorBody),
        (status = 422, description = "The order does not name every stage exactly once", body = ErrorBody)
    )
)]
/// Set the pipeline's evaluation order
///
/// Replaces the whole order in one request: send `stage_ids` in the sequence
/// the stages should run and the pipeline is rewritten to match. A
/// drag-and-drop is one call, whatever moved: send the list you ended up
/// with.
///
/// `stage_ids` must name every stage exactly once. A partial list is refused
/// with `422` rather than applied, because the stages it omits would collect
/// at the front of the pipeline: a security control moving without anyone
/// asking it to. Duplicates and unknown ids are refused the same way.
/// `Identity` always runs before `Policy`.
///
/// Positions are derived from the sequence, so no two stages can end up
/// sharing one. Reordering requires the pipeline to be `Draft` or `Disabled`;
/// an `Active` pipeline returns `403`. Records `proxy.pipeline_reordered`.
/// Requires `Pipeline(Update)`.
pub(crate) async fn reorder_stages(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Path(path): Path<PipelinePath>,
    Json(body): Json<ReorderStagesBody>,
) -> Result<NoContent, ApiError> {
    proxy
        .stages
        .reorder
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.pipeline()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/canary-tokens/generate",
    tag = "Pipeline",
    responses(
        (status = 201, description = "Created", body = GeneratedCanaryTokenResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Generate a canary token
///
/// Returns a cryptographically random decoy credential value
/// (`sk-decoy-...`). It is **not** added to any stage: add it to a
/// `CanaryToken` stage's `tokens` list yourself, with
/// `PATCH .../stages/{id}` and the updated list. Records `proxy.canary_token_generated`, without the token. Requires
/// `Pipeline(Update)`.
pub(crate) async fn generate_canary_token(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
) -> Result<Created<GeneratedCanaryTokenResponse>, ApiError> {
    let token = proxy
        .stages
        .generate_canary_token
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Created(GeneratedCanaryTokenResponse { token }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines/wasm-modules",
    tag = "Pipeline",
    request_body = UploadWasmModuleBody,
    responses(
        (status = 201, description = "Created", body = WasmModuleResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Upload a WASM stage module
///
/// Stores a tenant-authored WASM module (see "Ianua WASM Stage ABI v1") and
/// returns its content-addressed `module_ref` (`sha256:<hex>`). Uploading
/// does not create or change any stage: put the returned ref in a `Custom`
/// stage's `module_ref` yourself, with `PATCH .../stages/{id}`.
///
/// Returns `422` if `bytecode_base64` is not valid base64 or the decoded
/// module exceeds the platform's size limit. Records
/// `proxy.wasm_module_uploaded`. Requires `Pipeline(Update)`.
pub(crate) async fn upload_wasm_module(
    State(proxy): State<ProxyState>,
    tenant: TenantCaller,
    Json(body): Json<UploadWasmModuleBody>,
) -> Result<Created<WasmModuleResponse>, ApiError> {
    let module_ref = proxy
        .stages
        .upload_wasm_module
        .execute(&tenant.caller, &tenant.auditor, body.bytecode()?)
        .await?;
    Ok(Created(module_ref.into()))
}
