//! Proxy endpoints: a tenant's pipelines, their stages, canary tokens and
//! WASM stage modules; the request records the gateway kept and the places
//! they are shipped to.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::proxy::log_targets::{ChangeLogTargetBody, CreateLogTargetBody, LogTargetResponse};
use crate::dto::proxy::requests::{
    ConnectionCloseResponse, DecidedByResponse, RecordSubjectResponse, RequestRecordResponse,
};
use crate::dto::proxy::{
    AddStageBody, CreatePipelineBody, CreatePipelineResponse, GeneratedCanaryTokenResponse,
    PipelineResponse, PipelineSummaryResponse, ReconfigureStageBody, RenamePipelineBody,
    ReorderStagesBody, StageResponse, UploadWasmModuleBody, WasmModuleResponse,
};
use crate::handlers::proxy::{log_targets, pipelines, requests, stages};
use crate::method::{get, patch, post, put, shared};
use crate::state::ApiState;

/// The proxy endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    pipeline_routes().merge(record_routes())
}

/// A tenant's pipelines and their stages.
fn pipeline_routes() -> Router<ApiState> {
    let base = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/pipelines";
    Router::new()
        .route(
            base,
            post(pipelines::configure_pipeline).get(shared(pipelines::list_pipelines)),
        )
        .route(
            &format!("{base}/canary-tokens/generate"),
            post(stages::generate_canary_token),
        )
        .route(
            &format!("{base}/wasm-modules"),
            post(stages::upload_wasm_module),
        )
        .route(
            &format!("{base}/{{pipeline_id}}"),
            get(pipelines::get_pipeline)
                .patch(shared(pipelines::rename_pipeline))
                .delete(shared(pipelines::delete_pipeline)),
        )
        .route(
            &format!("{base}/{{pipeline_id}}/activate"),
            post(pipelines::activate_pipeline),
        )
        .route(
            &format!("{base}/{{pipeline_id}}/disable"),
            post(pipelines::disable_pipeline),
        )
        .merge(stage_routes(base))
}

/// Registers pipeline stage order, configuration and enabled state.
fn stage_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/{{pipeline_id}}/stages"),
            post(stages::add_stage),
        )
        .route(
            &format!("{base}/{{pipeline_id}}/stages/order"),
            put(stages::reorder_stages),
        )
        .route(
            &format!("{base}/{{pipeline_id}}/stages/{{id}}"),
            patch(stages::reconfigure_stage).delete(shared(stages::remove_stage)),
        )
        .route(
            &format!("{base}/{{pipeline_id}}/stages/{{id}}/enable"),
            post(stages::enable_stage),
        )
        .route(
            &format!("{base}/{{pipeline_id}}/stages/{{id}}/disable"),
            post(stages::disable_stage),
        )
}

/// The request records the gateway kept, and where they are shipped.
fn record_routes() -> Router<ApiState> {
    let gateway = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway";
    Router::new()
        .route(
            &format!("{gateway}/requests"),
            get(requests::search_requests),
        )
        .route(
            &format!("{gateway}/log-targets"),
            post(log_targets::create_log_target).get(shared(log_targets::list_log_targets)),
        )
        .route(
            &format!("{gateway}/log-targets/{{id}}"),
            get(log_targets::get_log_target)
                .put(shared(log_targets::change_log_target))
                .delete(shared(log_targets::delete_log_target)),
        )
        .route(
            &format!("{gateway}/log-targets/{{id}}/pause"),
            post(log_targets::pause_log_target),
        )
        .route(
            &format!("{gateway}/log-targets/{{id}}/resume"),
            post(log_targets::resume_log_target),
        )
}

/// The proxy part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        pipelines::configure_pipeline,
        pipelines::list_pipelines,
        pipelines::get_pipeline,
        pipelines::rename_pipeline,
        pipelines::delete_pipeline,
        pipelines::activate_pipeline,
        pipelines::disable_pipeline,
        stages::add_stage,
        stages::reconfigure_stage,
        stages::remove_stage,
        stages::enable_stage,
        stages::disable_stage,
        stages::reorder_stages,
        stages::generate_canary_token,
        stages::upload_wasm_module,
        requests::search_requests,
        log_targets::create_log_target,
        log_targets::list_log_targets,
        log_targets::get_log_target,
        log_targets::change_log_target,
        log_targets::pause_log_target,
        log_targets::resume_log_target,
        log_targets::delete_log_target,
    ),
    components(schemas(
        CreatePipelineBody,
        RenamePipelineBody,
        CreatePipelineResponse,
        PipelineResponse,
        PipelineSummaryResponse,
        StageResponse,
        AddStageBody,
        ReconfigureStageBody,
        ReorderStagesBody,
        UploadWasmModuleBody,
        GeneratedCanaryTokenResponse,
        WasmModuleResponse,
        RequestRecordResponse,
        ConnectionCloseResponse,
        RecordSubjectResponse,
        DecidedByResponse,
        CreateLogTargetBody,
        ChangeLogTargetBody,
        LogTargetResponse,
    ))
)]
pub(crate) struct Document;
