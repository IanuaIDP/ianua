//! Gateway configuration endpoints: export, apply, and drafting a
//! configuration from an OpenAPI 3 document.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::gateway::edge::{
    ConsumerConfigBody, ConsumerCredentialConfigBody, EgressPolicyConfigBody,
    StreamAccessConfigBody, StreamRouteConfigBody,
};
use crate::dto::gateway::openapi::OpenApiImportBody;
use crate::dto::gateway::{
    ApplyPlanBody, ConfigDiffResponse, GatewayConfigBody, ImportConfigBody, ImportModeBody,
    PipelineConfigBody, ResourceChangeResponse, RouteConfigBody, ServiceConfigBody,
    StageConfigBody,
};
use crate::handlers::gateway as handlers;
use crate::method::{get, post, shared};
use crate::state::ApiState;

/// The gateway configuration endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let config = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/config";
    Router::new()
        .route(
            config,
            get(handlers::export_config).post(shared(handlers::import_config)),
        )
        .route(
            &format!("{config}/openapi"),
            post(handlers::convert_openapi),
        )
}

/// The gateway configuration part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::export_config,
        handlers::import_config,
        handlers::convert_openapi,
    ),
    components(schemas(
        GatewayConfigBody,
        ServiceConfigBody,
        PipelineConfigBody,
        StageConfigBody,
        RouteConfigBody,
        StreamRouteConfigBody,
        StreamAccessConfigBody,
        EgressPolicyConfigBody,
        ConsumerConfigBody,
        ConsumerCredentialConfigBody,
        ImportConfigBody,
        ImportModeBody,
        ApplyPlanBody,
        ConfigDiffResponse,
        ResourceChangeResponse,
        OpenApiImportBody,
    ))
)]
pub(crate) struct Document;
