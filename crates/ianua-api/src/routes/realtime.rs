//! Live stream endpoints: notifications, the platform dashboard and
//! provisioning progress, over WebSocket.

use axum::Router;
use utoipa::OpenApi;

use crate::handlers::realtime as handlers;
use crate::method::get;
use crate::state::ApiState;

/// The live stream endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let org = "/api/v1/organizations/{org_slug}/ws";
    Router::new()
        .route("/api/v1/ws/notifications", get(handlers::platform_ws))
        .route("/api/v1/ws/dashboard", get(handlers::platform_dashboard))
        .route(&format!("{org}/notifications"), get(handlers::org_ws))
        .route(
            "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/ws/notifications",
            get(handlers::tenant_ws),
        )
        .route(&format!("{org}/workflows"), get(handlers::org_workflows_ws))
        .route(
            &format!("{org}/workflow/{{reference_id}}"),
            get(handlers::workflow_progress_ws),
        )
}

/// The live stream part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(paths(
    handlers::platform_ws,
    handlers::platform_dashboard,
    handlers::org_ws,
    handlers::tenant_ws,
    handlers::org_workflows_ws,
    handlers::workflow_progress_ws,
))]
pub(crate) struct Document;
