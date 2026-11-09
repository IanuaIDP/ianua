//! Activity endpoints: the contribution calendar of an organization and of
//! one tenant.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::activity::{ActivityCalendarResponse, ActivityDayResponse, CategoryCountResponse};
use crate::handlers::activity as handlers;
use crate::method::get;
use crate::state::ApiState;

/// The activity endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/organizations/{org_slug}/activity",
            get(handlers::org_activity),
        )
        .route(
            "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/activity",
            get(handlers::tenant_activity),
        )
}

/// The activity part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(handlers::org_activity, handlers::tenant_activity),
    components(schemas(ActivityCalendarResponse, ActivityDayResponse, CategoryCountResponse))
)]
pub(crate) struct Document;
