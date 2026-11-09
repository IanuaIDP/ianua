//! Reference data endpoints: the locales and timezones the platform
//! accepts.

use axum::Router;
use utoipa::OpenApi;

use crate::handlers::reference as handlers;
use crate::method::get;
use crate::state::ApiState;

/// The reference data endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/locales", get(handlers::list_locales))
        .route("/api/v1/timezones", get(handlers::list_timezones))
}

/// The reference data part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(paths(handlers::list_locales, handlers::list_timezones))]
pub(crate) struct Document;
