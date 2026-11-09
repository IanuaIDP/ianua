//! File endpoints: an export downloaded through its link, a tenant's logo,
//! the files the platform publishes: its mail logo and its AWS connect
//! template, and the pictures installed integrations carry. All are
//! public; the download carries the per-address limit of the public link
//! steps, since anyone may try a link.

use axum::Router;
use utoipa::OpenApi;

use crate::handlers::files;
use crate::method::get;
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The file endpoints, the download held to the sensitive window per
/// address, built with the deployment's windows from `state`.
pub(crate) fn routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sensitive;
    let limiter = per_address(state, window.max, window.window);
    let downloads = Router::new()
        .route("/api/v1/files/download/{token}", get(files::download))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit));
    Router::new()
        .route("/api/v1/files/logos/{key}", get(files::logo))
        .route(
            "/api/v1/files/integrations/{integration}/picture.svg",
            get(files::integration_picture),
        )
        .route("/email-logo.png", get(files::email_logo))
        .route(
            "/.well-known/ianua/aws-connect.yaml",
            get(files::aws_trust_template),
        )
        .merge(downloads)
}

/// The file part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(paths(
    files::download,
    files::logo,
    files::integration_picture,
    files::email_logo,
    files::aws_trust_template
))]
pub(crate) struct Document;
