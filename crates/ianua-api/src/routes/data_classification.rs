//! Data classification endpoints: a tenant's field-level sensitivity rules.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::data_classification::{
    AddRuleBody, ChangeRuleBody, ClassificationResponse, ClassificationRuleResponse,
};
use crate::handlers::data_classification as handlers;
use crate::method::{get, post, put, shared};
use crate::state::ApiState;

/// The data classification endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let base = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/classification";
    Router::new()
        .route(base, get(handlers::get_classification))
        .route(&format!("{base}/rules"), post(handlers::add_rule))
        .route(
            &format!("{base}/rules/{{id}}"),
            put(handlers::change_rule).delete(shared(handlers::remove_rule)),
        )
}

/// The data classification part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_classification,
        handlers::add_rule,
        handlers::change_rule,
        handlers::remove_rule,
    ),
    components(schemas(
        AddRuleBody,
        ChangeRuleBody,
        ClassificationRuleResponse,
        ClassificationResponse
    ))
)]
pub(crate) struct Document;
