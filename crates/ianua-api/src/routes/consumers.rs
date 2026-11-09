//! Consumer endpoints: a tenant's machine identities.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::consumers::{
    ChangeClearanceBody, ChangeCredentialExpiryBody, ChangeQuotaBody, ConsumerResponse,
    CreateConsumerBody, CreateConsumerResponse, CredentialBody, DescribeConsumerBody,
    PreviousCredentialResponse, QuotaBody, QuotaPeriodBody, RenameConsumerBody,
    RotateCredentialBody, RotatedCredentialResponse,
};
use crate::handlers::consumers as handlers;
use crate::method::{get, post, put, shared};
use crate::state::ApiState;

/// The consumer endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let consumers = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/consumers";
    lifecycle_routes(consumers)
        .merge(credential_routes(consumers))
        .merge(settings_routes(consumers))
}

/// Registers consumer creation, clearance and lifecycle changes.
fn lifecycle_routes(consumers: &str) -> Router<ApiState> {
    Router::new()
        .route(
            consumers,
            post(handlers::create_consumer).get(shared(handlers::list_consumers)),
        )
        .route(
            &format!("{consumers}/{{id}}"),
            get(handlers::get_consumer)
                .patch(shared(handlers::rename_consumer))
                .delete(shared(handlers::delete_consumer)),
        )
        .route(
            &format!("{consumers}/{{id}}/clearance"),
            put(handlers::change_clearance),
        )
        .route(
            &format!("{consumers}/{{id}}/disable"),
            post(handlers::disable_consumer),
        )
        .route(
            &format!("{consumers}/{{id}}/enable"),
            post(handlers::enable_consumer),
        )
}

/// Registers credential rotation, overlap and expiry changes.
fn credential_routes(consumers: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{consumers}/{{id}}/rotate"),
            post(handlers::rotate_credential),
        )
        .route(
            &format!("{consumers}/{{id}}/end-overlap"),
            post(handlers::end_credential_overlap),
        )
        .route(
            &format!("{consumers}/{{id}}/expiry"),
            put(handlers::change_credential_expiry),
        )
}

/// Registers consumer quota and description changes.
fn settings_routes(consumers: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{consumers}/{{id}}/quota"),
            put(handlers::change_quota),
        )
        .route(
            &format!("{consumers}/{{id}}/description"),
            put(handlers::describe_consumer),
        )
}

/// The consumer part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::create_consumer,
        handlers::list_consumers,
        handlers::get_consumer,
        handlers::rename_consumer,
        handlers::change_clearance,
        handlers::disable_consumer,
        handlers::enable_consumer,
        handlers::rotate_credential,
        handlers::end_credential_overlap,
        handlers::change_credential_expiry,
        handlers::change_quota,
        handlers::describe_consumer,
        handlers::delete_consumer,
    ),
    components(schemas(
        CreateConsumerBody,
        CreateConsumerResponse,
        CredentialBody,
        ConsumerResponse,
        PreviousCredentialResponse,
        QuotaBody,
        QuotaPeriodBody,
        RenameConsumerBody,
        DescribeConsumerBody,
        ChangeClearanceBody,
        ChangeCredentialExpiryBody,
        ChangeQuotaBody,
        RotateCredentialBody,
        RotatedCredentialResponse,
    ))
)]
pub(crate) struct Document;
