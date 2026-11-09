//! Audit endpoints: the audit log of an organization, of a tenant and of
//! the whole platform, its exports, and a tenant's audit chain.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::audit::{
    AuditChainVerificationResponse, AuditExportAcceptedResponse, AuditExportBody,
    AuditExportFormatBody, AuditExportResponse, AuditLogEntryResponse,
};
use crate::handlers::audit as handlers;
use crate::method::{get, post};
use crate::state::ApiState;

/// The audit endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    organization_routes()
        .merge(tenant_routes())
        .merge(platform_routes())
        .route(
            "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit/verify",
            get(handlers::verify_audit_chain),
        )
}

/// Registers organization log reads and export requests.
fn organization_routes() -> Router<ApiState> {
    let log = "/api/v1/organizations/{org_slug}/audit-log";
    Router::new()
        .route(log, get(handlers::list_audit_log))
        .route(
            &format!("{log}/exports"),
            post(handlers::request_audit_log_export),
        )
        .route(
            &format!("{log}/exports/{{id}}"),
            get(handlers::get_audit_log_export),
        )
}

/// Registers tenant log reads and exports.
fn tenant_routes() -> Router<ApiState> {
    let tenant_log = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/audit-log";
    Router::new()
        .route(tenant_log, get(handlers::list_tenant_audit_log))
        .route(
            &format!("{tenant_log}/exports"),
            post(handlers::request_tenant_audit_log_export),
        )
        .route(
            &format!("{tenant_log}/exports/{{id}}"),
            get(handlers::get_tenant_audit_log_export),
        )
}

/// Registers platform log reads and exports under operator authority.
fn platform_routes() -> Router<ApiState> {
    let platform_log = "/api/v1/audit-log";
    Router::new()
        .route(platform_log, get(handlers::list_platform_audit_log))
        .route(
            &format!("{platform_log}/exports"),
            post(handlers::request_platform_audit_log_export),
        )
        .route(
            &format!("{platform_log}/exports/{{id}}"),
            get(handlers::get_platform_audit_log_export),
        )
}

/// The audit part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::list_audit_log,
        handlers::request_audit_log_export,
        handlers::get_audit_log_export,
        handlers::list_tenant_audit_log,
        handlers::request_tenant_audit_log_export,
        handlers::get_tenant_audit_log_export,
        handlers::list_platform_audit_log,
        handlers::request_platform_audit_log_export,
        handlers::get_platform_audit_log_export,
        handlers::verify_audit_chain,
    ),
    components(schemas(
        AuditLogEntryResponse,
        AuditChainVerificationResponse,
        AuditExportBody,
        AuditExportFormatBody,
        AuditExportAcceptedResponse,
        AuditExportResponse,
    ))
)]
pub(crate) struct Document;
