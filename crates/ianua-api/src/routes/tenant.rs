//! Tenant endpoints: a tenant's life, its metrics overview, its settings,
//! copies of its setup into another tenant and the streams of its audit
//! records, under its organization.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::metrics::{
    ApiUsageMetricsResponse, AuthenticationMetricsResponse, CountMetricResponse,
    FailedAttemptsResponse, LatencyMetricResponse, MetricsWindowResponse, RateMetricResponse,
    SuccessRatePointResponse, TrendDirectionResponse, TrendResponse,
};
use crate::dto::tenant::audit_streams::{
    AuditStreamBody, AuditStreamCreatedResponse, AuditStreamResponse, StreamDestinationResponse,
    StreamHeaderBody, StreamTargetBody,
};
use crate::dto::tenant::clones::{CloneStartedResponse, StartCloneBody, TenantCloneResponse};
use crate::dto::tenant::lifecycle::{
    ApiKeysStatusResponse, EarlyDeletionBody, EarlyDeletionReason, ProvisionTenantBody,
    ProvisionTenantResponse, TenantCompanyOverview, TenantMetricsResponse, TenantResponse,
    TenantSetupResponse,
};
use crate::dto::tenant::proof::FreshProofBody;
use crate::dto::tenant::residency::{ResidencyBody, ResidencyResponse};
use crate::dto::tenant::settings::{
    AuthConfigBody, BreakGlassPolicyBody, ChangeComplianceBody, ChangeEnvironmentBody,
    ComplianceResponse, HostnameConfigResponse, MtlsConfigResponse, UpdateAuthConfigBody,
    UpdateMtlsConfigBody, UpdateTenantBody,
};
use crate::handlers::tenant::{audit_streams, clones, lifecycle, settings};
use crate::method::{get, post, put, shared};
use crate::state::ApiState;

/// The tenant endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let tenants = "/api/v1/organizations/{org_slug}/tenants";
    let tenant = format!("{tenants}/{{tenant_slug}}");
    Router::new()
        .route(
            tenants,
            post(lifecycle::provision_tenant).get(shared(lifecycle::list_tenants)),
        )
        .route(
            &tenant,
            get(lifecycle::get_tenant)
                .patch(shared(settings::update_tenant))
                .delete(shared(lifecycle::delete_tenant)),
        )
        .merge(lifecycle_routes(&tenant))
        .merge(settings_routes(&tenant))
        .merge(clone_routes())
        .merge(audit_stream_routes(&tenant))
}

/// Changes in tenant standing, deletion scheduling, and operational metrics.
fn lifecycle_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/activate"),
            post(lifecycle::activate_tenant),
        )
        .route(
            &format!("{tenant}/suspend"),
            post(lifecycle::suspend_tenant),
        )
        .route(
            &format!("{tenant}/reactivate"),
            post(lifecycle::reactivate_tenant),
        )
        .route(
            &format!("{tenant}/archive"),
            post(lifecycle::archive_tenant),
        )
        .route(
            &format!("{tenant}/restore"),
            post(lifecycle::restore_tenant),
        )
        .route(
            &format!("{tenant}/early-deletion"),
            post(lifecycle::delete_tenant_early),
        )
        .route(
            &format!("{tenant}/metrics"),
            get(lifecycle::get_tenant_metrics),
        )
}

/// Authentication, network identity, and compliance settings for a tenant.
fn settings_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/auth-config"),
            get(settings::get_auth_config).put(shared(settings::update_auth_config)),
        )
        .route(
            &format!("{tenant}/mtls"),
            get(settings::get_mtls_config).patch(shared(settings::update_mtls_config)),
        )
        .route(
            &format!("{tenant}/hostname"),
            get(settings::get_hostname_config),
        )
        .route(
            &format!("{tenant}/compliance"),
            get(settings::get_compliance).put(shared(settings::change_compliance)),
        )
        .route(
            &format!("{tenant}/break-glass-policy"),
            put(settings::change_break_glass_policy),
        )
        .route(
            &format!("{tenant}/environment"),
            put(settings::change_environment),
        )
}

/// Copying one tenant's setup into another, and following the copy.
fn clone_routes() -> Router<ApiState> {
    let clones_path = "/api/v1/organizations/{org_slug}/tenant-clones";
    Router::new()
        .route(clones_path, post(clones::start_clone))
        .route(
            &format!("{clones_path}/{{clone_id}}"),
            get(clones::get_clone),
        )
}

/// The streams of the audit records of the tenant at `tenant`.
fn audit_stream_routes(tenant: &str) -> Router<ApiState> {
    let streams = format!("{tenant}/audit-streams");
    let stream = format!("{streams}/{{stream_id}}");
    Router::new()
        .route(
            &streams,
            get(audit_streams::list_audit_streams).post(shared(audit_streams::create_audit_stream)),
        )
        .route(
            &stream,
            put(audit_streams::reconfigure_audit_stream)
                .delete(shared(audit_streams::remove_audit_stream)),
        )
        .route(
            &format!("{stream}/pause"),
            post(audit_streams::pause_audit_stream),
        )
        .route(
            &format!("{stream}/resume"),
            post(audit_streams::resume_audit_stream),
        )
}

/// The tenant part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        lifecycle::provision_tenant,
        lifecycle::list_tenants,
        lifecycle::get_tenant,
        lifecycle::activate_tenant,
        lifecycle::suspend_tenant,
        lifecycle::reactivate_tenant,
        lifecycle::archive_tenant,
        lifecycle::restore_tenant,
        lifecycle::delete_tenant,
        lifecycle::delete_tenant_early,
        lifecycle::get_tenant_metrics,
        settings::update_tenant,
        settings::get_auth_config,
        settings::update_auth_config,
        settings::get_mtls_config,
        settings::update_mtls_config,
        settings::get_hostname_config,
        settings::get_compliance,
        settings::change_compliance,
        settings::change_break_glass_policy,
        settings::change_environment,
        clones::start_clone,
        clones::get_clone,
        audit_streams::list_audit_streams,
        audit_streams::create_audit_stream,
        audit_streams::reconfigure_audit_stream,
        audit_streams::pause_audit_stream,
        audit_streams::resume_audit_stream,
        audit_streams::remove_audit_stream,
    ),
    components(schemas(
        ProvisionTenantBody,
        ProvisionTenantResponse,
        ResidencyBody,
        ResidencyResponse,
        TenantResponse,
        TenantSetupResponse,
        EarlyDeletionBody,
        EarlyDeletionReason,
        TenantMetricsResponse,
        TenantCompanyOverview,
        ApiKeysStatusResponse,
        MetricsWindowResponse,
        AuthenticationMetricsResponse,
        ApiUsageMetricsResponse,
        CountMetricResponse,
        RateMetricResponse,
        LatencyMetricResponse,
        FailedAttemptsResponse,
        SuccessRatePointResponse,
        TrendResponse,
        TrendDirectionResponse,
        UpdateTenantBody,
        AuthConfigBody,
        UpdateAuthConfigBody,
        MtlsConfigResponse,
        UpdateMtlsConfigBody,
        HostnameConfigResponse,
        ComplianceResponse,
        ChangeComplianceBody,
        BreakGlassPolicyBody,
        FreshProofBody,
        ChangeEnvironmentBody,
        StartCloneBody,
        CloneStartedResponse,
        TenantCloneResponse,
        AuditStreamBody,
        StreamTargetBody,
        StreamHeaderBody,
        AuditStreamCreatedResponse,
        AuditStreamResponse,
        StreamDestinationResponse,
    ))
)]
pub(crate) struct Document;
