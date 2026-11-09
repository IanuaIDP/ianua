//! Tenant settings handlers: the general settings, how the tenant's users
//! sign in, its mTLS trust anchor, the names it is reached on, its
//! compliance posture, its break-glass policy and its environment.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::tenant::TenantState;

use crate::dto::tenant::settings::{
    AuthConfigBody, BreakGlassPolicyBody, ChangeComplianceBody, ChangeEnvironmentBody,
    ComplianceResponse, HostnameConfigResponse, MtlsConfigResponse, UpdateAuthConfigBody,
    UpdateMtlsConfigBody, UpdateTenantBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::response::NoContent;

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}",
    tag = "Tenants",
    request_body = UpdateTenantBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Update tenant settings
///
/// Partial update: send any of `display_name`, `contact_email`,
/// `timezone`, `locale`, `primary_domain` and `readable_address` to change just those; omit a
/// field to leave it. The primary domain must be one the tenant has
/// registered and proved (`422` otherwise). The token issuer changes with
/// the authentication configuration, not here. Records `tenant.renamed`,
/// `tenant.contact_email_changed`, `tenant.timezone_changed`,
/// `tenant.locale_changed` and `tenant.primary_domain_changed` for what
/// changed.
///
/// `readable_address` defaults to false. True explicitly publishes the tenant
/// and organization names in DNS and public certificate transparency logs;
/// false withdraws serving without erasing that public history. Null is
/// refused. Enabling requires nested platform addressing. Each actual change
/// records `tenant.readable_address_changed`.
///
/// Requires `TenantSettings(Update)`.
pub(crate) async fn update_tenant(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<UpdateTenantBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .settings
        .update
        .execute(
            &caller.caller,
            &caller.auditor,
            body.into_request(&tenant.domain_limits)?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth-config",
    tag = "Tenants",
    responses(
        (status = 200, description = "Success", body = AuthConfigBody),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the tenant's authentication configuration
///
/// Everything about how this tenant's users sign in: the methods allowed,
/// the password rules, the MFA policy, session and idle lifetimes, the
/// lockout threshold, self-registration, the IP allowlist, the token
/// issuer and the step-up policy.
///
/// A tenant that has never changed it gets the defaults: password only,
/// 12 characters with upper, lower and a digit, MFA off, 8-hour sessions,
/// 10 attempts then a 15-minute lockout, and a relaxed step-up policy.
///
/// Read-only. Requires `AuthConfig(View)`.
pub(crate) async fn get_auth_config(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
) -> Result<Json<AuthConfigBody>, ApiError> {
    let config = tenant
        .settings
        .get_auth_config
        .execute(&caller.caller, ())
        .await?;
    Ok(Json(AuthConfigBody::from(&config)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth-config",
    tag = "Tenants",
    request_body = UpdateAuthConfigBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Replace the tenant's authentication configuration
///
/// Replaces all fields together. Requires a session and fresh `proof`: password
/// with second-factor `code`, mailed sign-in link or passkey answer. API keys
/// and invalid proof give `403`. Remembered devices matter only with `require_mfa_new_device`.
///
/// `mfa_policy: Required` demands a factor immediately; removing `enabled_methods`
/// stops those sign-ins. Refuses changes that shut out the current sign-in.
/// Password rules apply at the next change/reset, not to existing passwords.
///
/// Returns `422` when the configuration contradicts itself: no method
/// enabled, a password floor below 8, an idle timeout outlasting its
/// session, a lockout threshold under 2, or a sensitive assurance level
/// below the ordinary one. Records `tenant.auth_config_updated`.
///
/// Requires `AuthConfig(Update)`.
pub(crate) async fn update_auth_config(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<UpdateAuthConfigBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .settings
        .update_auth_config
        .execute(&caller.caller, &caller.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/mtls",
    tag = "Tenants",
    responses(
        (status = 200, description = "Success", body = MtlsConfigResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the tenant's mTLS trust anchor
///
/// Returns the tenant's mTLS mode and trusted CA certificates. A tenant
/// that never configured this returns `Disabled` with an empty CA list.
/// Read-only. Requires `Mtls(View)`.
pub(crate) async fn get_mtls_config(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
) -> Result<Json<MtlsConfigResponse>, ApiError> {
    let config = tenant.settings.get_mtls.execute(&caller.caller, ()).await?;
    Ok(Json(MtlsConfigResponse::from(&config)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/mtls",
    tag = "Tenants",
    request_body = UpdateMtlsConfigBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Replace the tenant's mTLS trust anchor
///
/// Full replace, not a partial update: send the complete `mode` and
/// `trusted_ca_certs` list, the `revocation_lists` to check client
/// certificates against (none to check no revocation), plus `proof`, the
/// caller's own sign-in typed again. Each certificate must be a well-formed
/// PEM X.509 certificate and each list a well-formed PEM `X509 CRL`
/// (`422` otherwise); lists with `mode` `Disabled` are `422` too. Once
/// lists are given, a client certificate is refused in the handshake when
/// revoked, when no list covers its issuer, or once a list is past its
/// next update, so replace them before they expire. A change made with an
/// API key, or with a proof that does not hold, is `403`. Records
/// `tenant.mtls_config_updated`.
///
/// Requires `Mtls(Update)`.
pub(crate) async fn update_mtls_config(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<UpdateMtlsConfigBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .settings
        .update_mtls
        .execute(&caller.caller, &caller.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/hostname",
    tag = "Tenants",
    responses(
        (status = 200, description = "Success", body = HostnameConfigResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Tenant hostname configuration
///
/// Returns the permanent `platform_label` and consent in `readable_address`.
/// The historical `uuid_subdomain` key carries the random hostname, or an
/// empty string when platform addresses are off. `slug_subdomain` contains a
/// name only with readable consent on a nested deployment. Also returns
/// the `custom_domain` / `primary_domain` when one is primary, and the
/// `jwt_issuer` when the tenant set one of its own. Read-only.
///
/// Requires `TenantSettings(View)`.
pub(crate) async fn get_hostname_config(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
) -> Result<Json<HostnameConfigResponse>, ApiError> {
    let hostnames = tenant
        .settings
        .get_hostnames
        .execute(&caller.caller, ())
        .await?;
    Ok(Json(HostnameConfigResponse::new(
        &hostnames,
        &tenant.base_domain,
        tenant.platform_addressing,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/compliance",
    tag = "Tenants",
    responses(
        (status = 200, description = "Success", body = ComplianceResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the tenant's compliance posture
///
/// Where the tenant's data must stay (`data_residency`, `null` for
/// anywhere), how many days its audit records are kept, and whether
/// operators may act as its users. Read-only.
///
/// Requires `Compliance(View)`.
pub(crate) async fn get_compliance(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
) -> Result<Json<ComplianceResponse>, ApiError> {
    let posture = tenant
        .settings
        .get_compliance
        .execute(&caller.caller, ())
        .await?;
    Ok(Json(ComplianceResponse::from(&posture)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/compliance",
    tag = "Tenants",
    request_body = ChangeComplianceBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Replace the tenant's compliance posture
///
/// Full replace: where the tenant's data must stay (`null` for anywhere),
/// how many days audit records are kept, and whether operators may act as
/// its users, plus `proof`, the caller's own sign-in typed again. A
/// retention outside the deployment's range, a residency the deployment
/// does not allow or the tenant's data is not placed in, or a closed
/// tenant, is `422`. A change made with an API key, or with a proof that
/// does not hold, is `403`; a proof missing the code of the caller's
/// second factor is `403` asking for a step-up. Records
/// `tenant.compliance_changed` with the posture before and after.
///
/// Requires `Compliance(Update)`.
pub(crate) async fn change_compliance(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<ChangeComplianceBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .settings
        .change_compliance
        .execute(&caller.caller, &caller.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/break-glass-policy",
    tag = "Tenants",
    request_body = BreakGlassPolicyBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change the tenant's break-glass policy
///
/// Decides what the tenant's users may give themselves in an emergency,
/// with nobody else approving: the built-in and custom permissions listed,
/// or nothing at all when both lists are empty, in which case every
/// emergency grant needs someone else's approval. A tenant starts letting
/// nothing.
///
/// Letting every user give themselves an access hands it to each of them,
/// and taking it away takes it from each of them, so the caller must hold
/// both what was let and what will be (`403` otherwise). Records
/// `authorization.break_glass_policy_changed`.
pub(crate) async fn change_break_glass_policy(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<BreakGlassPolicyBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .settings
        .change_break_glass
        .execute(&caller.caller, &caller.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/environment",
    tag = "Tenants",
    request_body = ChangeEnvironmentBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change the tenant's environment
///
/// Labels the tenant as the `production`, `staging` or `development`
/// stage of the product it serves. The label is shown with the tenant
/// (`environment`) and changes nothing else about it. A closed tenant is
/// refused (`422`), and so is a name that is no stage. Records
/// `tenant.environment_changed` with both labels.
///
/// Requires the right to change the tenant's settings.
pub(crate) async fn change_environment(
    State(tenant): State<TenantState>,
    caller: TenantCaller,
    Json(body): Json<ChangeEnvironmentBody>,
) -> Result<NoContent, ApiError> {
    tenant
        .settings
        .change_environment
        .execute(&caller.caller, &caller.auditor, body.environment()?)
        .await?;
    Ok(NoContent)
}
