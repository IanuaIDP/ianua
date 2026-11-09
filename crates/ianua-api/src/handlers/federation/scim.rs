//! SCIM switch handlers: whether a tenant's SCIM endpoint is set up,
//! turning it on and off, rotating its bearer token, and its settings.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::federation::FederationState;

use crate::dto::federation::scim::{ScimSettingsBody, ScimStatusResponse, ScimTokenResponse};
use crate::dto::federation::site::FederationSite;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/scim",
    tag = "Federation",
    responses(
        (status = 200, description = "Success", body = ScimStatusResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Get SCIM provisioning status
///
/// Whether SCIM was ever set up (`configured`) and takes requests now
/// (`enabled`), when a directory last synced, the SCIM base path to give the
/// directory, and the settings once set up. Never the token. Records
/// nothing.
pub(crate) async fn get_scim_status(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    site: FederationSite,
) -> Result<Json<ScimStatusResponse>, ApiError> {
    let status = federation.scim.get.execute(&tenant.caller, ()).await?;
    Ok(Json(ScimStatusResponse::new(status, site.scim_path())))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/scim",
    tag = "Federation",
    responses(
        (status = 201, description = "Created", body = ScimTokenResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Already on", body = ErrorBody)
    )
)]
/// Enable SCIM provisioning
///
/// Turns on the tenant's SCIM endpoint. The first time, it returns the
/// bearer token an identity provider or HR system uses to push users in:
/// the raw token is shown once, only its hash is stored, so store it
/// immediately. Switched on again later, the endpoint keeps the token it
/// had and `bearer_token` is `null`; rotate the token to get a new one.
/// Returns `422` if SCIM is already on. Records `federation.scim_enabled`.
pub(crate) async fn enable_scim(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
) -> Result<Created<ScimTokenResponse>, ApiError> {
    let switched = federation
        .scim
        .enable
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Created(ScimTokenResponse::from(switched)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/scim",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "SCIM was never set up", body = ErrorBody),
        (status = 422, description = "Already off", body = ErrorBody)
    )
)]
/// Disable SCIM provisioning
///
/// Turns off the SCIM endpoint: incoming SCIM requests are refused. The
/// configuration and token hash are kept, so it can be switched on again.
/// Returns `404` if SCIM was never set up, or `422` if it is already off.
/// Records `federation.scim_disabled`.
pub(crate) async fn disable_scim(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
) -> Result<NoContent, ApiError> {
    federation
        .scim
        .disable
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/scim/rotate-token",
    tag = "Federation",
    responses(
        (status = 200, description = "Success", body = ScimTokenResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "SCIM was never set up", body = ErrorBody)
    )
)]
/// Rotate the SCIM bearer token
///
/// Issues a new SCIM bearer token and invalidates the old one at once. The
/// new token is shown once; store it right away and update the external
/// system. Returns `404` if SCIM was never set up. Records
/// `federation.scim_token_rotated`.
pub(crate) async fn rotate_scim_token(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
) -> Result<Json<ScimTokenResponse>, ApiError> {
    let token = federation
        .scim
        .rotate_token
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Json(ScimTokenResponse::from(token)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/scim/settings",
    tag = "Federation",
    request_body = ScimSettingsBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "SCIM is not set up, or the role does not exist", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update SCIM settings
///
/// Sets the role every SCIM-created user starts with, whether those users
/// are active at once, and whether a user the identity provider removes is
/// deactivated or deleted. An address SCIM sends is never verified: the
/// person confirms it by link. Records `federation.scim_settings_updated`.
pub(crate) async fn update_scim_settings(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Json(body): Json<ScimSettingsBody>,
) -> Result<NoContent, ApiError> {
    federation
        .scim
        .update_settings
        .execute(&tenant.caller, &tenant.auditor, body.into())
        .await?;
    Ok(NoContent)
}
