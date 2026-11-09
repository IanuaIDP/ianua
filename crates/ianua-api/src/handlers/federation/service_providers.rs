//! SAML app handlers: the outside services a tenant's people sign in to,
//! with this platform as their identity provider. Adding, reading,
//! changing, switching and removing them.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::federation::service_providers::ChangeStatusRequest;
use ianua_assembly::federation::FederationState;
use ianua_domain::domains::federation::connection_status::ConnectionStatus;

use crate::dto::federation::service_providers::{
    CreateSamlAppBody, CreateSamlAppResponse, SamlAppResponse, UpdateSamlAppBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::federation::SamlAppPath;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps",
    tag = "SAML IdP",
    request_body = CreateSamlAppBody,
    responses(
        (status = 201, description = "Created", body = CreateSamlAppResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's limit is reached", body = ErrorBody),
        (status = 409, description = "Another app has the entity id", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Add a SAML app
///
/// Adds an active app people sign in to with this tenant as their identity
/// provider: its `entity_id`, the `acs_urls` its assertions may be posted
/// to (the first is the default), an optional `logout_url` for single
/// logout, the `name_id_format` (`persistent`, `email_address` or
/// `transient`), the `attributes` it is sent and under which names, what is
/// signed (`assertion` or `assertion_and_response`), and optionally the
/// certificates its assertions are encrypted to and its requests must be
/// signed with. Checked against the plan's limit. Records
/// `federation.service_provider_created`.
pub(crate) async fn create_saml_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Json(body): Json<CreateSamlAppBody>,
) -> Result<Created<CreateSamlAppResponse>, ApiError> {
    let id = federation
        .apps
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(CreateSamlAppResponse { id }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps",
    tag = "SAML IdP",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<SamlAppResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List SAML apps
///
/// The tenant's SAML apps, newest first, paginated. Records nothing.
pub(crate) async fn list_saml_apps(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<SamlAppResponse>>, ApiError> {
    let page = federation
        .apps
        .list
        .execute(&tenant.caller, pagination)
        .await?;
    Ok(Json(PageResponse::from_page(page, SamlAppResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps/{app_id}",
    tag = "SAML IdP",
    responses(
        (status = 200, description = "Success", body = SamlAppResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such app", body = ErrorBody)
    )
)]
/// Get a SAML app
///
/// One app with everything it is set up with. Records nothing.
pub(crate) async fn get_saml_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<SamlAppPath>,
) -> Result<Json<SamlAppResponse>, ApiError> {
    let app = federation
        .apps
        .get
        .execute(&tenant.caller, path.app())
        .await?;
    Ok(Json(app.into()))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps/{app_id}",
    tag = "SAML IdP",
    request_body = UpdateSamlAppBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such app", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a SAML app
///
/// Partial update: send any of the fields an app is added with; omit one
/// to leave it, and send `null` to clear `logout_url`,
/// `encryption_certificate` or `request_signing_certificate`. A change
/// that sends the app more of a person, sends it to more places or checks
/// it less needs the full federation right. Records
/// `federation.service_provider_updated` once.
pub(crate) async fn update_saml_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<SamlAppPath>,
    Json(body): Json<UpdateSamlAppBody>,
) -> Result<NoContent, ApiError> {
    federation
        .apps
        .update
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.changes_to(path.app())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps/{app_id}/activate",
    tag = "SAML IdP",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such app", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Switch a SAML app on
///
/// `Disabled -> Active`: sign-ins to it are answered again. Needs the full
/// federation right. Records `federation.service_provider_updated`.
pub(crate) async fn activate_saml_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<SamlAppPath>,
) -> Result<NoContent, ApiError> {
    let request = ChangeStatusRequest {
        id: path.app(),
        status: ConnectionStatus::Active,
    };
    federation
        .apps
        .change_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps/{app_id}/disable",
    tag = "SAML IdP",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such app", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Switch a SAML app off
///
/// `Active -> Disabled`: no more sign-ins to it are answered, which anyone
/// who may update connections may do in an incident. Records
/// `federation.service_provider_updated`.
pub(crate) async fn disable_saml_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<SamlAppPath>,
) -> Result<NoContent, ApiError> {
    let request = ChangeStatusRequest {
        id: path.app(),
        status: ConnectionStatus::Disabled,
    };
    federation
        .apps
        .change_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/saml/apps/{app_id}",
    tag = "SAML IdP",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such app", body = ErrorBody)
    )
)]
/// Remove a SAML app
///
/// Removes the app; sign-ins to it are no longer answered. Records
/// `federation.service_provider_deleted`.
pub(crate) async fn delete_saml_app(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<SamlAppPath>,
) -> Result<NoContent, ApiError> {
    federation
        .apps
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.app())
        .await?;
    Ok(NoContent)
}
