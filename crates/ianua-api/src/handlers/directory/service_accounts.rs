//! Service account handlers: the accounts applications such as Jira, GitLab
//! and SSSD bind to the tenant's directory as, instead of a person's
//! password.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::directory::service_accounts::{ChangeStatusRequest, DeleteRequest};
use ianua_assembly::directory::DirectoryState;
use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;

use crate::dto::directory::{
    CreateServiceAccountBody, CreatedServiceAccountResponse, ServiceAccountListResponse,
    ServiceAccountResponse, ServiceAccountScopeBody, ServiceAccountSecretResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::directory::ServiceAccountPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts",
    tag = "Authentication",
    request_body = CreateServiceAccountBody,
    responses(
        (status = 201, description = "Created, with its secret shown once", body = CreatedServiceAccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's limit is reached", body = ErrorBody),
        (status = 409, description = "Another account has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create an LDAP service account
///
/// Makes an active account an application binds to the directory as, with
/// what it may reach: `ReadOnly`, the only access, under one to sixteen
/// base DNs. The answer carries its `secret` this once; only its hash is kept.
/// Checked against the plan's limit. Records
/// `authentication.directory_service_account_created`.
pub(crate) async fn create_service_account(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Json(body): Json<CreateServiceAccountBody>,
) -> Result<Created<CreatedServiceAccountResponse>, ApiError> {
    let created = directory
        .service_accounts
        .create
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(created.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = ServiceAccountListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List LDAP service accounts
///
/// Every service account of the tenant, by name, with its scope and status.
/// Never a secret. Records nothing.
pub(crate) async fn list_service_accounts(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
) -> Result<Json<ServiceAccountListResponse>, ApiError> {
    let accounts = directory
        .service_accounts
        .list
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(accounts.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts/{account_id}",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = ServiceAccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody)
    )
)]
/// Get an LDAP service account
///
/// One service account with its scope and status. Never its secret.
/// Records nothing.
pub(crate) async fn get_service_account(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<ServiceAccountPath>,
) -> Result<Json<ServiceAccountResponse>, ApiError> {
    let account = directory
        .service_accounts
        .get
        .execute(&tenant.caller, path.account())
        .await?;
    Ok(Json(ServiceAccountResponse::from(&account)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts/{account_id}/scope",
    tag = "Authentication",
    request_body = ServiceAccountScopeBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change what an LDAP service account may reach
///
/// Replaces the account's access and base DNs. Connections bound before
/// read the new scope at their next request. Records
/// `authentication.directory_service_account_scope_changed`.
pub(crate) async fn change_service_account_scope(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<ServiceAccountPath>,
    Json(body): Json<ServiceAccountScopeBody>,
) -> Result<NoContent, ApiError> {
    directory
        .service_accounts
        .change_scope
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.account())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts/{account_id}/activate",
    tag = "Authentication",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Switch an LDAP service account on
///
/// `Disabled -> Active`: it binds again. Records
/// `authentication.directory_service_account_status_changed`.
pub(crate) async fn activate_service_account(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<ServiceAccountPath>,
) -> Result<NoContent, ApiError> {
    let request = ChangeStatusRequest {
        id: path.account(),
        status: ServiceAccountStatus::Active,
    };
    directory
        .service_accounts
        .change_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts/{account_id}/disable",
    tag = "Authentication",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Switch an LDAP service account off
///
/// `Active -> Disabled`: it binds no more, and connections bound before
/// stop counting at their next request. Records
/// `authentication.directory_service_account_status_changed`.
pub(crate) async fn disable_service_account(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<ServiceAccountPath>,
) -> Result<NoContent, ApiError> {
    let request = ChangeStatusRequest {
        id: path.account(),
        status: ServiceAccountStatus::Disabled,
    };
    directory
        .service_accounts
        .change_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts/{account_id}/rotate-secret",
    tag = "Authentication",
    responses(
        (status = 200, description = "The new secret, shown once", body = ServiceAccountSecretResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody)
    )
)]
/// Rotate an LDAP service account's secret
///
/// Gives the account a new secret, shown this once; every connection bound
/// with the old one stops counting at its next request. Records
/// `authentication.directory_service_account_secret_rotated`.
pub(crate) async fn rotate_service_account_secret(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<ServiceAccountPath>,
) -> Result<Json<ServiceAccountSecretResponse>, ApiError> {
    let secret = directory
        .service_accounts
        .rotate_secret
        .execute(&tenant.caller, &tenant.auditor, path.account())
        .await?;
    Ok(Json(secret.into()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-service-accounts/{account_id}",
    tag = "Authentication",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody)
    )
)]
/// Delete an LDAP service account
///
/// Removes the account; a connection bound as it reads nothing more from
/// its next search. Records
/// `authentication.directory_service_account_deleted`.
pub(crate) async fn delete_service_account(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<ServiceAccountPath>,
) -> Result<NoContent, ApiError> {
    directory
        .service_accounts
        .delete
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DeleteRequest { id: path.account() },
        )
        .await?;
    Ok(NoContent)
}
