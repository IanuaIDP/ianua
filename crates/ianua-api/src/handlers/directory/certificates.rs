//! LDAP client certificate handlers: what lets a person write to the
//! directory over LDAP.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::directory::DirectoryState;

use crate::dto::directory::{
    IssueLdapCertificateBody, IssuedLdapCertificateResponse, LdapCertificateListResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::directory::LdapCertificatePath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-certificates",
    tag = "Authentication",
    request_body = IssueLdapCertificateBody,
    responses(
        (status = 200, description = "Certificate issued", body = IssuedLdapCertificateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The proof did not prove who they are", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Issue an LDAP client certificate
///
/// Signs a certificate from a signing request made on the device: the
/// private key never leaves it. A person binds to the LDAP directory only
/// over a connection presenting this certificate, with their password; a
/// password alone binds nobody. Issuing one is as sensitive as changing a
/// password, so the
/// body carries a fresh `proof` (password, mailbox link or passkey). The
/// PEM is answered once and not kept for showing again. Requires a tenant
/// user's own session.
pub(crate) async fn issue_ldap_certificate(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Json(body): Json<IssueLdapCertificateBody>,
) -> Result<Json<IssuedLdapCertificateResponse>, ApiError> {
    let issued = directory
        .issue_certificate
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(issued.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-certificates",
    tag = "Authentication",
    responses(
        (status = 200, description = "The caller's LDAP client certificates", body = LdapCertificateListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody)
    )
)]
/// List my LDAP client certificates
///
/// The caller's own certificates, as recorded when issued: label, validity
/// and whether revoked. Never the PEM. Requires a tenant user's own
/// session.
pub(crate) async fn list_ldap_certificates(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
) -> Result<Json<LdapCertificateListResponse>, ApiError> {
    let certificates = directory
        .list_certificates
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(certificates.into()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/ldap-certificates/{certificate_id}",
    tag = "Authentication",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Revoke an LDAP client certificate
///
/// Ends the certificate's power to authenticate LDAP writes at once. A
/// certificate of someone else's answers `404`, as one that does not exist
/// does. Records `authentication.ldap_certificate_revoked`.
pub(crate) async fn revoke_ldap_certificate(
    State(directory): State<DirectoryState>,
    tenant: TenantCaller,
    Path(path): Path<LdapCertificatePath>,
) -> Result<NoContent, ApiError> {
    directory
        .revoke_certificate
        .execute(&tenant.caller, &tenant.auditor, path.certificate())
        .await?;
    Ok(NoContent)
}
