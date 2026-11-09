//! Domain certificate handlers: asking for a verified domain's TLS
//! certificate, and uploading, replacing and removing the tenant's own.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use ianua_app::use_case::Command as _;
use ianua_assembly::domain::DomainState;

use crate::dto::domain::certificates::{CertificateResponse, UploadCertificateBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::domain::DomainPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/provision-tls",
    tag = "Domains",
    responses(
        (status = 202, description = "Certificate requested; issued in the background"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Domain not verified, or certificate already active", body = ErrorBody)
    )
)]
/// Request a TLS certificate
///
/// Returns `202` while the worker moves TLS from `Provisioning` to `Active`;
/// poll the domain for completion. `SelfManaged` uses HTTP-01 on its hostname;
/// `Delegated` uses DNS-01 in our zone, allowing automatic renewal and wildcards.
/// Requires `Domains(Update)`. Missing domains return `404`; unverified
/// domains or already-active certificates return `409`. Records
/// `tenant.domain_tls_requested`, then `tenant.domain_tls_provisioned` on issue.
pub(crate) async fn provision_tls(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
) -> Result<StatusCode, ApiError> {
    domains
        .certificates
        .request
        .execute(&tenant.caller, &tenant.auditor, path.domain())
        .await?;
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/certificate",
    tag = "Domains",
    request_body = UploadCertificateBody,
    responses(
        (status = 200, description = "The certificate now serving", body = CertificateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Domain not verified, or the certificate does not name it or is not valid now", body = ErrorBody),
        (status = 422, description = "Unreadable chain or key, or a key that is not the certificate's", body = ErrorBody)
    )
)]
/// Upload or replace a domain's certificate
///
/// Serves a certificate the tenant brings itself on a verified domain: the
/// chain, leaf first, and the leaf's private key, both PEM. It takes the
/// place of whatever serves the name now, issued through ACME or uploaded
/// before, and the replaced one is dropped so nothing renews over it. The
/// tenant renews an uploaded certificate by uploading another, and is
/// warned as it nears its end.
///
/// Answers what the certificate says about itself (issuer, names, validity)
/// and never the key, which is sealed when stored. `409` when the domain is
/// not `Verified`, or the certificate does not name it or is not valid now;
/// `422` when the chain or key cannot be read or do not belong together.
/// Records `tenant.domain_certificate_uploaded`, or
/// `tenant.domain_certificate_replaced` when one was serving already.
///
/// Requires `Domains(Update)`.
pub(crate) async fn upload_certificate(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
    Json(body): Json<UploadCertificateBody>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let detail = domains
        .certificates
        .upload
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.upload_for(path.domain())?,
        )
        .await?;
    Ok(Json(CertificateResponse::from(detail)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/certificate",
    tag = "Domains",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such domain, or it serves no certificate", body = ErrorBody),
        (status = 409, description = "The certificate serving was issued through ACME", body = ErrorBody)
    )
)]
/// Remove a domain's uploaded certificate
///
/// Stops serving the certificate the tenant uploaded for the domain. The
/// name then serves none, and its `tls_status` reads `NoCertificate`, until
/// the tenant uploads another or asks for one through ACME
/// (`provision-tls`). A certificate issued through ACME is the platform's
/// to replace (`409`). `404` when the domain is missing or serves no
/// certificate. Records `tenant.domain_certificate_removed`.
///
/// Requires `Domains(Update)`.
pub(crate) async fn remove_certificate(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
) -> Result<NoContent, ApiError> {
    domains
        .certificates
        .remove
        .execute(&tenant.caller, &tenant.auditor, path.domain())
        .await?;
    Ok(NoContent)
}
