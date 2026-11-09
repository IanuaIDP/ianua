//! SAML connection handlers: the service provider metadata an
//! administrator imports into the provider, the provider's certificate
//! rollover, and the key its assertions are sealed to.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::federation::FederationState;

use crate::dto::federation::encryption::{EncryptionCertificateResponse, EncryptionKeyBody};
use crate::dto::federation::idp::SamlMetadata;
use crate::dto::federation::site::FederationSite;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::federation::ConnectionSite;
use crate::extractors::json::Json;
use crate::extractors::paths::federation::ConnectionPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/saml/metadata",
    tag = "Federation",
    responses(
        (status = 200, description = "SAML metadata", content_type = "application/samlmetadata+xml", body = String),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant or connection, or no signing key for signed requests", body = ErrorBody),
        (status = 409, description = "Not a SAML connection", body = ErrorBody)
    )
)]
/// SAML service provider metadata of a connection
///
/// The document an administrator imports into their identity provider so
/// it knows this platform's entity id, where to post its answers and send
/// logouts for this connection, the certificate its sign-in requests are
/// signed with when the connection signs them, and the certificate to
/// encrypt assertions to when it takes only encrypted ones. It asks for the
/// persistent `NameID` format. Public: an identity provider fetches it
/// before any trust exists. Records nothing.
pub(crate) async fn sp_metadata(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    site: FederationSite,
    Path(path): Path<ConnectionPath>,
) -> Result<SamlMetadata, ApiError> {
    let xml = federation
        .connections
        .sp_metadata
        .execute(&tenant.tenant, site.sp_metadata(path.connection())?)
        .await?;
    Ok(SamlMetadata::service_provider(xml))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/certificate/roll-over",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody),
        (status = 409, description = "Not a SAML connection, or no next certificate is set", body = ErrorBody)
    )
)]
/// Roll a SAML connection over to its next certificate
///
/// Once the provider signs with its new key, the `next_certificate` set in
/// the connection's configuration becomes its only one, and the old
/// certificate signs nobody in any more. Records
/// `federation.connection_updated`.
pub(crate) async fn roll_over_certificate(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .roll_over_certificate
        .execute(&tenant.caller, &tenant.auditor, path.connection())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/encrypted-assertions",
    tag = "Federation",
    request_body = EncryptionKeyBody,
    responses(
        (status = 200, description = "The certificate to give the provider", body = EncryptionCertificateResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody),
        (status = 409, description = "Not a SAML connection", body = ErrorBody),
        (status = 422, description = "The certificate is not PEM, or the private key does not match it", body = ErrorBody)
    )
)]
/// Require encrypted assertions
///
/// Makes the SAML connection refuse readable assertions and take only ones
/// its provider encrypted to this platform, so the browser they pass
/// through cannot read them. The key pair is made here (an empty body `{}`)
/// or brought by the tenant (`certificate` and `private_key`, PEM); the
/// private key is only ever stored sealed and never shown. Returns the certificate to give the
/// provider; it replaces any key the connection held. Records
/// `federation.connection_updated`.
pub(crate) async fn require_encrypted_assertions(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    ConnectionSite { site, path }: ConnectionSite,
    Json(body): Json<EncryptionKeyBody>,
) -> Result<Json<EncryptionCertificateResponse>, ApiError> {
    let request = body.for_connection(path.connection(), site.sp_entity_id()?)?;
    let certificate = federation
        .connections
        .require_encrypted_assertions
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(certificate.into()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/encrypted-assertions",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody),
        (status = 409, description = "Not a SAML connection", body = ErrorBody)
    )
)]
/// Accept readable assertions again
///
/// Makes the SAML connection take readable assertions and drops its
/// decryption key. Assertions then pass through the browser readable, so
/// this needs the full federation right. Records
/// `federation.connection_updated`.
pub(crate) async fn accept_readable_assertions(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .accept_readable_assertions
        .execute(&tenant.caller, &tenant.auditor, path.connection())
        .await?;
    Ok(NoContent)
}
