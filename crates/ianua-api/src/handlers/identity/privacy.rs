//! Privacy handlers: consent decisions and data erasure.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::identity::IdentityState;

use crate::dto::identity::links::TokenStatusBody;
use crate::dto::identity::privacy::{
    ConsentBody, ConsentDecision, ConsentRecordResponse, ErasureBody, ErasureRequestResponse,
    ExportBody, ExportDownloadResponse, ExportRequestedResponse, ExportResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::identity::visitors::TenantVisitor;
use crate::extractors::json::Json;
use crate::extractors::paths::identity::{ErasurePath, ExportPath, UserPath};
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/consent",
    tag = "Users",
    responses(
        (status = 200, description = "Every consent decision, newest first", body = Vec<ConsentRecordResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// A user's consent history
///
/// Every consent the user gave or withdrew, on every set of terms, with
/// when and where from. A person reads their own with their session;
/// anyone else needs the right to view users. Read-only.
pub(crate) async fn consent_history(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<Json<Vec<ConsentRecordResponse>>, ApiError> {
    let records = identity
        .privacy
        .consent_history
        .execute(&tenant.caller, path.whose(&tenant.caller))
        .await?;
    Ok(Json(ConsentRecordResponse::history(&records)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/exports",
    tag = "Users",
    request_body = ExportBody,
    responses(
        (status = 201, description = "The export is being gathered", body = ExportRequestedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "An export is already being gathered", body = ErrorBody)
    )
)]
/// Ask for a copy of a user's data
///
/// Starts gathering a copy of what is kept about the user (`access`, GDPR
/// article 15) or what they gave the service themselves, in a form another
/// service reads (`portability`, article 20). The file never holds a
/// secret. The person is mailed when it is ready, and only they download
/// it, for a week. A person asks for their own; staff need the right to
/// view users. Records `identity.data_export_requested`.
pub(crate) async fn request_export(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<ExportBody>,
) -> Result<Created<ExportRequestedResponse>, ApiError> {
    let request = body.request(path.whose(&tenant.caller));
    let id = identity
        .privacy
        .request_export
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/exports",
    tag = "Users",
    responses(
        (status = 200, description = "The user's exports", body = Vec<ExportResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List a user's data exports
///
/// Every copy of their data asked for, and where each stands. A person
/// reads their own; anyone else needs the right to view users. Read-only.
pub(crate) async fn list_exports(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<Json<Vec<ExportResponse>>, ApiError> {
    let exports = identity
        .privacy
        .list_exports
        .execute(&tenant.caller, path.whose(&tenant.caller))
        .await?;
    Ok(Json(ExportResponse::listing(&exports)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/exports/{id}/download",
    tag = "Users",
    responses(
        (status = 200, description = "Where to fetch the file", body = ExportDownloadResponse),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 404, description = "None of my exports", body = ErrorBody),
        (status = 409, description = "Not ready, or its week is over", body = ErrorBody)
    )
)]
/// Download my data export
///
/// A short-lived address of a ready export's file. Only the person the
/// export is about downloads it, never staff, even one who asked for it.
/// Records `identity.data_export_downloaded`. Requires a tenant user's own
/// session.
pub(crate) async fn download_export(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ExportPath>,
) -> Result<Json<ExportDownloadResponse>, ApiError> {
    let url = identity
        .privacy
        .download_export
        .execute(&tenant.caller, &tenant.auditor, path.export())
        .await?;
    Ok(Json(url.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/consent",
    tag = "Users",
    request_body = ConsentBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or consent given for someone else", body = ErrorBody),
        (status = 404, description = "No consent was given before", body = ErrorBody),
        (status = 409, description = "Consent already withdrawn", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Give or withdraw consent
///
/// Records a decision on one set of terms (`consent_type` and `version`).
/// Only the person gives their own consent, from their own session.
/// Withdrawing is as easy as giving: the person does it, or someone who may
/// record it for them does, since withdrawing only lowers what is done with
/// their data. Records `identity.consent_granted` or
/// `identity.consent_revoked`.
pub(crate) async fn grant_or_revoke_consent(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<ConsentBody>,
) -> Result<NoContent, ApiError> {
    let (caller, auditor) = (&tenant.caller, &tenant.auditor);
    let privacy = &identity.privacy;
    match body.decision(path.whose(caller))? {
        ConsentDecision::Grant(terms) => {
            privacy
                .grant_consent
                .execute(caller, auditor, terms)
                .await?;
        }
        ConsentDecision::Withdraw(request) => {
            privacy
                .revoke_consent
                .execute(caller, auditor, request)
                .await?;
        }
    }
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/erasure",
    tag = "Users",
    request_body = ErasureBody,
    responses(
        (status = 200, description = "Success", body = ErasureRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "An erasure is already under way, or the tenant's last administrator", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 502, description = "The mail service refused the cancel link; the request stands", body = ErrorBody)
    )
)]
/// Request data erasure
///
/// Asks for the person's data to be erased once the grace period passes.
/// The person asks from their own session, or someone who may erase them
/// asks for them. The account closes at once, its sessions and delegations
/// end, and a link to cancel goes to its address: the person cannot sign
/// in meanwhile, so the link is how they change their mind. Records
/// `identity.erasure_requested`.
pub(crate) async fn request_erasure(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<ErasureBody>,
) -> Result<Json<ErasureRequestResponse>, ApiError> {
    let request = body.request(path.whose(&tenant.caller), path.link_scope())?;
    let requested = identity
        .privacy
        .request_erasure
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(requested.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/erasure/{id}/cancel",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The request can no longer be cancelled", body = ErrorBody)
    )
)]
/// Cancel a pending erasure request
///
/// Stops an erasure before it is carried out and opens the account again.
/// The person themselves cancels from the link mailed to them; this is for
/// someone who may erase the person. Records `identity.erasure_cancelled`.
pub(crate) async fn cancel_erasure(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ErasurePath>,
) -> Result<NoContent, ApiError> {
    identity
        .privacy
        .cancel_erasure
        .execute(&tenant.caller, &tenant.auditor, path.request())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/erasure/cancel-by-link",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Unknown token, or a request no longer waiting", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Cancel an erasure from its emailed link
///
/// Follows the cancel link mailed when the erasure was asked for: the
/// request is dropped and the account opens again. Public: the person
/// cannot sign in while their account is closing, so the token is what
/// proves the request is theirs. Records `identity.erasure_cancelled`.
pub(crate) async fn cancel_erasure_by_link(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<NoContent, ApiError> {
    identity
        .privacy
        .cancel_erasure_by_link
        .execute(&visitor.tenant, &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/erasure/{id}/hold",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "The request cannot be held", body = ErrorBody)
    )
)]
/// Put an erasure under a legal hold
///
/// A held request is never carried out, whatever its date, until the hold
/// is released. Records `identity.erasure_held`. Requires the right to
/// erase the person.
pub(crate) async fn hold_erasure(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ErasurePath>,
) -> Result<NoContent, ApiError> {
    identity
        .privacy
        .hold_erasure
        .execute(&tenant.caller, &tenant.auditor, path.request())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/erasure/{id}/release",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "The request is not held", body = ErrorBody)
    )
)]
/// Release an erasure from its legal hold
///
/// The request is due again on its own date. Records
/// `identity.erasure_released`. Requires the right to erase the person.
pub(crate) async fn release_erasure(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ErasurePath>,
) -> Result<NoContent, ApiError> {
    identity
        .privacy
        .release_erasure
        .execute(&tenant.caller, &tenant.auditor, path.request())
        .await?;
    Ok(NoContent)
}
