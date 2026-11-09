//! Member privacy handlers: consent decisions and their history, and the
//! erasure of a member's data.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::organization::OrganizationState;

use crate::dto::identity::privacy::ErasureRequestResponse;
use crate::dto::organization::invitations::OrgTokenBody;
use crate::dto::organization::privacy::{
    OrgConsentBody, OrgConsentDecision, OrgConsentResponse, OrgErasureBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{OrgMember, Visitor};
use crate::extractors::json::Json;
use crate::extractors::paths::organization::{OrgErasurePath, OrgUserPath};
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/consent",
    tag = "Organizations",
    request_body = OrgConsentBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or consent given for someone else", body = ErrorBody),
        (status = 404, description = "No such member, or no consent was given before", body = ErrorBody),
        (status = 409, description = "Consent already withdrawn", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Give or withdraw a member's consent
///
/// Records a decision on one set of terms (`consent_type` and `version`).
/// Only the member gives their own consent, from their own session.
/// Withdrawing is as easy as giving: the member does it, or someone who
/// may record it for them does, since withdrawing only lowers what is done
/// with their data. Records `organization.org_user_consent_granted` or
/// `organization.org_user_consent_revoked`.
pub(crate) async fn grant_or_revoke_consent(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
    Json(body): Json<OrgConsentBody>,
) -> Result<NoContent, ApiError> {
    let (caller, auditor) = (&member.caller, &member.auditor);
    let privacy = &organization.privacy;
    match body.decision(path.whose(caller))? {
        OrgConsentDecision::Grant(terms) => {
            privacy
                .grant_consent
                .execute(caller, auditor, terms)
                .await?;
        }
        OrgConsentDecision::Withdraw(request) => {
            privacy
                .revoke_consent
                .execute(caller, auditor, request)
                .await?;
        }
    }
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/consents",
    tag = "Organizations",
    responses(
        (status = 200, description = "Every decision, newest first", body = Vec<OrgConsentResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such member", body = ErrorBody)
    )
)]
/// List a member's consent history
///
/// Every consent decision the member made, given and withdrawn. A member
/// reads their own; reading another member's is the app's to allow.
/// Read-only.
pub(crate) async fn list_consents(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
) -> Result<Json<Vec<OrgConsentResponse>>, ApiError> {
    let records = organization
        .privacy
        .list_consents
        .execute(&member.caller, path.whose(&member.caller))
        .await?;
    Ok(Json(
        records.into_iter().map(OrgConsentResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/erasure",
    tag = "Organizations",
    request_body = OrgErasureBody,
    responses(
        (status = 200, description = "Success", body = ErasureRequestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such member", body = ErrorBody),
        (status = 409, description = "An erasure is already under way, or the member is the last active owner", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 502, description = "The mail service refused the cancel link; the request stands", body = ErrorBody)
    )
)]
/// Request a member's data erasure
///
/// Asks for the member's data to be erased once the grace period passes.
/// The member asks from their own session, or someone who may remove them
/// asks for them. The account closes at once, its sessions and what it
/// granted end, and a link to cancel goes to its address: the member
/// cannot sign in meanwhile, so the link is how they change their mind.
/// Records `organization.org_user_erasure_requested`.
pub(crate) async fn request_erasure(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
    Json(body): Json<OrgErasureBody>,
) -> Result<Json<ErasureRequestResponse>, ApiError> {
    let request = body.request(path.whose(&member.caller))?;
    let requested = organization
        .privacy
        .request_erasure
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(Json(ErasureRequestResponse::from(requested)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/erasure/{id}/cancel",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "The request can no longer be cancelled", body = ErrorBody)
    )
)]
/// Cancel a member's pending erasure
///
/// Stops an erasure before it is carried out and opens the account again.
/// The member themselves cancels from the link mailed to them; this is for
/// someone who may remove the member. Records
/// `organization.org_user_erasure_cancelled`.
pub(crate) async fn cancel_erasure(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgErasurePath>,
) -> Result<NoContent, ApiError> {
    organization
        .privacy
        .cancel_erasure
        .execute(&member.caller, &member.auditor, path.request())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/erasure/{id}/hold",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "The request is not pending", body = ErrorBody)
    )
)]
/// Hold a member's erasure
///
/// Puts a pending erasure under legal hold: it waits, past its grace
/// period, until the hold is lifted, and the member may still cancel it
/// meanwhile. Records `organization.org_user_erasure_held`.
pub(crate) async fn hold_erasure(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgErasurePath>,
) -> Result<NoContent, ApiError> {
    organization
        .privacy
        .hold_erasure
        .execute(&member.caller, &member.auditor, path.request())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/erasure/{id}/release",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "The request is not held", body = ErrorBody)
    )
)]
/// Release a member's erasure from hold
///
/// Lifts a legal hold, so the erasure goes ahead as it was asked for.
/// Records `organization.org_user_erasure_released`.
pub(crate) async fn release_erasure(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgErasurePath>,
) -> Result<NoContent, ApiError> {
    organization
        .privacy
        .release_erasure
        .execute(&member.caller, &member.auditor, path.request())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/erasure/cancel-by-link",
    tag = "Organizations",
    request_body = OrgTokenBody,
    responses(
        (status = 204, description = "No content"),
        (status = 403, description = "The member left the address the link went to", body = ErrorBody),
        (status = 404, description = "Unknown link", body = ErrorBody),
        (status = 422, description = "Malformed token, or a request past cancelling", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Cancel my erasure from the mailed link
///
/// The member whose erasure was asked for changes their mind: submit the
/// `token` from the link mailed to them, and the erasure stops and the
/// account opens again. Public: the member cannot sign in while the
/// erasure waits. Records `organization.org_user_erasure_cancelled`.
pub(crate) async fn cancel_erasure_by_link(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<NoContent, ApiError> {
    organization
        .privacy
        .cancel_erasure_by_link
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}
