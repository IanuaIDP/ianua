//! A member's password reset, reached by people who cannot sign in: asking
//! for a link, reading what it is worth, replacing a dead one and setting
//! the new password.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::organization::OrganizationState;
use ianua_domain::types::Email;

use crate::dto::organization::password_reset::{
    OrgResetConfirmBody, OrgResetLinkStatusResponse, OrgResetRequestBody, OrgResetResentResponse,
    OrgResetTokenBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::Visitor;
use crate::extractors::json::Json;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/password/reset-request",
    tag = "Authentication",
    request_body = OrgResetRequestBody,
    responses(
        (status = 204, description = "No content: sent whether or not the address is known"),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Ask for a password reset link
///
/// Public endpoint taking only an email address: no organization slug,
/// because a locked-out user has no way to know one. The organization is
/// resolved from the address and carried in the emailed link so the
/// browser lands in the right place. A new link supersedes earlier ones.
///
/// Always returns `204`, whether or not the address belongs to an account,
/// so this cannot be used to discover who has one. Records
/// `organization.org_user_password_reset_requested` for a known address.
pub(crate) async fn request(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgResetRequestBody>,
) -> Result<NoContent, ApiError> {
    organization
        .password_reset
        .request
        .execute(&(), &visitor.auditor, Email::try_from(body)?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/password/reset-confirm",
    tag = "Authentication",
    request_body = OrgResetConfirmBody,
    responses(
        (status = 204, description = "No content"),
        (status = 403, description = "Wrong or used authenticator code", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Complete a password reset
///
/// Public endpoint: submit the `token` from the reset email and the new
/// `password`. The token identifies the account by itself, so no
/// organization is needed. A member with a second factor also sends
/// `mfa_code` from it (`403 step_up_required` without one). Every existing
/// session is signed out.
///
/// Returns `404` if the token is unknown, expired, or already used, and
/// `422` when the password breaks the organization's rules. Records
/// `organization.org_user_password_changed`.
pub(crate) async fn confirm(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgResetConfirmBody>,
) -> Result<NoContent, ApiError> {
    organization
        .password_reset
        .confirm
        .execute(&(), &visitor.auditor, body.into())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/password/reset-status",
    tag = "Authentication",
    request_body = OrgResetTokenBody,
    responses(
        (status = 200, description = "What the link is worth", body = OrgResetLinkStatusResponse),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check a reset link without following it
///
/// Submit the `token` and get back `Valid`, `Expired`, `AlreadyUsed`, or
/// `Invalid`, so the page a link lands on can show the right thing before
/// the reader types a password. Nothing here spends the token.
///
/// `AlreadyUsed` means the password was changed on this link: offering the
/// form again would be wrong. `Expired` means it was not, and another link
/// can be requested.
///
/// A `Valid` link also returns the organization's `password_policy`: the
/// rules the reset will enforce. The route names no organization; the link
/// itself says whose rules apply. Other statuses carry no policy.
///
/// Public, because the reader of a reset email is by definition signed out.
pub(crate) async fn status(
    State(organization): State<OrganizationState>,
    Json(body): Json<OrgResetTokenBody>,
) -> Result<Json<OrgResetLinkStatusResponse>, ApiError> {
    let answer = organization
        .password_reset
        .status
        .execute(&(), body.token)
        .await?;
    Ok(Json(OrgResetLinkStatusResponse::from(answer)))
}

#[utoipa::path(
    post,
    path = "/api/v1/password/reset-resend",
    tag = "Authentication",
    request_body = OrgResetTokenBody,
    responses(
        (status = 200, description = "Sent", body = OrgResetResentResponse),
        (status = 404, description = "Unknown token", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody),
        (status = 429, description = "Asked again inside the cooldown", body = ErrorBody)
    )
)]
/// Replace a dead reset link
///
/// Submit the `token` from an expired reset link to mail a replacement that supersedes it.
///
/// Keyed on the token, not an address, so it reveals nothing about who has
/// an account: only someone who was sent a link can ask for its
/// replacement, and the replacement goes where the first one did. An
/// expired or already-spent token is exactly what this expects; it only has
/// to name its user.
///
/// The response carries `retry_after_seconds`, the cooldown before another
/// is accepted, measured from the member's newest link. Asking again inside
/// it returns `429` with the seconds still to wait in the message.
///
/// Public, because the reader of a reset email is by definition signed out.
pub(crate) async fn resend(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgResetTokenBody>,
) -> Result<Json<OrgResetResentResponse>, ApiError> {
    let resent = organization
        .password_reset
        .resend
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    Ok(Json(OrgResetResentResponse::from(resent)))
}
