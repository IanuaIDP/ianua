//! Invitation handlers: inviting members and managing waiting invitations,
//! the invitee's public pages, the welcome mail, and confirming a member's
//! address from the link mailed to it.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::invitations::{
    ResendOrgRequest, RevokeOrgRequest, SendOrgWelcomeRequest,
};
use ianua_assembly::organization::OrganizationState;

use crate::dto::identity::invitations::InvitationLinkResponse;
use crate::dto::identity::links::TokenResentResponse;
use crate::dto::organization::invitations::{
    AcceptOrgInvitationBody, InviteOrgUserBody, InvitedOrgUserResponse, OrgEmailBody, OrgTokenBody,
    OrgUserIdResponse, PasswordLinkStatusResponse, VerificationResentResponse,
    VerificationTokenStatusResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{OrgMember, Visitor};
use crate::extractors::input_state::InputState;
use crate::extractors::json::Json;
use crate::extractors::organization::{OrgLinks, OrgSteward, OrgVisitor};
use crate::extractors::paths::organization::OrgUserPath;
use crate::response::{Created, MaybeBody, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users",
    tag = "Organizations",
    request_body = InviteOrgUserBody,
    responses(
        (status = 201, description = "User invited", body = InvitedOrgUserResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Invite an org user (team member)
///
/// Opens an account in `Invited` status and emails the invitee a single-use
/// link, with the optional personal `message`. The invitee follows the link
/// and accepts at `.../users/accept-invitation`, choosing their own
/// password. The link carries the organization slug and the token, so it
/// works on a cold open, and expires after the invitation lifetime. Use
/// `.../users/{user_id}/resend-invitation` for a lost or expired one; an
/// address with an invitation already waiting is `409`. On a deployment
/// with no mail server nothing is mailed: the answer carries the
/// `accept_link` for you to pass on to the invitee.
///
/// An address whose account in the organization was closed gets that same
/// account back, opened again, with none of its old tenant access, second
/// factor or passkeys. Only an owner invites an owner. Records
/// `organization.org_user_invited`, after `organization.org_user_reopened`
/// for a reopened account.
pub(crate) async fn invite_org_user(
    InputState {
        use_cases: organization,
        limits,
    }: InputState<OrganizationState>,
    member: OrgMember,
    OrgLinks(links): OrgLinks,
    Json(body): Json<InviteOrgUserBody>,
) -> Result<Created<InvitedOrgUserResponse>, ApiError> {
    let request = body.into_request(links, &limits)?;
    let invited = organization
        .invitations
        .invite
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(Created(InvitedOrgUserResponse::from(invited)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/resend-invitation",
    tag = "Organizations",
    responses(
        (status = 204, description = "Mailed"),
        (status = 200, description = "No mail server is set up: the new accept link to pass on", body = InvitationLinkResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Resend a pending org invitation
///
/// Sends the invitation again with a fresh link and expiry; the previous
/// link stops working at once. Use this when an invitation was lost or
/// expired, instead of inviting the same address again. The invitation
/// stays `Pending` and the member `Invited`. Returns `404` if the member
/// has no pending invitation. Records
/// `organization.org_user_invitation_resent`.
///
/// On a deployment with no mail server nothing is mailed: the answer is
/// `200` with the new single-use `accept_link`, for you to pass on to the
/// invitee. Whoever holds it joins as the invited member.
pub(crate) async fn resend_org_invitation(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    OrgLinks(links): OrgLinks,
    Path(path): Path<OrgUserPath>,
) -> Result<MaybeBody<InvitationLinkResponse>, ApiError> {
    let request = ResendOrgRequest {
        org_user_id: path.member(),
        scope: links,
    };
    let delivery = organization
        .invitations
        .resend
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(InvitationLinkResponse::handed_over(&delivery).into())
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/revoke-invitation",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Revoke a pending org invitation
///
/// Withdraws an outstanding invitation so its link can no longer be used,
/// and closes the account that waited on it. Use this to undo an invite
/// sent to the wrong person. An owner or the platform may withdraw one.
///
/// **State transitions.** Invitation: `Pending -> Revoked` (terminal).
/// Returns `404` if the member has no pending invitation. Records
/// `organization.org_user_invitation_revoked`.
pub(crate) async fn revoke_org_invitation(
    State(organization): State<OrganizationState>,
    steward: OrgSteward,
    Path(path): Path<OrgUserPath>,
) -> Result<NoContent, ApiError> {
    let request = RevokeOrgRequest {
        organization_id: steward.organization,
        org_user_id: path.member(),
    };
    organization
        .invitations
        .revoke
        .execute(&steward.caller, &steward.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/welcome",
    tag = "Organizations",
    responses(
        (status = 204, description = "Welcome sent"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Send a member their welcome
///
/// Mails a member of the organization a notice that an account was made for
/// them, with a link to sign in and no secret: an account let in at once is
/// one its holder has never heard of. A member who is gone is no error,
/// since the account was made a moment ago: nothing is mailed. Records
/// `organization.org_welcome_email_sent` once the mail is accepted.
pub(crate) async fn send_org_welcome(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    OrgLinks(links): OrgLinks,
    Path(path): Path<OrgUserPath>,
) -> Result<NoContent, ApiError> {
    let request = SendOrgWelcomeRequest {
        org_user_id: path.member(),
        scope: links,
    };
    organization
        .invitations
        .send_welcome
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/accept-invitation",
    tag = "Organizations",
    request_body = AcceptOrgInvitationBody,
    responses(
        (status = 200, description = "Success", body = OrgUserIdResponse),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 410, description = "Invitation expired; ask an admin to resend it", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Accept an org invitation and set a password
///
/// Public endpoint, no session required. The invitee follows the link in
/// the invitation email and submits its `token` together with a chosen
/// `password`. The token proves the recipient controls the invited address,
/// so this sets the password and activates the account in one step, and
/// mails the member that joining worked.
///
/// **State transitions.** Invitation: `Pending -> Accepted` (terminal).
/// Member: `Invited -> Active`, with `joined_at` recorded. The password is
/// checked against the organization's rules before any state changes.
///
/// Returns `404` if the token is unknown or already accepted or revoked,
/// `410` if it is past its expiry, and `422` if the password is too weak.
/// Records `organization.org_user_invitation_accepted` and
/// `organization.org_welcome_email_sent`.
pub(crate) async fn accept_org_invitation(
    State(organization): State<OrganizationState>,
    visitor: OrgVisitor,
    Json(body): Json<AcceptOrgInvitationBody>,
) -> Result<Json<OrgUserIdResponse>, ApiError> {
    let joined = organization
        .invitations
        .accept
        .execute(
            &(),
            &visitor.auditor,
            body.for_organization(visitor.organization),
        )
        .await?;
    organization
        .invitations
        .send_activation_welcome
        .execute(&(), &visitor.auditor, joined)
        .await?;
    Ok(Json(OrgUserIdResponse::from(joined)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/decline-invitation",
    tag = "Organizations",
    request_body = OrgTokenBody,
    responses(
        (status = 204, description = "Declined"),
        (status = 404, description = "Unknown token, or a closed invitation", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Decline an org invitation
///
/// Public endpoint, no session required. The invitee follows the link in
/// the invitation email and turns the invitation down with its `token`;
/// the account that waited on it is closed. Returns `404` if the token is
/// unknown or the invitation is no longer pending. Records
/// `organization.org_user_invitation_declined`.
pub(crate) async fn decline_org_invitation(
    State(organization): State<OrganizationState>,
    visitor: OrgVisitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<NoContent, ApiError> {
    organization
        .invitations
        .decline
        .execute(
            &(),
            &visitor.auditor,
            body.invitation_of(visitor.organization),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/invitation-resend",
    tag = "Organizations",
    request_body = OrgTokenBody,
    responses(
        (status = 200, description = "A new link went to the invited address", body = TokenResentResponse),
        (status = 403, description = "The member left the invited address, or no mail server is set up and the inviter must send it again", body = ErrorBody),
        (status = 404, description = "Unknown link", body = ErrorBody),
        (status = 409, description = "The link still works, or the member no longer waits to join", body = ErrorBody),
        (status = 422, description = "Malformed token, or the invitation was answered or revoked", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody),
        (status = 502, description = "The mail service refused it", body = ErrorBody)
    )
)]
/// Renew an invitation from its link
///
/// For an invitee holding a link that ran out: submit its `token` and a
/// new link goes to the invited address, never one the caller names.
/// Only a link that ran out is renewed, and only while the invitation
/// stands as it was sent. The answer says how long before another may be
/// asked for. Records `organization.org_user_invitation_resent`. Public
/// within the organization: the invitee has no account yet.
pub(crate) async fn renew_org_invitation(
    State(organization): State<OrganizationState>,
    visitor: OrgVisitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<Json<TokenResentResponse>, ApiError> {
    let resent = organization
        .invitations
        .renew
        .execute(
            &(),
            &visitor.auditor,
            body.renewal_of(visitor.organization, visitor.links),
        )
        .await?;
    Ok(Json(TokenResentResponse::from(resent)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/invitation-status",
    tag = "Organizations",
    request_body = OrgTokenBody,
    responses(
        (status = 200, description = "What the link is worth", body = PasswordLinkStatusResponse),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check an invitation link without accepting it
///
/// Submit the `token` and get back `Valid`, `Expired`, `AlreadyUsed`, or
/// `Invalid`. `AlreadyUsed` covers an invitation that was accepted,
/// declined, or revoked: all terminal, and none of them something a
/// replacement link would fix. A `Valid` link also returns the
/// organization's `password_policy`, the rules accepting will enforce.
/// Nothing is spent. Public within the organization, matching the accept
/// endpoint: the reader has no account yet.
pub(crate) async fn org_invitation_status(
    State(organization): State<OrganizationState>,
    visitor: OrgVisitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<Json<PasswordLinkStatusResponse>, ApiError> {
    let answer = organization
        .invitations
        .status
        .execute(&(), body.invitation_of(visitor.organization))
        .await?;
    Ok(Json(answer.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/send-verification",
    tag = "Organizations",
    request_body = OrgEmailBody,
    responses(
        (status = 204, description = "No content"),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Resend a member's email verification link
///
/// Public endpoint, no session required, because an unverified account is
/// refused at sign-in and so could never call an authenticated one. Send
/// the address; a fresh link is emailed and the previous one stops working.
///
/// Always returns `204`, whether or not the address belongs to an account,
/// whether it is already verified, and whether the last link is still
/// within its resend wait: the response must not reveal which. Records
/// `organization.org_verification_email_sent` when a mail goes out.
pub(crate) async fn send_org_verification(
    State(organization): State<OrganizationState>,
    visitor: OrgVisitor,
    Json(body): Json<OrgEmailBody>,
) -> Result<NoContent, ApiError> {
    let request = body.resend_in(visitor.organization, visitor.links)?;
    organization
        .invitations
        .resend_verification
        .execute(&(), &visitor.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/verify-email",
    tag = "Organizations",
    request_body = OrgTokenBody,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 410, description = "Link expired", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Confirm a member's email address
///
/// Public endpoint: the recipient submits the `token` from their
/// verification email. The token is single-use: presenting it proves
/// control of the address, which marks it verified and lets the account
/// sign in, and the member is mailed that it worked. Returns `404` if the
/// token is unknown or already used, and `410` if it ran out of time.
/// Records `organization.org_user_email_verified` and
/// `organization.org_welcome_email_sent`.
pub(crate) async fn verify_org_email(
    State(organization): State<OrganizationState>,
    visitor: OrgVisitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<NoContent, ApiError> {
    let confirmed = organization
        .invitations
        .confirm_verification
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    organization
        .invitations
        .send_activation_welcome
        .execute(&(), &visitor.auditor, confirmed)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/users/send-verification",
    tag = "Authentication",
    request_body = OrgEmailBody,
    responses(
        (status = 204, description = "No content; sent whether or not the address is known"),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Ask for another verification link
///
/// Public endpoint taking only an email address. An unverified account
/// cannot sign in, so the person asking has no way to know their
/// organization's slug. Sending again supersedes the previous link rather
/// than leaving both live. Always returns `204`, also while the last link
/// is within its resend wait. Records
/// `organization.org_verification_email_sent` when a mail goes out.
pub(crate) async fn send_verification_by_email(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgEmailBody>,
) -> Result<NoContent, ApiError> {
    organization
        .invitations
        .resend_verification_by_email
        .execute(&(), &visitor.auditor, body.email()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/users/verify-email",
    tag = "Authentication",
    request_body = OrgTokenBody,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 410, description = "Link expired", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm an email address
///
/// Public endpoint: submit the `token` from the verification email. The
/// token identifies the account, so no organization is needed. Confirming
/// activates an account that was waiting on it, which is what lets it sign
/// in, and the member is mailed that it worked.
///
/// Returns `404` if the token is unknown or already used, and `410` with
/// `error: "link_expired"` if it ran out of time: the holder can ask
/// for a replacement at `/api/v1/users/verify-email/resend`. Records
/// `organization.org_user_email_verified` and
/// `organization.org_welcome_email_sent`.
pub(crate) async fn verify_email_by_token(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<NoContent, ApiError> {
    let confirmed = organization
        .invitations
        .confirm_verification
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    organization
        .invitations
        .send_activation_welcome
        .execute(&(), &visitor.auditor, confirmed)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/users/verify-email/status",
    tag = "Authentication",
    request_body = OrgTokenBody,
    responses(
        (status = 200, description = "The token's state", body = VerificationTokenStatusResponse),
        (status = 404, description = "Unknown token", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Check a verification link without following it
///
/// Public endpoint for the page a verification link lands on. Submit the
/// `token` and get back `Valid`, `Expired`, or `Verified`, so the page can
/// show the right thing before it acts. Nothing here spends the token or
/// changes the account. `Expired` covers a link that ran out of time and
/// one a newer link superseded. An unknown token is `404`.
pub(crate) async fn verification_token_status(
    State(organization): State<OrganizationState>,
    Json(body): Json<OrgTokenBody>,
) -> Result<Json<VerificationTokenStatusResponse>, ApiError> {
    let status = organization
        .invitations
        .verification_status
        .execute(&(), body.token)
        .await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/users/verify-email/resend",
    tag = "Authentication",
    request_body = OrgTokenBody,
    responses(
        (status = 200, description = "Sent", body = VerificationResentResponse),
        (status = 404, description = "Unknown or already-used token", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Asked again inside the cooldown", body = ErrorBody)
    )
)]
/// Replace an expired verification link
///
/// Public endpoint for the page shown when a verification link has expired.
/// Submit the same `token` from the dead link and another email goes out,
/// superseding it. Keyed on the token, not an address, so it reveals
/// nothing about who is registered. An already-confirmed address is `404`.
///
/// The response carries `retry_after_seconds`, the cooldown before another
/// request is accepted; asking again inside it returns `429`. Records
/// `organization.org_verification_email_sent`.
pub(crate) async fn resend_verification_by_token(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<Json<VerificationResentResponse>, ApiError> {
    let resent = organization
        .invitations
        .resend_verification_from_link
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    Ok(Json(resent.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/users/confirm-installer",
    tag = "Authentication",
    request_body = OrgTokenBody,
    responses(
        (status = 200, description = "The first owner's address is confirmed", body = OrgUserIdResponse),
        (status = 404, description = "Unknown or already-used token", body = ErrorBody),
        (status = 410, description = "Token expired", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm the installation's first owner
///
/// Public endpoint for a fresh self-hosted installation. The person who
/// ran the install submits the one-time setup `token` it printed; that
/// confirms the first owner's address without a mail server, so they can
/// sign in the first time. Returns the owner's `id`. Records
/// `organization.org_user_email_verified`.
pub(crate) async fn confirm_installer(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgTokenBody>,
) -> Result<Json<OrgUserIdResponse>, ApiError> {
    let owner = organization
        .invitations
        .confirm_installer
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    Ok(Json(OrgUserIdResponse::from(owner)))
}
