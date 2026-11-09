//! Invitation handlers: inviting someone into a tenant, the invitee
//! answering from the emailed link, and welcoming a new user.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::identity::invitations::{
    RenewRequest, ResendRequest, SendWelcomeRequest,
};
use ianua_assembly::identity::IdentityState;

use crate::dto::identity::invitations::{
    AcceptInvitationBody, InvitationLinkResponse, InviteUserBody, InviteUserResponse,
};
use crate::dto::identity::links::{
    PasswordLinkStatusResponse, TokenResentResponse, TokenStatusBody,
};
use crate::dto::identity::users::RegisterUserResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::identity::visitors::TenantVisitor;
use crate::extractors::input_state::InputState;
use crate::extractors::json::Json;
use crate::extractors::paths::identity::{TenantPath, UserPath};
use crate::response::{Created, MaybeBody, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/invite",
    tag = "Users",
    request_body = InviteUserBody,
    responses(
        (status = 201, description = "Created", body = InviteUserResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, a role you cannot hand out, or the plan allows no more users", body = ErrorBody),
        (status = 404, description = "The role does not exist", body = ErrorBody),
        (status = 409, description = "The address is taken or already invited", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Invite a user to this tenant
///
/// Creates a user in `Invited` status and emails them a single-use link.
/// The invitee follows it and accepts at `.../users/accept-invitation` to
/// activate their account, or declines at `.../users/decline-invitation`.
/// On a deployment with no mail server nothing is mailed: the answer
/// carries the `accept_link` for you to pass on to the invitee.
///
/// The link carries both slugs and its token, needing no session. It expires after the
/// configured invitation lifetime; to re-issue a lost or expired invitation
/// use `.../users/{id}/resend-invitation` rather than inviting the same
/// address again, which answers `409` while an invitation waits.
///
/// The `role_id` is granted on acceptance, so it must be a role you could
/// hand out yourself: one carrying a permission you do not hold is refused
/// with `403`. An optional personal `message` goes into the email. The
/// tenant's user limit counts an invited user. Records
/// `identity.user_invited`. Requires the right to create users.
pub(crate) async fn invite_user(
    InputState {
        use_cases: identity,
        limits,
    }: InputState<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<TenantPath>,
    Json(body): Json<InviteUserBody>,
) -> Result<Created<InviteUserResponse>, ApiError> {
    let request = body.request(&limits.display_name, path.link_scope())?;
    let invited = identity
        .invitations
        .invite
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(invited.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/accept-invitation",
    tag = "Users",
    request_body = AcceptInvitationBody,
    responses(
        (status = 200, description = "Success", body = RegisterUserResponse),
        (status = 404, description = "Unknown token, or an invitation already answered", body = ErrorBody),
        (status = 410, description = "Invitation expired; ask for a new link", body = ErrorBody),
        (status = 422, description = "Validation error, including a password the policy refuses", body = ErrorBody)
    )
)]
/// Accept a user invitation
///
/// Public: no session required. The invitee follows the link in the
/// invitation email and submits its `token` here with the `password` they
/// chose. The token is a single-use secret: presenting it proves the
/// recipient reads the invited address, so this both authenticates and
/// activates the account.
///
/// The `password` is held to the tenant's password policy, which the
/// invitation-status check returns so the form can show it. A password that
/// fails it, or a missing one, answers `422` and changes nothing. A tenant
/// without password sign-in takes no password: one that is sent is never
/// stored.
///
/// Invitation `Pending -> Accepted`; user `Invited -> Active`, address
/// confirmed, join time recorded, the invited role granted if the sender
/// still holds what it carries. An unknown token, or one whose invitation
/// was already answered or revoked, answers `404`; one past its expiry
/// answers `410`, so the page can offer a new link. A welcome mail follows.
/// Records `identity.invitation_accepted`.
pub(crate) async fn accept_invitation(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<AcceptInvitationBody>,
) -> Result<Json<RegisterUserResponse>, ApiError> {
    let (tenant, auditor) = (&visitor.tenant, &visitor.auditor);
    let user_id = identity
        .invitations
        .accept
        .execute(tenant, auditor, body.into())
        .await?;
    let welcome = SendWelcomeRequest {
        user_id,
        scope: visitor.scope,
    };
    identity
        .invitations
        .send_activation_welcome
        .execute(tenant, auditor, welcome)
        .await?;
    Ok(Json(user_id.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/decline-invitation",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 204, description = "Declined"),
        (status = 404, description = "Unknown token, or an invitation already answered", body = ErrorBody),
        (status = 410, description = "Invitation expired", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Decline a user invitation
///
/// Public, matching the accept endpoint: the invitee turns the invitation
/// down from its link. Invitation `Pending -> Declined` (terminal); the
/// account that waited on it is closed. Records
/// `identity.invitation_declined`.
pub(crate) async fn decline_invitation(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<NoContent, ApiError> {
    identity
        .invitations
        .decline
        .execute(&visitor.tenant, &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/invitation-status",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "What the link is worth", body = PasswordLinkStatusResponse),
        (status = 404, description = "Unknown organization or tenant", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check an invitation link without accepting it
///
/// Submit the `token` and get back `Valid`, `Expired`, `AlreadyUsed` or
/// `Invalid`. `AlreadyUsed` covers an invitation accepted, declined or
/// revoked: all final, and none of them something a new link would fix.
///
/// A `Valid` link also returns the tenant's `password_policy`, the rules
/// accepting will hold the chosen password to. It is left out for a tenant
/// without password sign-in, and for every other status. Public, matching
/// the accept endpoint: the invitee has no account yet.
pub(crate) async fn invitation_status(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<PasswordLinkStatusResponse>, ApiError> {
    let status = identity
        .invitations
        .status
        .execute(&visitor.tenant, body.token)
        .await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/invitation-resend",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "Sent", body = TokenResentResponse),
        (status = 403, description = "No mail server is set up; ask whoever invited you to send it again", body = ErrorBody),
        (status = 404, description = "Unknown token, or a closed invitation", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Replace a dead invitation link
///
/// The way out of the `Expired` screen the invitation-status endpoint
/// shows. Submit the same `token` and another invitation goes to the
/// address it was sent to, never to one supplied here.
///
/// Keyed on the token, so it tells nothing about who has been invited. An
/// invitation that was accepted, declined or revoked is closed and answers
/// `404`; an admin inviting again is the only way back from those. The old
/// link stops working the moment this succeeds, so a second try with the
/// same token answers `404`. `retry_after_seconds` is how long to hold the
/// button down. Records `identity.invitation_resent`. Public, matching the
/// accept endpoint.
pub(crate) async fn invitation_resend(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<TokenResentResponse>, ApiError> {
    let request = RenewRequest {
        raw_token: body.token,
        scope: visitor.scope,
    };
    let resent = identity
        .invitations
        .renew
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(Json(resent.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/resend-invitation",
    tag = "Users",
    responses(
        (status = 204, description = "Mailed"),
        (status = 200, description = "No mail server is set up: the new accept link to pass on", body = InvitationLinkResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No waiting invitation for this user", body = ErrorBody)
    )
)]
/// Resend a pending user invitation
///
/// Re-issues the invitation email for an invited user. The previous link
/// stops working at once and a fresh expiry window opens: use this when an
/// invitation was lost or has expired, instead of inviting the same address
/// again. The invitation stays `Pending` and the user `Invited`.
///
/// On a deployment with no mail server nothing is mailed: the answer is
/// `200` with the new single-use `accept_link`, for you to pass on to the
/// invitee. Whoever holds it joins as the invited account.
///
/// `404` when the user has no waiting invitation (they already answered,
/// or it was revoked). Records `identity.invitation_resent`. Requires the
/// right to create users.
pub(crate) async fn resend_invitation(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<MaybeBody<InvitationLinkResponse>, ApiError> {
    let request = ResendRequest {
        user_id: path.user(),
        scope: path.link_scope(),
    };
    let delivery = identity
        .invitations
        .resend
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(InvitationLinkResponse::handed_over(&delivery).into())
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/revoke-invitation",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No waiting invitation for this user", body = ErrorBody)
    )
)]
/// Revoke a pending user invitation
///
/// Cancels an outstanding invitation so its link can no longer activate
/// the account: to undo an invitation sent to the wrong person, or to clear
/// one that will never be accepted. Invitation `Pending -> Revoked`
/// (terminal); the account that waited on it is closed. An expired
/// invitation can still be revoked.
///
/// `404` when the user has no waiting invitation. Records
/// `identity.invitation_revoked`. Requires the right to shut the invited
/// account out.
pub(crate) async fn revoke_invitation(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    identity
        .invitations
        .revoke
        .execute(&tenant.caller, &tenant.auditor, path.user())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/send-welcome",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Welcome a user
///
/// Mails the user that their account exists and where to sign in, carrying
/// no password: whoever made the account relays that, or the user takes the
/// forgotten-password route. A user who is gone, or a mail the mail service
/// refuses, is no error. Records `identity.welcome_email_sent` once the
/// mail is accepted. Requires the right to create users.
pub(crate) async fn send_welcome(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    let request = SendWelcomeRequest {
        user_id: path.user(),
        scope: path.link_scope(),
    };
    identity
        .invitations
        .send_welcome
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}
