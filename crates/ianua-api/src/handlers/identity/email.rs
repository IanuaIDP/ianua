//! Address handlers: confirming a tenant user's address, moving a tenant
//! user or an organization member onto a new one, and the emailed links
//! both flows send.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::identity::email::{
    ResendChangeRequest, ResendVerificationRequest, SendVerificationRequest,
};
use ianua_app::use_cases::identity::invitations::SendWelcomeRequest;
use ianua_assembly::identity::IdentityState;

use crate::dto::identity::email::RequestEmailChangeBody;
use crate::dto::identity::links::{
    ConfirmEmailChangeBody, TokenResentResponse, TokenStatusBody, TokenStatusResponse,
    VerificationResentResponse, VerificationTokenStatusResponse, VerifyEmailBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{OrgMember, TenantCaller};
use crate::extractors::identity::visitors::{OrgVisitor, TenantVisitor};
use crate::extractors::json::Json;
use crate::extractors::paths::identity::{OrgPath, TenantPath, UserPath};
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/email/request-change",
    tag = "Users",
    request_body = RequestEmailChangeBody,
    responses(
        (status = 204, description = "Change requested"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "What was typed again does not prove who you are", body = ErrorBody),
        (status = 409, description = "Another user has the address", body = ErrorBody),
        (status = 422, description = "Validation error, or the address you already have", body = ErrorBody)
    )
)]
/// Request a change of my email address
///
/// Starts moving the calling user's own account to `new_email`. Asking needs
/// more than an open session: the person proves who they are again with
/// their `password` (or a sign-in `link` mailed to them just now), and a
/// `code` from their second factor when they have one, so whoever stole a
/// session cannot move the address to their own mailbox.
///
/// A link to confirm goes to the new address; the current one is warned,
/// with a link that stops the change. The account keeps its address until
/// the confirmation is followed at `.../users/email/confirm-change`.
/// Records `identity.email_change_requested`. Requires a tenant user's own
/// session.
pub(crate) async fn request_email_change(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<TenantPath>,
    Json(body): Json<RequestEmailChangeBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(path.link_scope())?;
    identity
        .email
        .request_change
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/email/confirm-change",
    tag = "Users",
    request_body = ConfirmEmailChangeBody,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Unknown or already used token", body = ErrorBody),
        (status = 409, description = "The new address was taken meanwhile", body = ErrorBody),
        (status = 410, description = "The link has expired", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Confirm a pending email change
///
/// Follows the `token` mailed to the new address and only now applies the
/// change: the account moves to the new address, marked verified, and the
/// old address is told where it went. Links mailed to the old address stop
/// working. Until this succeeds the original address stays in use.
///
/// The token alone authorizes it, as for address verification: it applies
/// to whichever account's change it names. A change is void once the
/// address moved some other way or the password changed since. `409` if
/// the new address was claimed by someone else in this tenant meanwhile.
/// Records `identity.email_changed`. Public.
pub(crate) async fn confirm_email_change(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<ConfirmEmailChangeBody>,
) -> Result<NoContent, ApiError> {
    identity
        .email
        .confirm_change
        .execute(&visitor.tenant, &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/email/cancel-change",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 204, description = "Change stopped"),
        (status = 404, description = "Unknown token, or a change no longer waiting", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Stop a pending email change
///
/// Follows the cancel link mailed to the address the account has now when
/// someone asked to move it: the change is dropped and its confirmation
/// link stops working. Records `identity.email_change_cancelled`. Public:
/// the token is what proves the request came from the current mailbox.
pub(crate) async fn cancel_email_change(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<NoContent, ApiError> {
    identity
        .email
        .cancel_change
        .execute(&visitor.tenant, &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/email/change-status",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "What the link is worth", body = TokenStatusResponse),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check an email change link without confirming it
///
/// Submit the `token` and get back `Valid`, `Expired`, `AlreadyUsed` or
/// `Invalid`, so the page a link lands on can show the right thing before it
/// acts. A link for a change whose account is gone reads `Invalid`. Public,
/// matching the confirm endpoint.
pub(crate) async fn email_change_status(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<TokenStatusResponse>, ApiError> {
    let status = identity
        .email
        .change_status
        .execute(&visitor.tenant, body.token)
        .await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/email/change-resend",
    tag = "Users",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "Sent", body = TokenResentResponse),
        (status = 404, description = "Unknown token", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Replace a dead email change link
///
/// The way out of the `Expired` screen the change-status endpoint shows.
/// Submit the same `token` and another confirmation goes to the address the
/// change waits on, never to one supplied here. A change already confirmed
/// no longer waits, so its token answers `404`; so does the old token once
/// this succeeds. `retry_after_seconds` is how long to hold the button
/// down. Records `identity.email_change_link_resent`. Public, matching the
/// confirm endpoint.
pub(crate) async fn email_change_resend(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<TokenResentResponse>, ApiError> {
    let request = ResendChangeRequest {
        raw_token: body.token,
        scope: visitor.scope,
    };
    let resent = identity
        .email
        .resend_change
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(Json(resent.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/send-verification",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "A link went out moments ago", body = ErrorBody)
    )
)]
/// Send an email verification link
///
/// Mails a user a one-time link that confirms they read their address; they
/// follow it at `.../users/verify-email`. This changes no status: the
/// address is marked verified only when the link is followed. Allowed for
/// the user themselves, or someone who may change their sign-in. `429`
/// when a link went out very recently. Records
/// `identity.verification_email_sent`.
pub(crate) async fn send_verification(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    let request = SendVerificationRequest {
        user_id: path.user(),
        scope: path.link_scope(),
    };
    identity
        .email
        .send_verification
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/verify-email",
    tag = "Users",
    request_body = VerifyEmailBody,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Unknown or already used token", body = ErrorBody),
        (status = 410, description = "The link has expired", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Verify an email address with the emailed token
///
/// Public: the person confirming has no session yet, since an unconfirmed
/// account cannot sign in, and the emailed token is what proves the address
/// is theirs. Confirming activates the account and a welcome mail follows.
/// Records `identity.email_verified`.
pub(crate) async fn verify_email(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<VerifyEmailBody>,
) -> Result<NoContent, ApiError> {
    let (tenant, auditor) = (&visitor.tenant, &visitor.auditor);
    let user_id = identity
        .email
        .verify
        .execute(tenant, auditor, body.token)
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
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/verify-email/status",
    tag = "Users",
    request_body = VerifyEmailBody,
    responses(
        (status = 200, description = "The token's state", body = VerificationTokenStatusResponse),
        (status = 404, description = "Unknown token", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check a verification link without following it
///
/// Submit the `token` and get back `Valid`, `Expired` or `Verified`, so the
/// page a link lands on can show the right thing before it acts. Nothing
/// here spends the token. Public: the page is reached from an email and its
/// reader is not signed in yet.
pub(crate) async fn verification_status(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<VerifyEmailBody>,
) -> Result<Json<VerificationTokenStatusResponse>, ApiError> {
    let status = identity
        .email
        .verification_status
        .execute(&visitor.tenant, body.token)
        .await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/verify-email/resend",
    tag = "Users",
    request_body = VerifyEmailBody,
    responses(
        (status = 200, description = "Another verification email is on its way", body = VerificationResentResponse),
        (status = 404, description = "Unknown token, or the address is already confirmed", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Request another verification email from an expired or lost link
///
/// Keyed on the token rather than an address, so only someone who was sent
/// a link can ask for its replacement; an expired token is as good as a live
/// one for this. The new link goes to the account's address. Public, for
/// the same reason the status check is: the caller has no session yet.
pub(crate) async fn resend_verification(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
    Json(body): Json<VerifyEmailBody>,
) -> Result<Json<VerificationResentResponse>, ApiError> {
    let request = ResendVerificationRequest {
        raw_token: body.token,
        scope: visitor.scope,
    };
    let resent = identity
        .email
        .resend_verification
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(Json(resent.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/email/request-change",
    tag = "Organizations",
    request_body = RequestEmailChangeBody,
    responses(
        (status = 204, description = "Email change requested"),
        (status = 401, description = "Unauthenticated, or acting through a key", body = ErrorBody),
        (status = 403, description = "What was typed again does not prove who you are, or a code is owed", body = ErrorBody),
        (status = 409, description = "Another organization account has the address", body = ErrorBody),
        (status = 422, description = "Validation error, or the address you already have", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Request an email change (organization member)
///
/// Starts moving the calling member's own account to `new_email`. The
/// member proves who they are again with their `password` and, when they
/// have a second factor, a `code` from it. A link to confirm goes to the new
/// address, the current one is warned with a link that stops the change,
/// and nothing moves until the confirmation is followed at
/// `.../email/confirm-change`. Records
/// `identity.management_email_change_requested`. Requires a member's own
/// session.
pub(crate) async fn org_request_email_change(
    State(identity): State<IdentityState>,
    member: OrgMember,
    Path(path): Path<OrgPath>,
    Json(body): Json<RequestEmailChangeBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(path.link_scope())?;
    identity
        .email
        .request_org_change
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/email/confirm-change",
    tag = "Organizations",
    request_body = ConfirmEmailChangeBody,
    responses(
        (status = 204, description = "Email change confirmed"),
        (status = 404, description = "Unknown or already used token", body = ErrorBody),
        (status = 409, description = "The new address was taken meanwhile", body = ErrorBody),
        (status = 410, description = "The link has expired", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Confirm an email change (organization member)
///
/// Follows the `token` mailed to the new address and moves the account its
/// change was asked for onto it, marked verified; the old address is told
/// where it went. The token alone authorizes it, so it applies to the
/// account the change names, never to whoever happens to be signed in.
/// Records `identity.management_email_change_confirmed`. Public.
pub(crate) async fn org_confirm_email_change(
    State(identity): State<IdentityState>,
    visitor: OrgVisitor,
    Json(body): Json<ConfirmEmailChangeBody>,
) -> Result<NoContent, ApiError> {
    identity
        .email
        .confirm_org_change
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/email/cancel-change",
    tag = "Organizations",
    request_body = TokenStatusBody,
    responses(
        (status = 204, description = "Change stopped"),
        (status = 404, description = "Unknown token, or a change no longer waiting", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Stop a pending email change (organization member)
///
/// Follows the cancel link mailed to the address the account has now: the
/// change is dropped and its confirmation link stops working. Records
/// `identity.management_email_change_cancelled`. Public: the token is what
/// proves the request came from the current mailbox.
pub(crate) async fn org_cancel_email_change(
    State(identity): State<IdentityState>,
    visitor: OrgVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<NoContent, ApiError> {
    identity
        .email
        .cancel_org_change
        .execute(&(), &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/email/change-status",
    tag = "Organizations",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "What the link is worth", body = TokenStatusResponse),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check an email change link without confirming it (organization member)
///
/// Submit the `token` and get back `Valid`, `Expired`, `AlreadyUsed` or
/// `Invalid`. A link for a change whose account is gone reads `Invalid`.
/// Public, matching the confirm endpoint.
pub(crate) async fn org_email_change_status(
    State(identity): State<IdentityState>,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<TokenStatusResponse>, ApiError> {
    let status = identity
        .email
        .org_change_status
        .execute(&(), body.token)
        .await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/email/change-resend",
    tag = "Organizations",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "Sent", body = TokenResentResponse),
        (status = 404, description = "Unknown token, or no such organization", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Replace a dead email change link (organization member)
///
/// Submit the same `token` and another confirmation goes to the address the
/// change waits on, never to one supplied here. A change already confirmed
/// answers `404`, and so does the old token once this succeeds.
/// `retry_after_seconds` is how long to hold the button down. Records
/// `identity.management_email_change_link_resent`. Public, matching the
/// confirm endpoint.
pub(crate) async fn org_email_change_resend(
    State(identity): State<IdentityState>,
    visitor: OrgVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<TokenResentResponse>, ApiError> {
    let request = ResendChangeRequest {
        raw_token: body.token,
        scope: visitor.scope,
    };
    let resent = identity
        .email
        .resend_org_change
        .execute(&(), &visitor.auditor, request)
        .await?;
    Ok(Json(resent.into()))
}
