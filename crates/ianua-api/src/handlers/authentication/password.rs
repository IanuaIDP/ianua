//! Password and mailbox sign-in handlers: a tenant user's password sign-in,
//! confirming a sign-in by mail, magic links, and changing or resetting a
//! password.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::authentication::AuthenticationState;
use ianua_domain::types::Fact;

use crate::dto::authentication::password::{
    ConfirmSignInBody, ConfirmedSignInResponse, ConsumeMagicLinkBody, DuePasswordChangeBody,
    MagicLinkLoginResponse, PasswordChangeBody, PasswordLinkStatusResponse,
    PasswordResetConfirmBody, PasswordResetRequestBody, PasswordSetResponse, RequestMagicLinkBody,
    SignInPuzzleResponse, TenantLoginAnswer, TenantLoginBody, TokenResentResponse, TokenStatusBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authentication::SignInVisitor;
use crate::extractors::callers::{RequestMeta, TenantCaller, Visitor};
use crate::extractors::json::Json;
use crate::extractors::paths::authentication::TenantLoginPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/login",
    tag = "Authentication",
    request_body = TenantLoginBody,
    responses(
        (status = 200, description = "A session, or the new password the sign-in owes first (`password_change_required`)", body = TenantLoginAnswer),
        (status = 401, description = "The tenant's sign-in is under pressure and this device must pass a challenge first (`challenge_required`, naming it in `challenge`)", body = ErrorBody),
        (status = 403, description = "The tenant takes no sign-ins now, or a password an admin set cannot be changed here (no factor and no mail server): an admin must send an invitation", body = ErrorBody),
        (status = 404, description = "Invalid credentials (unknown org/tenant/email or wrong password)", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests or failed attempts, or the server is busy checking passwords (with `Retry-After`)", body = ErrorBody)
    )
)]
/// Log in as a tenant user
///
/// Checks a tenant user's email and password; unknown org, tenant, email
/// and wrong password share `404`. Returns a session and bearer `refresh_token`.
/// `mfa_required`, `mfa_enrollment_required` and `email_confirmation_required`
/// restrict it to completing the indicated factor, enrollment or mailed link.
/// `password_change_required` instead returns no session: change the password
/// at `…/login/password-change` using its single-use token before `expires_at`.
/// Reasons are `set_by_admin` or `expired`; an admin-set password needs
/// `own_factor` proof with `code`, or `mailed_link` proof whose token is mailed
/// instead of returned. Neither available means `403`; send an invitation.
/// Under sign-in pressure, an untrusted `fingerprint_hash` needs a challenge
/// before hashing: `401 challenge_required` names `challenge`; retry with
/// `challenge_proof`. With no challenge available, only trusted devices or
/// single sign-on work. These answers reveal nothing about the address.
/// Busy password hashing returns `429` with `Retry-After`. Sessions start
/// `Active`, end permanently on revocation, or expire by age or idle time.
/// Both successful and failed sign-ins are recorded in the tenant's trail.
pub(crate) async fn tenant_login(
    State(auth): State<AuthenticationState>,
    visitor: Visitor,
    Path(path): Path<TenantLoginPath>,
    Json(body): Json<TenantLoginBody>,
) -> Result<Json<TenantLoginAnswer>, ApiError> {
    let request = body.login(path.tenant()?, visitor.meta.into())?;
    let outcome = auth
        .password
        .tenant_login
        .execute(&(), &visitor.auditor, request)
        .await?;
    Ok(Json(outcome.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/login/password-change",
    tag = "Authentication",
    request_body = DuePasswordChangeBody,
    responses(
        (status = 200, description = "The new password is set and the sign-in finished", body = TenantLoginAnswer),
        (status = 403, description = "The tenant takes no passwords or no sign-ins now, a code from the person's factor is missing (`step_up_required`) or wrong, or nothing only the person holds can confirm the change", body = ErrorBody),
        (status = 404, description = "Unknown org or tenant, or an unknown, used or expired change token", body = ErrorBody),
        (status = 422, description = "The new password breaks the tenant's rules or was used recently", body = ErrorBody),
        (status = 429, description = "Too many requests or refused passwords (with `Retry-After`)", body = ErrorBody)
    )
)]
/// Set the new password a sign-in owes
///
/// When a sign-in answered `password_change_required`, send its
/// `change_token`, or the token from the mailed link, here with the new
/// password, and a `code` from the person's own factor when `proof` was
/// `own_factor` (`403 step_up_required` without one). The password must
/// meet the tenant's rules and repeat none of the account's recent ones;
/// each one refused counts against the address's lockout, as a wrong
/// password does.
/// Once set, every earlier session of the account ends and the sign-in
/// finishes: the answer is a session, owing whatever second factor the
/// sign-in asks (`mfa_required`, `mfa_enrollment_required`). The token works
/// once, for a few minutes.
pub(crate) async fn change_due_password(
    State(auth): State<AuthenticationState>,
    visitor: Visitor,
    Path(path): Path<TenantLoginPath>,
    Json(body): Json<DuePasswordChangeBody>,
) -> Result<Json<TenantLoginAnswer>, ApiError> {
    let request = body.change(path.tenant()?, visitor.meta.into())?;
    let outcome = auth
        .password
        .change_due_password
        .execute(&(), &visitor.auditor, request)
        .await?;
    Ok(Json(outcome.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/sign-in/puzzle",
    tag = "Authentication",
    responses(
        (status = 200, description = "A puzzle to solve", body = SignInPuzzleResponse),
        (status = 404, description = "This deployment's challenge is Turnstile, which sets no puzzle", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Ask for a sign-in puzzle
///
/// While a flood of failed sign-ins puts sign-in under pressure, a sign-in
/// from a device nobody trusted answers `401 challenge_required` with
/// `challenge` set to `proof_of_work`. Ask here for a puzzle, find a
/// decimal counter whose SHA-256 of `challenge:counter` starts with
/// `difficulty_bits` zero bits, and send `challenge.counter` as the
/// sign-in's `challenge_proof` before `expires_at`. A puzzle is bound to
/// the address that asked for it and lets one sign-in through. Public: the
/// answer is the same whether sign-in is under pressure or not.
pub(crate) async fn sign_in_puzzle(
    State(auth): State<AuthenticationState>,
    meta: RequestMeta,
) -> Result<Json<SignInPuzzleResponse>, ApiError> {
    let puzzle = auth
        .password
        .sign_in_puzzle
        .execute(&(), Fact::from_option(meta.ip_address))
        .await?;
    Ok(Json(puzzle.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sign-in/confirm",
    tag = "Authentication",
    request_body = ConfirmSignInBody,
    responses(
        (status = 200, description = "The sign-in is confirmed", body = ConfirmedSignInResponse),
        (status = 403, description = "The sign-in owes another factor", body = ErrorBody),
        (status = 404, description = "Unknown, used or someone else's link, or no live sign-in holds the token", body = ErrorBody),
        (status = 409, description = "The sign-in owes nothing", body = ErrorBody),
        (status = 410, description = "The link ran out", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm a sign-in by mail
///
/// When a sign-in answered `email_confirmation_required`, the person was
/// mailed a link. The page it opens posts the link's token here with the
/// refresh token the browser holds for that sign-in, so only the browser
/// that began the sign-in finishes it. Answers what the session still owes,
/// such as a factor to set up next.
///
/// Records `authentication.mfa_verified`. Public: the session is not
/// finished yet.
pub(crate) async fn confirm_sign_in(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<ConfirmSignInBody>,
) -> Result<Json<ConfirmedSignInResponse>, ApiError> {
    let confirmed = auth
        .password
        .confirm_sign_in
        .execute(
            &visitor.tenant,
            &visitor.auditor,
            body.request(visitor.origin),
        )
        .await?;
    Ok(Json(confirmed.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/magic-link",
    tag = "Authentication",
    request_body = RequestMagicLinkBody,
    responses(
        (status = 204, description = "If the email belongs to an active user, a sign-in link was sent"),
        (status = 404, description = "Unknown org/tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Request a magic-link sign-in email
///
/// Passwordless login: emails a single-use sign-in link to the address.
/// Always returns `204` regardless of whether the email exists, to prevent
/// enumeration. Public, no session required.
pub(crate) async fn request_magic_link(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<RequestMagicLinkBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(visitor.link_scope, visitor.origin)?;
    auth.password
        .request_magic_link
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/magic-link/verify",
    tag = "Authentication",
    request_body = ConsumeMagicLinkBody,
    responses(
        (status = 200, description = "Signed in", body = MagicLinkLoginResponse),
        (status = 404, description = "Invalid, expired, or already-used link", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Consume a magic link and start a session
///
/// Verifies the single-use token from the emailed link and returns a
/// session (`session_id` + `refresh_token`). The token is consumed, so the
/// link can't be used again. Public, no prior session required.
///
/// Like a password sign-in, the session may still owe a second factor
/// (`mfa_required`), or one being set up first (`mfa_enrollment_required`).
pub(crate) async fn consume_magic_link(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<ConsumeMagicLinkBody>,
) -> Result<Json<MagicLinkLoginResponse>, ApiError> {
    let success = auth
        .password
        .consume_magic_link
        .execute(
            &visitor.tenant,
            &visitor.auditor,
            body.request(visitor.origin),
        )
        .await?;
    Ok(Json(success.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/password/change",
    tag = "Authentication",
    request_body = PasswordChangeBody,
    responses(
        (status = 200, description = "Changed, with what the breach lookup said", body = PasswordSetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The current password is wrong, or a code is needed (`step_up_required`)", body = ErrorBody),
        (status = 404, description = "The account has no password", body = ErrorBody),
        (status = 409, description = "Changed too recently, or the new password was used recently", body = ErrorBody),
        (status = 422, description = "The new password breaks the tenant's rules", body = ErrorBody),
        (status = 429, description = "Too many requests or wrong codes", body = ErrorBody)
    )
)]
/// Change your password
///
/// Updates the signed-in user's password. Requires the **current** password
/// as proof, and a code from their authenticator (`mfa_code`) when they
/// have one: knowing a live session isn't enough, so a stolen token alone
/// can't lock the real owner out.
///
/// The new password must satisfy the tenant's password policy (length,
/// complexity, reuse history, common passwords). A tenant that blocks
/// breached passwords refuses one with `422`; one that only warns takes it
/// and says so in `password_breach`. Every other session the user holds
/// ends; the one the change was made from stays. Records
/// `authentication.password_changed`.
pub(crate) async fn change_password(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Json(body): Json<PasswordChangeBody>,
) -> Result<Json<PasswordSetResponse>, ApiError> {
    let breach = auth
        .password
        .change
        .execute(&tenant.caller, &tenant.auditor, body.into())
        .await?;
    Ok(Json(breach.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/password/reset-request",
    tag = "Authentication",
    request_body = PasswordResetRequestBody,
    responses(
        (status = 204, description = "No content"),
        (status = 404, description = "Unknown org/tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Request a password reset
///
/// Kicks off the forgot-password flow. If the email maps to a real account,
/// a time-limited, single-use reset link is sent to it.
///
/// The response is **always** `204`, whether or not the address exists: the
/// endpoint never reveals which emails are registered. Complete the flow at
/// the reset-confirm endpoint with the token from the email.
pub(crate) async fn request_password_reset(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<PasswordResetRequestBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(visitor.link_scope)?;
    auth.password
        .reset_request
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/password/reset-confirm",
    tag = "Authentication",
    request_body = PasswordResetConfirmBody,
    responses(
        (status = 200, description = "Reset, with what the breach lookup said", body = PasswordSetResponse),
        (status = 403, description = "A code is needed (`step_up_required`), or the code is wrong", body = ErrorBody),
        (status = 404, description = "Used, expired, or forged token", body = ErrorBody),
        (status = 422, description = "The new password breaks the tenant's rules", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Complete a password reset
///
/// Finishes the forgot-password flow. Present the token from the reset
/// email together with a new password. The token is single-use and expires
/// quickly: a used, expired, or forged token returns `404`.
///
/// The new password must meet the tenant's password policy. On success the
/// password is replaced and **all existing sessions are revoked**, so every
/// device has to sign in again with the new credentials.
///
/// If the account has an active second factor, `mfa_code` is required: the
/// response is `403` with a step-up-required code when it is absent, and a
/// plain `403` when it is wrong. A factor that mails or texts its codes is
/// sent one through the reset-code endpoint first. `password_breach` says
/// what the breach lookup found.
pub(crate) async fn confirm_password_reset(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<PasswordResetConfirmBody>,
) -> Result<Json<PasswordSetResponse>, ApiError> {
    let breach = auth
        .password
        .reset_confirm
        .execute(&visitor.tenant, &visitor.auditor, body.into())
        .await?;
    Ok(Json(breach.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/password/reset-code",
    tag = "Authentication",
    request_body = TokenStatusBody,
    responses(
        (status = 204, description = "No content"),
        (status = 422, description = "Malformed token", body = ErrorBody),
        (status = 429, description = "A code went out moments ago, or too many requests", body = ErrorBody)
    )
)]
/// Send the code a password reset asks for
///
/// Public: the reset link's `token` proves access without a session.
/// For mailed or texted factors, replaces the current code and sends it to
/// the factor's destination; submit it as `mfa_code` at reset-confirm.
/// Unknown, expired or spent links, authenticator factors and absent factors
/// send nothing and return the same `204`. Asking again during the cooldown
/// returns `429`. Sending records `authentication.mfa_code_sent`.
pub(crate) async fn send_password_reset_code(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<NoContent, ApiError> {
    auth.password
        .reset_code
        .execute(&visitor.tenant, &visitor.auditor, body.token)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/password/reset-status",
    tag = "Authentication",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "What the link is worth", body = PasswordLinkStatusResponse),
        (status = 422, description = "Malformed token", body = ErrorBody)
    )
)]
/// Check a reset link without following it
///
/// The tenant twin of the org plane's check. Submit the `token` and get back
/// `Valid`, `Expired`, `AlreadyUsed`, or `Invalid`, so the page a link lands
/// on can show the right thing before the reader types a password. Nothing
/// here spends the token.
///
/// `AlreadyUsed` means the password was changed on this link; `Expired`
/// means it was not, and another can be requested.
///
/// A `Valid` link also returns the tenant's `password_policy`, the rules the
/// reset will enforce, so the form can check a password before submitting
/// it. Other statuses carry no policy.
///
/// Public, because the reader of a reset email is by definition signed out.
pub(crate) async fn password_reset_status(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<PasswordLinkStatusResponse>, ApiError> {
    let answer = auth
        .password
        .reset_status
        .execute(&visitor.tenant, body.token)
        .await?;
    Ok(Json(answer.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/password/reset-resend",
    tag = "Authentication",
    request_body = TokenStatusBody,
    responses(
        (status = 200, description = "Sent", body = TokenResentResponse),
        (status = 404, description = "Unknown token", body = ErrorBody),
        (status = 422, description = "Malformed token", body = ErrorBody),
        (status = 429, description = "Asked again inside the cooldown", body = ErrorBody)
    )
)]
/// Replace a dead reset link
///
/// The tenant twin of the org plane's re-send, and the way out of the
/// `Expired` screen the reset-status endpoint produces. Submit the same
/// `token` from the dead link and another email goes out, superseding it.
///
/// Keyed on the token, not an address, so it reveals nothing about who has
/// an account. An expired or already-spent token is exactly what this
/// expects; it only has to name its user.
///
/// The response carries `retry_after_seconds`, the cooldown before another
/// is accepted. Asking again inside it returns `429` with the seconds still
/// to wait in the message.
///
/// Public, because the reader of a reset email is by definition signed out.
pub(crate) async fn resend_password_reset(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<TokenStatusBody>,
) -> Result<Json<TokenResentResponse>, ApiError> {
    let resent = auth
        .password
        .reset_resend
        .execute(
            &visitor.tenant,
            &visitor.auditor,
            body.resend(visitor.link_scope),
        )
        .await?;
    Ok(Json(resent.into()))
}
