//! Second-factor handlers: setting up an authenticator app, answering a
//! session's second factor with it or a recovery code, resuming a suspended
//! session, and turning the factor off.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::authentication::AuthenticationState;

use crate::dto::authentication::mfa::{
    CodeFactorBody, CodeSentResponse, FactorOptionsResponse, MfaCodeBody, MfaConfirmBody,
    MfaConfirmResponse, MfaEnrollResponse, MfaSetupBody, MfaStatusResponse,
    RegenerateRecoveryCodesBody, SessionCodeBody, WaitingSignInParams,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authentication::SessionHolder;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::query::Query;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/enroll",
    tag = "Authentication",
    request_body = MfaSetupBody,
    responses(
        (status = 200, description = "Success", body = MfaEnrollResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The proof does not prove the person, a code is needed (`step_up_required`), or the tenant has second factors off", body = ErrorBody),
        (status = 409, description = "MFA is already active", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start MFA enrollment
///
/// Returns a fresh TOTP secret as an `otpauth://` URI for a QR code.
/// Signed-in people supply `proof` (password and any existing factor);
/// a waiting `mfa_enrollment_required` sign-in uses its temporary permission.
/// Enrollment stays `Pending` until a code confirms `Pending → Verified`.
/// Calling again replaces the pending secret and requires scanning again.
/// Active MFA returns `409` and must first be disabled, except that a
/// waiting sign-in which spent a recovery code may replace the lost factor
/// while its enrollment permission remains fresh.
pub(crate) async fn enroll(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    body: Option<Json<MfaSetupBody>>,
) -> Result<Json<MfaEnrollResponse>, ApiError> {
    let Json(body) = body.unwrap_or_default();
    let proof = body.setup_proof()?;
    let setter = holder.factor_setter(&proof);
    let qr = auth
        .mfa
        .begin
        .execute(&setter, &holder.auditor, proof)
        .await?;
    Ok(Json(qr.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/enroll/code",
    tag = "Authentication",
    request_body = CodeFactorBody,
    responses(
        (status = 200, description = "The first code is on its way", body = CodeSentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The proof does not prove the person, or the tenant does not offer this factor", body = ErrorBody),
        (status = 409, description = "A second factor is already in force", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start setting up mailed or texted codes
///
/// Begins a second factor whose codes are mailed to the account's address
/// (`email_code`) or texted to `phone_number` (`sms_code`), and sends the
/// first code at once. Confirm it with that code at the enroll-confirm
/// endpoint. A signed-in person sends a `proof` of who they are; a sign-in
/// that answered `mfa_enrollment_required` sends none. A setup still waiting
/// to be confirmed is replaced. Codes reach a lower assurance than an
/// authenticator app, so a tenant whose baseline needs more does not offer
/// them. Records `authentication.mfa_enrollment_started` and
/// `authentication.mfa_code_sent`.
pub(crate) async fn enroll_code_factor(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<CodeFactorBody>,
) -> Result<Json<CodeSentResponse>, ApiError> {
    let request = body.request()?;
    let setter = holder.factor_setter(&request.proof);
    let sent = auth
        .mfa
        .begin_code_factor
        .execute(&setter, &holder.auditor, request)
        .await?;
    Ok(Json(sent.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/options",
    tag = "Authentication",
    params(WaitingSignInParams),
    responses(
        (status = 200, description = "What may be set up, what is held, what is owed", body = FactorOptionsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The sign-in named is not the bearer's own session", body = ErrorBody),
        (status = 404, description = "The waiting sign-in is gone", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// My second-factor options
///
/// The kinds of second factor the tenant offers the person (`totp`,
/// `email_code`, `sms_code`), the one they hold and how far it went, and,
/// for a sign-in waiting for its factor (named by `session_id`), what it
/// still owes. Read-only.
pub(crate) async fn options(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Query(params): Query<WaitingSignInParams>,
) -> Result<Json<FactorOptionsResponse>, ApiError> {
    let setter = holder.confirming_setter(params.completing()?)?;
    let options = auth.mfa.options.execute(&setter, ()).await?;
    Ok(Json(options.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/send-code",
    tag = "Authentication",
    request_body = WaitingSignInParams,
    responses(
        (status = 200, description = "A code is on its way", body = CodeSentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The sign-in named is not the bearer's own session", body = ErrorBody),
        (status = 404, description = "No factor in use, or the waiting sign-in is gone", body = ErrorBody),
        (status = 409, description = "The factor is an authenticator app, or the sign-in owes nothing", body = ErrorBody),
        (status = 429, description = "A code went out moments ago", body = ErrorBody)
    )
)]
/// Send me a code
///
/// Mails or texts a fresh code for the person's code factor, in force or
/// still to be confirmed: for a sign-in waiting for it (name its
/// `session_id`), or for a person signed in who must prove the factor again
/// before a change. The code replaces any sent before. Records
/// `authentication.mfa_code_sent`.
pub(crate) async fn send_code(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    body: Option<Json<WaitingSignInParams>>,
) -> Result<Json<CodeSentResponse>, ApiError> {
    let Json(body) = body.unwrap_or_default();
    let setter = holder.confirming_setter(body.completing()?)?;
    let sent = auth
        .mfa
        .send_code
        .execute(&setter, &holder.auditor, ())
        .await?;
    Ok(Json(sent.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/recovery-codes/regenerate",
    tag = "Authentication",
    request_body = RegenerateRecoveryCodesBody,
    responses(
        (status = 200, description = "The new codes, shown this once", body = MfaConfirmResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The proof does not prove the person, or a code is needed (`step_up_required`)", body = ErrorBody),
        (status = 404, description = "No second factor in force", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Regenerate my recovery codes
///
/// Replaces the person's recovery codes with a fresh set, shown this once;
/// every earlier code stops working. The person proves who they are again
/// first. Records `authentication.recovery_codes_generated`.
pub(crate) async fn regenerate_recovery_codes(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Json(body): Json<RegenerateRecoveryCodesBody>,
) -> Result<Json<MfaConfirmResponse>, ApiError> {
    let codes = auth
        .mfa
        .regenerate_recovery_codes
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(codes.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/enroll/confirm",
    tag = "Authentication",
    request_body = MfaConfirmBody,
    responses(
        (status = 200, description = "Success", body = MfaConfirmResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Wrong or used code, or the sign-in named is not the bearer's own session", body = ErrorBody),
        (status = 404, description = "No pending enrollment", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Confirm MFA enrollment
///
/// A valid code activates the pending authenticator (`Pending → Verified`)
/// and returns single-use recovery codes, shown only once; keep them safe.
/// Wrong or stale codes return `403` and leave enrollment pending; repeated
/// failures lock it (`429`). Records `authentication.mfa_enrolled` and
/// `authentication.recovery_codes_generated`.
/// To finish a `mfa_enrollment_required` sign-in, send its `session_id`
/// with its refresh token as bearer. Different sessions return `403`;
/// matching ones finish enrollment and make that session usable at once.
pub(crate) async fn confirm_enrollment(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<MfaConfirmBody>,
) -> Result<Json<MfaConfirmResponse>, ApiError> {
    let setter = holder.confirming_setter(body.completing()?)?;
    let confirmed = auth
        .mfa
        .confirm
        .execute(&setter, &holder.auditor, body.request())
        .await?;
    Ok(Json(confirmed.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/enroll/abandon",
    tag = "Authentication",
    request_body = MfaSetupBody,
    responses(
        (status = 204, description = "The pending enrollment is gone"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The proof does not prove the person", body = ErrorBody),
        (status = 404, description = "No pending enrollment", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Abandon MFA enrollment
///
/// Gives up an authenticator setup that was begun and never confirmed, so
/// the next enrollment starts from a new secret. Takes the same `proof` as
/// starting one: a signed-in person proves who they are again, a sign-in
/// waiting for the factor sends none. An active factor is not touched; turn
/// it off with `DELETE …/auth/mfa`.
pub(crate) async fn abandon_enrollment(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    body: Option<Json<MfaSetupBody>>,
) -> Result<NoContent, ApiError> {
    let Json(body) = body.unwrap_or_default();
    let proof = body.setup_proof()?;
    let setter = holder.factor_setter(&proof);
    auth.mfa
        .abandon
        .execute(&setter, &holder.auditor, proof)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa",
    tag = "Authentication",
    request_body = MfaCodeBody,
    responses(
        (status = 204, description = "MFA disabled"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Wrong code", body = ErrorBody),
        (status = 404, description = "MFA not enrolled", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Disable MFA
///
/// Turns off the signed-in tenant user's second factor. Requires a `code`
/// from the authenticator being removed, the same proof changing a password
/// requires of the old password: without it, a stolen session was enough to
/// strip the factor and enrol another. If the tenant's policy requires MFA,
/// the user is asked to set one up again on their next sign-in.
pub(crate) async fn disable(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Json(body): Json<MfaCodeBody>,
) -> Result<NoContent, ApiError> {
    auth.mfa
        .disable
        .execute(&tenant.caller, &tenant.auditor, body.into())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/status",
    tag = "Authentication",
    responses(
        (status = 200, description = "MFA status", body = MfaStatusResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody)
    )
)]
/// My MFA status
///
/// Returns whether the signed-in tenant user has MFA enrolled (`enabled`)
/// and the `method` (e.g. `Totp`) if so. An enrollment that was begun but
/// never confirmed with a code counts as not enabled. Read-only: the tenant
/// twin of the organization plane's MFA status.
pub(crate) async fn status(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
) -> Result<Json<MfaStatusResponse>, ApiError> {
    let status = auth.mfa.status.execute(&tenant.caller, ()).await?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/mfa/verify",
    tag = "Authentication",
    request_body = SessionCodeBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Wrong or expired code", body = ErrorBody),
        (status = 404, description = "Not the caller's session", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Verify an MFA code
///
/// Completes a step-up challenge. When a login returns `mfa_required: true`,
/// the session is limited until the user submits a valid code from their
/// authenticator app here, with the session's own bearer.
///
/// A correct code promotes the session to fully authenticated. Codes are
/// time-based and short-lived; a wrong or expired code returns `403`.
/// Repeated failures count toward lockout: once exceeded, the response is
/// `429` (account locked). No authenticator handy? Use a recovery code
/// instead.
///
/// **Enrollment status.** Only a **`Verified`** enrollment can answer a
/// step-up challenge. This endpoint doesn't change the enrollment status; it
/// clears the session's step-up requirement.
pub(crate) async fn verify(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<SessionCodeBody>,
) -> Result<NoContent, ApiError> {
    let request = body.verification(holder.user_id())?;
    auth.mfa
        .verify
        .execute(&holder.tenant(), &holder.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/recovery-code",
    tag = "Authentication",
    request_body = SessionCodeBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Unknown or used code", body = ErrorBody),
        (status = 404, description = "Not the caller's session", body = ErrorBody),
        (status = 409, description = "The session owes no factor", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many attempts", body = ErrorBody)
    )
)]
/// Redeem a recovery code
///
/// The fallback for MFA when the authenticator device is lost or
/// unavailable. Satisfies a step-up challenge using one of the recovery
/// codes issued at enrollment instead of a TOTP code.
///
/// Recovery codes are **single-use**: redeeming one burns it, and the
/// remaining count drops by one. When they run low, the user should
/// re-enroll to generate a fresh set. An unknown or already-used code
/// returns `403`; too many attempts lock the account (`429`). Redeeming
/// against a session that's already MFA-verified returns `409`.
pub(crate) async fn redeem_recovery_code(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<SessionCodeBody>,
) -> Result<NoContent, ApiError> {
    let request = body.recovery(holder.user_id())?;
    auth.mfa
        .recovery_code
        .execute(&holder.tenant(), &holder.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/session/resume",
    tag = "Authentication",
    request_body = SessionCodeBody,
    responses(
        (status = 204, description = "The session counts again"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Wrong code", body = ErrorBody),
        (status = 404, description = "Not the caller's session, or no active second factor", body = ErrorBody),
        (status = 422, description = "Malformed code, or the session is not suspended", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Resume a suspended session
///
/// A session the platform suspended, because its binding broke or its risk
/// rose, stops counting until its holder proves themselves again. Submit a
/// code from the authenticator, with the session's own bearer, to lift the
/// suspension. Records `authentication.session_resumed`, or
/// `authentication.mfa_failed` for a wrong code, which counts toward the
/// factor's lockout.
pub(crate) async fn resume_session(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<SessionCodeBody>,
) -> Result<NoContent, ApiError> {
    let request = body.resumption(holder.user_id())?;
    auth.mfa
        .resume_session
        .execute(&holder.tenant(), &holder.auditor, request)
        .await?;
    Ok(NoContent)
}
