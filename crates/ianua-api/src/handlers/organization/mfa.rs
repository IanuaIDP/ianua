//! A member's second factor: status, setting it up, answering it at sign-in
//! with a code or a recovery code, renewing the recovery codes and turning
//! it off.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::organization::OrganizationState;

use crate::dto::organization::mfa::{
    OrgFactorSetupBody, OrgMfaBeginResponse, OrgMfaConfirmBody, OrgMfaConfirmResponse,
    OrgMfaDisableBody, OrgMfaStatusResponse, OrgMfaVerifyBody, OrgRecoveryCodeBody,
    OrgRecoveryCodeResponse, OrgRecoveryCodesResponse, OrgRegenerateCodesBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::extractors::organization::sign_in::SignInHolder;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/mfa/status",
    tag = "Organizations",
    responses(
        (status = 200, description = "MFA status", body = OrgMfaStatusResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Get my MFA status
///
/// Returns whether the calling org user has MFA enrolled (`enabled`) and
/// the `method` (e.g. `Totp`) if so. Read-only. Requires the member's own
/// session or key.
pub(crate) async fn status(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgMfaStatusResponse>, ApiError> {
    let status = organization.mfa.status.execute(&member.caller, ()).await?;
    Ok(Json(OrgMfaStatusResponse::from(status)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/mfa/begin",
    tag = "Organizations",
    request_body(content = OrgFactorSetupBody, description = "Optional: the member's password typed again when signed in; nothing from a sign-in waiting for its factor"),
    responses(
        (status = 200, description = "MFA enrollment challenge", body = OrgMfaBeginResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Begin MFA enrollment
///
/// Starts TOTP enrollment for the calling org user and returns the
/// `otpauth_uri` to render as a QR code in an authenticator app. MFA isn't
/// active until the user confirms a code from the app.
///
/// Setting up a factor changes how the member signs in, so a member signed
/// in proves who they are again first: send `proof` with their password,
/// and a code from any factor they already hold (`403 step_up_required`
/// without it). A sign-in that must set up a factor before it is let in
/// (`mfa_enrollment_required`) sends no body: the sign-in itself is its
/// leave, for a few minutes after it began. Records
/// `organization.org_mfa_enrollment_started`.
pub(crate) async fn begin(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    body: Option<Json<OrgFactorSetupBody>>,
) -> Result<Json<OrgMfaBeginResponse>, ApiError> {
    let proof = OrgFactorSetupBody::setup_proof(body);
    let setter = holder.held.factor_setter(&proof)?;
    let started = organization
        .mfa
        .begin
        .execute(&setter, &holder.auditor, proof)
        .await?;
    Ok(Json(OrgMfaBeginResponse::from(started)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/mfa/abandon",
    tag = "Organizations",
    request_body(content = OrgFactorSetupBody, description = "Optional: the member's password typed again when signed in; nothing from a sign-in waiting for its factor"),
    responses(
        (status = 204, description = "The pending setup was given up"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No setup is pending", body = ErrorBody)
    )
)]
/// Give up an MFA enrollment
///
/// Drops the calling member's authenticator setup that was begun and never
/// confirmed, so they can start again with a new secret. Giving up is the
/// first step of starting again, so it asks for the same proof as begin:
/// `proof` from a member signed in, nothing from a sign-in waiting for its
/// factor. Otherwise whoever held a stolen session could give up each setup
/// the member starts. Nothing is recorded: the setup never protected
/// anything.
pub(crate) async fn abandon(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    body: Option<Json<OrgFactorSetupBody>>,
) -> Result<NoContent, ApiError> {
    let proof = OrgFactorSetupBody::setup_proof(body);
    let setter = holder.held.factor_setter(&proof)?;
    organization
        .mfa
        .abandon
        .execute(&setter, &holder.auditor, proof)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/mfa/confirm",
    tag = "Organizations",
    request_body = OrgMfaConfirmBody,
    responses(
        (status = 200, description = "MFA enrolled", body = OrgMfaConfirmResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No setup is pending", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Confirm MFA enrollment
///
/// Completes enrollment: the user enters a `code` from their authenticator
/// app; if it verifies, MFA is enabled and a set of single-use
/// `recovery_codes` is returned (shown once: store them). Records
/// `organization.org_mfa_enrolled`.
///
/// A sign-in that had to set up its first factor passes its `session_id`,
/// with that sign-in's refresh token as the bearer (`403` when the two are
/// different sessions): the code proves the new factor, so that session is
/// complete and can be used straight away.
pub(crate) async fn confirm(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    Json(body): Json<OrgMfaConfirmBody>,
) -> Result<Json<OrgMfaConfirmResponse>, ApiError> {
    let (request, waiting) = body.into_parts()?;
    let setter = holder.held.confirming_setter(waiting)?;
    let confirmed = organization
        .mfa
        .confirm
        .execute(&setter, &holder.auditor, request)
        .await?;
    Ok(Json(OrgMfaConfirmResponse::from(confirmed)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/mfa/verify",
    tag = "Organizations",
    request_body = OrgMfaVerifyBody,
    responses(
        (status = 204, description = "MFA verified"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown sign-in or no authenticator", body = ErrorBody),
        (status = 409, description = "The sign-in already proved a factor", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Verify MFA during login
///
/// Second step of an MFA-gated login: the caller, authenticated by the
/// refresh token of the sign-in that owes the factor, submits a TOTP `code`
/// from their authenticator. On success the sign-in records the factor and
/// can proceed. Returns `403` if the code is wrong or already used, and
/// `422` if it is empty. Records `organization.org_mfa_verified`.
pub(crate) async fn verify(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    Json(body): Json<OrgMfaVerifyBody>,
) -> Result<NoContent, ApiError> {
    let pending = holder.held.pending_session()?;
    organization
        .mfa
        .verify
        .execute(&pending, &holder.auditor, body.into())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/mfa/recovery",
    tag = "Organizations",
    request_body = OrgRecoveryCodeBody,
    responses(
        (status = 200, description = "The code was taken", body = OrgRecoveryCodeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The code is wrong, used, or the sign-in does not take it", body = ErrorBody),
        (status = 404, description = "Unknown sign-in, or no second factor or codes", body = ErrorBody),
        (status = 409, description = "The sign-in already proved a factor", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody)
    )
)]
/// Answer a sign-in with a recovery code
///
/// For a member who lost their authenticator: the caller, authenticated by
/// the refresh token of the sign-in that owes a second factor, sends one of
/// their unused recovery `code`s in its place. The code is spent; of two
/// sign-ins offering it at once, only one gets through. It shares the
/// factor's lock, so switching between the two buys no extra guesses.
///
/// When the organization asks for more than a password,
/// `mfa_enrollment_required` is `true`: the member sets up a new factor
/// (`…/mfa/begin`, `…/mfa/confirm`) before the session is let in. Records
/// `organization.org_mfa_verified`.
pub(crate) async fn recovery_sign_in(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    Json(body): Json<OrgRecoveryCodeBody>,
) -> Result<Json<OrgRecoveryCodeResponse>, ApiError> {
    let pending = holder.held.pending_session()?;
    let owed = organization
        .mfa
        .recovery_sign_in
        .execute(&pending, &holder.auditor, body.into())
        .await?;
    Ok(Json(OrgRecoveryCodeResponse::from(owed)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/mfa/recovery-codes",
    tag = "Organizations",
    request_body = OrgRegenerateCodesBody,
    responses(
        (status = 200, description = "The new codes", body = OrgRecoveryCodesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the proof is wrong", body = ErrorBody),
        (status = 404, description = "No second factor or recovery codes", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Replace my recovery codes
///
/// Makes a new set of recovery codes for the caller, after using most of
/// them or fearing they were seen. A recovery code lets its holder past the
/// second factor, so the caller proves who they are again first: send
/// `proof` with their password and a code from their factor (`403
/// step_up_required` without it). The new codes come back once; every
/// earlier code stops working. Records
/// `organization.org_recovery_codes_generated`. Requires the member's own
/// session.
pub(crate) async fn regenerate_recovery_codes(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<OrgRegenerateCodesBody>,
) -> Result<Json<OrgRecoveryCodesResponse>, ApiError> {
    let codes = organization
        .mfa
        .regenerate_codes
        .execute(&member.caller, &member.auditor, body.into())
        .await?;
    Ok(Json(OrgRecoveryCodesResponse::from(codes)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/mfa",
    tag = "Organizations",
    request_body = OrgMfaDisableBody,
    responses(
        (status = 204, description = "MFA disabled"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "MFA not enrolled", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many wrong codes", body = ErrorBody),
    )
)]
/// Disable my MFA
///
/// Un-enrolls TOTP MFA for the calling org user: they'll no longer be
/// prompted for a code at login. Send a current `code` from the
/// authenticator, so a stolen session is not enough to strip it. Returns
/// `403` when the code is wrong or the organization requires a second
/// factor, and `404` if MFA isn't currently enrolled. Records
/// `organization.org_mfa_unenrolled`. Requires the member's own session.
pub(crate) async fn disable(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<OrgMfaDisableBody>,
) -> Result<NoContent, ApiError> {
    organization
        .mfa
        .disable
        .execute(&member.caller, &member.auditor, body.into())
        .await?;
    Ok(NoContent)
}
