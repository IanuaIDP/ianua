//! A member's passkeys: adding one, listing, renaming, removing, and
//! signing in with one on the management login page.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::passkeys::OrgRegisterConfirmRequest;
use ianua_assembly::organization::OrganizationState;
use ianua_domain::types::Email;

use crate::dto::organization::passkeys::{
    OrgPasskeyChallengeResponse, OrgPasskeyListResponse, OrgPasskeyLoginBeginBody,
    OrgPasskeyLoginConfirmBody, OrgPasskeyRegisterBeginBody, OrgPasskeyRegisterConfirmBody,
    OrgRenamePasskeyBody,
};
use crate::dto::organization::sign_in::OrgLoginResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{OrgMember, Visitor};
use crate::extractors::json::Json;
use crate::extractors::organization::sign_in::{Holding, SignInHolder};
use crate::extractors::paths::organization::OrgPasskeyPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/passkeys/register",
    tag = "Organizations",
    request_body(content = OrgPasskeyRegisterBeginBody, description = "Optional: which sign-in the passkey is added from"),
    responses(
        (status = 200, description = "Success", body = OrgPasskeyChallengeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start org passkey registration
///
/// Begins registering a WebAuthn passkey for the org user. Returns a
/// one-time challenge for `navigator.credentials.create()`; hand the
/// attestation to the register-confirm endpoint to finish. The name the
/// authenticator shows comes from the member's record, never from the
/// request.
///
/// A member signed in sends no body. A sign-in that waits for the second
/// factor the organization requires sends `{"from": "WaitingSignIn"}`,
/// with that sign-in's refresh token as the bearer: the passkey then
/// finishes it. Records `organization.org_passkey_registration_started`.
pub(crate) async fn register_begin(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    body: Option<Json<OrgPasskeyRegisterBeginBody>>,
) -> Result<Json<OrgPasskeyChallengeResponse>, ApiError> {
    let holding = body.map_or(Holding::FinishedSignIn, |Json(body)| body.from.into());
    let started = organization
        .passkeys
        .register_begin
        .execute(&holder.held.registrant(holding), &holder.auditor, ())
        .await?;
    Ok(Json(OrgPasskeyChallengeResponse::from(started)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/passkeys/register/confirm",
    tag = "Organizations",
    request_body = OrgPasskeyRegisterConfirmBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm org passkey registration
///
/// Finishes enrolling a passkey for the org user. From here on they can
/// sign in at the flat login page with the passkey: no password, and no
/// MFA step, since the authenticator itself proves a second factor.
///
/// A passkey signs in on its own, so adding one takes proof: a member
/// signed in sends `proof` with their password typed again (and a code
/// from any factor they hold); a sign-in waiting for its second factor
/// sends none, and the new passkey finishes it. A duplicate credential or
/// the per-member cap returns `409`. Records
/// `organization.org_passkey_registered`.
pub(crate) async fn register_confirm(
    State(organization): State<OrganizationState>,
    holder: SignInHolder,
    Json(body): Json<OrgPasskeyRegisterConfirmBody>,
) -> Result<NoContent, ApiError> {
    let request = OrgRegisterConfirmRequest::try_from(body)?;
    let registrant = holder.held.registrant(Holding::from(&request.proof));
    organization
        .passkeys
        .register_confirm
        .execute(&registrant, &holder.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/passkeys",
    tag = "Organizations",
    responses(
        (status = 200, description = "Success", body = OrgPasskeyListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List org passkeys
///
/// Returns the signed-in org user's registered passkeys: name,
/// authenticator type, when each was enrolled and last used. Only the
/// caller's own keys are visible; key material is never returned.
pub(crate) async fn list(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgPasskeyListResponse>, ApiError> {
    let passkeys = organization
        .passkeys
        .list
        .execute(&member.caller, ())
        .await?;
    Ok(Json(OrgPasskeyListResponse::of(&passkeys)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/passkeys/{passkey_id}",
    tag = "Organizations",
    request_body = OrgRenamePasskeyBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Rename an org passkey
///
/// Changes the display name of one of the caller's passkeys. A passkey
/// belonging to another user is `404`, indistinguishable from one that
/// doesn't exist. Records `organization.org_passkey_renamed`.
pub(crate) async fn rename(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgPasskeyPath>,
    Json(body): Json<OrgRenamePasskeyBody>,
) -> Result<NoContent, ApiError> {
    organization
        .passkeys
        .rename
        .execute(
            &member.caller,
            &member.auditor,
            body.into_request(path.passkey())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/passkeys/{passkey_id}",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove an org passkey
///
/// Deletes one of the caller's passkeys. The device can no longer be used
/// to sign in; password login is unaffected. Removing it changes how the
/// member signs in, so devices and sessions from before stop counting,
/// except the session it was removed from. A passkey belonging to another
/// user is `404`, indistinguishable from one that doesn't exist. Records
/// `organization.org_passkey_removed`.
pub(crate) async fn delete(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgPasskeyPath>,
) -> Result<NoContent, ApiError> {
    organization
        .passkeys
        .delete
        .execute(&member.caller, &member.auditor, path.passkey())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/passkey/login",
    tag = "Authentication",
    request_body = OrgPasskeyLoginBeginBody,
    responses(
        (status = 200, description = "Success", body = OrgPasskeyChallengeResponse),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start org passkey login
///
/// Begins a passwordless sign-in for an organization user on the flat
/// management login plane: the same plane as `POST /api/v1/login`, no
/// organization in the URL.
///
/// **Anti-enumeration.** An unknown email, or a known user with no
/// registered passkeys, returns a decoy challenge of the same shape and
/// records nothing, so the response cannot be used to probe which accounts
/// exist. Records `organization.org_passkey_sign_in_started` otherwise.
/// Public.
pub(crate) async fn login_begin(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgPasskeyLoginBeginBody>,
) -> Result<Json<OrgPasskeyChallengeResponse>, ApiError> {
    let started = organization
        .passkeys
        .login_begin
        .execute(&(), &visitor.auditor, Email::try_from(body)?)
        .await?;
    Ok(Json(OrgPasskeyChallengeResponse::from(started)))
}

#[utoipa::path(
    post,
    path = "/api/v1/passkey/login/discover",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = OrgPasskeyChallengeResponse),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start discoverable org passkey login
///
/// Begins a usernameless sign-in on the flat management login plane: no
/// email, no organization. The browser offers a saved passkey from the
/// empty email field, and the credential the user picks names its own
/// account and organization. Complete at the org login-confirm endpoint.
/// Records `organization.org_passkey_challenge_issued` on the platform,
/// since nobody is known yet. Public.
pub(crate) async fn login_discover(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
) -> Result<Json<OrgPasskeyChallengeResponse>, ApiError> {
    let started = organization
        .passkeys
        .login_discover
        .execute(&(), &visitor.auditor, ())
        .await?;
    Ok(Json(OrgPasskeyChallengeResponse::from(started)))
}

#[utoipa::path(
    post,
    path = "/api/v1/passkey/login/confirm",
    tag = "Authentication",
    request_body = OrgPasskeyLoginConfirmBody,
    responses(
        (status = 200, description = "Success", body = OrgLoginResponse),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm org passkey login
///
/// Completes a passwordless management-plane sign-in. The response is the
/// same shape as the password login at `POST /api/v1/login`; the
/// authenticator already proved possession and user verification, so no
/// MFA step-up follows, and a passkey that falls short of the assurance the
/// organization requires is refused (`403`). The ceremony is spent before the answer is
/// checked, so a failed answer burns it. Records
/// `organization.org_login_succeeded`, or `organization.org_login_failed`
/// once the member is known and the sign-in is refused. Public.
pub(crate) async fn login_confirm(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgPasskeyLoginConfirmBody>,
) -> Result<Json<OrgLoginResponse>, ApiError> {
    let success = organization
        .passkeys
        .login_confirm
        .execute(&(), &visitor.auditor, body.into_request(visitor.meta)?)
        .await?;
    Ok(Json(OrgLoginResponse::from(success)))
}
