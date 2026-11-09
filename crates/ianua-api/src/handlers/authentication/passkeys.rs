//! Passkey handlers: adding one, signing in with one, and the caller's own
//! list.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::authentication::AuthenticationState;

use crate::dto::authentication::passkeys::{
    PasskeyChallengeResponse, PasskeyListResponse, PasskeyLoginBeginBody, PasskeyLoginResponse,
    PasskeyRegisterConfirmBody, RenamePasskeyBody,
};
use crate::dto::authentication::sign_in::PasskeyAnswerBody;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authentication::{SessionHolder, SignInVisitor};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::authentication::PasskeyPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkey/register",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = PasskeyChallengeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start passkey registration
///
/// Begins registering a WebAuthn passkey: a phishing-resistant credential
/// backed by the device's secure hardware (Touch ID, Face ID, Windows Hello,
/// a security key). Returns a one-time challenge for the browser's
/// `navigator.credentials.create()` call.
///
/// Nothing is stored yet: the challenge is bound to the signed-in user and
/// expires quickly. The name the authenticator shows comes from their
/// account, never from the request. Hand the browser's attestation response
/// to the register-confirm endpoint to finish. Records
/// `authentication.passkey_registration_started`.
pub(crate) async fn begin_registration(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
) -> Result<Json<PasskeyChallengeResponse>, ApiError> {
    let started = auth
        .passkeys
        .register_begin
        .execute(&holder.signed_in_registrant(), &holder.auditor, ())
        .await?;
    Ok(Json(started.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkey/register/confirm",
    tag = "Authentication",
    request_body = PasskeyRegisterConfirmBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "No proof, a wrong one, a code needed (`step_up_required`), or an attestation that does not verify", body = ErrorBody),
        (status = 409, description = "Duplicate credential, or the passkey cap is reached", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm passkey registration
///
/// Finishes enrolling a passkey. Submit the attestation response from the
/// browser's `navigator.credentials.create()` call, with a `proof` that the
/// signed-in person is who they say (their password typed again, with a
/// code when they have one): a passkey signs in on its own, so a stolen
/// session must not add one. The server verifies the attestation against the
/// challenge issued at start and stores the resulting public-key credential.
///
/// From here on, the user can sign in with the passkey. A
/// challenge/attestation that fails verification returns `403`; a duplicate
/// credential id returns `409`; hitting the per-user passkey cap returns
/// `409` (remove one first). Every other session opened before the passkey
/// ends; this one stays. Records `authentication.passkey_registered`.
pub(crate) async fn confirm_registration(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<PasskeyRegisterConfirmBody>,
) -> Result<NoContent, ApiError> {
    auth.passkeys
        .register_confirm
        .execute(
            &holder.signed_in_registrant(),
            &holder.auditor,
            body.try_into()?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sign-in/passkey/register",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = PasskeyChallengeResponse),
        (status = 401, description = "The sign-in does not wait for a factor to be set up", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start passkey registration for a waiting sign-in
///
/// The passkey twin of `…/auth/mfa/enroll` for a sign-in that answered
/// `mfa_enrollment_required`: the person sets up a passkey as the second
/// factor the workspace requires, with the sign-in's own bearer. Returns the
/// challenge for `navigator.credentials.create()`.
pub(crate) async fn begin_sign_in_registration(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
) -> Result<Json<PasskeyChallengeResponse>, ApiError> {
    let started = auth
        .passkeys
        .register_begin
        .execute(&holder.waiting_registrant(), &holder.auditor, ())
        .await?;
    Ok(Json(started.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sign-in/passkey/register/confirm",
    tag = "Authentication",
    request_body = PasskeyRegisterConfirmBody,
    responses(
        (status = 204, description = "The passkey is added and the sign-in finished"),
        (status = 401, description = "The sign-in does not wait for a factor to be set up", body = ErrorBody),
        (status = 403, description = "The attestation does not verify", body = ErrorBody),
        (status = 409, description = "Duplicate credential, or the passkey cap is reached", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm passkey registration for a waiting sign-in
///
/// Finishes adding the passkey a waiting sign-in set up as its second
/// factor. Send the attestation without a `proof`: the sign-in itself is
/// the leave to add it, for a few minutes after it began. The new passkey
/// answers the factor the sign-in owed, so the session can be used straight
/// away. Records `authentication.passkey_registered`.
pub(crate) async fn confirm_sign_in_registration(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<PasskeyRegisterConfirmBody>,
) -> Result<NoContent, ApiError> {
    auth.passkeys
        .register_confirm
        .execute(
            &holder.waiting_registrant(),
            &holder.auditor,
            body.try_into()?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkey/login",
    tag = "Authentication",
    request_body = PasskeyLoginBeginBody,
    responses(
        (status = 200, description = "Success", body = PasskeyChallengeResponse),
        (status = 404, description = "Unknown org/tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start passkey login
///
/// Begins a passwordless sign-in with a registered passkey. Returns a
/// one-time challenge for the browser's `navigator.credentials.get()` call,
/// which the user satisfies with a biometric or security-key tap.
///
/// The challenge is short-lived and single-use. Pass the browser's
/// assertion response to the login-confirm endpoint to complete
/// authentication and receive a session.
///
/// **Anti-enumeration.** An unknown email, or a known user with no
/// registered passkeys, returns a **dummy challenge** of the same shape so
/// the response is indistinguishable from a real one: the endpoint can't be
/// used to probe which accounts or passkeys exist.
pub(crate) async fn begin_login(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<PasskeyLoginBeginBody>,
) -> Result<Json<PasskeyChallengeResponse>, ApiError> {
    let started = auth
        .passkeys
        .login_begin
        .execute(&visitor.tenant, &visitor.auditor, body.email()?)
        .await?;
    Ok(Json(started.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkey/login/discover",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = PasskeyChallengeResponse),
        (status = 404, description = "Unknown org/tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start discoverable passkey login
///
/// Begins a usernameless sign-in: no email, no credential list. This powers
/// conditional UI: the browser offers a saved passkey from the empty email
/// field, and the credential the user picks names its own account.
///
/// Returns a one-time challenge for `navigator.credentials.get()` with
/// `mediation: "conditional"`. Complete it at the regular login-confirm
/// endpoint with the assertion and the credential id.
pub(crate) async fn begin_discoverable_login(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
) -> Result<Json<PasskeyChallengeResponse>, ApiError> {
    let started = auth
        .passkeys
        .discover_begin
        .execute(&visitor.tenant, &visitor.auditor, ())
        .await?;
    Ok(Json(started.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkey/login/confirm",
    tag = "Authentication",
    request_body = PasskeyAnswerBody,
    responses(
        (status = 200, description = "Success", body = PasskeyLoginResponse),
        (status = 403, description = "The assertion does not verify, or a cloned authenticator", body = ErrorBody),
        (status = 404, description = "Unknown credential or ceremony", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm passkey login
///
/// Completes a passwordless sign-in. Submit the assertion from the browser's
/// `navigator.credentials.get()` call; the server verifies the signature
/// against the stored credential and the challenge issued at start, then
/// updates the authenticator's sign counter.
///
/// On success you get a session and a `refresh_token`, exactly like a
/// password login, but nothing phishable ever crossed the wire. The
/// authenticator proved possession and user verification, so the session
/// usually owes nothing more.
///
/// An unrecognized credential returns `404`; a failed assertion
/// verification returns `403`, as does a sign counter that went
/// **backwards** (a cloned authenticator).
pub(crate) async fn confirm_login(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
    Json(body): Json<PasskeyAnswerBody>,
) -> Result<Json<PasskeyLoginResponse>, ApiError> {
    let request = body.sign_in(visitor.origin)?;
    let success = auth
        .passkeys
        .login_confirm
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(Json(success.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkeys",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = PasskeyListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List passkeys
///
/// Returns the caller's registered passkeys: name, authenticator type, when
/// each was enrolled and last used. This backs the passkey table in the
/// account security settings. Only the caller's own keys are visible; the
/// public-key material itself is never returned.
pub(crate) async fn list(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
) -> Result<Json<PasskeyListResponse>, ApiError> {
    let passkeys = auth.passkeys.list.execute(&tenant.caller, ()).await?;
    Ok(Json(passkeys.into()))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkeys/{passkey_id}",
    tag = "Authentication",
    request_body = RenamePasskeyBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Rename a passkey
///
/// Changes the display name of one of the caller's passkeys. The name is
/// purely cosmetic: it exists so "MacBook Touch ID" and "YubiKey in the
/// drawer" stay tellable apart. A passkey belonging to another user is
/// `404`, indistinguishable from one that doesn't exist.
pub(crate) async fn rename(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Path(path): Path<PasskeyPath>,
    Json(body): Json<RenamePasskeyBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(path.passkey())?;
    auth.passkeys
        .rename
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/passkeys/{passkey_id}",
    tag = "Authentication",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove a passkey
///
/// Deletes one of the caller's passkeys. The device can no longer be used to
/// sign in; password login is unaffected. Removal is written to the audit
/// log. A passkey belonging to another user is `404`, indistinguishable from
/// one that doesn't exist.
pub(crate) async fn delete(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Path(path): Path<PasskeyPath>,
) -> Result<NoContent, ApiError> {
    auth.passkeys
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.passkey())
        .await?;
    Ok(NoContent)
}
