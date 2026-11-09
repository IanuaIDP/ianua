//! Session handlers: signing out, refreshing a session, what a sign-in page
//! offers, trusted devices and break-glass grants.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::identity::whose::Whose;
use ianua_assembly::authentication::AuthenticationState;

use crate::dto::authentication::sessions::{
    BreakGlassBody, BreakGlassGrantResponse, BreakGlassRevokeBody, DeviceListResponse,
    RevokeDeviceBody, SignInOptionsResponse, TokenRefreshBody, TokenRefreshResponse,
    TrustDeviceBody, TrustDeviceResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::authentication::{SessionHolder, SignInVisitor};
use crate::extractors::callers::{RequestMeta, TenantCaller};
use crate::extractors::json::Json;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/logout",
    tag = "Authentication",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No session holds the bearer", body = ErrorBody),
        (status = 409, description = "The session already ended", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Log out
///
/// Ends the session the bearer names, so its refresh token can no longer be
/// used, whether or not it finished signing in. Not idempotent: ending a
/// session that already ended returns `409`; guard the UI against
/// double-logouts, or ignore `409`.
///
/// Only this session is ended; the user's other active sessions (other
/// devices, browsers) keep working. Revoke those separately.
///
/// **Session status.** Moves the session `Active → Revoked`. `Revoked` is
/// terminal: the session can never be reactivated, so the user signs in
/// again for a new one. Records `authentication.session_revoked`.
pub(crate) async fn logout(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
) -> Result<NoContent, ApiError> {
    auth.sessions
        .logout
        .execute(&holder.signing_out(), &holder.auditor, ())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/token/refresh",
    tag = "Authentication",
    request_body = TokenRefreshBody,
    responses(
        (status = 200, description = "Success", body = TokenRefreshResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "A token already refreshed was replayed", body = ErrorBody),
        (status = 404, description = "Unknown or expired token", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Refresh a session
///
/// Trades a valid `refresh_token` for a fresh one and extends the session.
/// Refresh tokens are **single-use**: each call rotates the token, so the
/// one you send is immediately invalidated and replaced by the one you get
/// back. Store the new token and discard the old.
///
/// **Token-theft detection.** If a token that was *already rotated away* is
/// ever replayed, the server treats it as a stolen token: it returns `403`
/// and **revokes every session that user has**, not just this one. An
/// unknown or expired token returns `404`; in either case, log in again.
///
/// **Session status.** Refreshing ends the old session and starts a new one
/// with a new token, which ends when the original sign-in does: refreshing
/// never makes a sign-in last longer. Records
/// `authentication.token_refreshed`.
pub(crate) async fn refresh_token(
    State(auth): State<AuthenticationState>,
    holder: SessionHolder,
    Json(body): Json<TokenRefreshBody>,
) -> Result<Json<TokenRefreshResponse>, ApiError> {
    let success = auth
        .sessions
        .refresh
        .execute(
            &holder.tenant(),
            &holder.auditor,
            body.request(holder.user_id()),
        )
        .await?;
    Ok(Json(success.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sign-in-options",
    tag = "Authentication",
    responses(
        (status = 200, description = "What the sign-in page offers", body = SignInOptionsResponse),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sign-in options
///
/// Public (no session). What the tenant's sign-in page offers besides a
/// password: whether magic links and passkeys are switched on, and the
/// identity providers to show as "Sign in with ..." buttons (active
/// connections whose protocol is switched on, by name). Says nothing the
/// page does not need.
pub(crate) async fn sign_in_options(
    State(auth): State<AuthenticationState>,
    visitor: SignInVisitor,
) -> Result<Json<SignInOptionsResponse>, ApiError> {
    let options = auth
        .sessions
        .sign_in_options
        .execute(&visitor.tenant, ())
        .await?;
    Ok(Json(options.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/device/trust",
    tag = "Authentication",
    responses(
        (status = 200, description = "Success", body = DeviceListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List trusted devices
///
/// Returns the device entries the signed-in user has registered: all of
/// them, in creation order.
///
/// The list is **not** filtered to active devices: a `Revoked` device is
/// kept for history and still appears here, though it no longer gets the
/// MFA skip. Read `status` to tell the two apart: only `trusted` entries
/// take the fast path, and only they can be revoked.
///
/// **Device status.** Entries are `Trusted` until they move
/// `Trusted → Revoked` (terminal) via the device-revoke endpoint; there is
/// no automatic expiry.
pub(crate) async fn list_devices(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
) -> Result<Json<DeviceListResponse>, ApiError> {
    let devices = auth
        .sessions
        .list_devices
        .execute(&tenant.caller, Whose::Own)
        .await?;
    Ok(Json(devices.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/device/trust/add",
    tag = "Authentication",
    request_body = TrustDeviceBody,
    responses(
        (status = 201, description = "Created", body = TrustDeviceResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "The device cap is reached", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Trust this device
///
/// Marks the current device as trusted so future logins from it can skip
/// MFA step-up until the tenant's trust window expires. This is the
/// "remember this device" checkbox on the login screen.
///
/// Trust is a convenience traded against risk: only offer it on devices the
/// user controls, never shared or public machines. The grant is scoped to
/// this user and can be pulled at any time from the device list. Each user
/// has a capped number of trusted devices; exceeding it returns `409`
/// (revoke one first to free a slot). The address and user agent recorded
/// are the request's own.
///
/// **Device status.** Registers the device in **`Trusted`** status, letting
/// it skip MFA within the trust window. The only transition out is
/// `Trusted → Revoked`.
pub(crate) async fn trust_device(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    meta: RequestMeta,
    Json(body): Json<TrustDeviceBody>,
) -> Result<Created<TrustDeviceResponse>, ApiError> {
    let request = body.request(meta)?;
    let device = auth
        .sessions
        .trust_device
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(device.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/device/trust/revoke",
    tag = "Authentication",
    request_body = RevokeDeviceBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Already revoked", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Revoke a trusted device
///
/// Removes trust from a device. The next login from it has to pass full MFA
/// step-up again: the fast path is gone.
///
/// Use this the instant a device is lost, sold, or looks unfamiliar in the
/// trusted list. Revocation takes effect immediately and is scoped to the
/// signed-in user's own devices.
///
/// **Device status.** Moves the device `Trusted → Revoked`. `Revoked` is
/// terminal: a revoked device is treated as unknown on the next login and
/// must be trusted again from scratch. Revoking a device that's already
/// revoked returns `409`.
pub(crate) async fn revoke_device(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Json(body): Json<RevokeDeviceBody>,
) -> Result<NoContent, ApiError> {
    auth.sessions
        .revoke_device
        .execute(&tenant.caller, &tenant.auditor, body.own()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/break-glass",
    tag = "Authentication",
    request_body = BreakGlassBody,
    responses(
        (status = 201, description = "Created", body = BreakGlassGrantResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown user", body = ErrorBody),
        (status = 422, description = "Validation error, or a grant naming nothing", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Open a break-glass grant
///
/// Emergency access for when normal authorization is in the way of an
/// active incident. Mints a **time-boxed** grant of the permissions it
/// names (`system_permissions`, `custom_permissions`) so a user can act
/// during an outage or security event.
///
/// Break-glass is deliberately loud, not a backdoor: every grant is fully
/// audited with who, why, and for how long, and it expires on its own. The
/// approver is the caller; whether they may approve it, and how much they
/// may give, is the tenant's break-glass policy's to decide. Revoke it early
/// at the break-glass revoke endpoint once the incident is contained.
pub(crate) async fn grant_break_glass(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Json(body): Json<BreakGlassBody>,
) -> Result<Created<BreakGlassGrantResponse>, ApiError> {
    let grant = auth
        .sessions
        .break_glass_grant
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(grant.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/break-glass/revoke",
    tag = "Authentication",
    request_body = BreakGlassRevokeBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Already revoked or expired", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Close a break-glass grant
///
/// Ends an active emergency grant immediately, before its natural expiry.
/// Call this the moment elevated access is no longer needed: the shorter
/// the window, the smaller the blast radius.
///
/// The revocation is audited alongside the original grant, closing the loop
/// on the incident. Revoking a grant that is already revoked or has already
/// expired returns `409` (not a no-op); guard the UI accordingly.
pub(crate) async fn revoke_break_glass(
    State(auth): State<AuthenticationState>,
    tenant: TenantCaller,
    Json(body): Json<BreakGlassRevokeBody>,
) -> Result<NoContent, ApiError> {
    auth.sessions
        .break_glass_revoke
        .execute(&tenant.caller, &tenant.auditor, body.grant()?)
        .await?;
    Ok(NoContent)
}
