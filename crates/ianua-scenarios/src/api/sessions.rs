//! Signing in and the sessions it opens, on both planes: an organization
//! member at the dashboard, and a tenant user in their tenant, with their
//! password or a mailed link, the mailbox, a refresh, the devices they
//! remember, signing out, moving between tenants, a password changed or
//! reset, and a member signing in through the organization's identity
//! provider.

use super::{OrgPath, Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::federation::{Begin, Begun, Callback};
use crate::wire::organization::ActiveSession;
use crate::wire::people::Session;
use crate::wire::sign_in::{
    ConfirmMemberPasswordReset, ConfirmSignIn, ConfirmedSignIn, DeviceRemembered, Devices,
    ForgetDevice, MagicLinkRequest, MagicLinkSignIn, MemberPasswordResetFor, MovedSession,
    PasswordSignIn, RememberDevice, ResetLinkResent, ResetLinkStatus, ResetLinkToken, SignInPuzzle,
    SignOut, SignedIn, SwitchTenant,
};
use crate::wire::tenant_sign_in::{
    ChangePassword, ConfirmPasswordReset, ConfirmTenantSignIn, ConfirmedTenantSignIn,
    PasswordResetFor, PasswordSet, RefreshSession, RefreshedSession, ResetLinkWorth, SignInOptions,
    TenantPasswordSignIn, TenantSignedIn,
};

/// `POST /api/v1/login`: a member signs in to the dashboard.
#[must_use]
pub fn member_sign_in(sign_in: &PasswordSignIn) -> Request<SignedIn> {
    Request::of(Call::post("/api/v1/login").json(sign_in))
}

/// `POST /api/v1/login/confirm`: confirms a member's sign-in from the
/// mailed link.
#[must_use]
pub fn confirm_member_sign_in(confirm: &ConfirmSignIn) -> Request<ConfirmedSignIn> {
    Request::of(Call::post("/api/v1/login/confirm").json(confirm))
}

/// `POST /api/v1/login/magic-link`: asks for a sign-in link by mail.
#[must_use]
pub fn request_magic_link(request: &MagicLinkRequest) -> Request<()> {
    Request::of(Call::post("/api/v1/login/magic-link").json(request))
}

/// `POST /api/v1/login/magic-link/verify`: a member signs in with the
/// mailed link.
#[must_use]
pub fn sign_in_by_magic_link(sign_in: &MagicLinkSignIn) -> Request<SignedIn> {
    Request::of(Call::post("/api/v1/login/magic-link/verify").json(sign_in))
}

/// `POST /api/v1/login/sso`: a member starts signing in through their
/// organization's identity provider; the browser is sent there with a
/// binding only it keeps.
#[must_use]
pub fn start_sso(begin: &Begin) -> Request<Begun> {
    Request::of(Call::post("/api/v1/login/sso").json(begin))
}

/// `POST /api/v1/login/sso/callback`: the browser hands on the provider's
/// answer with its binding.
#[must_use]
pub fn finish_sso(callback: &Callback) -> Request<SignedIn> {
    Request::of(Call::post("/api/v1/login/sso/callback").json(callback))
}

/// `POST …/logout`: a member ends their own session.
#[must_use]
pub fn member_sign_out(org: &OrgPath, sign_out: &SignOut) -> Request<()> {
    Request::of(Call::post(org.at("/logout")).json(sign_out))
}

/// `GET …/devices`: the member's own remembered devices.
#[must_use]
pub fn member_devices(org: &OrgPath) -> Request<Devices> {
    Request::of(Call::get(org.at("/devices")))
}

/// `POST …/devices`: the member remembers the device they signed in from.
#[must_use]
pub fn remember_device(org: &OrgPath, remember: &RememberDevice) -> Request<DeviceRemembered> {
    Request::of(Call::post(org.at("/devices")).json(remember))
}

/// `POST …/devices/revoke`: the member forgets one of their devices.
#[must_use]
pub fn forget_device(org: &OrgPath, forget: &ForgetDevice) -> Request<()> {
    Request::of(Call::post(org.at("/devices/revoke")).json(forget))
}

/// `POST …/switch-tenant`: the member's session moves into a tenant.
#[must_use]
pub fn switch_tenant(org: &OrgPath, switch: &SwitchTenant) -> Request<MovedSession> {
    Request::of(Call::post(org.at("/switch-tenant")).json(switch))
}

/// `POST /api/v1/password/reset-request`: mails a member a reset link.
#[must_use]
pub fn request_member_password_reset(whose: &MemberPasswordResetFor) -> Request<()> {
    Request::of(Call::post("/api/v1/password/reset-request").json(whose))
}

/// `POST /api/v1/password/reset-confirm`: sets the member's new password
/// with the mailed token.
#[must_use]
pub fn confirm_member_password_reset(confirm: &ConfirmMemberPasswordReset) -> Request<()> {
    Request::of(Call::post("/api/v1/password/reset-confirm").json(confirm))
}

/// `POST /api/v1/password/reset-status`: what a reset link is worth,
/// without spending it.
#[must_use]
pub fn member_reset_link_status(token: &ResetLinkToken) -> Request<ResetLinkStatus> {
    Request::of(Call::post("/api/v1/password/reset-status").json(token))
}

/// `POST /api/v1/password/reset-resend`: replaces a member's mailed reset proof.
#[must_use]
pub fn resend_member_password_reset(token: &ResetLinkToken) -> Request<ResetLinkResent> {
    Request::of(Call::post("/api/v1/password/reset-resend").json(token))
}

/// `GET …/sessions/active`: the organization's live sessions.
#[must_use]
pub fn member_sessions(org: &OrgPath) -> Request<Page<ActiveSession>> {
    Request::of(Call::get(org.at("/sessions/active")))
}

/// `POST …/sessions/{id}/revoke`: ends a member's session.
#[must_use]
pub fn end_member_session(org: &OrgPath, session_id: &str) -> Request<()> {
    Request::of(Call::post(
        org.at(&format!("/sessions/{session_id}/revoke")),
    ))
}

/// `POST …/tenants/{tenant}/login`: a tenant user signs in with their
/// password.
#[must_use]
pub fn sign_in(tenant: &TenantPath, sign_in: &TenantPasswordSignIn) -> Request<TenantSignedIn> {
    Request::of(Call::post(tenant.at("/login")).json(sign_in))
}

/// `POST …/auth/sign-in/confirm`: confirms a waiting sign-in from the
/// mailed link.
#[must_use]
pub fn confirm_sign_in(
    tenant: &TenantPath,
    confirm: &ConfirmTenantSignIn,
) -> Request<ConfirmedTenantSignIn> {
    Request::of(Call::post(tenant.at("/auth/sign-in/confirm")).json(confirm))
}

/// `POST …/auth/token/refresh`: trades the session's token for a new one.
#[must_use]
pub fn refresh(tenant: &TenantPath, refresh: &RefreshSession) -> Request<RefreshedSession> {
    Request::of(Call::post(tenant.at("/auth/token/refresh")).json(refresh))
}

/// `POST …/auth/logout`: ends the session the bearer names.
#[must_use]
pub fn sign_out(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/logout")))
}

/// `GET …/me/sessions`: the caller's own sessions.
#[must_use]
pub fn my_sessions(tenant: &TenantPath) -> Request<Vec<Session>> {
    Request::of(Call::get(tenant.at("/me/sessions")))
}

/// `DELETE …/me/sessions/{id}`: ends one of the caller's own sessions.
#[must_use]
pub fn end_my_session(tenant: &TenantPath, session_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/me/sessions/{session_id}")),
    ))
}

/// `GET …/users/{id}/sessions`: a user's sessions, as an administrator
/// reads them.
#[must_use]
pub fn user_sessions(tenant: &TenantPath, user_id: &str) -> Request<Vec<Session>> {
    Request::of(Call::get(tenant.at(&format!("/users/{user_id}/sessions"))))
}

/// `DELETE …/users/{id}/sessions/{session}`: an administrator ends a
/// user's session.
#[must_use]
pub fn end_user_session(tenant: &TenantPath, user_id: &str, session_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/users/{user_id}/sessions/{session_id}"));
    Request::of(Call::delete(path))
}

/// `POST …/auth/password/reset-request`: mails a reset link.
#[must_use]
pub fn request_password_reset(tenant: &TenantPath, whose: &PasswordResetFor) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/password/reset-request")).json(whose))
}

/// `POST …/auth/password/reset-status`: what a tenant's reset link is
/// worth, without spending it.
#[must_use]
pub fn reset_link_status(tenant: &TenantPath, token: &ResetLinkToken) -> Request<ResetLinkWorth> {
    Request::of(Call::post(tenant.at("/auth/password/reset-status")).json(token))
}

/// `POST …/auth/password/reset-resend`: replaces a tenant user's mailed
/// reset proof.
#[must_use]
pub fn resend_reset_link(tenant: &TenantPath, token: &ResetLinkToken) -> Request<ResetLinkResent> {
    Request::of(Call::post(tenant.at("/auth/password/reset-resend")).json(token))
}

/// `POST …/auth/password/reset-code`: sends the code a reset asks for to
/// a person whose second factor is mailed or texted.
#[must_use]
pub fn send_reset_code(tenant: &TenantPath, token: &ResetLinkToken) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/password/reset-code")).json(token))
}

/// `GET …/auth/sign-in-options`: what the tenant's sign-in page offers.
#[must_use]
pub fn sign_in_options(tenant: &TenantPath) -> Request<SignInOptions> {
    Request::of(Call::get(tenant.at("/auth/sign-in-options")))
}

/// `POST …/auth/password/reset-confirm`: sets the new password with the
/// mailed token.
#[must_use]
pub fn confirm_password_reset(
    tenant: &TenantPath,
    confirm: &ConfirmPasswordReset,
) -> Request<PasswordSet> {
    Request::of(Call::post(tenant.at("/auth/password/reset-confirm")).json(confirm))
}

/// `POST …/auth/password/change`: a signed-in user changes their password.
#[must_use]
pub fn change_password(tenant: &TenantPath, change: &ChangePassword) -> Request<PasswordSet> {
    Request::of(Call::post(tenant.at("/auth/password/change")).json(change))
}

/// `POST /api/v1/sign-in/puzzle`: the puzzle a browser must solve before
/// its next sign-in, once sign-in is under pressure.
#[must_use]
pub fn sign_in_puzzle() -> Request<SignInPuzzle> {
    Request::of(Call::post("/api/v1/sign-in/puzzle"))
}
