//! Loading the session, trusted device or break-glass grant a sessions use
//! case names, failing with not-found when there is none.

use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::break_glass::{BreakGlassGrant, may_ask_for};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{BreakGlassGrantId, PrincipalId, TokenHash, TrustedDeviceId, UserId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{BreakGlassStore, TrustedDeviceStore};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;

/// The dashboard session holding the refresh token whose hash is
/// `token_hash`, which must belong to `user_id`.
///
/// A token for someone else, or for a session an app holds, answers the
/// same as an unknown one.
///
/// # Errors
///
/// - `AppError::NotFound` if no such session is the user's to refresh.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::sessions) async fn owned_refresh_session(
    store: &dyn SessionStore,
    tenant: &ScopedTenant,
    token_hash: &TokenHash,
    user_id: &UserId,
) -> Result<Session<ResolvedTenant>, AppError> {
    store
        .find_by_refresh_token_hash(tenant, token_hash)
        .await
        .or_internal()?
        .filter(|session| session.user_id() == user_id && session.channel().app_service().is_none())
        .or_not_found(message!(
            "authentication-invalid-refresh-token",
            "invalid refresh token"
        ))
}

/// The trusted device with `device_id`, which must belong to `user_id`.
///
/// Someone else's device answers the same as a missing one, so its
/// existence is not revealed.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such device or it is another
///   user's.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::sessions) async fn owned_device(
    store: &dyn TrustedDeviceStore,
    tenant: &ScopedTenant,
    device_id: &TrustedDeviceId,
    user_id: &UserId,
) -> Result<TrustedDevice<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, device_id)
        .await
        .or_internal()?
        .filter(|device| device.subject_id() == PrincipalId::from(*user_id))
        .or_not_found(message!(
            "authentication-device-not-found",
            "device not found"
        ))
}

/// The tenant's break-glass grant with `grant_id`, active or not, read as
/// missing unless `authority` may end it, so nobody can tell a grant they
/// may not touch from one that does not exist.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such grant, or `authority`
///   is neither its user nor its approver and may not update users.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::sessions) async fn owned_break_glass_grant(
    store: &dyn BreakGlassStore,
    tenant: &ScopedTenant,
    grant_id: &BreakGlassGrantId,
    authority: &TenantAuthority,
) -> Result<BreakGlassGrant, AppError> {
    store
        .find_by_id(tenant, grant_id)
        .await
        .or_internal()?
        .filter(|grant| grant.may_be_revoked_by(authority))
        .or_not_found(message!(
            "authentication-grant-not-found",
            "grant not found"
        ))
}

/// The tenant's user `user_id` that `authority` asks emergency access for,
/// read as missing unless they may ask for it for them: themselves, or
/// anyone when they may update users.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such user, or `authority`
///   may not ask for access for them.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication::sessions) async fn owned_grantee(
    store: &dyn UserStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
    authority: &TenantAuthority,
) -> Result<User<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, user_id)
        .await
        .or_internal()?
        .filter(|user| may_ask_for(authority, user))
        .or_not_found(message!("app-user-not-found", "user not found"))
}
