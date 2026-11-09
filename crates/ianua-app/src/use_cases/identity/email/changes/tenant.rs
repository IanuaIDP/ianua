//! Loading a tenant user's pending email change by one of its links, and the
//! account it was asked for, which every step after the request does first.

use ianua_domain::domains::identity::account::email_change::PendingEmailChange;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{TokenHash, UserId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::identity::UserStore;
use crate::ports::shared::TenantEmailChangeStore;
use crate::tenancy::ScopedTenant;

/// The change whose confirmation link hashes to `token_hash`.
///
/// # Errors
///
/// - `AppError::NotFound` when no change carries that link.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn change_by_link(
    store: &dyn TenantEmailChangeStore,
    tenant: &ScopedTenant,
    token_hash: &TokenHash,
) -> Result<PendingEmailChange, AppError> {
    store
        .find_by_token_hash(tenant, token_hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-email-change-link",
            "invalid email change link"
        ))
}

/// The change whose cancel link, mailed to the old address, hashes to
/// `cancel_token_hash`.
///
/// # Errors
///
/// - `AppError::NotFound` when no change carries that link.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn change_by_cancel_link(
    store: &dyn TenantEmailChangeStore,
    tenant: &ScopedTenant,
    cancel_token_hash: &TokenHash,
) -> Result<PendingEmailChange, AppError> {
    store
        .find_by_cancel_token_hash(tenant, cancel_token_hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-email-change-cancel-link",
            "invalid email change cancel link"
        ))
}

/// The account `change` was asked for, as it stands now.
///
/// # Errors
///
/// - `AppError::NotFound` when the account is gone.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn changing_user(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    change: &PendingEmailChange,
) -> Result<User<ResolvedTenant>, AppError> {
    let user_id = UserId::from_uuid(*change.principal_id().as_uuid());
    users
        .find_by_id(tenant, &user_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-email-change-link",
            "invalid email change link"
        ))
}
