//! What every way of signing in into a tenant session leaves behind on the
//! account: when it last signed in. The record of who signed in, how, from
//! where and how long it took is raised by the session itself.

use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;

/// Stamps `user_id`'s account as signed in now, so it shows when it was
/// last used. Every way of opening a tenant session calls it once the
/// session is kept, beside recording the sign-in the session raises.
///
/// # Errors
///
/// - `AppError::NotFound` when the account is gone.
/// - `AppError::Internal` when the account cannot be read or saved.
pub(in crate::use_cases::authentication) async fn record_login(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<(), AppError> {
    let mut account = existing_user(users, tenant, user_id).await?;
    account.record_login();
    users.save(tenant, &account).await.or_internal()
}
