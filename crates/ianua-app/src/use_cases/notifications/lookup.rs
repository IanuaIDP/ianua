//! Loading a tenant user's notification preferences.

use ianua_domain::domains::notifications::preference::NotificationPreferenceSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal};
use crate::ports::notifications::NotificationPreferenceStore;
use crate::tenancy::ScopedTenant;

/// The user's stored preferences, with every category they never set filled
/// in with its default.
///
/// # Errors
///
/// `AppError::Internal` on storage failure.
pub(super) async fn current_preferences(
    store: &dyn NotificationPreferenceStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<NotificationPreferenceSet<ResolvedTenant>, AppError> {
    let stored = store.get(tenant, user_id).await.or_internal()?;

    Ok(NotificationPreferenceSet::from_preferences(stored))
}
