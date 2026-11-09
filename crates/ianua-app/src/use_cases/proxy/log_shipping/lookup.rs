//! Loading the log shipping target a caller names.

use ianua_domain::domains::proxy::log_shipping::LogShippingTarget;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::LogShippingTargetId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::proxy::LogShippingStore;
use crate::tenancy::ScopedTenant;

/// The tenant's log shipping target with `target_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such target.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_log_target(
    store: &dyn LogShippingStore,
    tenant: &ScopedTenant,
    target_id: &LogShippingTargetId,
) -> Result<LogShippingTarget<ResolvedTenant>, AppError> {
    store
        .find(tenant, target_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "proxy-log-shipping-target-not-found",
            "log shipping target not found"
        ))
}
