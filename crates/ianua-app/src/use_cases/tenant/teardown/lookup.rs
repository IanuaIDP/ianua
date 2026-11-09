//! What running and failing a step both read: the teardown, which must
//! exist.

use ianua_domain::domains::tenant::teardown::TenantTeardown;
use ianua_domain::message;
use ianua_domain::types::TenantId;

use crate::error::{AppError, OrInternal, OrNotFound as _};
use crate::ports::tenant::TenantTeardownStore;

/// The teardown of `tenant_id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no teardown.
/// - `AppError::Internal` when it cannot be read.
pub(super) async fn existing_teardown(
    teardowns: &dyn TenantTeardownStore,
    tenant_id: &TenantId,
) -> Result<TenantTeardown, AppError> {
    teardowns
        .find(tenant_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "tenant-tenant-teardown-not-found",
            "tenant teardown not found"
        ))
}
