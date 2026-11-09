//! Loading the clone a caller or the worker names.

use ianua_domain::domains::tenant::clone::TenantClone;
use ianua_domain::message;
use ianua_domain::types::TenantCloneId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::tenant::TenantCloneStore;

/// The clone `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when there is no such clone.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_clone(
    store: &dyn TenantCloneStore,
    id: &TenantCloneId,
) -> Result<TenantClone, AppError> {
    store
        .find_by_id(id)
        .await
        .or_internal()?
        .or_not_found(message!("tenant-clone-not-found", "clone not found"))
}
