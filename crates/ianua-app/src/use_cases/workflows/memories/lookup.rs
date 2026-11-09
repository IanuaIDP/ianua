//! Loading the memory a use case acts on, or saying it is not there.

use ianua_domain::domains::workflows::memory::Memory;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::MemoryId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::workflows::MemoryStore;
use crate::tenancy::ScopedTenant;

/// The tenant's memory `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such memory.
/// - `AppError::Internal` when the store fails.
pub(crate) async fn existing_memory(
    store: &dyn MemoryStore,
    tenant: &ScopedTenant,
    id: &MemoryId,
) -> Result<Memory<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-memory", "memory"))
}
