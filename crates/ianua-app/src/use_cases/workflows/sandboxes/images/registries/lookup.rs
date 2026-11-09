//! Loading the registry a use case acts on, or saying it is not there.

use ianua_domain::domains::workflows::sandbox::registry::ImageRegistry;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::ImageRegistryId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::workflows::ImageRegistryStore;
use crate::tenancy::ScopedTenant;

/// The tenant's allowed registry `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such registry.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_registry(
    store: &dyn ImageRegistryStore,
    tenant: &ScopedTenant,
    id: &ImageRegistryId,
) -> Result<ImageRegistry<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-image-registry", "image registry"))
}
