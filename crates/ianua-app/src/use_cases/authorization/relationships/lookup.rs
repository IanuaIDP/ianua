//! Loading the relationship a caller names and the catalogue relationships
//! are checked against.

use ianua_domain::domains::authorization::relationship::Relationship;
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::RelationshipId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{RelationshipStore, ResourceTypeStore};
use crate::tenancy::ScopedTenant;

/// The tenant's relationship `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such relationship.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_relationship(
    store: &dyn RelationshipStore,
    tenant: &ScopedTenant,
    id: &RelationshipId,
) -> Result<Relationship<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-relationship-not-found",
            "relationship not found"
        ))
}

/// Every resource type the tenant declares.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn catalogue(
    store: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
) -> Result<Vec<ResourceType<ResolvedTenant>>, AppError> {
    store.list_every(tenant).await.or_internal()
}
