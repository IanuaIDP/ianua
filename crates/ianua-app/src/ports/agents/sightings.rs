//! The agents seen at work that nobody registered, kept until someone
//! registers or dismisses each.

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::sighting::{
    AgentSighting, SightingFingerprint, SightingSource,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentSightingId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting agent sightings.
///
/// One sighting is kept per source and fingerprint. The adapter holds that
/// with a unique key, so two workers seeing the same caller at once keep
/// one sighting between them.
#[async_trait]
pub trait AgentSightingStore: Send + Sync + TenantScoped {
    /// Saves a new or changed sighting.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when a new sighting's source and
    ///   fingerprint are already kept under another sighting.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        sighting: &AgentSighting<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds a sighting by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentSightingId,
    ) -> Result<Option<AgentSighting<ResolvedTenant>>, DomainError>;

    /// The sighting kept for the caller `fingerprint` names, as `source`
    /// saw it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        source: SightingSource,
        fingerprint: &SightingFingerprint,
    ) -> Result<Option<AgentSighting<ResolvedTenant>>, DomainError>;

    /// Every sighting of the tenant, last seen first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AgentSighting<ResolvedTenant>>, DomainError>;
}
