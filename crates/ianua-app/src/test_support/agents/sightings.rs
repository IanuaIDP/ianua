//! The agents seen at work that nobody registered, kept in memory.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::sighting::{
    AgentSighting, SightingFingerprint, SightingSource,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentSightingId;

use crate::ports::TenantScoped;
use crate::ports::agents::AgentSightingStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::shelf::Shelf;
use crate::test_support::{Fake, block_on, test_ctx};

/// In-memory sighting store: sightings are kept per tenant, one per source
/// and fingerprint, and saved in place.
#[derive(Default)]
pub struct FakeAgentSightingStore {
    sightings: Shelf<AgentSighting<ResolvedTenant>>,
}

impl TenantScoped for FakeAgentSightingStore {}

impl FakeAgentSightingStore {
    /// A store holding no sightings.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `sightings` in the test tenant.
    ///
    /// # Panics
    ///
    /// - Never: the fake store keeps every distinct sighting.
    #[must_use]
    pub fn holding(sightings: impl IntoIterator<Item = AgentSighting<ResolvedTenant>>) -> Self {
        let store = Self::empty();
        for sighting in sightings {
            block_on(store.save(&test_ctx().tenant(), &sighting)).expect("the fake store keeps it");
        }
        store
    }

    /// Every sighting kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<AgentSighting<ResolvedTenant>> {
        self.sightings.all()
    }
}

#[async_trait]
impl AgentSightingStore for FakeAgentSightingStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        sighting: &AgentSighting<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let taken = self.sightings.find(tenant_id, |stored| {
            stored.id() != sighting.id()
                && stored.source() == sighting.source()
                && stored.fingerprint() == sighting.fingerprint()
        });
        if taken.is_some() {
            return Err(DomainError::conflict("the caller is already sighted"));
        }
        self.sightings.put(tenant_id, sighting.clone(), |stored| {
            stored.id() == sighting.id()
        });
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentSightingId,
    ) -> Result<Option<AgentSighting<ResolvedTenant>>, DomainError> {
        Ok(self.sightings.find(tenant_id, |stored| stored.id() == id))
    }

    async fn find_by_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        source: SightingSource,
        fingerprint: &SightingFingerprint,
    ) -> Result<Option<AgentSighting<ResolvedTenant>>, DomainError> {
        Ok(self.sightings.find(tenant_id, |stored| {
            stored.source() == source && stored.fingerprint() == fingerprint
        }))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AgentSighting<ResolvedTenant>>, DomainError> {
        let mut sightings = self.sightings.filter(tenant_id, |_| true);
        sightings.sort_by_key(|sighting| std::cmp::Reverse(sighting.last_seen_at()));
        Ok(sightings)
    }
}

impl Fake for Arc<dyn AgentSightingStore> {
    fn fake() -> Self {
        Arc::new(FakeAgentSightingStore::empty())
    }
}

/// A first sighting of the OAuth client `fingerprint`, calling itself
/// `calls_itself`.
///
/// # Panics
///
/// - When `fingerprint` is not a valid fingerprint.
#[must_use]
pub fn sighted_client(fingerprint: &str, calls_itself: &str) -> AgentSighting<ResolvedTenant> {
    AgentSighting::observe(
        SightingSource::OAuthClient,
        SightingFingerprint::new(fingerprint).expect("the fingerprint is valid"),
        calls_itself,
    )
}
