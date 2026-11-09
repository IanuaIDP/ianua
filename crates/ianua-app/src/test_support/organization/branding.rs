//! An in-memory store for organizations' branding.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

use crate::ports::organization::OrgBrandingStore;
use crate::test_support::Fake;

/// In-memory branding, one per organization.
#[derive(Default)]
pub struct FakeOrgBrandingStore {
    brandings: Mutex<Vec<OrgBranding>>,
}

impl FakeOrgBrandingStore {
    /// Nothing held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `branding`.
    #[must_use]
    pub fn holding(branding: OrgBranding) -> Self {
        let store = Self::empty();
        store.brandings.lock().unwrap().push(branding);
        store
    }

    /// The branding of `organization_id`, when one was saved.
    #[must_use]
    pub fn stored(&self, organization_id: &OrganizationId) -> Option<OrgBranding> {
        self.brandings
            .lock()
            .unwrap()
            .iter()
            .find(|branding| branding.organization_id() == organization_id)
            .cloned()
    }
}

#[async_trait]
impl OrgBrandingStore for FakeOrgBrandingStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgBranding>, DomainError> {
        Ok(self.stored(organization_id))
    }

    async fn save(&self, branding: &OrgBranding) -> Result<(), DomainError> {
        let mut brandings = self.brandings.lock().unwrap();
        brandings.retain(|held| held.organization_id() != branding.organization_id());
        brandings.push(branding.clone());
        Ok(())
    }
}

impl Fake for Arc<dyn OrgBrandingStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgBrandingStore::empty())
    }
}
