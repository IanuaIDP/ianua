//! In-memory linked identities: one person's accounts across an
//! organization's tenants, found by their shared address.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::organization::members::linked_identity::{
    LinkedIdentity, LinkedIdentityRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrganizationId};

use crate::ports::organization::{LinkedIdentityLookup, LinkedIdentityStore};
use crate::test_support::Fake;

/// A copy of `identity`, read back the way storage reads it.
fn copy_identity(identity: &LinkedIdentity) -> Result<LinkedIdentity, DomainError> {
    LinkedIdentity::reconstitute(LinkedIdentityRow {
        id: *identity.id(),
        organization_id: *identity.organization_id(),
        email: identity.email().clone(),
        links: identity.links().to_vec(),
        created_at: identity.created_at(),
    })
}

/// Whether `identity` is the one under `email` in `organization_id`.
fn is_under(identity: &LinkedIdentity, organization_id: &OrganizationId, email: &Email) -> bool {
    identity.organization_id() == organization_id && identity.email() == email
}

/// Linked identity lookup holding at most one identity.
#[derive(Default)]
pub struct FakeLinkedIdentityLookup {
    identity: Mutex<Option<LinkedIdentity>>,
}

impl FakeLinkedIdentityLookup {
    /// A lookup that finds `identity`, asked in its organization under its
    /// address.
    #[must_use]
    pub fn with_identity(identity: LinkedIdentity) -> Self {
        Self {
            identity: Mutex::new(Some(identity)),
        }
    }

    /// A lookup that finds nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

#[async_trait]
impl LinkedIdentityLookup for FakeLinkedIdentityLookup {
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<LinkedIdentity>, DomainError> {
        self.identity
            .lock()
            .unwrap()
            .as_ref()
            .filter(|held| is_under(held, organization_id, email))
            .map(copy_identity)
            .transpose()
    }
}

/// In-memory linked identity store that keeps every identity it is handed.
#[derive(Default)]
pub struct FakeLinkedIdentityStore {
    identities: Mutex<Vec<LinkedIdentity>>,
}

impl FakeLinkedIdentityStore {
    /// A store holding no identity.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `identities`.
    #[must_use]
    pub fn holding(identities: impl IntoIterator<Item = LinkedIdentity>) -> Self {
        let store = Self::default();
        store.identities.lock().unwrap().extend(identities);
        store
    }

    /// How many identities are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.identities.lock().unwrap().len()
    }
}

#[async_trait]
impl LinkedIdentityStore for FakeLinkedIdentityStore {
    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<LinkedIdentity>, DomainError> {
        self.identities
            .lock()
            .unwrap()
            .iter()
            .find(|held| is_under(held, organization_id, email))
            .map(copy_identity)
            .transpose()
    }

    async fn save(&self, identity: &LinkedIdentity) -> Result<(), DomainError> {
        let copy = copy_identity(identity)?;
        let mut identities = self.identities.lock().unwrap();
        if let Some(held) = identities
            .iter_mut()
            .find(|held| held.id() == identity.id())
        {
            *held = copy;
            return Ok(());
        }
        if identities
            .iter()
            .any(|held| is_under(held, identity.organization_id(), identity.email()))
        {
            return Err(DomainError::conflict(
                "another group of the organization already holds this address",
            ));
        }
        identities.push(copy);
        Ok(())
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<(), DomainError> {
        self.identities
            .lock()
            .unwrap()
            .retain(|held| !is_under(held, organization_id, email));
        Ok(())
    }
}

impl Fake for Arc<dyn LinkedIdentityLookup> {
    fn fake() -> Self {
        Arc::new(FakeLinkedIdentityLookup::empty())
    }
}

impl Fake for Arc<dyn LinkedIdentityStore> {
    fn fake() -> Self {
        Arc::new(FakeLinkedIdentityStore::empty())
    }
}
