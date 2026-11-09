//! An in-memory store of pending email changes, for tenant users and
//! organization principals alike.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::account::email_change::{
    ChangeState, EmailChangeRow, PendingEmailChange,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, PrincipalId, TenantId, TokenHash, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::shared::{OrgEmailChangeStore, TenantEmailChangeStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::tokens::hash_of_link;
/// Which database keeps a pending email change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeHome {
    /// A tenant's database, for one of its users.
    Tenant(TenantId),
    /// The control plane's, for organization members and operators.
    ControlPlane,
}

/// In-memory pending email changes: at most one per person in each
/// database, replaced on save the way the real upsert does, with a record of
/// whose change was deleted.
#[derive(Default)]
pub struct FakeEmailChangeStore {
    pending: Mutex<Vec<(ChangeHome, PendingEmailChange)>>,
    deleted: Mutex<Vec<PrincipalId>>,
}

impl FakeEmailChangeStore {
    /// Nobody has a pending change.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Holds `change` in `home`.
    #[must_use]
    pub fn with_pending(home: ChangeHome, change: PendingEmailChange) -> Self {
        let store = Self::empty();
        store.upsert(home, change);
        store
    }

    /// How many pending changes are held, in every database.
    #[must_use]
    pub fn count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Whose pending changes were deleted, in order.
    #[must_use]
    pub fn deleted(&self) -> Vec<PrincipalId> {
        self.deleted.lock().unwrap().clone()
    }

    fn find(
        &self,
        home: ChangeHome,
        pick: impl Fn(&PendingEmailChange) -> bool,
    ) -> Option<PendingEmailChange> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .find(|(kept_in, change)| *kept_in == home && pick(change))
            .map(|(_, change)| change.clone())
    }

    fn upsert(&self, home: ChangeHome, change: PendingEmailChange) {
        let mut pending = self.pending.lock().unwrap();
        let slot = pending.iter_mut().find(|(kept_in, held)| {
            *kept_in == home && held.principal_id() == change.principal_id()
        });
        match slot {
            Some((_, held)) => *held = change,
            None => pending.push((home, change)),
        }
    }

    fn remove(&self, home: ChangeHome, principal_id: PrincipalId) {
        self.deleted.lock().unwrap().push(principal_id);
        self.pending
            .lock()
            .unwrap()
            .retain(|(kept_in, change)| *kept_in != home || *change.principal_id() != principal_id);
    }
}

impl TenantScoped for FakeEmailChangeStore {}

/// A change `principal_id` asked for from `from` to `to`, waiting on the
/// link `raw`, which runs out at `expires_at`, asked two hours before that
/// or now, whichever is earlier, as storage would hand it back.
///
/// # Panics
///
/// If an address is not valid or they are the same. Tests pass literals
/// that are valid and differ.
#[must_use]
pub fn stored_change(
    principal_id: PrincipalId,
    (from, to): (&str, &str),
    raw: &str,
    expires_at: OffsetDateTime,
) -> PendingEmailChange {
    PendingEmailChange::reconstitute(EmailChangeRow {
        principal_id,
        from_email: Email::new(from).expect("a valid address"),
        new_email: Email::new(to).expect("a valid address"),
        token_hash: hash_of_link(raw),
        cancel_token_hash: hash_of_link(&format!("cancel-{raw}")),
        created_at: expires_at.min(clock::now()) - time::Duration::hours(2),
        expires_at,
        state: ChangeState::Waiting,
    })
    .expect("a waiting change to another address is a consistent row")
}

#[async_trait]
impl TenantEmailChangeStore for FakeEmailChangeStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        let principal = PrincipalId::from(*user_id);
        Ok(self.find(in_tenant(tenant_id), |change| {
            *change.principal_id() == principal
        }))
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        Ok(self.find(in_tenant(tenant_id), |change| {
            change.token_hash() == token_hash
        }))
    }

    async fn find_by_cancel_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        Ok(self.find(in_tenant(tenant_id), |change| {
            change.cancel_token_hash() == cancel_token_hash
        }))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        change: &PendingEmailChange,
    ) -> Result<(), DomainError> {
        self.upsert(in_tenant(tenant_id), change.clone());
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, user_id: &UserId) -> Result<(), DomainError> {
        self.remove(in_tenant(tenant_id), PrincipalId::from(*user_id));
        Ok(())
    }
}

#[async_trait]
impl OrgEmailChangeStore for FakeEmailChangeStore {
    async fn find_by_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        Ok(self.find(ChangeHome::ControlPlane, |change| {
            change.principal_id() == principal_id
        }))
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        Ok(self.find(ChangeHome::ControlPlane, |change| {
            change.token_hash() == token_hash
        }))
    }

    async fn find_by_cancel_token_hash(
        &self,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError> {
        Ok(self.find(ChangeHome::ControlPlane, |change| {
            change.cancel_token_hash() == cancel_token_hash
        }))
    }

    async fn save(&self, change: &PendingEmailChange) -> Result<(), DomainError> {
        self.upsert(ChangeHome::ControlPlane, change.clone());
        Ok(())
    }

    async fn delete(&self, principal_id: &PrincipalId) -> Result<(), DomainError> {
        self.remove(ChangeHome::ControlPlane, *principal_id);
        Ok(())
    }
}

impl Fake for Arc<dyn OrgEmailChangeStore> {
    fn fake() -> Self {
        Arc::new(FakeEmailChangeStore::empty())
    }
}

impl Fake for Arc<dyn TenantEmailChangeStore> {
    fn fake() -> Self {
        Arc::new(FakeEmailChangeStore::empty())
    }
}

fn in_tenant(tenant_id: &ScopedTenant) -> ChangeHome {
    ChangeHome::Tenant(**tenant_id)
}
