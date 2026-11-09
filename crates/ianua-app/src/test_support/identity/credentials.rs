//! A credential store that keeps the password hashes written to it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password_rules::{
    CurrentPassword, PasswordOrigin,
};
use ianua_domain::domains::identity::account::admin_password_reset::AdminPasswordReset;
use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PasswordHash, TenantId, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::authentication::CredentialStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::held::seeded_tenant;

/// Credential store that keeps each tenant's password hashes, so a test can
/// ask whether a user ended up with a password at all.
///
/// Its seeding helpers file hashes under the tenant [`test_ctx`] carries.
///
/// [`test_ctx`]: crate::test_support::test_ctx
#[derive(Default)]
pub struct RecordingCredentialStore {
    hashes: Mutex<HashMap<(TenantId, UserId), PasswordHash>>,
    changed_at: Mutex<Option<OffsetDateTime>>,
    origins: Mutex<HashMap<(TenantId, UserId), PasswordOrigin>>,
    rehashed: Mutex<Vec<UserId>>,
}

impl RecordingCredentialStore {
    /// Reports `user_id`'s password as set by an admin, as after an admin's
    /// reset.
    #[must_use]
    pub fn set_by_admin(self, user_id: UserId) -> Self {
        self.origins
            .lock()
            .unwrap()
            .insert((seeded_tenant(), user_id), PasswordOrigin::SetByAdmin);
        self
    }

    /// Who set `user_id`'s password in the seeded tenant, as last written.
    #[must_use]
    pub fn origin_of(&self, user_id: &UserId) -> Option<PasswordOrigin> {
        self.hash_of(user_id)?;
        Some(self.origin(&seeded_tenant(), user_id))
    }

    /// Whose hashes were replaced by a fresh hash of the same password.
    #[must_use]
    pub fn rehashed(&self) -> Vec<UserId> {
        self.rehashed.lock().unwrap().clone()
    }

    fn origin(&self, tenant: &TenantId, user_id: &UserId) -> PasswordOrigin {
        self.origins
            .lock()
            .unwrap()
            .get(&(*tenant, *user_id))
            .copied()
            .unwrap_or(PasswordOrigin::ChosenByHolder)
    }

    fn write(&self, tenant: &TenantId, user_id: &UserId, hash: &PasswordHash) {
        self.hashes
            .lock()
            .unwrap()
            .insert((*tenant, *user_id), hash.clone());
    }

    fn set_origin(&self, tenant: &TenantId, user_id: &UserId, origin: PasswordOrigin) {
        self.origins
            .lock()
            .unwrap()
            .insert((*tenant, *user_id), origin);
        *self.changed_at.lock().unwrap() = Some(clock::now());
    }
    /// A store where `user_id` already has the password `hash`.
    #[must_use]
    pub fn holding(user_id: UserId, hash: &PasswordHash) -> Self {
        let store = Self::default();
        store
            .hashes
            .lock()
            .unwrap()
            .insert((seeded_tenant(), user_id), hash.clone());
        store
    }

    /// Reports the password as last changed `seconds` ago.
    #[must_use]
    pub fn changed_seconds_ago(self, seconds: i64) -> Self {
        *self.changed_at.lock().unwrap() = Some(clock::now() - time::Duration::seconds(seconds));
        self
    }

    /// The hash stored for the seeded tenant's `user_id`, if one was ever
    /// written.
    #[must_use]
    pub fn hash_of(&self, user_id: &UserId) -> Option<PasswordHash> {
        self.stored(&seeded_tenant(), user_id)
    }

    fn stored(&self, tenant: &TenantId, user_id: &UserId) -> Option<PasswordHash> {
        self.hashes
            .lock()
            .unwrap()
            .get(&(*tenant, *user_id))
            .cloned()
    }
}

impl TenantScoped for RecordingCredentialStore {}

#[async_trait]
impl CredentialStore for RecordingCredentialStore {
    async fn find_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordHash>, DomainError> {
        Ok(self.stored(tenant_id, user_id))
    }

    async fn password_changed_at(
        &self,
        _: &ScopedTenant,
        _: &UserId,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        Ok(*self.changed_at.lock().unwrap())
    }

    async fn current_password(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<CurrentPassword>, DomainError> {
        if self.stored(tenant_id, user_id).is_none() {
            return Ok(None);
        }
        Ok(Some(CurrentPassword {
            origin: self.origin(tenant_id, user_id),
            changed_at: self.changed_at.lock().unwrap().unwrap_or_else(clock::now),
        }))
    }

    async fn update_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        self.write(tenant_id, user_id, hash);
        self.set_origin(tenant_id, user_id, PasswordOrigin::ChosenByHolder);
        Ok(())
    }

    async fn import_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &ImportedPasswordHash,
    ) -> Result<(), DomainError> {
        self.update_password_hash(tenant_id, user_id, hash.hash())
            .await
    }

    async fn rehash_password(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        replaced: &PasswordHash,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        if self.stored(tenant_id, user_id).as_ref() != Some(replaced) {
            return Ok(());
        }
        self.write(tenant_id, user_id, hash);
        self.rehashed.lock().unwrap().push(*user_id);
        Ok(())
    }

    async fn reset_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        leave: &AdminPasswordReset<ResolvedTenant>,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        self.write(tenant_id, leave.user_id(), hash);
        self.set_origin(tenant_id, leave.user_id(), PasswordOrigin::SetByAdmin);
        Ok(())
    }
}

impl Fake for Arc<dyn CredentialStore> {
    fn fake() -> Self {
        Arc::new(RecordingCredentialStore::default())
    }
}
