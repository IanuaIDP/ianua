//! Fakes for the crypto stores and key generator: signing keys and algorithm migrations

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::crypto::algorithm_migration::{
    AlgorithmMigration, AlgorithmMigrationRow,
};
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKey, SigningKeySet};
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PublicKeyPem, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::crypto::{
    CrossTenantKeySets, GeneratedKey, KeyGenerator, MigrationStore, SigningKeyStore,
    VerifyingKeyStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::{Fake, test_ctx};

/// In-memory signing key store, holding one key set per tenant as it was
/// last saved.
#[derive(Default)]
pub struct FakeSigningKeyStore {
    sets: Mutex<HashMap<TenantId, SigningKeySet<ResolvedTenant>>>,
}

impl TenantScoped for FakeSigningKeyStore {}

impl FakeSigningKeyStore {
    /// No tenant has signing keys.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The test tenant holds `set`.
    #[must_use]
    pub fn holding(set: SigningKeySet<ResolvedTenant>) -> Self {
        let store = Self::default();
        store.put(test_ctx().tenant_id(), set);
        store
    }

    /// `tenant_id` holds `set`, beside whatever other tenants hold.
    pub fn put(&self, tenant_id: TenantId, set: SigningKeySet<ResolvedTenant>) {
        self.sets.lock().unwrap().insert(tenant_id, set);
    }

    /// The key set `tenant_id` holds, as last saved.
    #[must_use]
    pub fn set_of(&self, tenant_id: TenantId) -> Option<SigningKeySet<ResolvedTenant>> {
        self.sets.lock().unwrap().get(&tenant_id).cloned()
    }
}

#[async_trait]
impl SigningKeyStore for FakeSigningKeyStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<SigningKeySet<ResolvedTenant>>, DomainError> {
        Ok(self.set_of(**tenant_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        key_set: &SigningKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.put(**tenant_id, key_set.clone());
        Ok(())
    }
}

/// The public halves of the keys the fake holds, as a verifier reads them.
#[async_trait]
impl VerifyingKeyStore for FakeSigningKeyStore {
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Vec<VerifyingKey>, DomainError> {
        Ok(self
            .set_of(**tenant_id)
            .map(|set| set.verifying_keys())
            .unwrap_or_default())
    }
}

impl Fake for Arc<dyn VerifyingKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeSigningKeyStore::empty())
    }
}

#[async_trait]
impl CrossTenantKeySets for FakeSigningKeyStore {
    async fn tenants_with_rotated_keys(&self) -> Result<Vec<TenantId>, DomainError> {
        let sets = self.sets.lock().unwrap();
        Ok(tenants_holding_rotated(
            sets.iter(),
            SigningKeySet::keys,
            SigningKey::status,
        ))
    }

    async fn tenants_with_keys_made_before(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<TenantId>, DomainError> {
        let sets = self.sets.lock().unwrap();
        Ok(sets
            .iter()
            .filter(|(_, set)| {
                set.keys()
                    .iter()
                    .any(|key| key.is_active() && key.created_at() < cutoff)
            })
            .map(|(tenant_id, _)| *tenant_id)
            .collect())
    }
}

/// Key generator handing out numbered placeholder keys: the public half a
/// well-formed PEM, the private half `private-key-1`, `private-key-2` and so
/// on.
#[derive(Default)]
pub struct FakeKeyGenerator {
    generated: Mutex<u32>,
}

impl FakeKeyGenerator {
    /// A generator that has generated nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many keys it has generated.
    #[must_use]
    pub fn generated(&self) -> u32 {
        *self.generated.lock().unwrap()
    }
}

#[async_trait]
impl KeyGenerator for FakeKeyGenerator {
    async fn generate(&self, algorithm: SigningAlgorithm) -> Result<GeneratedKey, DomainError> {
        let mut generated = self.generated.lock().unwrap();
        *generated += 1;
        let public_key = PublicKeyPem::new(format!(
            "-----BEGIN PUBLIC KEY-----\nPublicKey{algorithm}{generated}\n-----END PUBLIC KEY-----\n"
        ))?;
        Ok(GeneratedKey {
            public_key,
            private_key: Secret::new(format!("private-key-{generated}")),
        })
    }
}

/// In-memory migration store, holding each tenant's latest migration as it
/// was last saved.
#[derive(Default)]
pub struct FakeMigrationStore {
    migrations: Mutex<HashMap<TenantId, AlgorithmMigrationRow>>,
}

impl TenantScoped for FakeMigrationStore {}

impl FakeMigrationStore {
    /// No tenant has a migration.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The test tenant holds `migration`.
    #[must_use]
    pub fn holding(migration: &AlgorithmMigration<ResolvedTenant>) -> Self {
        let store = Self::default();
        store.put(test_ctx().tenant_id(), migration);
        store
    }

    /// The migration `tenant_id` holds, as last saved, finished or not.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] if the held row no longer
    /// rebuilds.
    pub fn migration_of(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<AlgorithmMigration<ResolvedTenant>>, DomainError> {
        let migrations = self.migrations.lock().unwrap();
        migrations
            .get(&tenant_id)
            .map(|row| AlgorithmMigration::reconstitute(copy_row(row)))
            .transpose()
    }

    fn put(&self, tenant_id: TenantId, migration: &AlgorithmMigration<ResolvedTenant>) {
        self.migrations
            .lock()
            .unwrap()
            .insert(tenant_id, row_of(migration));
    }
}

#[async_trait]
impl MigrationStore for FakeMigrationStore {
    async fn find_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AlgorithmMigration<ResolvedTenant>>, DomainError> {
        let migration = self.migration_of(**tenant_id)?;
        Ok(migration.filter(|held| !held.status().is_terminal()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        migration: &AlgorithmMigration<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let held = self.migration_of(**tenant_id)?;
        if held.is_some_and(|held| !held.status().is_terminal() && !is_same(&held, migration)) {
            return Err(DomainError::conflict(
                "another migration of the tenant is under way",
            ));
        }
        self.put(**tenant_id, migration);
        Ok(())
    }
}

/// The tenants among `sets` holding a key rotated out, reading each set's
/// keys with `keys_of` and each key's status with `status_of`, so every
/// fake key store answers the rotation sweep by one rule.
pub(crate) fn tenants_holding_rotated<'s, S: 's, K: 's>(
    sets: impl IntoIterator<Item = (&'s TenantId, &'s S)>,
    keys_of: impl Fn(&'s S) -> &'s [K],
    status_of: impl Fn(&K) -> KeyStatus,
) -> Vec<TenantId> {
    sets.into_iter()
        .filter(|&(_, set)| {
            keys_of(set)
                .iter()
                .any(|key| status_of(key) == KeyStatus::Rotated)
        })
        .map(|(tenant_id, _)| *tenant_id)
        .collect()
}

/// Whether `held` and `migration` are one migration at two steps: begun
/// at the same moment, from the same key.
fn is_same(
    held: &AlgorithmMigration<ResolvedTenant>,
    migration: &AlgorithmMigration<ResolvedTenant>,
) -> bool {
    held.created_at() == migration.created_at() && held.source_key_id() == migration.source_key_id()
}

/// The stored row of `migration`.
fn row_of(migration: &AlgorithmMigration<ResolvedTenant>) -> AlgorithmMigrationRow {
    AlgorithmMigrationRow {
        source_algorithm: migration.source_algorithm(),
        target_algorithm: migration.target_algorithm(),
        source_key_id: migration.source_key_id().clone(),
        state: migration.state().clone(),
        created_at: migration.created_at(),
        updated_at: migration.updated_at(),
    }
}

/// A copy of `row`, which does not implement `Clone`.
fn copy_row(row: &AlgorithmMigrationRow) -> AlgorithmMigrationRow {
    AlgorithmMigrationRow {
        source_algorithm: row.source_algorithm,
        target_algorithm: row.target_algorithm,
        source_key_id: row.source_key_id.clone(),
        state: row.state.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

impl Fake for Arc<dyn CrossTenantKeySets> {
    fn fake() -> Self {
        Arc::new(FakeSigningKeyStore::empty())
    }
}

impl Fake for Arc<dyn KeyGenerator> {
    fn fake() -> Self {
        Arc::new(FakeKeyGenerator::new())
    }
}

impl Fake for Arc<dyn MigrationStore> {
    fn fake() -> Self {
        Arc::new(FakeMigrationStore::empty())
    }
}

impl Fake for Arc<dyn SigningKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeSigningKeyStore::empty())
    }
}
