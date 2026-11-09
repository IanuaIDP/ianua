//! Signing keys, their public halves alone, and the read of them across
//! every tenant: the three stores of signing keys in `ports/crypto.rs`,
//! sharing one mapping.
//!
//! A tenant's keys are tenant rows, under row-level security. A private key
//! is key material, so it is sealed by the platform's secret sealer before
//! it is written and opened as it is read; the database never holds it in
//! clear. A key set only grows: saving it writes every key in one
//! statement, and a key leaves service by rotation and revocation, never by
//! being removed.
//!
//! The sweeps read every tenant's keys: those of the tenants in the
//! platform database in one query, as platform work, and each tenant with
//! a database of its own from that database, all at once.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::crypto::{CrossTenantKeySets, SigningKeyStore, VerifyingKeyStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::signing_key::{SigningKey, SigningKeySet};
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SealedSecret, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{KeySetColumns, SigningKeyRecord, VerifyingKeyRecord};
use crate::postgres::crypto::assertion_keys::every_tenant;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Where `tenant`'s signing key `kid` keeps its private key sealed.
fn key_place(tenant: &ScopedTenant, kid: &str) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::SigningKey, kid)
}

/// The Postgres signing key store.
pub struct PgSigningKeyStore {
    databases: Arc<Databases>,
    sealer: Arc<dyn SecretEncryptor>,
}

impl TenantScoped for PgSigningKeyStore {}

impl PgSigningKeyStore {
    /// A store keeping signing keys in `databases`, every private key sealed
    /// and opened by `sealer`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, sealer: Arc<dyn SecretEncryptor>) -> Self {
        Self { databases, sealer }
    }

    /// The private key of `tenant`'s `key`, sealed for storage.
    async fn sealed(
        &self,
        tenant: &ScopedTenant,
        key: &SigningKey,
    ) -> Result<SealedSecret, DomainError> {
        self.sealer
            .encrypt(
                key.private_key().expose().as_bytes(),
                &key_place(tenant, key.kid().as_str()),
            )
            .await
    }

    /// The key `record` of `tenant` holds, its private key opened.
    async fn opened(
        &self,
        tenant: &ScopedTenant,
        record: SigningKeyRecord,
    ) -> Result<SigningKey, DomainError> {
        let sealed = record.sealed_private_key()?;
        let opened = self
            .sealer
            .decrypt(&sealed, &key_place(tenant, &record.kid))
            .await?;
        let pem = String::from_utf8(opened).map_err(DomainError::infra)?;
        record.into_signing_key(Secret::new(pem))
    }
}

#[async_trait]
impl SigningKeyStore for PgSigningKeyStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<SigningKeySet<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SigningKeyRecord,
                    "queries/signing_keys/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        if records.is_empty() {
            return Ok(None);
        }
        let keys = try_join_all(
            records
                .into_iter()
                .map(|record| self.opened(tenant_id, record)),
        )
        .await?;
        SigningKeySet::from_keys(keys).map(Some)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        key_set: &SigningKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let sealed =
            try_join_all(key_set.keys().iter().map(|key| self.sealed(tenant_id, key))).await?;
        let columns = KeySetColumns::of(key_set.keys(), &sealed);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/signing_keys/save.sql",
                    tenant_id.as_uuid(),
                    &columns.kids,
                    &columns.algorithms,
                    &columns.public_keys,
                    &columns.private_keys,
                    &columns.statuses,
                    &columns.rotated_at as &[Option<OffsetDateTime>],
                    &columns.expires_at as &[Option<OffsetDateTime>],
                    &columns.created_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

/// The Postgres read of the public halves of a tenant's signing keys, for
/// the gateway. It names the public columns alone, the only ones the
/// gateway's role may read.
pub struct PgVerifyingKeyStore {
    databases: Arc<Databases>,
}

impl PgVerifyingKeyStore {
    /// A read of the verifying keys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgVerifyingKeyStore {}

#[async_trait]
impl VerifyingKeyStore for PgVerifyingKeyStore {
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Vec<VerifyingKey>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    VerifyingKeyRecord,
                    "queries/signing_keys/verifying_of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(VerifyingKeyRecord::into_verifying_key)
            .collect()
    }
}

/// The Postgres read of signing keys across every tenant.
pub struct PgCrossTenantKeySets {
    databases: Arc<Databases>,
}

impl PgCrossTenantKeySets {
    /// A read of the signing keys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The tenants in the platform database holding a rotated key.
    async fn shared_rotated(&self) -> Result<Vec<Uuid>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/signing_keys/rotated.sql")
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// Whether `tenant`, in its own database, holds a rotated key.
    async fn own_rotated(&self, tenant: TenantId) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/signing_keys/rotated_of_tenant.sql",
                    tenant.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }

    /// The tenants in the platform database holding an active key made
    /// before `cutoff`.
    async fn shared_made_before(&self, cutoff: OffsetDateTime) -> Result<Vec<Uuid>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/signing_keys/active_before.sql", cutoff)
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// Whether `tenant`, in its own database, holds an active key made
    /// before `cutoff`.
    async fn own_made_before(
        &self,
        tenant: TenantId,
        cutoff: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/signing_keys/active_before_of_tenant.sql",
                    tenant.as_uuid(),
                    cutoff
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl CrossTenantKeySets for PgCrossTenantKeySets {
    async fn tenants_with_rotated_keys(&self) -> Result<Vec<TenantId>, DomainError> {
        let own = self.databases.with_own_database();
        let (shared, held) = futures_util::try_join!(
            self.shared_rotated(),
            try_join_all(own.iter().map(|tenant| self.own_rotated(*tenant)))
        )?;
        Ok(every_tenant(shared, own, held))
    }

    async fn tenants_with_keys_made_before(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<TenantId>, DomainError> {
        let own = self.databases.with_own_database();
        let (shared, held) = futures_util::try_join!(
            self.shared_made_before(cutoff),
            try_join_all(
                own.iter()
                    .map(|tenant| self.own_made_before(*tenant, cutoff))
            )
        )?;
        Ok(every_tenant(shared, own, held))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::authentication::FakeEncryptor;
    use ianua_domain::domains::crypto::key_status::{KeyState, PriorRotation};
    use ianua_domain::domains::crypto::signing_key::SigningKeyRow;
    use ianua_domain::types::Expiry;

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::crypto::{private_pem, rotated_key_row, signing_key_row};

    struct Fixture {
        db: TestDb,
        store: PgSigningKeyStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it sealing with the fake sealer, and
    /// one tenant to keep keys for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: store_on(&db),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn store_on(db: &TestDb) -> PgSigningKeyStore {
        PgSigningKeyStore::new(Arc::clone(&db.databases), Arc::new(FakeEncryptor))
    }

    fn set_of(rows: Vec<SigningKeyRow>) -> SigningKeySet<ResolvedTenant> {
        let keys = rows
            .into_iter()
            .map(|row| SigningKey::reconstitute(row).unwrap())
            .collect();
        SigningKeySet::from_keys(keys).unwrap()
    }

    fn kids(set: &SigningKeySet<ResolvedTenant>) -> Vec<&str> {
        set.keys().iter().map(|key| key.kid().as_str()).collect()
    }

    impl Fixture {
        async fn found(&self) -> SigningKeySet<ResolvedTenant> {
            self.store.find(&self.tenant).await.unwrap().unwrap()
        }
    }

    /// A tenant's key set, one key active and expiring, one rotated out,
    /// is found again with every key as it was saved, the private key
    /// opened again.
    #[tokio::test]
    async fn a_saved_key_set_is_found_with_every_key() {
        let fx = fixture().await;
        let saved = set_of(vec![
            SigningKeyRow {
                expires_at: Expiry::At(at(500)),
                ..signing_key_row("key-a")
            },
            rotated_key_row("key-b", 5),
        ]);

        fx.store.save(&fx.tenant, &saved).await.unwrap();

        let found = fx.found().await;
        assert_eq!(kids(&found), ["key-a", "key-b"]);
        for (found, saved) in found.keys().iter().zip(saved.keys()) {
            assert_eq!(found.algorithm(), saved.algorithm());
            assert_eq!(found.public_key(), saved.public_key());
            assert_eq!(found.private_key().expose(), saved.private_key().expose());
            assert_eq!(found.state(), saved.state());
            assert_eq!(found.expires_at(), saved.expires_at());
            assert_eq!(found.created_at(), saved.created_at());
        }
    }

    /// A tenant that never had keys finds none, rather than failing.
    #[tokio::test]
    async fn a_tenant_without_keys_finds_none() {
        let fx = fixture().await;

        let found = fx.store.find(&fx.tenant).await.unwrap();

        assert!(found.is_none());
    }

    /// Another tenant sees none of Acme's keys, and may hold a key of the
    /// same id.
    #[tokio::test]
    async fn another_tenants_keys_are_invisible() {
        let fx = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(&fx.tenant, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();

        let before = fx.store.find(&other).await.unwrap();
        fx.store
            .save(&other, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();

        assert!(before.is_none());
        assert_eq!(kids(&fx.found().await), ["key-a"]);
    }

    /// Acme rotates: saving the set again keeps the old key rotated out
    /// and the new one beside it.
    #[tokio::test]
    async fn saving_again_keeps_the_new_standing() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        let rotated = set_of(vec![rotated_key_row("key-a", 5), signing_key_row("key-b")]);

        fx.store.save(&fx.tenant, &rotated).await.unwrap();

        let found = fx.found().await;
        assert_eq!(kids(&found), ["key-a", "key-b"]);
        assert_eq!(found.keys()[0].state(), KeyState::Rotated { at: at(5) });
        assert!(found.keys()[1].is_active());
    }

    /// Sealing a signing key for storage hides both its private PEM and
    /// the private-key header.
    #[tokio::test]
    async fn a_private_key_is_never_written_in_clear() {
        let fx = fixture().await;
        let key = SigningKey::reconstitute(signing_key_row("key-a")).unwrap();

        let written = fx.store.sealed(&fx.tenant, &key).await.unwrap();

        assert_ne!(written.as_str(), private_pem("key-a"));
        assert!(!written.as_str().contains("PRIVATE KEY"));
    }

    /// Copying Globex's sealed key into Acme's row makes Acme's read fail
    /// as corrupt storage; Globex's own key set remains readable.
    #[tokio::test]
    async fn a_private_key_moved_to_another_tenant_does_not_open() {
        let db = TestDb::fresh().await;
        let sealer =
            AesGcmSecretEncryptor::new(SealingKey::new("k1", [7; 32]).unwrap(), Vec::new());
        let store = PgSigningKeyStore::new(Arc::clone(&db.databases), Arc::new(sealer));
        let (acme, globex) = (
            ScopedTenant::for_background(TenantId::new()),
            ScopedTenant::for_background(TenantId::new()),
        );
        for tenant in [&acme, &globex] {
            store
                .save(tenant, &set_of(vec![signing_key_row("key-a")]))
                .await
                .unwrap();
        }
        db.tamper(&format!(
            "UPDATE signing_keys SET private_key_sealed = globex.private_key_sealed \
             FROM signing_keys globex \
             WHERE globex.tenant_id = '{}' AND signing_keys.tenant_id = '{}'",
            globex.as_uuid(),
            acme.as_uuid()
        ))
        .await;

        let moved = store.find(&acme).await;
        let own = store.find(&globex).await;

        assert!(matches!(moved, Err(DomainError::Infrastructure(_))));
        assert!(own.unwrap().is_some());
    }

    /// An unreadable sealed private key makes the key-set read fail as
    /// corrupt storage.
    #[tokio::test]
    async fn a_private_key_that_does_not_open_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE signing_keys SET private_key_sealed = 'v1.AAECAwQF'")
            .await;

        let read = fx.store.find(&fx.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Replacing a stored public key with invalid text makes the key-set
    /// read report corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_key_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE signing_keys SET public_key = 'not a key'")
            .await;

        let read = fx.store.find(&fx.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// The sweep after the grace finds the tenants holding a rotated key,
    /// and passes over one whose keys all sign.
    #[tokio::test]
    async fn the_sweep_finds_the_tenants_holding_a_rotated_key() {
        let fx = fixture().await;
        let calm = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(
                &fx.tenant,
                &set_of(vec![rotated_key_row("key-a", 5), signing_key_row("key-b")]),
            )
            .await
            .unwrap();
        fx.store
            .save(&calm, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        let sweep = PgCrossTenantKeySets::new(Arc::clone(&fx.db.databases));

        let found = sweep.tenants_with_rotated_keys().await.unwrap();

        assert_eq!(found, [*fx.tenant]);
    }

    /// The rotation by age finds the tenants holding an active key made
    /// before the cutoff, and passes over one whose key is younger or whose
    /// old key no longer signs.
    #[tokio::test]
    async fn the_sweep_finds_the_tenants_holding_an_old_active_key() {
        let fx = fixture().await;
        let young = ScopedTenant::for_background(TenantId::new());
        let rotated = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(&fx.tenant, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        let made_late = SigningKeyRow {
            created_at: at(100),
            ..signing_key_row("key-a")
        };
        fx.store
            .save(&young, &set_of(vec![made_late]))
            .await
            .unwrap();
        fx.store
            .save(&rotated, &set_of(vec![rotated_key_row("key-a", 5)]))
            .await
            .unwrap();
        let sweep = PgCrossTenantKeySets::new(Arc::clone(&fx.db.databases));

        let found = sweep.tenants_with_keys_made_before(at(50)).await.unwrap();

        assert_eq!(found, [*fx.tenant]);
    }

    /// Rotation sweeps include keys in a tenant's dedicated database:
    /// rotated keys appear with shared tenants, and old active keys are found.
    #[tokio::test]
    async fn the_sweeps_reach_a_tenant_with_its_own_database() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        fx.store
            .save(&fx.tenant, &set_of(vec![rotated_key_row("key-a", 5)]))
            .await
            .unwrap();
        fx.store
            .save(
                &apart,
                &set_of(vec![rotated_key_row("key-a", 5), signing_key_row("key-b")]),
            )
            .await
            .unwrap();
        let sweep = PgCrossTenantKeySets::new(Arc::clone(&fx.db.databases));

        let rotated = sweep.tenants_with_rotated_keys().await.unwrap();
        let old = sweep.tenants_with_keys_made_before(at(50)).await.unwrap();

        assert_eq!(rotated, [*fx.tenant, *apart]);
        assert_eq!(old, [*apart]);
        assert!(store_on(&own).find(&apart).await.unwrap().is_some());
    }

    /// The gateway, signed in as its own role, reads the public half of
    /// every key that still verifies, newest first; a revoked key is left
    /// out.
    #[tokio::test]
    async fn the_gateway_reads_the_public_halves_newest_first() {
        let fx = fixture().await;
        let revoked = SigningKeyRow {
            state: KeyState::Revoked {
                before: PriorRotation::NotRotated,
            },
            ..signing_key_row("key-c")
        };
        let newest = SigningKeyRow {
            created_at: at(10),
            ..signing_key_row("key-b")
        };
        fx.store
            .save(
                &fx.tenant,
                &set_of(vec![rotated_key_row("key-a", 5), newest, revoked]),
            )
            .await
            .unwrap();
        let gateway = PgVerifyingKeyStore::new(Arc::clone(&fx.db.gateway));

        let found = gateway.find(&fx.tenant).await.unwrap();

        let kids: Vec<&str> = found.iter().map(|key| key.kid().as_str()).collect();
        assert_eq!(kids, ["key-b", "key-a"]);
    }

    /// Another tenant's keys are not among the ones the gateway reads for
    /// a tenant, and a tenant with none has none.
    #[tokio::test]
    async fn the_gateway_reads_no_other_tenants_keys() {
        let fx = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(&other, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        let gateway = PgVerifyingKeyStore::new(Arc::clone(&fx.db.gateway));

        let found = gateway.find(&fx.tenant).await.unwrap();

        assert!(found.is_empty());
    }

    /// The gateway's verifying-key read rejects invalid stored public-key
    /// text as corrupt storage.
    #[tokio::test]
    async fn a_public_half_that_breaks_a_rule_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &set_of(vec![signing_key_row("key-a")]))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE signing_keys SET public_key = 'not a key'")
            .await;
        let gateway = PgVerifyingKeyStore::new(Arc::clone(&fx.db.gateway));

        let read = gateway.find(&fx.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
