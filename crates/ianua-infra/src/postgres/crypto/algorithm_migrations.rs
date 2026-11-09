//! A tenant's algorithm migration, under row-level security.
//!
//! A tenant holds one migration row, its latest: each step is saved over
//! it, and a migration planned once the last has finished replaces it,
//! while the audit log keeps every step of the one before. One planned
//! while another runs is refused, so two plans made at once cannot both
//! succeed. The keys it
//! names are kept by foreign keys to the tenant's signing keys.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::crypto::MigrationStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use self::record::{MigrationColumns, MigrationRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres algorithm migration store.
pub struct PgMigrationStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgMigrationStore {}

impl PgMigrationStore {
    /// A store keeping algorithm migrations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl MigrationStore for PgMigrationStore {
    async fn find_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AlgorithmMigration<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MigrationRecord,
                    "queries/algorithm_migrations/active.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(MigrationRecord::into_migration).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        migration: &AlgorithmMigration<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = MigrationColumns::of(migration);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/algorithm_migrations/save.sql",
                    tenant_id.as_uuid(),
                    columns.source_algorithm,
                    columns.target_algorithm,
                    columns.source_kid,
                    columns.status,
                    columns.target_kid,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await?;
        if written == 0 {
            return Err(DomainError::conflict(message!(
                "infra-another-migration-of-the-tenant-is",
                "another migration of the tenant is under way"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::crypto::SigningKeyStore;
    use ianua_app::test_support::authentication::FakeEncryptor;
    use ianua_domain::domains::crypto::algorithm_migration::{
        AlgorithmMigrationRow, MigrationState,
    };
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;
    use ianua_domain::domains::crypto::signing_key::{SigningKey, SigningKeySet};
    use ianua_domain::types::{KeyId, TenantId};

    use super::*;
    use crate::postgres::crypto::PgSigningKeyStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::crypto::{migration_row, signing_key_row};

    struct Fixture {
        db: TestDb,
        store: PgMigrationStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant holding the keys
    /// `key-src` and `key-dst` a migration names.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        keys_for(&db, &tenant).await;
        Fixture {
            store: PgMigrationStore::new(Arc::clone(&db.databases)),
            tenant,
            db,
        }
    }

    /// Saves the keys `key-src` and `key-dst` for `tenant` through their
    /// store.
    async fn keys_for(db: &TestDb, tenant: &ScopedTenant) {
        let keys = ["key-src", "key-dst"]
            .map(|kid| SigningKey::reconstitute(signing_key_row(kid)).unwrap())
            .into_iter()
            .collect();
        PgSigningKeyStore::new(Arc::clone(&db.databases), Arc::new(FakeEncryptor))
            .save(tenant, &SigningKeySet::from_keys(keys).unwrap())
            .await
            .unwrap();
    }

    fn migration(row: AlgorithmMigrationRow) -> AlgorithmMigration<ResolvedTenant> {
        AlgorithmMigration::reconstitute(row).unwrap()
    }

    fn onto_target() -> KeyId {
        KeyId::new("key-dst").unwrap()
    }

    impl Fixture {
        async fn save(&self, state: MigrationState) {
            self.store
                .save(&self.tenant, &migration(migration_row("key-src", state)))
                .await
                .unwrap();
        }

        async fn active(&self) -> Option<AlgorithmMigration<ResolvedTenant>> {
            self.store.find_active(&self.tenant).await.unwrap()
        }
    }

    /// A planned migration is found while it runs, as it was saved.
    #[tokio::test]
    async fn a_planned_migration_is_found_while_it_runs() {
        let fx = fixture().await;

        fx.save(MigrationState::Planned).await;

        let found = fx.active().await.unwrap();
        assert_eq!(found.status(), MigrationStatus::Planned);
        assert_eq!(found.source_key_id().as_str(), "key-src");
        assert_eq!(found.created_at(), at(0));
        assert_eq!(found.updated_at(), at(1));
    }

    /// A tenant with no migration, or another tenant than the one running
    /// it, finds none.
    #[tokio::test]
    async fn a_migration_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        let before = fx.active().await;
        fx.save(MigrationState::Planned).await;

        let theirs = fx.store.find_active(&other).await.unwrap();

        assert!(before.is_none());
        assert!(theirs.is_none());
    }

    /// A step saved over the migration keeps the key it moves onto.
    #[tokio::test]
    async fn a_started_migration_keeps_the_key_it_moves_onto() {
        let fx = fixture().await;
        fx.save(MigrationState::Planned).await;

        fx.save(MigrationState::InProgress(onto_target())).await;

        let found = fx.active().await.unwrap();
        assert_eq!(found.state(), &MigrationState::InProgress(onto_target()));
    }

    /// A finished migration is no longer active, and one planned after it
    /// replaces it.
    #[tokio::test]
    async fn a_finished_migration_gives_way_to_the_next() {
        let fx = fixture().await;
        fx.save(MigrationState::Completed(onto_target())).await;
        let finished = fx.active().await;
        let next = migration(AlgorithmMigrationRow {
            created_at: at(10),
            updated_at: at(10),
            ..migration_row("key-dst", MigrationState::Planned)
        });

        fx.store.save(&fx.tenant, &next).await.unwrap();

        let found = fx.active().await.unwrap();
        assert!(finished.is_none());
        assert_eq!(found.source_key_id().as_str(), "key-dst");
        assert_eq!(found.created_at(), at(10));
    }

    /// Planning a second migration while one is in progress conflicts;
    /// the running migration keeps its target and creation time.
    #[tokio::test]
    async fn a_migration_planned_while_another_runs_is_refused() {
        let fx = fixture().await;
        fx.save(MigrationState::InProgress(onto_target())).await;
        let second = migration(AlgorithmMigrationRow {
            created_at: at(10),
            updated_at: at(10),
            ..migration_row("key-dst", MigrationState::Planned)
        });

        let saved = fx.store.save(&fx.tenant, &second).await;

        let found = fx.active().await.unwrap();
        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        assert_eq!(found.state(), &MigrationState::InProgress(onto_target()));
        assert_eq!(found.created_at(), at(0));
    }

    /// Saving a migration with an unknown target key fails at storage.
    #[tokio::test]
    async fn a_migration_naming_an_unknown_key_is_refused() {
        let fx = fixture().await;
        let unknown = KeyId::new("key-nowhere").unwrap();

        let saved = fx
            .store
            .save(
                &fx.tenant,
                &migration(migration_row(
                    "key-src",
                    MigrationState::InProgress(unknown),
                )),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A stored migration with identical source and target algorithms is
    /// rejected as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_migration_is_refused() {
        let fx = fixture().await;
        fx.save(MigrationState::Planned).await;
        fx.db
            .tamper(
                "ALTER TABLE algorithm_migrations DROP CONSTRAINT algorithm_migrations_moves; \
                 UPDATE algorithm_migrations SET target_algorithm = source_algorithm",
            )
            .await;

        let read = fx.store.find_active(&fx.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
