//! Rollback migration: abandon a started migration and stay on the old
//! algorithm. The key the migration created is revoked.

use std::sync::Arc;

use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{KeyId, Text};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{MigrationStore, SigningKeyStore};
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{migrating_key_set, save_key_set, save_migration};
use crate::use_cases::crypto::lookup::existing_migration;

/// The ports [`RollbackUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RollbackPorts {
    /// Loads and saves the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Loads and saves the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Rolls a started signing-algorithm migration back.
pub struct RollbackUseCase {
    ports: RollbackPorts,
}

impl RollbackUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RollbackPorts) -> Self {
        Self { ports }
    }
}

impl Command for RollbackUseCase {
    type Caller = CallerContext;
    type Input = Text;
    type Output = Result<(), AppError>;

    /// Rolls the migration back, revokes the key it created, and records
    /// `crypto.migration_rolled_back` with `reason`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signing keys.
    /// - `AppError::NotFound` when no migration is under way, or its new key
    ///   is gone from the set.
    /// - `AppError::Domain` when the migration is only planned or already
    ///   promoted, or its new key is already revoked.
    /// - `AppError::Internal` on persistence or audit failure, or when the
    ///   key set is gone.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        reason: Text,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let migration_store = self.ports.migration_store.as_ref();
        let key_store = self.ports.key_store.as_ref();
        let mut migration = existing_migration(migration_store, &tenant).await?;
        migration
            .rollback(reason, &authority)
            .map_err(AppError::from_domain)?;
        let target = created_key(migration.target_key_id())?;

        let mut key_set = migrating_key_set(key_store, &tenant).await?;
        key_set
            .revoke_migrated_key(&target, &authority)
            .map_err(AppError::from_domain)?;
        save_key_set(key_store, &tenant, &key_set).await?;
        save_migration(migration_store, &tenant, &migration).await?;

        auditor
            .dispatch_by(&caller.actor(), migration.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The key a rolled-back migration created, which it always names.
fn created_key(named: Option<&KeyId>) -> Result<KeyId, AppError> {
    named
        .cloned()
        .ok_or_else(|| AppError::internal_msg("a rolled-back migration names no new key"))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;
    use ianua_domain::domains::crypto::signing_key::SigningKeySet;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{
        FakeMigrationStore, FakeSigningKeyStore, planned_migration, premigration_keys,
        started_migration,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: RollbackUseCase,
        keys: Arc<FakeSigningKeyStore>,
        migrations: Arc<FakeMigrationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(
        keys: SigningKeySet<ResolvedTenant>,
        migration: Option<&AlgorithmMigration<ResolvedTenant>>,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let keys = Arc::new(FakeSigningKeyStore::holding(keys));
        let migrations = Arc::new(migration.map_or_else(FakeMigrationStore::empty, |held| {
            FakeMigrationStore::holding(held)
        }));
        let use_case = RollbackUseCase::new(RollbackPorts {
            key_store: keys.clone(),
            migration_store: migrations.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            keys,
            migrations,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn started_with(authorities: FakeTenantAuthorities) -> Fixture {
        let (keys, migration) = started_migration();
        fixture_with(keys, Some(&migration), authorities)
    }

    fn reason() -> Text {
        Text::new("reason", "relying parties reject ES256").unwrap()
    }

    fn roll_back(f: &Fixture) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), reason()),
        )
    }

    fn status_of(f: &Fixture, kid: &str) -> KeyStatus {
        let set = f.keys.set_of(test_ctx().tenant_id()).unwrap();
        set.keys()
            .iter()
            .find(|k| k.kid().as_str() == kid)
            .unwrap()
            .status()
    }

    /// Ann rolls back Acme's started migration because relying parties
    /// reject ES256. The new key is revoked, the old one keeps signing, and
    /// the rollback is recorded with her reason.
    #[test]
    fn rolling_back_revokes_the_new_key() {
        let f = started_with(FakeTenantAuthorities::holding_everything());

        roll_back(&f).unwrap();

        let migration = f
            .migrations
            .migration_of(test_ctx().tenant_id())
            .unwrap()
            .unwrap();
        assert_eq!(migration.status(), MigrationStatus::RolledBack);
        assert_eq!(status_of(&f, "key-new"), KeyStatus::Revoked);
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Active);
        assert_eq!(
            f.audit
                .payload_of("crypto.migration_rolled_back")
                .get("reason"),
            Some("relying parties reject ES256")
        );
    }

    /// Acme's migration is only planned. There is nothing to roll back, so
    /// it is refused; a planned migration is cancelled instead.
    #[test]
    fn a_planned_migration_cannot_be_rolled_back() {
        let f = fixture_with(
            premigration_keys(),
            Some(&planned_migration()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = roll_back(&f);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Acme is not migrating. Rolling back is not found.
    #[test]
    fn no_migration_is_not_found() {
        let f = fixture_with(
            premigration_keys(),
            None,
            FakeTenantAuthorities::holding_everything(),
        );

        let result = roll_back(&f);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A key viewer cannot roll back an algorithm migration, and its target
    /// key remains active.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = started_with(FakeTenantAuthorities::holding(&[SystemPermission::Crypto(
            CryptoAction::View,
        )]));

        let result = roll_back(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&f, "key-new"), KeyStatus::Active);
    }

    /// A signed-out session cannot roll back an algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = started_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = roll_back(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
