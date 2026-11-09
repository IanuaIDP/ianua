//! Complete migration: finish a promoted migration once relying parties have
//! picked up the new key, and revoke the old key it moved away from.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::signing_key::SigningKeySet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::KeyId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{MigrationStore, SigningKeyStore};
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{migrating_key_set, save_key_set, save_migration};
use crate::use_cases::crypto::lookup::existing_migration;

/// The ports [`CompleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CompletePorts {
    /// Loads and saves the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Loads and saves the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Completes a promoted signing-algorithm migration.
pub struct CompleteUseCase {
    ports: CompletePorts,
}

impl CompleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CompletePorts) -> Self {
        Self { ports }
    }
}

impl Command for CompleteUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Marks the migration completed, revokes the old key unless its grace
    /// already ran out and revoked it, and records
    /// `crypto.migration_completed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without signing-key rights.
    /// - `AppError::NotFound` for no migration; `Domain` for one not yet promoted.
    /// - `AppError::Conflict` when the old key is the only signer; `Internal` for a missing key set or persistence/audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let migration_store = self.ports.migration_store.as_ref();
        let key_store = self.ports.key_store.as_ref();
        let mut migration = existing_migration(migration_store, &tenant).await?;
        migration
            .complete(&authority)
            .map_err(AppError::from_domain)?;

        let mut key_set = migrating_key_set(key_store, &tenant).await?;
        retire_source(&mut key_set, migration.source_key_id(), &authority)?;
        save_key_set(key_store, &tenant, &key_set).await?;
        save_migration(migration_store, &tenant, &migration).await?;

        auditor
            .dispatch_by(&caller.actor(), migration.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Revokes the key the migration moved away from, unless it is already
/// revoked or gone.
fn retire_source(
    key_set: &mut SigningKeySet<ResolvedTenant>,
    source: &KeyId,
    by: &TenantAuthority,
) -> Result<(), AppError> {
    let still_published = key_set
        .keys()
        .iter()
        .any(|key| key.kid() == source && key.status() != KeyStatus::Revoked);
    if !still_published {
        return Ok(());
    }
    key_set
        .revoke_migrated_key(source, by)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{
        FakeMigrationStore, FakeSigningKeyStore, key_keeper, premigration_keys, promoted_migration,
        started_migration,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: CompleteUseCase,
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
        let use_case = CompleteUseCase::new(CompletePorts {
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

    fn promoted_with(authorities: FakeTenantAuthorities) -> Fixture {
        let (keys, migration) = promoted_migration();
        fixture_with(keys, Some(&migration), authorities)
    }

    fn complete(f: &Fixture) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), ()),
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

    /// Ann completes Acme's promoted migration. The old key is revoked, the
    /// migration is completed, and the completion is recorded.
    #[test]
    fn completing_revokes_the_old_key() {
        let f = promoted_with(FakeTenantAuthorities::holding_everything());

        complete(&f).unwrap();

        let migration = f
            .migrations
            .migration_of(test_ctx().tenant_id())
            .unwrap()
            .unwrap();
        assert_eq!(migration.status(), MigrationStatus::Completed);
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Revoked);
        assert_eq!(status_of(&f, "key-new"), KeyStatus::Active);
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "crypto.migration_completed"
        );
    }

    /// The old key's grace ran out and it was revoked before Ann completes
    /// the migration. Completing still succeeds.
    #[test]
    fn an_old_key_revoked_already_is_left_as_it_is() {
        let (mut keys, migration) = promoted_migration();
        keys.revoke_key(&KeyId::new("key-old").unwrap(), key_keeper())
            .unwrap();
        let f = fixture_with(
            keys,
            Some(&migration),
            FakeTenantAuthorities::holding_everything(),
        );

        complete(&f).unwrap();

        assert_eq!(status_of(&f, "key-old"), KeyStatus::Revoked);
    }

    /// Acme's migration was started but not promoted. Completing it is
    /// refused and the old key keeps signing.
    #[test]
    fn a_migration_not_yet_promoted_cannot_complete() {
        let (keys, migration) = started_migration();
        let f = fixture_with(
            keys,
            Some(&migration),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = complete(&f);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Active);
    }

    /// Acme is not migrating. Completing is not found.
    #[test]
    fn no_migration_is_not_found() {
        let f = fixture_with(
            premigration_keys(),
            None,
            FakeTenantAuthorities::holding_everything(),
        );

        let result = complete(&f);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A key viewer cannot complete the migration, and the source key
    /// remains rotated rather than revoked.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = promoted_with(FakeTenantAuthorities::holding(&[SystemPermission::Crypto(
            CryptoAction::View,
        )]));

        let result = complete(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Rotated);
    }

    /// A signed-out session cannot complete an algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = promoted_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = complete(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
