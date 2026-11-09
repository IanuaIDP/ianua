//! Promote migration: make the migration's new key the signer. The old key
//! is rotated out and stays published for its grace period, so tokens it
//! signed still verify.

use std::sync::Arc;

use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{MigrationStore, SigningKeyStore};
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{migrating_key_set, save_key_set, save_migration};
use crate::use_cases::crypto::lookup::existing_migration;

/// The ports [`PromoteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PromotePorts {
    /// Loads and saves the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Loads and saves the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Promotes a started migration's new key to signer.
pub struct PromoteUseCase {
    ports: PromotePorts,
}

impl PromoteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PromotePorts) -> Self {
        Self { ports }
    }
}

impl Command for PromoteUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Moves the migration on to validating, rotates the old key out so the
    /// new one signs, and records `crypto.migration_promoted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without signing-key rights.
    /// - `AppError::NotFound` for no migration or a missing old key; `Conflict` when the old key is the only signer.
    /// - `AppError::Domain` for an unstarted migration or old key that cannot sign; `Internal` for a missing key set or persistence/audit failure.
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
            .promote(&authority)
            .map_err(AppError::from_domain)?;

        let mut key_set = migrating_key_set(key_store, &tenant).await?;
        key_set
            .rotate_out(migration.source_key_id(), &authority)
            .map_err(AppError::from_domain)?;
        save_key_set(key_store, &tenant, &key_set).await?;
        save_migration(migration_store, &tenant, &migration).await?;

        auditor
            .dispatch_by(&caller.actor(), migration.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{
        FakeMigrationStore, FakeSigningKeyStore, planned_migration, premigration_keys,
        started_migration,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: PromoteUseCase,
        keys: Arc<FakeSigningKeyStore>,
        migrations: Arc<FakeMigrationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(
        keys: FakeSigningKeyStore,
        migrations: FakeMigrationStore,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let keys = Arc::new(keys);
        let migrations = Arc::new(migrations);
        let use_case = PromoteUseCase::new(PromotePorts {
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
        fixture_with(
            FakeSigningKeyStore::holding(keys),
            FakeMigrationStore::holding(&migration),
            authorities,
        )
    }

    fn promote(f: &Fixture) -> Result<(), AppError> {
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

    /// Ann promotes Acme's migration. The new key signs, the old one is
    /// rotated out but still published, and the promotion is recorded.
    #[test]
    fn promoting_makes_the_new_key_sign() {
        let f = started_with(FakeTenantAuthorities::holding_everything());

        promote(&f).unwrap();

        let set = f.keys.set_of(test_ctx().tenant_id()).unwrap();
        let migration = f
            .migrations
            .migration_of(test_ctx().tenant_id())
            .unwrap()
            .unwrap();
        assert_eq!(
            set.active_key(clock::now()).unwrap().kid().as_str(),
            "key-new"
        );
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Rotated);
        assert_eq!(migration.status(), MigrationStatus::Validating);
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "crypto.migration_promoted"
        );
    }

    /// Acme is not migrating. Promoting is not found.
    #[test]
    fn no_migration_is_not_found() {
        let f = fixture_with(
            FakeSigningKeyStore::holding(premigration_keys()),
            FakeMigrationStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = promote(&f);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Acme's migration is only planned, with no new key yet. Promoting it is
    /// refused and the old key keeps signing.
    #[test]
    fn a_planned_migration_cannot_be_promoted() {
        let f = fixture_with(
            FakeSigningKeyStore::holding(premigration_keys()),
            FakeMigrationStore::holding(&planned_migration()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = promote(&f);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Active);
    }

    /// A key viewer cannot promote an algorithm migration, and the source
    /// key remains active.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = started_with(FakeTenantAuthorities::holding(&[SystemPermission::Crypto(
            CryptoAction::View,
        )]));

        let result = promote(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&f, "key-old"), KeyStatus::Active);
    }

    /// A signed-out session cannot promote an algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = started_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = promote(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
