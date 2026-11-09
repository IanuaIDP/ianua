//! Start migration: create the key the migration moves to and publish it
//! beside the old one. The old key keeps signing until the new one is
//! promoted.

use std::sync::Arc;

use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::KeyId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{KeyGenerator, MigrationStore, SigningKeyStore};
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{
    generated_signing_key, migrating_key_set, save_key_set, save_migration,
};
use crate::use_cases::crypto::lookup::existing_migration;

/// The ports [`StartUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartPorts {
    /// Loads and saves the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Generates the key the migration moves to.
    pub key_generator: Arc<dyn KeyGenerator>,
    /// Loads and saves the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Starts a planned signing-algorithm migration.
pub struct StartUseCase {
    ports: StartPorts,
}

impl StartUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartPorts) -> Self {
        Self { ports }
    }
}

impl Command for StartUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<KeyId, AppError>;

    /// Generates a key with the migration's target algorithm, publishes it
    /// beside the key that signs now, and records
    /// `crypto.migration_started`. Returns the new key's id.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signing keys.
    ///   Nothing is generated then.
    /// - `AppError::NotFound` when no migration is under way.
    /// - `AppError::Domain` when the migration is no longer planned.
    /// - `AppError::Internal` on key generation, persistence or audit
    ///   failure, or when the key set is gone.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<KeyId, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let migration_store = self.ports.migration_store.as_ref();
        let key_store = self.ports.key_store.as_ref();
        let mut migration = existing_migration(migration_store, &tenant).await?;
        let new_key = generated_signing_key(
            self.ports.key_generator.as_ref(),
            migration.target_algorithm(),
        )
        .await?;
        let new_kid = new_key.kid().clone();
        migration
            .start(&new_key, &authority)
            .map_err(AppError::from_domain)?;

        let mut key_set = migrating_key_set(key_store, &tenant).await?;
        key_set
            .add_key(new_key, &authority)
            .map_err(AppError::from_domain)?;
        save_key_set(key_store, &tenant, &key_set).await?;
        save_migration(migration_store, &tenant, &migration).await?;

        auditor
            .dispatch_by(&caller.actor(), migration.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(new_kid)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{
        FakeKeyGenerator, FakeMigrationStore, FakeSigningKeyStore, planned_migration,
        premigration_keys, started_migration,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: StartUseCase,
        keys: Arc<FakeSigningKeyStore>,
        migrations: Arc<FakeMigrationStore>,
        generator: Arc<FakeKeyGenerator>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(migrations: FakeMigrationStore, authorities: FakeTenantAuthorities) -> Fixture {
        let keys = Arc::new(FakeSigningKeyStore::holding(premigration_keys()));
        let migrations = Arc::new(migrations);
        let generator = Arc::new(FakeKeyGenerator::new());
        let use_case = StartUseCase::new(StartPorts {
            key_store: keys.clone(),
            key_generator: generator.clone(),
            migration_store: migrations.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            keys,
            migrations,
            generator,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn planned() -> FakeMigrationStore {
        FakeMigrationStore::holding(&planned_migration())
    }

    fn start(f: &Fixture) -> Result<KeyId, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), ()),
        )
    }

    /// Ann starts Acme's planned move to ES256. An ES256 key is published
    /// beside the old one, the old key keeps signing, and the start is
    /// recorded.
    #[test]
    fn starting_publishes_the_new_key_beside_the_old() {
        let f = fixture_with(planned(), FakeTenantAuthorities::holding_everything());

        let new_kid = start(&f).unwrap();

        let set = f.keys.set_of(test_ctx().tenant_id()).unwrap();
        let new_key = set.keys().iter().find(|k| k.kid() == &new_kid).unwrap();
        let migration = f
            .migrations
            .migration_of(test_ctx().tenant_id())
            .unwrap()
            .unwrap();
        assert_eq!(new_key.algorithm(), SigningAlgorithm::Es256);
        assert_eq!(
            set.active_key(clock::now()).unwrap().kid().as_str(),
            "key-old"
        );
        assert_eq!(migration.status(), MigrationStatus::InProgress);
        assert_eq!(migration.target_key_id(), Some(&new_kid));
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "crypto.migration_started"
        );
    }

    /// Acme is not migrating. Starting is not found.
    #[test]
    fn no_migration_is_not_found() {
        let f = fixture_with(
            FakeMigrationStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = start(&f);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Acme's migration was already started. Starting it again is refused
    /// and no second key joins the set.
    #[test]
    fn a_started_migration_cannot_start_again() {
        let (_, migration) = started_migration();
        let f = fixture_with(
            FakeMigrationStore::holding(&migration),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = start(&f);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(
            f.keys.set_of(test_ctx().tenant_id()).unwrap().keys().len(),
            1
        );
    }

    /// A key viewer cannot start the planned migration, and no key is
    /// generated.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = fixture_with(
            planned(),
            FakeTenantAuthorities::holding(&[SystemPermission::Crypto(CryptoAction::View)]),
        );

        let result = start(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.generator.generated(), 0);
    }

    /// A signed-out session cannot start the planned algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            planned(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = start(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
