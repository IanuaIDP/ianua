//! Plan migration: schedule a move of the tenant's signing key to another
//! algorithm. A tenant runs one migration at a time.

use std::sync::Arc;

use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::crypto::{MigrationStore, SigningKeyStore};
use crate::services::lookup::existing_key_set;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::save_migration;

/// The ports [`PlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanPorts {
    /// Loads the tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Loads and saves the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Plans a signing-algorithm migration.
pub struct PlanUseCase {
    ports: PlanPorts,
}

impl PlanUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PlanPorts) -> Self {
        Self { ports }
    }
}

impl Command for PlanUseCase {
    type Caller = CallerContext;
    type Input = SigningAlgorithm;
    type Output = Result<(), AppError>;

    /// Plans moving the key that signs now onto `target_algorithm`, and
    /// records `crypto.migration_planned`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without signing-key rights.
    /// - `AppError::Conflict` for an ongoing migration; `NotFound` for no key set or current signer.
    /// - `AppError::Domain` for the algorithm already in use; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        target_algorithm: SigningAlgorithm,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        ensure_none_under_way(self.ports.migration_store.as_ref(), caller).await?;
        let tenant = caller.tenant();
        let key_set = existing_key_set(self.ports.key_store.as_ref(), &tenant).await?;
        let now = clock::now();
        let source = key_set
            .active_key(now)
            .or_not_found(message!("crypto-no-key-signs-now", "no key signs now"))?;

        let mut migration: AlgorithmMigration<ResolvedTenant> =
            AlgorithmMigration::plan(source, target_algorithm, &authority)
                .map_err(AppError::from_domain)?;
        save_migration(self.ports.migration_store.as_ref(), &tenant, &migration).await?;

        auditor
            .dispatch_by(&caller.actor(), migration.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Refuses a plan while another migration is under way.
async fn ensure_none_under_way(
    store: &dyn MigrationStore,
    caller: &CallerContext,
) -> Result<(), AppError> {
    let existing = store.find_active(&caller.tenant()).await.or_internal()?;
    if existing.is_none() {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "crypto-a-migration-is-already-under-way",
        "a migration is already under way"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;
    use ianua_domain::domains::crypto::signing_key::SigningKeySet;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{
        FakeMigrationStore, FakeSigningKeyStore, planned_migration, test_signing_key,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: PlanUseCase,
        migrations: Arc<FakeMigrationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(migrations: FakeMigrationStore, authorities: FakeTenantAuthorities) -> Fixture {
        let migrations = Arc::new(migrations);
        let use_case = PlanUseCase::new(PlanPorts {
            key_store: Arc::new(FakeSigningKeyStore::holding(SigningKeySet::new(
                test_signing_key("key-old", SigningAlgorithm::Rs256),
            ))),
            migration_store: migrations.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            migrations,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn fixture() -> Fixture {
        fixture_with(
            FakeMigrationStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        )
    }

    fn plan(f: &Fixture, target: SigningAlgorithm) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), target),
        )
    }

    fn held(f: &Fixture) -> Option<AlgorithmMigration<ResolvedTenant>> {
        f.migrations.migration_of(test_ctx().tenant_id()).unwrap()
    }

    /// Ann plans moving Acme from RS256 to ES256. The migration is planned
    /// from the key that signs now, and the plan is recorded.
    #[test]
    fn a_migration_is_planned_from_the_signing_key() {
        let f = fixture();

        plan(&f, SigningAlgorithm::Es256).unwrap();

        let migration = held(&f).unwrap();
        assert_eq!(migration.status(), MigrationStatus::Planned);
        assert_eq!(migration.source_key_id().as_str(), "key-old");
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "crypto.migration_planned"
        );
    }

    /// Ann plans a move to RS256, which Acme already signs with. It is
    /// refused and nothing is planned.
    #[test]
    fn a_move_to_the_same_algorithm_is_refused() {
        let f = fixture();

        let result = plan(&f, SigningAlgorithm::Rs256);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(held(&f).is_none());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A migration is already under way when Ann plans another. The second
    /// is refused.
    #[test]
    fn a_second_migration_is_refused() {
        let f = fixture_with(
            FakeMigrationStore::holding(&planned_migration()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = plan(&f, SigningAlgorithm::EdDsa);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Acme has no signing keys. There is nothing to migrate.
    #[test]
    fn a_tenant_without_keys_is_not_found() {
        let use_case = PlanUseCase::new(PlanPorts::fakes());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            SigningAlgorithm::Es256,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A key viewer cannot plan an algorithm migration, and no migration
    /// is stored.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = fixture_with(
            FakeMigrationStore::empty(),
            FakeTenantAuthorities::holding(&[SystemPermission::Crypto(CryptoAction::View)]),
        );

        let result = plan(&f, SigningAlgorithm::Es256);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(held(&f).is_none());
    }

    /// A signed-out session cannot plan an algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            FakeMigrationStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = plan(&f, SigningAlgorithm::Es256);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
