//! Cancel migration: drop a planned migration before it starts. No key was
//! created for it, so the plan is all that goes.

use std::sync::Arc;

use ianua_domain::domains::crypto::control::CryptoControlCheck;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::MigrationStore;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::save_migration;
use crate::use_cases::crypto::lookup::existing_migration;

/// The ports [`CancelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelPorts {
    /// Loads and saves the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Cancels a planned signing-algorithm migration.
pub struct CancelUseCase {
    ports: CancelPorts,
}

impl CancelUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Cancels the planned migration and records
    /// `crypto.migration_cancelled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signing keys.
    /// - `AppError::NotFound` when no migration is under way.
    /// - `AppError::Domain` when the migration has already started.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        CryptoControlCheck::ensure_may_change_keys(&authority).map_err(AppError::from_domain)?;
        let store = self.ports.migration_store.as_ref();
        let tenant = caller.tenant();
        let mut migration = existing_migration(store, &tenant).await?;
        migration
            .cancel(&authority)
            .map_err(AppError::from_domain)?;
        save_migration(store, &tenant, &migration).await?;

        auditor
            .dispatch_by(&caller.actor(), migration.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeMigrationStore, planned_migration, started_migration};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: CancelUseCase,
        migrations: Arc<FakeMigrationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(migrations: FakeMigrationStore, authorities: FakeTenantAuthorities) -> Fixture {
        let migrations = Arc::new(migrations);
        let use_case = CancelUseCase::new(CancelPorts {
            migration_store: migrations.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            migrations,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn planned_with(authorities: FakeTenantAuthorities) -> Fixture {
        fixture_with(
            FakeMigrationStore::holding(&planned_migration()),
            authorities,
        )
    }

    fn cancel(f: &Fixture) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), ()),
        )
    }

    fn held_status(f: &Fixture) -> MigrationStatus {
        f.migrations
            .migration_of(test_ctx().tenant_id())
            .unwrap()
            .unwrap()
            .status()
    }

    /// Ann cancels Acme's planned migration. It is cancelled and the
    /// cancellation is recorded.
    #[test]
    fn a_planned_migration_is_cancelled() {
        let f = planned_with(FakeTenantAuthorities::holding_everything());

        cancel(&f).unwrap();

        assert_eq!(held_status(&f), MigrationStatus::Cancelled);
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "crypto.migration_cancelled"
        );
    }

    /// Acme's migration has started and created its key. Cancelling is
    /// refused; a started migration is rolled back instead.
    #[test]
    fn a_started_migration_cannot_be_cancelled() {
        let (_, migration) = started_migration();
        let f = fixture_with(
            FakeMigrationStore::holding(&migration),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = cancel(&f);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(held_status(&f), MigrationStatus::InProgress);
    }

    /// Acme is not migrating. Cancelling is not found.
    #[test]
    fn no_migration_is_not_found() {
        let f = fixture_with(
            FakeMigrationStore::empty(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = cancel(&f);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A key viewer cannot cancel an algorithm migration, which remains
    /// planned.
    #[test]
    fn a_caller_who_may_only_view_keys_is_refused() {
        let f = planned_with(FakeTenantAuthorities::holding(&[SystemPermission::Crypto(
            CryptoAction::View,
        )]));

        let result = cancel(&f);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(held_status(&f), MigrationStatus::Planned);
    }

    /// A signed-out session cannot cancel an algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = planned_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = cancel(&f);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
