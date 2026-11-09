//! Get migration: the tenant's signing-algorithm migration in progress.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{CryptoAction, SystemPermission};
use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::crypto::MigrationStore;
use crate::use_case::Query;
use crate::use_cases::crypto::lookup::existing_migration;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads the tenant's migration.
    pub migration_store: Arc<dyn MigrationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the migration a tenant has not finished.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<AlgorithmMigration<ResolvedTenant>, AppError>;

    /// The caller's tenant's migration that has not finished, once they may
    /// view its signing keys.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view signing keys.
    /// - `AppError::NotFound` when no migration is under way.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<AlgorithmMigration<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Crypto(CryptoAction::View))
            .map_err(AppError::from_domain)?;
        existing_migration(self.ports.migration_store.as_ref(), &caller.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::migration_status::MigrationStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeMigrationStore, planned_migration};
    use crate::test_support::{block_on, test_ctx};

    fn use_case_with(authorities: FakeTenantAuthorities) -> GetUseCase {
        GetUseCase::new(GetPorts {
            migration_store: Arc::new(FakeMigrationStore::holding(&planned_migration())),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Ann planned a move to ES256. Asking for the migration shows it
    /// planned.
    #[test]
    fn the_migration_under_way_is_returned() {
        let use_case = use_case_with(FakeTenantAuthorities::holding_everything());

        let migration = block_on(use_case.execute(&test_ctx(), ())).unwrap();

        assert_eq!(migration.status(), MigrationStatus::Planned);
    }

    /// Acme is not migrating. Nothing is found.
    #[test]
    fn no_migration_is_not_found() {
        let use_case = GetUseCase::new(GetPorts::fakes());

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading the tenant's algorithm migration requires the crypto view
    /// right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let use_case = use_case_with(FakeTenantAuthorities::holding(&[]));

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's algorithm migration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
