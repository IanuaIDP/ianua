//! Loading the migration a crypto use case works on, failing with not-found
//! when the tenant has none.

use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::crypto::MigrationStore;
use crate::tenancy::ScopedTenant;

/// The tenant's migration that has not yet reached a terminal state.
///
/// # Errors
///
/// - `AppError::NotFound` if no active migration exists.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_migration(
    store: &dyn MigrationStore,
    tenant: &ScopedTenant,
) -> Result<AlgorithmMigration<ResolvedTenant>, AppError> {
    store
        .find_active(tenant)
        .await
        .or_internal()?
        .or_not_found(message!(
            "crypto-no-active-migration",
            "no active migration"
        ))
}
