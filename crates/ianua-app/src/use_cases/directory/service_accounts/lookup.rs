//! Loading the service account a caller names.

use ianua_domain::domains::authentication::directory_service::account::DirectoryServiceAccount;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::DirectoryServiceAccountId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::directory::DirectoryServiceAccountStore;
use crate::tenancy::ScopedTenant;

/// The tenant's service account with `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such account.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_service_account(
    store: &dyn DirectoryServiceAccountStore,
    tenant: &ScopedTenant,
    id: &DirectoryServiceAccountId,
) -> Result<DirectoryServiceAccount<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "directory-service-account-not-found",
            "service account not found"
        ))
}
