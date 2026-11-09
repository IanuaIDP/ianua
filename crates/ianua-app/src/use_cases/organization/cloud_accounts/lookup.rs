//! Loading an organization's connection to one cloud, and the external id it
//! was begun with.

use ianua_domain::domains::organization::cloud::account::CloudAccount;
use ianua_domain::domains::organization::cloud::credential::ExternalId;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::message;
use ianua_domain::types::OrganizationId;

use crate::error::{AppError, OrInternal};
use crate::ports::cloud::CloudAccountStore;

/// The organization's connection to `provider`.
///
/// # Errors
///
/// - `AppError::NotFound` if no connection to that cloud was begun.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::cloud_accounts) async fn existing_cloud_account(
    store: &dyn CloudAccountStore,
    organization_id: &OrganizationId,
    provider: CloudProvider,
) -> Result<CloudAccount, AppError> {
    store
        .find(organization_id, provider)
        .await
        .or_internal()?
        .ok_or_else(never_begun)
}

/// The external id the organization's connection to `provider` was begun
/// with.
///
/// # Errors
///
/// - `AppError::NotFound` if no connection to that cloud was begun.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::cloud_accounts) async fn begun_external_id(
    store: &dyn CloudAccountStore,
    organization_id: &OrganizationId,
    provider: CloudProvider,
) -> Result<ExternalId, AppError> {
    store
        .external_id(organization_id, provider)
        .await
        .or_internal()?
        .ok_or_else(never_begun)
}

/// The refusal for a cloud whose connection was never begun.
fn never_begun() -> AppError {
    AppError::NotFound(message!(
        "organization-no-connection-has-been-started-for",
        "no connection has been started for this cloud"
    ))
}
