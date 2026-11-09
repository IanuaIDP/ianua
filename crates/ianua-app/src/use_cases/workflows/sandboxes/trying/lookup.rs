//! Loading the trials a use case acts on, or saying they are not there.

use ianua_domain::domains::workflows::sandbox::trial::SandboxTrial;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{SandboxId, SandboxTrialId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::workflows::SandboxTrialStore;
use crate::tenancy::ScopedTenant;

/// The tenant's trial `id` of sandbox `sandbox_id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such trial, or it tries a
///   version of another sandbox.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_trial(
    store: &dyn SandboxTrialStore,
    tenant: &ScopedTenant,
    sandbox_id: &SandboxId,
    id: &SandboxTrialId,
) -> Result<SandboxTrial<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|trial| trial.sandbox_id() == sandbox_id)
        .or_not_found(message!("workflows-trial", "trial"))
}
