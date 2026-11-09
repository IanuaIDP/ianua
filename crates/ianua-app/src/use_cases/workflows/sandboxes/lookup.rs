//! Loading the sandboxes a use case acts on, or saying they are not there.

use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{SandboxId, SandboxVersionId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::workflows::{SandboxStore, SandboxVersionStore};
use crate::tenancy::ScopedTenant;

/// The tenant's sandbox `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such sandbox.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_sandbox(
    store: &dyn SandboxStore,
    tenant: &ScopedTenant,
    id: &SandboxId,
) -> Result<Sandbox<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-sandbox", "sandbox"))
}

/// The tenant's sandbox version `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such version.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_version(
    store: &dyn SandboxVersionStore,
    tenant: &ScopedTenant,
    id: &SandboxVersionId,
) -> Result<SandboxVersion<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!("workflows-sandbox-version", "sandbox version"))
}
