//! Finding the sandbox version a run, a trial or an agent's check is about
//! to run, while it is built and ready: a version that is gone, still being
//! built, or failed to build runs nothing.

use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::SandboxVersionId;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::SandboxVersionStore;
use crate::tenancy::ScopedTenant;

/// The tenant's sandbox version `id` in `versions`, while it is built and
/// ready to run; `None` otherwise.
///
/// # Errors
///
/// - `AppError::Internal` when the store fails.
pub(crate) async fn ready_version(
    versions: &dyn SandboxVersionStore,
    tenant: &ScopedTenant,
    id: &SandboxVersionId,
) -> Result<Option<SandboxVersion<ResolvedTenant>>, AppError> {
    Ok(versions
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|version| version.build().is_ready()))
}
