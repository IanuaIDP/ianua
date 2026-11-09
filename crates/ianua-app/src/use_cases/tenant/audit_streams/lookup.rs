//! Loading the tenant a stream belongs to, and the stream a caller names.

use ianua_domain::domains::tenant::audit_streams::AuditStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::AuditStreamId;

use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::audit::AuditStreamStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// The tenant `caller` acts in, as the scope its streams are kept in.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant is gone.
/// - `AppError::Internal` on storage failure.
pub(super) async fn acting_tenant(
    tenants: &dyn TenantStore,
    caller: &CallerContext,
) -> Result<ResolvedTenant, AppError> {
    let tenant = existing_tenant(tenants, &caller.tenant_id()).await?;
    Ok(ResolvedTenant::new(*tenant.id(), tenant.slug().clone()))
}

/// The tenant's stream `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such stream.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_stream(
    store: &dyn AuditStreamStore,
    tenant: &ScopedTenant,
    id: &AuditStreamId,
) -> Result<AuditStream<ResolvedTenant>, AppError> {
    store
        .find(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "tenant-audit-stream-not-found",
            "audit stream not found"
        ))
}
