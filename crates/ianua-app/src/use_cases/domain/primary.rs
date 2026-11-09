//! Letting go of a domain as the tenant's primary domain, once the domain
//! is no longer the tenant's: removed, or its proof lost.

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::DomainName;

use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantStore;

/// Lets `tenant` go of `domain` as its primary domain and saves it, giving
/// back what the tenant raised for the change. Gives back nothing, and
/// saves nothing, when `domain` was not the primary one.
///
/// # Errors
///
/// `AppError::Internal` when the tenant cannot be saved.
pub(super) async fn released_primary(
    tenants: &dyn TenantStore,
    tenant: &mut Tenant,
    domain: &DomainName,
) -> Result<Vec<DomainEvent>, AppError> {
    if tenant.release_domain(domain).is_none() {
        return Ok(Vec::new());
    }
    tenants.save(tenant).await.or_internal()?;
    Ok(tenant.take_events())
}
