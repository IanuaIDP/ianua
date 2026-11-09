//! Loading what the domain use cases work on: the registration a caller
//! names, the certificate it serves, and the tenant a caller registers in.

use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::DomainId;

use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::domain::{CertificateStore, RegisteredDomainStore};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// The tenant's registered domain with `domain_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such domain.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_domain(
    store: &dyn RegisteredDomainStore,
    tenant: &ScopedTenant,
    domain_id: &DomainId,
) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, domain_id)
        .await
        .or_internal()?
        .or_not_found(message!("domain-domain-not-found", "domain not found"))
}

/// The certificate the tenant's domain `domain_id` serves.
///
/// # Errors
///
/// - `AppError::NotFound` if the domain serves none.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_certificate(
    store: &dyn CertificateStore,
    tenant: &ScopedTenant,
    domain_id: &DomainId,
) -> Result<CertificateBundle, AppError> {
    store
        .find_current(tenant, domain_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "directory-certificate-not-found",
            "certificate not found"
        ))
}

/// The tenant `caller` acts in, as the scope its domains are registered in
/// and removed from.
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
    Ok(scope_of(&tenant))
}

/// `tenant`, as the scope its domains are registered in and removed from.
pub(super) fn scope_of(tenant: &Tenant) -> ResolvedTenant {
    ResolvedTenant::new(*tenant.id(), tenant.slug().clone())
}
