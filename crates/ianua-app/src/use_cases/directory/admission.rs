//! What every directory bind passes before its credential is looked at,
//! a person's and a service account's alike: the organization and tenant
//! its DN names, and the tenant's bind rate. Every refusal of a bind reads
//! the same.

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

use crate::error::{AppError, OrInternal};
use crate::ports::directory::BindThrottle;
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::directory::principal::DirectoryBase;

/// The organization and the tenant `base` names, found in `organizations`
/// and `tenants`. Either one unknown reads as bad credentials, so a bind
/// cannot find out which exist.
///
/// # Errors
///
/// - `AppError::NotFound` ("invalid credentials") when either is unknown.
/// - `AppError::Internal` on storage failure.
pub(super) async fn named_tenant(
    organizations: &dyn OrganizationStore,
    tenants: &dyn TenantStore,
    base: &DirectoryBase,
) -> Result<(OrganizationId, ScopedTenant), AppError> {
    let organization = organizations
        .find_by_slug(&base.organization)
        .await
        .or_internal()?
        .ok_or_else(invalid_credentials)?;
    let tenant = tenants
        .find_by_slug_in_org(&base.tenant, organization.id())
        .await
        .or_internal()?
        .ok_or_else(invalid_credentials)?;
    Ok((*organization.id(), ScopedTenant::from_registry(&tenant)))
}

/// Refuses a bind once the tenant's bind rate is exceeded. A throttle that
/// cannot be asked is a fault, not a refusal.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when the tenant's bind rate is exceeded.
/// - `AppError::Internal` when the throttle cannot be asked.
pub(super) async fn ensure_within_bind_rate(
    throttle: &dyn BindThrottle,
    tenant: &ScopedTenant,
) -> Result<(), AppError> {
    match throttle.check_and_record(tenant).await {
        Ok(()) => Ok(()),
        Err(DomainError::Forbidden(_)) => Err(AppError::TooManyRequests(message!(
            "directory-too-many-bind-attempts-try-again",
            "too many bind attempts, try again shortly"
        ))),
        Err(other) => Err(AppError::internal(other)),
    }
}

pub(super) use crate::services::authentication::refused::invalid_credentials;
