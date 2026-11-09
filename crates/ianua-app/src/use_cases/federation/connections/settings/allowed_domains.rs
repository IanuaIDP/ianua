//! The proof that the tenant owns each email domain a connection is to
//! vouch for.
//!
//! A provider trusted for a domain signs in every account at it, so a
//! connection only vouches for domains the tenant proved it owns. The
//! connection takes the proofs and decides who may bind them; this only
//! reads them from the tenant's own registrations.

use std::collections::HashMap;

use ianua_domain::domains::federation::connection::DomainHolders;
use ianua_domain::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;

use crate::error::{AppError, OrInternal};
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// The ports the proofs are read through.
pub(in crate::use_cases::federation::connections) struct DomainProofs<'a> {
    /// The tenant registry, for the tenant the proofs are made for.
    pub(in crate::use_cases::federation::connections) tenant_store: &'a dyn TenantStore,
    /// The tenant's registered domains.
    pub(in crate::use_cases::federation::connections) domain_store: &'a dyn RegisteredDomainStore,
}

impl DomainProofs<'_> {
    /// The proof that `tenant` owns each of `names`, in order.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` naming the first domain the tenant never
    ///   registered.
    /// - `AppError::Conflict` when one is registered and not verified now,
    ///   or is a wildcard.
    /// - `AppError::NotFound` if the tenant is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::federation::connections) async fn owned(
        &self,
        tenant: &ScopedTenant,
        names: &[DomainName],
    ) -> Result<Vec<OwnedDomain>, AppError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let registered = existing_tenant(self.tenant_store, tenant).await?;
        let resolved = ResolvedTenant::new(*registered.id(), registered.slug().clone());
        let registrations = self
            .domain_store
            .find_by_names(tenant, names)
            .await
            .or_internal()?;
        let registrations: HashMap<_, _> = registrations
            .into_iter()
            .map(|registration| (registration.domain().clone(), registration))
            .collect();
        names
            .iter()
            .map(|name| {
                let registration = registrations.get(name).ok_or_else(|| unregistered(name))?;
                registration
                    .owned_by(&resolved)
                    .map_err(AppError::from_domain)
            })
            .collect()
    }
}

/// The tenants whose proved domains a connection of `tenant` may bind.
///
/// Only the tenant's own: binding a domain another tenant of the same
/// organization proved is not offered yet.
pub(in crate::use_cases::federation::connections) fn own_tenant(
    tenant: &ScopedTenant,
) -> DomainHolders<'static> {
    DomainHolders {
        this_tenant: **tenant,
        organization_tenants: &[],
    }
}

/// The refusal for a domain the tenant never registered.
fn unregistered(name: &DomainName) -> AppError {
    AppError::Domain(DomainError::invalid(message!(
        "federation-is-not-a-registered-domain-of",
        format!(
            "{name} is not a registered domain of this tenant; register and verify it before a \
         connection may sign in addresses there"
        )
    )))
}
