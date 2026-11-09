//! Clearance rules: which of a tenant's app permissions clear their holders
//! for confidential or restricted data.

use async_trait::async_trait;
use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving a tenant's clearance rules,
/// kept as one record per tenant.
#[async_trait]
pub trait ClearanceRuleStore: Send + Sync + TenantScoped {
    /// The tenant's rules, or `None` when nobody ever wrote one, which
    /// reads as no app permission clearing for anything.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn load(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClearanceRules<ResolvedTenant>>, DomainError>;

    /// Saves the tenant's rules, replacing what was stored.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the rules cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rules: &ClearanceRules<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
