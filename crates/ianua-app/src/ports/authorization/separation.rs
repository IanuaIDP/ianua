//! Separation of duties: the pairs of roles nobody in a tenant holds
//! together.

use async_trait::async_trait;
use ianua_domain::domains::authorization::separation::SeparationRule;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SeparationRuleId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving separation-of-duties rules.
#[async_trait]
pub trait SeparationRuleStore: Send + Sync + TenantScoped {
    /// Every rule of the tenant, oldest first. Each grant of a role or a
    /// group is checked against all of them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SeparationRule<ResolvedTenant>>, DomainError>;

    /// Finds a rule by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SeparationRuleId,
    ) -> Result<Option<SeparationRule<ResolvedTenant>>, DomainError>;

    /// Saves a new rule.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the rule cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule: &SeparationRule<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes a rule.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the rule cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SeparationRuleId,
    ) -> Result<(), DomainError>;
}
