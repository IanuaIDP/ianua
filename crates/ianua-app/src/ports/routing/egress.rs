//! Egress policies.

use async_trait::async_trait;
use ianua_domain::domains::routing::egress::{EgressPolicy, ServiceIdentity};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EgressPolicyId, TenantId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for the egress policies that say where services may go.
#[async_trait]
pub trait EgressPolicyStore: Send + Sync + TenantScoped {
    /// Inserts or updates a policy.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the service already has a
    /// policy, `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        policy: &EgressPolicy<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds a policy by id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EgressPolicyId,
    ) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError>;

    /// The policy for a service, if it has one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_service(
        &self,
        tenant_id: &ScopedTenant,
        service: &ServiceIdentity,
    ) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError>;

    /// Every policy in the tenant, by name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<EgressPolicy<ResolvedTenant>>, DomainError>;

    /// Removes a policy.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &EgressPolicyId,
    ) -> Result<(), DomainError>;
}

/// One tenant's egress policy for a service.
#[derive(Debug, Clone)]
pub struct ClaimedEgressPolicy {
    /// The tenant that wrote it.
    pub tenant_id: TenantId,
    /// The rules this tenant applies to outbound calls to the service.
    pub policy: EgressPolicy<ResolvedTenant>,
}

/// Dyn-safe port finding, across every tenant, the policies written for one
/// service, for the egress gateway.
///
/// Not [`TenantScoped`]: a service is named by its certificate, which says
/// nothing of a tenant, so the gateway learns whose policy applies from
/// the claims themselves.
#[async_trait]
pub trait CrossTenantEgressPolicies: Send + Sync {
    /// Every tenant's policy for `service`, wherever each tenant lives.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a database cannot be read,
    /// or a stored policy no longer passes its rules.
    async fn claiming(
        &self,
        service: &ServiceIdentity,
    ) -> Result<Vec<ClaimedEgressPolicy>, DomainError>;
}
