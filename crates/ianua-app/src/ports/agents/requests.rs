//! The delegations agents ask people for, kept until the person asked
//! answers or the request lapses.

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::delegation_request::DelegationRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, DelegationRequestId, PrincipalRef};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting the delegations agents ask people for.
#[async_trait]
pub trait DelegationRequestStore: Send + Sync + TenantScoped {
    /// Saves a new or answered request.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &DelegationRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds a request by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DelegationRequestId,
    ) -> Result<Option<DelegationRequest<ResolvedTenant>>, DomainError>;

    /// Every request `agent` made, newest first, answered or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError>;

    /// Every request made of the person behind `asked_of`, through that
    /// account, newest first, answered or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_asked_of(
        &self,
        tenant_id: &ScopedTenant,
        asked_of: &PrincipalRef,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError>;
}
