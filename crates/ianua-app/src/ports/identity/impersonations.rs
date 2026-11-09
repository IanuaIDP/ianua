//! Tenant admins acting as one of the tenant's people for support: the
//! requests and where each stands.

use async_trait::async_trait;
use ianua_domain::domains::identity::impersonation::SupportImpersonation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SupportImpersonationId, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting support impersonations.
#[async_trait]
pub trait SupportImpersonationStore: Send + Sync + TenantScoped {
    /// Saves a new or changed impersonation. A known one only moves the way
    /// its status allows from where it is stored now: a copy read before
    /// another answer or end is refused, so an ended one never comes back.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Conflict`] when the stored one was answered or
    /// ended meanwhile, or another [`DomainError`] if it cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        impersonation: &SupportImpersonation<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// The impersonation with `id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if it cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SupportImpersonationId,
    ) -> Result<Option<SupportImpersonation<ResolvedTenant>>, DomainError>;

    /// Every impersonation that names `user_id` as the admin or as the
    /// person acted as, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if they cannot be read.
    async fn list_involving(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError>;

    /// Every impersonation in the tenant, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if they cannot be read.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, DomainError>;
}
