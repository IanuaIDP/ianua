//! Whether a user or a principal exists.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, TenantId, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for checking user existence within a tenant.
///
/// Used by authorization (role assignment, group membership) and other
/// tenant-scoped contexts that check a user exists before linking to them.
#[async_trait]
pub trait UserExistenceChecker: Send + Sync + TenantScoped {
    /// Checks whether a user exists within the tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn user_exists(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for checking that a principal exists within a tenant.
///
/// A group holds principals, not only people, so the check that a member
/// exists before it is linked has to be able to ask about a consumer or an
/// agent as readily as about a user.
#[async_trait]
pub trait PrincipalExistenceChecker: Send + Sync + TenantScoped {
    /// Checks whether the principal exists within the tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn principal_exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for checking user existence across tenants.
///
/// Used by the organization context for cross-tenant work such as identity
/// linking, where the user may be in another tenant than the caller.
#[async_trait]
pub trait CrossTenantUserChecker: Send + Sync {
    /// Checks whether a user exists in a specific tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn exists_in_tenant(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<bool, DomainError>;
}
