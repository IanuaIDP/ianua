//! Pending email changes on both planes.

use async_trait::async_trait;
use ianua_domain::domains::identity::account::email_change::PendingEmailChange;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalId, TokenHash, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for pending email changes in the control plane database.
///
/// Used for organization members and operators. Not tenant-scoped.
#[async_trait]
pub trait OrgEmailChangeStore: Send + Sync {
    /// Finds the pending email change for a principal.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<PendingEmailChange>, DomainError>;

    /// Finds a pending email change by its token hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError>;

    /// Finds a pending email change by the token in the cancel link mailed
    /// to the old address.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_cancel_token_hash(
        &self,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError>;

    /// Saves a pending email change, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn save(&self, change: &PendingEmailChange) -> Result<(), DomainError>;

    /// Deletes the pending email change for a principal.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn delete(&self, principal_id: &PrincipalId) -> Result<(), DomainError>;
}

/// Dyn-safe port for pending email changes in the tenant database.
///
/// Used for tenant users.
#[async_trait]
pub trait TenantEmailChangeStore: Send + Sync + TenantScoped {
    /// Finds the pending email change for a user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PendingEmailChange>, DomainError>;

    /// Finds a pending email change by its token hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError>;

    /// Finds a pending email change by the token in the cancel link mailed
    /// to the old address.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_cancel_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<PendingEmailChange>, DomainError>;

    /// Saves a pending email change, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        change: &PendingEmailChange,
    ) -> Result<(), DomainError>;

    /// Deletes the pending email change for a user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn delete(&self, tenant_id: &ScopedTenant, user_id: &UserId) -> Result<(), DomainError>;
}
