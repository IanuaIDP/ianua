//! Initial access tokens, with which apps register themselves as clients.

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::registration::InitialAccessToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{InitialAccessTokenId, TokenHash};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting initial access tokens.
#[async_trait]
pub trait InitialAccessTokenStore: Send + Sync + TenantScoped {
    /// Finds a token by its id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError>;

    /// Finds the token whose hash is `token_hash`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError>;

    /// Every token the tenant issued, newest first, revoked ones too.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<InitialAccessToken<ResolvedTenant>>, DomainError>;

    /// Saves a new or revoked token.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes the uses `token` has left, one fewer after an admission, only
    /// while the stored token is unrevoked and has exactly one more. Returns
    /// whether it did: of two registrations spending the last use together,
    /// only one is admitted. Storage does it in one `UPDATE .. WHERE
    /// uses_left = $n + 1 AND revoked_at IS NULL`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn spend_use(
        &self,
        tenant_id: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<bool, DomainError>;
}
