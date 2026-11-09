//! Authorization requests clients push before sending the browser.

use async_trait::async_trait;
use ianua_domain::domains::oauth::grants::pushed_request::PushedRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PushedRequestId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting pushed authorization requests (RFC 9126).
///
/// Storage may drop a request once it expired; it lives sixty seconds.
#[async_trait]
pub trait PushedRequestStore: Send + Sync + TenantScoped {
    /// Finds a pushed request by its id, used or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &PushedRequestId,
    ) -> Result<Option<PushedRequest<ResolvedTenant>>, DomainError>;

    /// Keeps a request just pushed, with the parameters
    /// [`PushedRequest::parameters`] hands out.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        request: &PushedRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Stores `request`, just used, only if the stored one is still unused.
    /// Returns whether this call did: of two browsers arriving with one
    /// `request_uri`, only one gets a code. Storage does it in one
    /// statement, such as an `UPDATE .. WHERE used_at IS NULL`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        request: &PushedRequest<ResolvedTenant>,
    ) -> Result<bool, DomainError>;
}
