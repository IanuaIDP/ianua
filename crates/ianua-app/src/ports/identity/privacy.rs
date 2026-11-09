//! A user's privacy requests and consent records.

use async_trait::async_trait;
use ianua_domain::domains::identity::privacy::consent::{ConsentRecord, ConsentType};
use ianua_domain::domains::identity::privacy::erasure::ErasureRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ErasureRequestId, TokenHash, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// The stable position of an erasure in oldest-due-first order.
#[derive(Clone, Copy, Debug)]
pub struct ErasurePosition {
    /// When the request became due, unchanged by retries.
    pub scheduled_at: OffsetDateTime,
    /// Breaks ties between requests with the same due time.
    pub id: ErasureRequestId,
}

/// One bounded read of an erasure sweep, keeping its original time cutoff.
#[derive(Clone, Copy, Debug)]
pub struct ErasureBatch {
    /// The cutoff captured when this sweep started.
    pub now: OffsetDateTime,
    /// The last request already attempted in this sweep, whether it succeeded.
    pub after: Option<ErasurePosition>,
}

impl ErasureBatch {
    /// The maximum requests one read materializes.
    pub const LIMIT: usize = 500;

    /// Starts before every due request at the sweep's fixed cutoff.
    #[must_use]
    pub fn first(now: OffsetDateTime) -> Self {
        Self { now, after: None }
    }
}

/// Dyn-safe port for persisting and retrieving erasure requests.
#[async_trait]
pub trait ErasureRequestStore: Send + Sync + TenantScoped {
    /// Finds an active (pending or processing) erasure request for a user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError>;

    /// Finds an erasure request by its ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ErasureRequestId,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError>;

    /// Finds an erasure request by the token in the cancel link mailed to
    /// the person.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_cancel_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated erasure request.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &ErasureRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// The requests in the tenant whose grace period ended by `batch.now` and
    /// that still have to be carried out, pending or failed and due a retry,
    /// oldest first, strictly after the batch's position and with no more than
    /// [`ErasureBatch::LIMIT`] entries. A failed request already attempted in
    /// this sweep is skipped by its stable position, not retried immediately.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_due(
        &self,
        tenant_id: &ScopedTenant,
        batch: ErasureBatch,
    ) -> Result<Vec<ErasureRequest<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for persisting consent records (append-only).
#[async_trait]
pub trait ConsentStore: Send + Sync + TenantScoped {
    /// Finds the latest consent record for a user and consent type.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        consent_type: ConsentType,
    ) -> Result<Option<ConsentRecord<ResolvedTenant>>, DomainError>;

    /// Appends a new consent record.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        record: &ConsentRecord<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Every consent record of `user_id`, of every type, newest first: each
    /// consent given and each withdrawal.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn history(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<ConsentRecord<ResolvedTenant>>, DomainError>;
}
