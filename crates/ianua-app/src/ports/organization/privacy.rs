//! An organization member's erasure requests and consent records.

use async_trait::async_trait;
use ianua_domain::domains::identity::privacy::consent::ConsentType;
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecord;
use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequest;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ErasureRequestId, OrgUserId, OrganizationId, TokenHash};

use crate::ports::identity::ErasureBatch;

/// Dyn-safe port for persisting and retrieving members' erasure requests.
#[async_trait]
pub trait OrgErasureRequestStore: Send + Sync {
    /// The request for `org_user_id` of `organization_id` still under way:
    /// pending, held, processing or failed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_active_by_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgErasureRequest>, DomainError>;

    /// The request `id` of `organization_id`. A request of another
    /// organization reads as absent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        organization_id: &OrganizationId,
        id: &ErasureRequestId,
    ) -> Result<Option<OrgErasureRequest>, DomainError>;

    /// The request whose cancel link carries the token hashed to
    /// `cancel_token_hash`, in whichever organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_cancel_token_hash(
        &self,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<OrgErasureRequest>, DomainError>;

    /// Saves a new or changed request. A member has at most one request
    /// under way, so of two asked at once only one is kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the member already has another
    /// request under way, and `DomainError::Infrastructure` on persistence
    /// failure.
    async fn save(&self, request: &OrgErasureRequest) -> Result<(), DomainError>;

    /// Pending requests whose grace period ended by `batch.now`, together
    /// with failed requests due a retry, across every organization, oldest
    /// first. Reads at most [`ErasureBatch::LIMIT`] requests
    /// strictly after the batch's stable position, including failed attempts.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_due(&self, batch: ErasureBatch) -> Result<Vec<OrgErasureRequest>, DomainError>;
}

/// Dyn-safe port for members' consent records. Records are only ever
/// added, never changed.
#[async_trait]
pub trait OrgConsentStore: Send + Sync {
    /// The latest decision `org_user_id` of `organization_id` made on
    /// `consent_type`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_latest(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        consent_type: ConsentType,
    ) -> Result<Option<OrgConsentRecord>, DomainError>;

    /// Every decision `org_user_id` of `organization_id` made, newest
    /// first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_by_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgConsentRecord>, DomainError>;

    /// Appends a new record.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, record: &OrgConsentRecord) -> Result<(), DomainError>;
}
