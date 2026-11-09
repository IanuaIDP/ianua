//! Access reviews: who keeps a role or a group, decided by reviewers.

use async_trait::async_trait;
use ianua_domain::domains::authorization::access_review::{
    AccessReview, AccessReviewDraft, ReviewItem,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AccessReviewId, PrincipalRef};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order access reviews are listed in: newest first.
    pub enum AccessReviewSortField {
        /// Order by when the review started.
        StartedAt => "started_at",
    }
    default = StartedAt;
    default direction = Desc;
}

impl SortKeys<AccessReviewSortField> for AccessReview<ResolvedTenant> {
    fn sort_key(&self, field: AccessReviewSortField) -> SortKey {
        match field {
            AccessReviewSortField::StartedAt => self.started_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

define_sort_field! {
    /// The fixed oldest-due-first order used by the review sweep.
    pub enum OverdueReviewSortField {
        /// Order by the deadline the sweep checks.
        Due => "due",
    }
    default = Due;
}

/// A review the overdue sweep may complete, without its holder collection.
#[derive(Debug, Clone, Copy)]
pub struct OverdueReview {
    /// The review to hydrate immediately before its individual completion.
    pub id: AccessReviewId,
    /// The immutable deadline used to advance the parent cursor.
    pub due: OffsetDateTime,
}

impl SortKeys<OverdueReviewSortField> for OverdueReview {
    /// Uses the deadline unchanged by a blocked completion attempt.
    fn sort_key(&self, field: OverdueReviewSortField) -> SortKey {
        match field {
            OverdueReviewSortField::Due => self.due.into(),
        }
    }

    /// Keeps reviews sharing a deadline in a stable order.
    fn tiebreak(&self) -> SortKey {
        self.id.as_uuid().into()
    }
}

/// Which of a tenant's access reviews a listing shows, newest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessReviewFilter {
    /// Every review.
    All,
    /// Only those reviewers are still deciding.
    Open,
}

define_sort_field! {
    /// Immutable snapshot order for a review's paginated holders.
    pub enum ReviewItemSortField {
        /// The holder's position assigned when the snapshot was created.
        Position => "position",
    }
    default = Position;
}

impl SortKeys<ReviewItemSortField> for ReviewItem {
    /// Domain validation restricts persisted positions to signed storage range.
    fn sort_key(&self, _: ReviewItemSortField) -> SortKey {
        SortKey::Integer(i64::try_from(self.position()).unwrap_or(i64::MAX))
    }

    /// Positions are unique within one immutable review snapshot.
    fn tiebreak(&self) -> SortKey {
        self.sort_key(ReviewItemSortField::Position)
    }
}

/// Review headers and independently paged holder snapshots. Commands retain
/// the header lock until their existing unit of work commits or rolls back.
#[async_trait]
pub trait AccessReviewStore: Send + Sync + TenantScoped {
    /// Persists one atomic snapshot of every direct active scope holder and
    /// opens the authorized draft with its actual count, without hydrating it.
    ///
    /// # Errors
    ///
    /// Refuses an empty scope or persistence failure; creation must roll back.
    async fn start(
        &self,
        tenant_id: &ScopedTenant,
        draft: AccessReviewDraft<ResolvedTenant>,
    ) -> Result<AccessReview<ResolvedTenant>, DomainError>;

    /// Locks one header against decisions, cancellation and completion until
    /// the caller's unit of work settles; holder rows remain unloaded.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the header cannot be locked or decoded.
    async fn hold(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccessReviewId,
    ) -> Result<Option<AccessReview<ResolvedTenant>>, DomainError>;

    /// Finds a review by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccessReviewId,
    ) -> Result<Option<AccessReview<ResolvedTenant>>, DomainError>;

    /// The reviews `filter` keeps, newest first, one page of them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: AccessReviewFilter,
        page: &PageRequest,
    ) -> Result<Page<AccessReview<ResolvedTenant>>, DomainError>;

    /// One page of positions for the tenant's open reviews due by `now`,
    /// oldest first. Selection does not hydrate holders; the sweep reads
    /// each header immediately before processing its bounded holder pages.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_overdue(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<OverdueReview>, DomainError>;

    /// One bounded holder page, checked against its owning review header.
    ///
    /// # Errors
    ///
    /// Returns a storage error for corrupt rows or an invalid cursor.
    async fn list_items(
        &self,
        tenant_id: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        page: &PageRequest,
    ) -> Result<Page<ReviewItem>, DomainError>;

    /// Reads only the named holder, without loading the rest of the review.
    ///
    /// # Errors
    ///
    /// Returns a storage error when its row cannot be read or validated.
    async fn find_item(
        &self,
        tenant_id: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        holder: &PrincipalRef,
    ) -> Result<Option<ReviewItem>, DomainError>;

    /// Reads the items of the named holders in one go, those the review
    /// lists; a holder it does not list is left out.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read or validated.
    async fn find_items(
        &self,
        tenant_id: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        holders: &[PrincipalRef],
    ) -> Result<Vec<ReviewItem>, DomainError>;

    /// Saves the suggestion beside each of `items` in one go, under their
    /// review's header lock; decisions are left as they are.
    ///
    /// # Errors
    ///
    /// Returns a storage error when an item disappeared or cannot be saved.
    async fn save_suggestions(
        &self,
        tenant_id: &ScopedTenant,
        items: &[ReviewItem],
    ) -> Result<(), DomainError>;

    /// Updates one existing decision under its review's header lock.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the item disappeared or cannot be saved.
    async fn save_item(
        &self,
        tenant_id: &ScopedTenant,
        item: &ReviewItem,
    ) -> Result<(), DomainError>;

    /// Saves only header metadata and counters, leaving snapshot rows intact.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the review cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
