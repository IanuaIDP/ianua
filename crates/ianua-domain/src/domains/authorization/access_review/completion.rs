//! Bounded-memory traversal of a review completed in one atomic unit of work.

use crate::domains::authorization::access_review::{
    AccessReview, ReviewItem, ReviewScope, Unanswered,
};
use crate::domains::authorization::review_removals::ReviewRemovals;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{AccessReviewId, Human, PrincipalRef};

/// Which domain authorization permitted traversal of the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionOrigin {
    /// Each removal still requires the caller's standing.
    Manual,
    /// The deadline authorizes the review's own bounded removal proofs.
    Overdue,
}

/// An authorized traversal retaining counters and bounded reviewers, never holders.
/// Dropping it after failure leaves the header open; persistence rolls back the unit.
#[derive(Debug)]
pub struct ReviewCompletion {
    review_id: AccessReviewId,
    scope: ReviewScope,
    unanswered: Unanswered,
    reviewers: Vec<Human>,
    total: u64,
    pending: u64,
    explicit_removals: u64,
    processed: u64,
    seen_pending: u64,
    seen_explicit_removals: u64,
    removed: u64,
    origin: CompletionOrigin,
}

impl ReviewCompletion {
    /// Captures a header after its caller has been authorized.
    pub(super) fn manual<T: TenantScope>(review: &AccessReview<T>) -> Self {
        Self::new(review, CompletionOrigin::Manual)
    }

    /// Captures a header after its fixed deadline has passed.
    pub(super) fn overdue<T: TenantScope>(review: &AccessReview<T>) -> Self {
        Self::new(review, CompletionOrigin::Overdue)
    }

    /// Keeps only metadata needed to verify the paged traversal.
    fn new<T: TenantScope>(review: &AccessReview<T>, origin: CompletionOrigin) -> Self {
        Self {
            review_id: *review.id(),
            scope: review.scope(),
            unanswered: review.unanswered(),
            reviewers: review.reviewers().to_vec(),
            total: review.holder_count(),
            pending: review.pending_count(),
            explicit_removals: review.remove_count(),
            processed: 0,
            seen_pending: 0,
            seen_explicit_removals: 0,
            removed: 0,
            origin,
        }
    }

    /// The last fully validated snapshot position, zero before the first page.
    #[must_use]
    pub fn processed(&self) -> u64 {
        self.processed
    }

    /// Takes the next contiguous page for ordinary caller-authorized removals.
    ///
    /// # Errors
    ///
    /// Refuses skipped, replayed, foreign or corrupt items without advancing.
    pub fn removals(&mut self, items: &[ReviewItem]) -> Result<Vec<PrincipalRef>, DomainError> {
        self.accept(items)
    }

    /// Takes the next page and grants only its due-review withdrawal proof.
    ///
    /// # Errors
    ///
    /// Refuses a manual completion token and invalid or noncontiguous items.
    pub fn overdue_removals(
        &mut self,
        items: &[ReviewItem],
    ) -> Result<ReviewRemovals, DomainError> {
        if self.origin != CompletionOrigin::Overdue {
            return Err(DomainError::forbidden(message!(
                "authorization-only-an-overdue-review-authorizes-system",
                "only an overdue review authorizes system removals"
            )));
        }
        let holders = self.accept(items)?;
        Ok(ReviewRemovals::of(self.review_id, self.scope, holders))
    }

    /// Validates a whole bounded page before changing any traversal counter.
    fn accept(&mut self, items: &[ReviewItem]) -> Result<Vec<PrincipalRef>, DomainError> {
        self.ensure_page(items)?;
        let pending = items.iter().filter(|item| item.is_pending()).count();
        let explicit = items
            .iter()
            .filter(|item| item.explicitly_removed())
            .count();
        let holders: Vec<_> = items
            .iter()
            .filter(|item| item.removed(self.unanswered))
            .map(|item| *item.holder())
            .collect();
        let processed = increased(self.processed, items.len())?;
        let seen_pending = increased(self.seen_pending, pending)?;
        let seen_explicit_removals = increased(self.seen_explicit_removals, explicit)?;
        let removed = increased(self.removed, holders.len())?;
        self.processed = processed;
        self.seen_pending = seen_pending;
        self.seen_explicit_removals = seen_explicit_removals;
        self.removed = removed;
        Ok(holders)
    }

    /// Ensures exact traversal order and prevents a forged page crossing reviews.
    fn ensure_page(&self, items: &[ReviewItem]) -> Result<(), DomainError> {
        let count = u64::try_from(items.len()).map_err(DomainError::infra)?;
        if self
            .processed
            .checked_add(count)
            .is_none_or(|end| end > self.total)
        {
            return Err(DomainError::corrupt_row(
                "access review",
                "page exceeds snapshot",
            ));
        }
        for (offset, item) in items.iter().enumerate() {
            let position = increased(increased(self.processed, offset)?, 1)?;
            self.ensure_item(item, position)?;
        }
        Ok(())
    }

    /// Checks one position against the authorized snapshot and its reviewers.
    fn ensure_item(&self, item: &ReviewItem, position: u64) -> Result<(), DomainError> {
        RowCheck::of("access review item")
            .holds(
                *item.review_id() == self.review_id,
                "belongs to another review",
            )
            .holds(item.position() == position, "skipped or repeated position")
            .holds(
                item.reviewed_by(&self.reviewers),
                "decision by someone not reviewing",
            )
            .finish()
    }

    /// Checks that every item was read and the locked header did not change.
    pub(super) fn ensure_finished<T: TenantScope>(
        &self,
        review: &AccessReview<T>,
    ) -> Result<(), DomainError> {
        RowCheck::of("access review completion")
            .holds(
                self.review_id == *review.id() && self.scope == review.scope(),
                "belongs to another review",
            )
            .holds(
                self.unanswered == review.unanswered() && self.reviewers == review.reviewers(),
                "review metadata changed",
            )
            .holds(
                self.total == review.holder_count() && self.processed == self.total,
                "snapshot not fully traversed",
            )
            .holds(
                self.pending == review.pending_count() && self.seen_pending == self.pending,
                "pending count disagrees with items",
            )
            .holds(
                self.explicit_removals == review.remove_count()
                    && self.seen_explicit_removals == self.explicit_removals,
                "remove count disagrees with items",
            )
            .finish()
    }

    /// The number that lose access, including unanswered holders when configured.
    pub(super) fn removed(&self) -> u64 {
        self.removed
    }
}

/// Advances a persisted counter only when conversion and addition both fit.
fn increased(current: u64, additional: usize) -> Result<u64, DomainError> {
    let additional = u64::try_from(additional).map_err(DomainError::infra)?;
    current
        .checked_add(additional)
        .ok_or_else(|| DomainError::corrupt_row("access review completion", "counter overflow"))
}
