//! One independently read holder in a review's immutable snapshot.

use crate::domains::authorization::access_review::{
    AccessReview, AccessReviewVerdict, ReviewChoice, Unanswered, names,
};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{AccessReviewId, Human, PrincipalRef, Text};

/// What is suggested beside one holder. The reviewer still decides; a
/// suggestion changes nothing by itself.
///
/// Ann's workflow reads what Bob really used in the last 90 days and
/// suggests removing him from Finance, "no Finance app opened since June".
/// Carol sees it beside Bob's name and marks him remove, or keeps him.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewSuggestion {
    /// Nothing is suggested.
    Nothing,
    /// Keep or remove, and why.
    Made {
        /// What is suggested.
        choice: ReviewChoice,
        /// Why, in a sentence the reviewer reads.
        reason: Text,
    },
}

/// One snapshot holder, its decision and what is suggested for it,
/// independent of other holders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewItem {
    review_id: AccessReviewId,
    position: u64,
    holder: PrincipalRef,
    verdict: AccessReviewVerdict,
    suggestion: ReviewSuggestion,
}

/// Stored fields rebuilt against the review header before use.
pub struct ReviewItemRow<'a, T: TenantScope> {
    /// The owning header used to validate snapshot bounds and reviewer identity.
    pub review: &'a AccessReview<T>,
    /// The parent review that owns this holder.
    pub review_id: AccessReviewId,
    /// The stable, one-based position in the snapshot.
    pub position: u64,
    /// The holder whose direct access is reviewed.
    pub holder: PrincipalRef,
    /// The decision or its pending state.
    pub verdict: AccessReviewVerdict,
    /// What is suggested beside it.
    pub suggestion: ReviewSuggestion,
}

impl ReviewItem {
    /// Rebuilds an item only when it belongs to this header and its reviewers.
    ///
    /// # Errors
    ///
    /// Returns infrastructure failure for another review, an invalid position,
    /// or a decision by a person not named to review.
    pub fn reconstitute<T: TenantScope>(row: ReviewItemRow<'_, T>) -> Result<Self, DomainError> {
        let item = Self {
            review_id: row.review_id,
            position: row.position,
            holder: row.holder,
            verdict: row.verdict,
            suggestion: row.suggestion,
        };
        item.ensure_review(row.review)?;
        Ok(item)
    }

    /// The parent review that owns the item.
    #[must_use]
    pub fn review_id(&self) -> &AccessReviewId {
        &self.review_id
    }

    /// The immutable, one-based snapshot position used by keyset paging.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The holder whose direct access is reviewed.
    #[must_use]
    pub fn holder(&self) -> &PrincipalRef {
        &self.holder
    }

    /// The recorded decision, or the fact nobody has decided.
    #[must_use]
    pub fn verdict(&self) -> &AccessReviewVerdict {
        &self.verdict
    }

    /// What is suggested beside the holder.
    #[must_use]
    pub fn suggestion(&self) -> &ReviewSuggestion {
        &self.suggestion
    }

    /// Puts a suggestion beside the holder after the owning header checks
    /// the caller and the review's state.
    pub(super) fn suggest(&mut self, suggestion: ReviewSuggestion) {
        self.suggestion = suggestion;
    }

    /// Whether the snapshot item contributes to the pending counter.
    pub(super) fn is_pending(&self) -> bool {
        matches!(self.verdict, AccessReviewVerdict::Pending)
    }

    /// Whether the reviewer explicitly chose removal, regardless of the default.
    pub(super) fn explicitly_removed(&self) -> bool {
        matches!(
            self.verdict,
            AccessReviewVerdict::Decided {
                choice: ReviewChoice::Remove,
                ..
            }
        )
    }

    /// Applies a choice after the owning header checks the caller and counters.
    pub(super) fn decide(&mut self, choice: ReviewChoice, reviewer: Human) {
        self.verdict = AccessReviewVerdict::Decided { choice, reviewer };
    }

    /// Checks persisted item identity, position and reviewer against its header.
    pub(super) fn ensure_review<T: TenantScope>(
        &self,
        review: &AccessReview<T>,
    ) -> Result<(), DomainError> {
        RowCheck::of("access review item")
            .holds(self.review_id == *review.id(), "belongs to another review")
            .holds(
                self.position > 0 && self.position <= review.holder_count(),
                "position outside its snapshot",
            )
            .holds(
                self.reviewed_by(review.reviewers()),
                "decision by someone not reviewing",
            )
            .finish()
    }

    /// Whether the stored reviewer was named by the snapshot's header.
    pub(super) fn reviewed_by(&self, reviewers: &[Human]) -> bool {
        match &self.verdict {
            AccessReviewVerdict::Pending => true,
            AccessReviewVerdict::Decided { reviewer, .. } => names(reviewers, reviewer),
        }
    }

    /// Whether completion removes this holder under the fixed unanswered rule.
    pub(super) fn removed(&self, unanswered: Unanswered) -> bool {
        match &self.verdict {
            AccessReviewVerdict::Pending => unanswered == Unanswered::RemoveAccess,
            AccessReviewVerdict::Decided { choice, .. } => *choice == ReviewChoice::Remove,
        }
    }
}
