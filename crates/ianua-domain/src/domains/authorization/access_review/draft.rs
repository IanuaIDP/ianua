//! Validated creation metadata awaiting its atomic holder snapshot.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::access_review::{
    AccessReview, AccessReviewStatus, NewAccessReview, ReviewScope, Unanswered, ensure_counts,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::types::{AccessReviewId, Human, Label};

/// Creation authorized by the domain, before the store counts the full snapshot.
#[derive(Debug)]
pub struct AccessReviewDraft<T: TenantScope> {
    id: AccessReviewId,
    new: NewAccessReview,
    started_at: OffsetDateTime,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AccessReviewDraft<T> {
    /// Reserves the identity after the parent has checked creation authority.
    pub(super) fn new(new: NewAccessReview, started_at: OffsetDateTime) -> Self {
        Self {
            id: AccessReviewId::new(),
            new,
            started_at,
            _scope: PhantomData,
        }
    }

    /// The identity reserved before snapshot persistence.
    #[must_use]
    pub fn id(&self) -> &AccessReviewId {
        &self.id
    }

    /// The requested display name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.new.name
    }

    /// The role or group whose direct active holders are snapshotted.
    #[must_use]
    pub fn scope(&self) -> ReviewScope {
        self.new.scope
    }

    /// The bounded set of named reviewers.
    #[must_use]
    pub fn reviewers(&self) -> &[Human] {
        &self.new.reviewers
    }

    /// The validated deadline.
    #[must_use]
    pub fn due(&self) -> OffsetDateTime {
        self.new.due
    }

    /// The policy for holders nobody decides on.
    #[must_use]
    pub fn unanswered(&self) -> Unanswered {
        self.new.unanswered
    }

    /// The fixed time used to select active holdings.
    #[must_use]
    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    /// Opens the complete persisted snapshot and records its actual holder count.
    ///
    /// # Errors
    ///
    /// Refuses an empty snapshot; the caller rolls back its creation unit.
    pub fn started(self, holder_count: u64) -> Result<AccessReview<T>, DomainError> {
        if holder_count == 0 {
            return Err(DomainError::conflict(message!(
                "authorization-nobody-holds-what-the-review-covers",
                "nobody holds what the review covers"
            )));
        }
        ensure_counts(holder_count, holder_count, 0)?;
        let scope_label = self.new.scope_label.clone();
        let mut review = self.header(holder_count);
        review.raise_started(scope_label);
        Ok(review)
    }

    /// Builds the all-pending header without allocating a holder collection.
    fn header(self, holder_count: u64) -> AccessReview<T> {
        AccessReview {
            id: self.id,
            name: self.new.name,
            scope: self.new.scope,
            reviewers: self.new.reviewers,
            due: self.new.due,
            unanswered: self.new.unanswered,
            holder_count,
            pending_count: holder_count,
            remove_count: 0,
            status: AccessReviewStatus::Open,
            started_at: self.started_at,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }
}
