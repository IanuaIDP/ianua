//! Access reviews: a campaign asking named reviewers, by a due date,
//! whether each holder of a role or member of a group keeps it.
//!
//! Access piles up. Bob joined Finance for a quarter-end and never left.
//! Once a quarter Ann starts a review of the Finance group, naming Carol and
//! Dan as reviewers. Each holder is listed when the review starts, a
//! reviewer marks each one keep or remove, and completing the review hands
//! back who is to lose it. The use case takes each away through the role
//! assignment or the membership, as anyone who could give it would.
//! Before the reviewers start, keep or remove may be suggested beside each
//! holder, with a reason; the reviewers still decide every one.

mod completion;
mod draft;
mod items;
mod suggestions;

use std::marker::PhantomData;

pub use completion::ReviewCompletion;
pub use draft::AccessReviewDraft;
pub use items::{ReviewItem, ReviewItemRow, ReviewSuggestion};
pub use suggestions::HolderSuggestion;
use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::access_reviews::{
    AccessReviewCancelled, AccessReviewCompleted, AccessReviewDecided, AccessReviewStarted,
};
use crate::domains::authorization::permission::{RoleAction, SystemPermission};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{AccessReviewId, EventLabel, GroupId, Human, Label, RoleId};

/// The most reviewers one review names.
pub(crate) const MAX_REVIEWERS: usize = 20;

/// The right that starts, completes and calls off a review: the right to
/// change who holds roles.
const RUNS_REVIEWS: SystemPermission = SystemPermission::Roles(RoleAction::Assign);

/// What a review covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewScope {
    /// Everyone given this role straight.
    Role(RoleId),
    /// Everyone in this group itself.
    Group(GroupId),
}

/// What happens to a holder nobody decided on by the due date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unanswered {
    /// They keep their access.
    KeepAccess,
    /// They lose it.
    RemoveAccess,
}

/// A reviewer's choice for one holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewChoice {
    /// They keep their access.
    Keep,
    /// They lose it.
    Remove,
}

impl ReviewChoice {
    /// The stable name a record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Remove => "remove",
        }
    }
}

/// Where one holder stands in a review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessReviewVerdict {
    /// Nobody has decided yet.
    Pending,
    /// This reviewer decided.
    Decided {
        /// What they chose.
        choice: ReviewChoice,
        /// Who chose it.
        reviewer: Human,
    },
}

/// Where a review is in its life. It moves from `Open` to `Completed` or
/// `Cancelled`, and no further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessReviewStatus {
    /// Reviewers are deciding.
    Open,
    /// Completed; its removals are settled.
    Completed,
    /// Called off; nothing it decided takes effect.
    Cancelled,
}

impl AccessReviewStatus {
    /// Moves to `to`, when [`AccessReviewStatus`] lists that move.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] when the move is not one listed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            from == Self::Open && matches!(to, Self::Completed | Self::Cancelled)
        })
    }
}

/// What starting a review asks.
#[derive(Debug, Clone)]
pub struct NewAccessReview {
    /// What the review is called, such as "Finance, Q3".
    pub name: Label,
    /// What it covers.
    pub scope: ReviewScope,
    /// The covered role's or group's name, for the audit trail.
    pub scope_label: EventLabel,
    /// Who decides.
    pub reviewers: Vec<Human>,
    /// By when.
    pub due: OffsetDateTime,
    /// What happens to holders nobody decided on.
    pub unanswered: Unanswered,
}

/// A review of who holds one role or is in one group.
#[derive(Debug)]
pub struct AccessReview<T: TenantScope> {
    id: AccessReviewId,
    name: Label,
    scope: ReviewScope,
    reviewers: Vec<Human>,
    due: OffsetDateTime,
    unanswered: Unanswered,
    holder_count: u64,
    pending_count: u64,
    remove_count: u64,
    status: AccessReviewStatus,
    started_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// An [`AccessReview`] as storage holds it, read back through
/// [`AccessReview::reconstitute`].
pub struct AccessReviewRow {
    /// The review.
    pub id: AccessReviewId,
    /// What it is called.
    pub name: Label,
    /// What it covers.
    pub scope: ReviewScope,
    /// Who decides.
    pub reviewers: Vec<Human>,
    /// By when.
    pub due: OffsetDateTime,
    /// What happens to holders nobody decided on.
    pub unanswered: Unanswered,
    /// The immutable number of holders in the initial snapshot.
    pub holder_count: u64,
    /// How many holders have no recorded choice.
    pub pending_count: u64,
    /// How many holders are explicitly marked remove.
    pub remove_count: u64,
    /// Where it is in its life.
    pub status: AccessReviewStatus,
    /// When it started.
    pub started_at: OffsetDateTime,
}

impl<T: TenantScope> AccessReview<T> {
    /// Validates creation and fixes the identity and time of its atomic snapshot.
    ///
    /// # Errors
    ///
    /// Refuses callers who cannot assign roles, invalid reviewers or deadlines.
    pub fn prepare(
        new: NewAccessReview,
        by: &TenantAuthority,
    ) -> Result<AccessReviewDraft<T>, DomainError> {
        by.ensure_holds(RUNS_REVIEWS)?;
        let now = crate::shared::clock::now();
        ensure_reviewers(&new.reviewers)?;
        if new.due <= now {
            return Err(DomainError::invalid(message!(
                "authorization-a-review-is-due-after-it",
                "a review is due after it starts"
            )));
        }
        Ok(AccessReviewDraft::new(new, now))
    }

    /// Starts from an already counted complete snapshot, including in fixtures.
    ///
    /// # Errors
    ///
    /// Refuses invalid creation metadata, unauthorized callers and an empty snapshot.
    pub fn start(
        new: NewAccessReview,
        holder_count: u64,
        by: &TenantAuthority,
    ) -> Result<Self, DomainError> {
        Self::prepare(new, by)?.started(holder_count)
    }

    /// Records the actual snapshot count after an authorized draft is persisted.
    pub(super) fn raise_started(&mut self, scope_label: EventLabel) {
        self.raised.raise(AccessReviewStarted {
            review_id: self.id,
            name: self.name.clone(),
            scope: self.scope,
            scope_label,
            holder_count: self.holder_count,
            due: self.due,
            occurred_at: self.started_at,
        });
    }

    /// Rebuilds a review from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it names no reviewer or one
    ///   twice, has impossible summary counts, or is due before or at its start.
    pub fn reconstitute(row: AccessReviewRow) -> Result<Self, DomainError> {
        check_row(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            scope: row.scope,
            reviewers: row.reviewers,
            due: row.due,
            unanswered: row.unanswered,
            holder_count: row.holder_count,
            pending_count: row.pending_count,
            remove_count: row.remove_count,
            status: row.status,
            started_at: row.started_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The review.
    #[must_use]
    pub fn id(&self) -> &AccessReviewId {
        &self.id
    }

    /// What it is called.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// What it covers.
    #[must_use]
    pub fn scope(&self) -> ReviewScope {
        self.scope
    }

    /// Who decides.
    #[must_use]
    pub fn reviewers(&self) -> &[Human] {
        &self.reviewers
    }

    /// Whether `person` is one of its reviewers, through any of their
    /// accounts.
    #[must_use]
    pub fn is_reviewed_by(&self, person: &Human) -> bool {
        names(&self.reviewers, person)
    }

    /// By when.
    #[must_use]
    pub fn due(&self) -> OffsetDateTime {
        self.due
    }

    /// What happens to holders nobody decided on.
    #[must_use]
    pub fn unanswered(&self) -> Unanswered {
        self.unanswered
    }

    /// The number of holders in the immutable snapshot.
    #[must_use]
    pub fn holder_count(&self) -> u64 {
        self.holder_count
    }

    /// The number of snapshot holders still awaiting a decision.
    #[must_use]
    pub fn pending_count(&self) -> u64 {
        self.pending_count
    }

    /// The number of explicit remove choices, excluding unanswered holders.
    #[must_use]
    pub fn remove_count(&self) -> u64 {
        self.remove_count
    }

    /// Where it is in its life.
    #[must_use]
    pub fn status(&self) -> AccessReviewStatus {
        self.status
    }

    /// When it started.
    #[must_use]
    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    /// Records a named reviewer's choice for one validated snapshot item.
    /// The caller persists this header and that item atomically.
    ///
    /// # Errors
    ///
    /// Refuses another review's item, an unnamed or self-reviewing caller,
    /// a closed or overdue review, or inconsistent stored counters.
    pub fn decide(
        &mut self,
        item: &mut ReviewItem,
        choice: ReviewChoice,
        reviewer: &TenantAuthority,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.ensure_decider(item, reviewer)?;
        let (pending, removed) = self.changed_counts(item.verdict(), choice)?;
        item.decide(choice, reviewer.who().clone());
        self.pending_count = pending;
        self.remove_count = removed;
        self.raised.raise(AccessReviewDecided {
            review_id: self.id,
            holder: *item.holder(),
            holder_label,
            choice,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Checks item ownership and the authority and timing of a decision.
    fn ensure_decider(
        &self,
        item: &ReviewItem,
        reviewer: &TenantAuthority,
    ) -> Result<(), DomainError> {
        item.ensure_review(self)?;
        let person = reviewer.who();
        if !names(&self.reviewers, person) {
            return Err(DomainError::forbidden(message!(
                "authorization-only-a-named-reviewer-decides",
                "only a named reviewer decides"
            )));
        }
        if person.principal() == *item.holder() {
            return Err(DomainError::forbidden(message!(
                "authorization-nobody-decides-whether-they-keep-their",
                "nobody decides whether they keep their own access"
            )));
        }
        self.ensure_open()
    }

    /// Puts each suggestion beside its holder's item, for the reviewers to
    /// follow or not; nothing is decided. A later suggestion for a holder
    /// replaces the earlier one. Either every item gets its suggestion or
    /// none does. The caller saves `items` with the event.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not run reviews, or a
    ///   suggestion is about `by`'s own access.
    /// - [`DomainError::Conflict`] when the review is no longer open.
    /// - [`DomainError::Validation`] for no suggestion or more than
    ///   `MAX_SUGGESTIONS`, a holder named twice, or a holder `items`
    ///   does not hold.
    pub fn suggest(
        &mut self,
        items: &mut [ReviewItem],
        suggestions: Vec<HolderSuggestion>,
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        by.ensure_holds(RUNS_REVIEWS)?;
        self.ensure_open()?;
        let made = suggestions::put_beside(self, items, suggestions, by)?;
        self.raised.raise(made);
        Ok(())
    }

    /// Refuses a review completed, called off or past its due date.
    fn ensure_open(&self) -> Result<(), DomainError> {
        if self.status != AccessReviewStatus::Open || crate::shared::clock::now() >= self.due {
            return Err(DomainError::conflict(message!(
                "authorization-this-review-is-no-longer-open",
                "this review is no longer open"
            )));
        }
        Ok(())
    }

    /// Adjusts counters for a replacement decision without changing state on failure.
    fn changed_counts(
        &self,
        before: &AccessReviewVerdict,
        choice: ReviewChoice,
    ) -> Result<(u64, u64), DomainError> {
        let was_pending = u64::from(matches!(before, AccessReviewVerdict::Pending));
        let was_removed = u64::from(matches!(
            before,
            AccessReviewVerdict::Decided {
                choice: ReviewChoice::Remove,
                ..
            }
        ));
        let pending = self.pending_count.checked_sub(was_pending);
        let removed = self
            .remove_count
            .checked_sub(was_removed)
            .and_then(|count| count.checked_add(u64::from(choice == ReviewChoice::Remove)));
        let (Some(pending), Some(removed)) = (pending, removed) else {
            return Err(DomainError::corrupt_row(
                "access review",
                "inconsistent decision counters",
            ));
        };
        ensure_counts(self.holder_count, pending, removed)?;
        Ok((pending, removed))
    }

    /// Authorizes manual completion without loading or closing the snapshot.
    /// Every removal still requires the caller's standing at its holding.
    ///
    /// # Errors
    ///
    /// Refuses unauthorized callers, closed reviews and unanswered holders
    /// before the deadline.
    pub fn complete(&self, by: &TenantAuthority) -> Result<ReviewCompletion, DomainError> {
        if !names(&self.reviewers, by.who()) && !by.holds(RUNS_REVIEWS) {
            return Err(DomainError::forbidden(message!(
                "authorization-a-review-is-completed-by-a",
                "a review is completed by a reviewer or someone who may assign roles"
            )));
        }
        self.status.try_transition(AccessReviewStatus::Completed)?;
        if self.pending_count > 0 && crate::shared::clock::now() < self.due {
            return Err(DomainError::conflict(message!(
                "authorization-someone-is-still-undecided-and-the",
                "someone is still undecided and the review is not due yet"
            )));
        }
        Ok(ReviewCompletion::manual(self))
    }

    /// Authorizes overdue completion and its bounded domain removal proofs.
    ///
    /// # Errors
    ///
    /// Refuses an early attempt or a review that is no longer open.
    pub fn complete_overdue(&self, now: OffsetDateTime) -> Result<ReviewCompletion, DomainError> {
        if now < self.due {
            return Err(DomainError::conflict(message!(
                "authorization-the-review-is-not-due-yet",
                "the review is not due yet"
            )));
        }
        self.status.try_transition(AccessReviewStatus::Completed)?;
        Ok(ReviewCompletion::overdue(self))
    }

    /// Closes a fully traversed snapshot after all removals have succeeded.
    /// Persist this header and its event in the same unit as all item pages.
    ///
    /// # Errors
    ///
    /// Refuses an incomplete, changed or unrelated snapshot and a closed review.
    // Consuming the traversal proof prevents its reuse after this completion attempt.
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish(&mut self, completion: ReviewCompletion) -> Result<(), DomainError> {
        completion.ensure_finished(self)?;
        let kept = self
            .holder_count
            .checked_sub(completion.removed())
            .ok_or_else(|| {
                DomainError::corrupt_row("access review completion", "removals exceed snapshot")
            })?;
        self.status = self.status.try_transition(AccessReviewStatus::Completed)?;
        self.raised.raise(AccessReviewCompleted {
            review_id: self.id,
            removed: completion.removed(),
            kept,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Calls the review off for `by`; nothing it decided takes effect.
    /// Raises `authorization.access_review_cancelled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not assign roles.
    /// - [`DomainError::InvalidTransition`] when the review is not open.
    pub fn cancel(&mut self, by: &TenantAuthority) -> Result<(), DomainError> {
        by.ensure_holds(RUNS_REVIEWS)?;
        self.status = self.status.try_transition(AccessReviewStatus::Cancelled)?;
        self.raised.raise(AccessReviewCancelled {
            review_id: self.id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for AccessReview<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Whether `reviewers` names `person`, through any of their accounts.
fn names(reviewers: &[Human], person: &Human) -> bool {
    reviewers
        .iter()
        .any(|reviewer| reviewer.is_same_person_as(person))
}

/// Refuses a stored header with invalid metadata or impossible counters.
fn check_row(row: &AccessReviewRow) -> Result<(), DomainError> {
    ensure_counts(row.holder_count, row.pending_count, row.remove_count)?;
    RowCheck::of("access review")
        .holds(
            ensure_reviewers(&row.reviewers).is_ok(),
            "invalid reviewers",
        )
        .holds(row.due > row.started_at, "due before or at its start")
        .finish()
}

/// Ensures persisted summary counts can describe one nonempty snapshot.
fn ensure_counts(total: u64, pending: u64, removed: u64) -> Result<(), DomainError> {
    RowCheck::of("access review")
        .holds(total > 0, "an empty snapshot")
        .holds(
            i64::try_from(total).is_ok(),
            "snapshot exceeds stored position range",
        )
        .holds(
            pending
                .checked_add(removed)
                .is_some_and(|count| count <= total),
            "inconsistent holder counts",
        )
        .finish()
}

/// Refuses no reviewer, too many, or one person twice.
fn ensure_reviewers(reviewers: &[Human]) -> Result<(), DomainError> {
    validate_count("reviewers", reviewers.len(), 1..=MAX_REVIEWERS)?;
    if first_repeat(reviewers.iter().map(Human::person)).is_some() {
        return Err(DomainError::invalid(message!(
            "authorization-a-review-names-each-reviewer-once",
            "a review names each reviewer once"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
