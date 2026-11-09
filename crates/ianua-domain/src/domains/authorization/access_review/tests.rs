//! Review metadata, item authorization and atomic paged completion invariants.

/// Completion traverses every snapshot page before closing the review.
mod completion;

use time::Duration;

use crate::domains::authorization::access_review::{
    AccessReview, AccessReviewRow, AccessReviewStatus, AccessReviewVerdict, HolderSuggestion,
    NewAccessReview, RUNS_REVIEWS, ReviewChoice, ReviewItem, ReviewItemRow, ReviewScope,
    ReviewSuggestion, Unanswered,
};
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::SystemPermission;
use crate::isolation::scope::ResolvedTenant;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::refused_as_corrupt;
use crate::test_support::authority::assumed_authority;
use crate::test_support::builders::label;
use crate::test_support::events::raised_names;
use crate::types::{
    AccessReviewId, EventLabel, Human, HumanAccount, PersonKey, PrincipalRef, RoleId, TenantId,
    Text, UserId,
};

/// A distinct human with the person identity checked by review authority.
fn person(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).unwrap(),
    )
}

/// Supplies test authority without bypassing the review's own checks.
fn acting(who: &Human, system: &[SystemPermission]) -> &'static TenantAuthority {
    assumed_authority(who, TenantId::new(), system, &[])
}

/// Names one reviewer and fixes a future deadline for a role snapshot.
fn request(reviewer: Human, unanswered: Unanswered) -> NewAccessReview {
    NewAccessReview {
        name: label("Finance"),
        scope: ReviewScope::Role(RoleId::new()),
        scope_label: EventLabel::of("finance"),
        reviewers: vec![reviewer],
        due: clock::now() + Duration::days(14),
        unanswered,
    }
}

/// A header with separately stored items, never an embedded holder collection.
struct Fixture {
    review: AccessReview<ResolvedTenant>,
    items: Vec<ReviewItem>,
    reviewer: Human,
}

impl Fixture {
    /// Creates an all-pending snapshot for testing independent item operations.
    fn new(unanswered: Unanswered) -> Self {
        let reviewer = person("carol@acme.test");
        let review = AccessReview::start(
            request(reviewer.clone(), unanswered),
            2,
            acting(&person("ann@acme.test"), &[RUNS_REVIEWS]),
        )
        .unwrap();
        let items = (1..=2).map(|position| item(&review, position)).collect();
        Self {
            review,
            items,
            reviewer,
        }
    }

    /// Decides one stored item while maintaining the locked header's counters.
    fn decide(&mut self, index: usize, choice: ReviewChoice) {
        self.review
            .decide(
                &mut self.items[index],
                choice,
                acting(&self.reviewer, &[]),
                EventLabel::of("holder"),
            )
            .unwrap();
    }
}

/// Reconstitutes one pending item against its owning snapshot header.
fn item(review: &AccessReview<ResolvedTenant>, position: u64) -> ReviewItem {
    pending_item(review, position, PrincipalRef::User(UserId::new()))
}

/// Reconstitutes a named holder's pending place in the snapshot.
fn pending_item(
    review: &AccessReview<ResolvedTenant>,
    position: u64,
    holder: PrincipalRef,
) -> ReviewItem {
    ReviewItem::reconstitute(ReviewItemRow {
        review,
        review_id: *review.id(),
        position,
        holder,
        verdict: AccessReviewVerdict::Pending,
        suggestion: ReviewSuggestion::Nothing,
    })
    .unwrap()
}

/// Captures metadata to exercise restart and corrupt-row checks independently.
fn stored(review: &AccessReview<ResolvedTenant>) -> AccessReviewRow {
    AccessReviewRow {
        id: *review.id(),
        name: review.name().clone(),
        scope: review.scope(),
        reviewers: review.reviewers().to_vec(),
        due: review.due(),
        unanswered: review.unanswered(),
        holder_count: review.holder_count(),
        pending_count: review.pending_count(),
        remove_count: review.remove_count(),
        status: review.status(),
        started_at: review.started_at(),
    }
}

/// A counted million-holder snapshot starts without allocating any items and
/// records the actual count once the authorized draft is opened.
#[test]
fn large_snapshots_start_without_allocating_holders() {
    let by = acting(&person("ann@acme.test"), &[RUNS_REVIEWS]);
    let draft = AccessReview::<ResolvedTenant>::prepare(
        request(person("carol@acme.test"), Unanswered::KeepAccess),
        by,
    )
    .unwrap();
    let id = *draft.id();
    let mut review = draft.started(1_000_000).unwrap();

    assert_eq!(*review.id(), id);
    assert_eq!(review.holder_count(), 1_000_000);
    assert_eq!(review.pending_count(), 1_000_000);
    assert_eq!(review.remove_count(), 0);
    assert_eq!(
        raised_names(&mut review),
        ["authorization.access_review_started"]
    );
}

/// A caller without assignment rights cannot prepare or cancel a review.
/// The refused cancellation leaves the review open.
#[test]
fn starting_and_cancelling_require_assignment_authority() {
    let sam = acting(&person("sam@acme.test"), &[]);
    let started = AccessReview::<ResolvedTenant>::prepare(
        request(person("carol@acme.test"), Unanswered::KeepAccess),
        sam,
    );
    let mut f = Fixture::new(Unanswered::KeepAccess);
    assert!(matches!(started, Err(DomainError::Forbidden(_))));
    assert!(matches!(
        f.review.cancel(sam),
        Err(DomainError::Forbidden(_))
    ));
    assert_eq!(f.review.status(), AccessReviewStatus::Open);
}

/// Review preparation rejects missing or repeated reviewers and a past deadline
/// as invalid input. Starting with an empty holder snapshot returns a conflict.
#[test]
fn creation_requires_reviewers_deadline_and_holders() {
    let by = acting(&person("ann@acme.test"), &[RUNS_REVIEWS]);
    let base = request(person("carol@acme.test"), Unanswered::KeepAccess);
    let mut none = base.clone();
    none.reviewers.clear();
    let mut repeated = base.clone();
    repeated.reviewers.push(base.reviewers[0].clone());
    let mut past = base.clone();
    past.due = clock::now() - Duration::DAY;
    for invalid in [none, repeated, past] {
        assert!(matches!(
            AccessReview::<ResolvedTenant>::prepare(invalid, by),
            Err(DomainError::Validation(_))
        ));
    }
    assert!(matches!(
        AccessReview::<ResolvedTenant>::start(base, 0, by),
        Err(DomainError::Conflict(_))
    ));
}

/// Replacing a choice updates only its item and summary counters, including
/// repeat remove and remove-to-keep decisions without counter drift.
#[test]
fn replacement_decisions_preserve_summary_counts() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    f.decide(0, ReviewChoice::Remove);
    f.decide(0, ReviewChoice::Remove);
    assert_eq!((f.review.pending_count(), f.review.remove_count()), (1, 1));
    f.decide(0, ReviewChoice::Keep);
    assert_eq!((f.review.pending_count(), f.review.remove_count()), (1, 0));
    assert_eq!(*f.items[1].verdict(), AccessReviewVerdict::Pending);
}

/// An unlisted reviewer and a reviewer deciding their own access are forbidden
/// from making a choice. The self-review item stays pending and the pending count stays two.
#[test]
fn decisions_require_independent_named_reviewers() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    let mut own = pending_item(&f.review, 1, f.reviewer.principal());
    let stranger = acting(&person("mallory@acme.test"), &[RUNS_REVIEWS]);
    assert!(matches!(
        f.review.decide(
            &mut f.items[0],
            ReviewChoice::Keep,
            stranger,
            EventLabel::of("holder")
        ),
        Err(DomainError::Forbidden(_))
    ));
    assert!(matches!(
        f.review.decide(
            &mut own,
            ReviewChoice::Keep,
            acting(&f.reviewer, &[]),
            EventLabel::of("holder")
        ),
        Err(DomainError::Forbidden(_))
    ));
    assert_eq!(f.review.pending_count(), 2);
    assert_eq!(*own.verdict(), AccessReviewVerdict::Pending);
}

/// Reconstituting an item rejects another review's identity, positions outside
/// its snapshot, and a decision by an unlisted reviewer as corrupt storage.
#[test]
fn item_reconstitution_refuses_header_mismatches() {
    let f = Fixture::new(Unanswered::KeepAccess);
    let make = |review_id, position, verdict| {
        ReviewItem::reconstitute(ReviewItemRow {
            review: &f.review,
            review_id,
            position,
            holder: *f.items[0].holder(),
            verdict,
            suggestion: ReviewSuggestion::Nothing,
        })
    };
    for (review_id, position) in [
        (AccessReviewId::new(), 1),
        (*f.review.id(), 0),
        (*f.review.id(), 3),
    ] {
        assert!(refused_as_corrupt(&make(
            review_id,
            position,
            AccessReviewVerdict::Pending
        )));
    }
    assert!(refused_as_corrupt(&make(
        *f.review.id(),
        1,
        AccessReviewVerdict::Decided {
            choice: ReviewChoice::Keep,
            reviewer: person("mallory@acme.test"),
        }
    )));
}

/// Reconstituting a header rejects empty, overflowing or inconsistent counts
/// as corrupt storage. A snapshot with the largest stored position count is valid.
#[test]
fn header_reconstitution_checks_counters_without_holders() {
    let f = Fixture::new(Unanswered::KeepAccess);
    for (total, pending, removed) in [
        (0, 0, 0),
        (2, 2, 1),
        (u64::MAX, u64::MAX, 0),
        (u64::MAX, u64::MAX, 1),
    ] {
        let mut row = stored(&f.review);
        row.holder_count = total;
        row.pending_count = pending;
        row.remove_count = removed;
        assert!(refused_as_corrupt(
            &AccessReview::<ResolvedTenant>::reconstitute(row)
        ));
    }
    let mut row = stored(&f.review);
    row.holder_count = u64::try_from(i64::MAX).unwrap();
    row.pending_count = row.holder_count;
    assert!(AccessReview::<ResolvedTenant>::reconstitute(row).is_ok());
}

/// A pending item cannot be decided when the stored header has no pending
/// holders. The corrupt-row refusal leaves the remove count at zero and the item pending.
#[test]
fn inconsistent_counters_refuse_item_changes() {
    let f = Fixture::new(Unanswered::KeepAccess);
    let mut row = stored(&f.review);
    row.pending_count = 0;
    let mut header = AccessReview::<ResolvedTenant>::reconstitute(row).unwrap();
    let mut pending = f.items[0].clone();
    let result = header.decide(
        &mut pending,
        ReviewChoice::Remove,
        acting(&f.reviewer, &[]),
        EventLabel::of("holder"),
    );
    assert!(refused_as_corrupt(&result));
    assert_eq!(header.remove_count(), 0);
    assert_eq!(*pending.verdict(), AccessReviewVerdict::Pending);
}

/// Cancellation raises one cancellation event and prevents overdue completion
/// and further decisions. The item used in the refused decision stays pending.
#[test]
fn cancellation_preserves_items_and_prevents_changes() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    let _ = raised_names(&mut f.review);
    f.review
        .cancel(acting(&person("ann@acme.test"), &[RUNS_REVIEWS]))
        .unwrap();
    assert_eq!(
        raised_names(&mut f.review),
        ["authorization.access_review_cancelled"]
    );
    assert!(f.review.complete_overdue(f.review.due()).is_err());
    assert!(
        f.review
            .decide(
                &mut f.items[0],
                ReviewChoice::Keep,
                acting(&f.reviewer, &[]),
                EventLabel::of("holder")
            )
            .is_err()
    );
    assert_eq!(*f.items[0].verdict(), AccessReviewVerdict::Pending);
}

/// After every holder has a decision, a caller who neither reviews nor assigns
/// roles cannot authorize completion. A named reviewer can authorize it.
#[test]
fn completion_requires_reviewer_or_assignment_authority() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    f.decide(0, ReviewChoice::Keep);
    f.decide(1, ReviewChoice::Keep);
    let stranger = acting(&person("mallory@acme.test"), &[]);
    assert!(matches!(
        f.review.complete(stranger),
        Err(DomainError::Forbidden(_))
    ));
    assert!(f.review.complete(acting(&f.reviewer, &[])).is_ok());
}

/// A review called off while someone is undecided is refused as closed, not
/// as waiting for that person: no wait would ever let it complete.
#[test]
fn a_called_off_review_answers_closed() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    f.review
        .cancel(acting(&person("ann@acme.test"), &[RUNS_REVIEWS]))
        .unwrap();
    assert!(matches!(
        f.review.complete(acting(&f.reviewer, &[])),
        Err(DomainError::InvalidTransition(_))
    ));
}

/// A suggestion for `holder`: `choice`, because of `reason`.
fn suggestion(holder: PrincipalRef, choice: ReviewChoice, reason: &str) -> HolderSuggestion {
    HolderSuggestion {
        holder,
        choice,
        reason: Text::new("reason", reason).unwrap(),
    }
}

/// Suggests removing the inactive Finance holder and retaining the payroll reader.
fn finance_suggestions(first: PrincipalRef, second: PrincipalRef) -> Vec<HolderSuggestion> {
    vec![
        suggestion(first, ReviewChoice::Remove, "no Finance app since June"),
        suggestion(second, ReviewChoice::Keep, "opens payroll weekly"),
    ]
}

/// Ann, who runs reviews, suggests removing the first holder and keeping
/// the second. Each suggestion sits beside its holder, nothing is decided,
/// and one record says two were suggested, one to remove.
#[test]
fn suggestions_preserve_verdicts_and_identify_holders() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    let _ = raised_names(&mut f.review);
    let (first, second) = (*f.items[0].holder(), *f.items[1].holder());
    let ann = acting(&person("ann@acme.test"), &[RUNS_REVIEWS]);

    f.review
        .suggest(&mut f.items, finance_suggestions(first, second), ann)
        .unwrap();

    assert!(matches!(
        f.items[0].suggestion(),
        ReviewSuggestion::Made { choice: ReviewChoice::Remove, reason }
            if reason.as_str() == "no Finance app since June"
    ));
    assert!(matches!(
        f.items[1].suggestion(),
        ReviewSuggestion::Made {
            choice: ReviewChoice::Keep,
            ..
        }
    ));
    assert_eq!(f.review.pending_count(), 2);
    assert_eq!(*f.items[0].verdict(), AccessReviewVerdict::Pending);
    assert_eq!(
        raised_names(&mut f.review),
        ["authorization.access_review_suggested"]
    );
}

/// Suggestions require review authority and cannot concern the caller's own
/// access or an unlisted holder. Each refusal leaves the first listed holder
/// without a suggestion, including when it precedes an unlisted holder.
#[test]
fn suggestions_require_authority_and_other_holders() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    let first = *f.items[0].holder();
    let ann_person = person("ann@acme.test");
    let ann = acting(&ann_person, &[RUNS_REVIEWS]);
    let sam = acting(&person("sam@acme.test"), &[]);
    let keep = |holder| suggestion(holder, ReviewChoice::Keep, "still on the team");

    let by_sam = f.review.suggest(&mut f.items, vec![keep(first)], sam);
    let own = f
        .review
        .suggest(&mut f.items, vec![keep(ann_person.principal())], ann);
    let stranger = PrincipalRef::User(UserId::new());
    let unlisted = f
        .review
        .suggest(&mut f.items, vec![keep(first), keep(stranger)], ann);

    assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
    assert!(matches!(own, Err(DomainError::Forbidden(_))));
    assert!(matches!(unlisted, Err(DomainError::Validation(_))));
    assert_eq!(*f.items[0].suggestion(), ReviewSuggestion::Nothing);
}

/// Repeated suggestions for one holder return a validation error. A suggestion
/// after cancellation returns a conflict.
#[test]
fn suggestions_refuse_duplicates_and_closed_reviews() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    let first = *f.items[0].holder();
    let ann = acting(&person("ann@acme.test"), &[RUNS_REVIEWS]);
    let keep = || suggestion(first, ReviewChoice::Keep, "still on the team");

    let twice = f.review.suggest(&mut f.items, vec![keep(), keep()], ann);
    f.review.cancel(ann).unwrap();
    let closed = f.review.suggest(&mut f.items, vec![keep()], ann);

    assert!(matches!(twice, Err(DomainError::Validation(_))));
    assert!(matches!(closed, Err(DomainError::Conflict(_))));
}
