//! Atomic completion, bounded traversal and restart behavior.

use time::Duration;

use crate::domains::authorization::access_review::tests::{Fixture, acting, stored};
use crate::domains::authorization::access_review::{
    AccessReview, AccessReviewStatus, ReviewChoice, Unanswered,
};
use crate::isolation::scope::ResolvedTenant;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::refused_as_corrupt;
use crate::test_support::events::raised_names;

/// Two decided items are read in separate pages. Only the remove choice is
/// returned; the header stays open and emits completion only after the last page.
#[test]
fn completion_waits_for_every_snapshot_page() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    f.decide(0, ReviewChoice::Keep);
    f.decide(1, ReviewChoice::Remove);
    let _ = raised_names(&mut f.review);
    let mut completion = f.review.complete(acting(&f.reviewer, &[])).unwrap();

    assert!(completion.removals(&f.items[..1]).unwrap().is_empty());
    assert_eq!(completion.processed(), 1);
    assert_eq!(f.review.status(), AccessReviewStatus::Open);
    assert!(raised_names(&mut f.review).is_empty());
    assert_eq!(
        completion.removals(&f.items[1..]).unwrap(),
        [*f.items[1].holder()]
    );
    f.review.finish(completion).unwrap();
    assert_eq!(f.review.status(), AccessReviewStatus::Completed);
    assert_eq!(
        raised_names(&mut f.review),
        ["authorization.access_review_completed"]
    );
    assert!(f.review.complete(acting(&f.reviewer, &[])).is_err());
}

/// A manual completion proof cannot authorize system withdrawals. The refusal
/// leaves its cursor at zero, and ordinary traversal still returns the removed holder.
#[test]
fn manual_completion_cannot_authorize_system_withdrawals() {
    let mut f = Fixture::new(Unanswered::KeepAccess);
    f.decide(0, ReviewChoice::Remove);
    f.decide(1, ReviewChoice::Keep);
    let mut completion = f.review.complete(acting(&f.reviewer, &[])).unwrap();
    assert!(matches!(
        completion.overdue_removals(&f.items),
        Err(DomainError::Forbidden(_))
    ));
    assert_eq!(completion.processed(), 0);
    assert_eq!(
        completion.removals(&f.items).unwrap(),
        [*f.items[0].holder()]
    );
}

/// Unanswered holders prevent early manual completion. At the deadline the
/// overdue permit removes only those whose fixed unanswered rule says remove.
#[test]
fn overdue_completion_applies_unanswered_rule() {
    let mut f = Fixture::new(Unanswered::RemoveAccess);
    f.decide(0, ReviewChoice::Keep);
    assert!(matches!(
        f.review.complete(acting(&f.reviewer, &[])),
        Err(DomainError::Conflict(_))
    ));
    assert!(matches!(
        f.review.complete_overdue(f.review.due() - Duration::SECOND),
        Err(DomainError::Conflict(_))
    ));
    let mut completion = f.review.complete_overdue(f.review.due()).unwrap();
    let removals = completion.overdue_removals(&f.items).unwrap();
    assert_eq!(removals.holders(), [*f.items[1].holder()]);
    assert_eq!(removals.scope(), f.review.scope());
    f.review.finish(completion).unwrap();
}

/// Completion rejects skipped positions, another review's items and repeated
/// positions as corrupt storage. Refused pages do not advance the cursor.
#[test]
fn invalid_pages_leave_cursor_unchanged() {
    let f = Fixture::new(Unanswered::RemoveAccess);
    let other = Fixture::new(Unanswered::RemoveAccess);
    let mut completion = f.review.complete_overdue(f.review.due()).unwrap();
    assert!(refused_as_corrupt(
        &completion.overdue_removals(&f.items[1..])
    ));
    assert!(refused_as_corrupt(
        &completion.overdue_removals(&other.items[..1])
    ));
    assert_eq!(completion.processed(), 0);
    completion.overdue_removals(&f.items[..1]).unwrap();
    assert!(refused_as_corrupt(
        &completion.overdue_removals(&f.items[..1])
    ));
    assert_eq!(completion.processed(), 1);
}

/// A failed attempt drops its in-memory traversal. Reconstitution starts a
/// fresh traversal at zero, and incomplete finishing never closes the header.
#[test]
fn reconstitution_restarts_incomplete_traversal() {
    let mut f = Fixture::new(Unanswered::RemoveAccess);
    let mut first = f.review.complete_overdue(f.review.due()).unwrap();
    first.overdue_removals(&f.items[..1]).unwrap();
    assert!(refused_as_corrupt(&f.review.finish(first)));
    assert_eq!(f.review.status(), AccessReviewStatus::Open);
    let restarted = AccessReview::<ResolvedTenant>::reconstitute(stored(&f.review)).unwrap();
    assert_eq!(
        restarted
            .complete_overdue(restarted.due())
            .unwrap()
            .processed(),
        0
    );
}

/// Completion rejects a stored pending count that disagrees with the traversed
/// items as corrupt storage and leaves the review open.
#[test]
fn completion_refuses_mismatched_item_totals() {
    let f = Fixture::new(Unanswered::RemoveAccess);
    let mut row = stored(&f.review);
    row.pending_count = 1;
    let mut corrupt = AccessReview::<ResolvedTenant>::reconstitute(row).unwrap();
    let mut completion = corrupt.complete_overdue(corrupt.due()).unwrap();
    completion.overdue_removals(&f.items).unwrap();
    assert!(refused_as_corrupt(&corrupt.finish(completion)));
    assert_eq!(corrupt.status(), AccessReviewStatus::Open);
}
