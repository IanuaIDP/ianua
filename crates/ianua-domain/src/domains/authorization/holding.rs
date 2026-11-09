//! Who is given a role or a place in a group, and until when.
//!
//! A contractor needs the billing role for a fortnight, an on-call engineer
//! the production group for a night. Either is given with an end, and from
//! that moment on it counts for nothing when rights are worked out, whether
//! or not a sweep has taken it away yet.

use time::OffsetDateTime;

use crate::domains::authorization::group::GroupMembership;
use crate::domains::authorization::role::RoleAssignment;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{EventLabel, Expiry, PrincipalRef};

/// One holding given or taken away: a role given straight, or a place in a
/// group.
///
/// An approved request gives one or the other, and a completed review takes
/// one or the other away. Each records itself, so whoever saves it takes
/// what it raised from here, whichever it is.
#[derive(Debug)]
pub enum HeldAccess<T: TenantScope> {
    /// A role given straight.
    Role(RoleAssignment<T>),
    /// A place in a group.
    Membership(GroupMembership<T>),
}

impl<T: TenantScope> Raises for HeldAccess<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        match self {
            Self::Role(assignment) => assignment.take_events(saved_for),
            Self::Membership(membership) => membership.take_events(saved_for),
        }
    }
}

/// Who is given a role or a group, the name the record shows them by, and
/// when it ends.
#[derive(Debug, Clone)]
pub struct NewHolding {
    /// Who holds it.
    pub principal: PrincipalRef,
    /// The name the audit trail shows them by.
    pub label: EventLabel,
    /// When it ends, or that it does not.
    pub until: Expiry,
}

impl NewHolding {
    /// `principal`, named `label`, holding it with no end.
    #[must_use]
    pub fn standing(principal: PrincipalRef, label: EventLabel) -> Self {
        Self {
            principal,
            label,
            until: Expiry::Never,
        }
    }
}

/// Refuses an end that is not after `now`. A holding that ends before it
/// begins would be recorded as given and grant nothing, and the record
/// would claim access nobody had.
///
/// # Errors
///
/// - [`DomainError::Validation`] when `until` is at or before `now`.
pub(crate) fn ensure_ends_later(until: Expiry, now: OffsetDateTime) -> Result<(), DomainError> {
    if until.has_passed(now) {
        return Err(DomainError::invalid(message!(
            "authorization-access-must-end-after-it-is",
            "access must end after it is given"
        )));
    }
    Ok(())
}

/// Refuses a stored holding that ends before it was given.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] naming `entity` when `until` is at or
///   before `given`.
pub(crate) fn ensure_stored_order(
    entity: &'static str,
    given: OffsetDateTime,
    until: Expiry,
) -> Result<(), DomainError> {
    RowCheck::of(entity)
        .holds(!until.has_passed(given), "ends before it was given")
        .finish()
}

/// Refuses sweeping a holding that has not ended.
///
/// # Errors
///
/// - [`DomainError::Conflict`] when `until` has not passed by `now`.
pub(crate) fn ensure_lapsed(until: Expiry, now: OffsetDateTime) -> Result<(), DomainError> {
    if !until.has_passed(now) {
        return Err(DomainError::conflict(message!(
            "authorization-this-access-has-not-ended-yet",
            "this access has not ended yet"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::fixtures::role;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::raised_names;
    use crate::types::UserId;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    /// Access given until tomorrow, or with no end, is accepted. Access
    /// ending now or an hour ago is refused.
    #[test]
    fn access_ends_after_it_is_given() {
        assert!(ensure_ends_later(Expiry::At(now() + Duration::days(1)), now()).is_ok());
        assert!(ensure_ends_later(Expiry::Never, now()).is_ok());
        assert!(ensure_ends_later(Expiry::At(now()), now()).is_err());
        assert!(ensure_ends_later(Expiry::At(now() - Duration::hours(1)), now()).is_err());
    }

    /// A sweep refuses access that has not expired or never expires, but permits
    /// removing it at its expiry time.
    #[test]
    fn only_ended_access_is_swept() {
        let until = Expiry::At(now() + Duration::days(1));

        assert!(matches!(
            ensure_lapsed(until, now()),
            Err(DomainError::Conflict(_))
        ));
        assert!(ensure_lapsed(until, now() + Duration::days(1)).is_ok());
        assert!(ensure_lapsed(Expiry::Never, now()).is_err());
    }

    /// A stored holding that ends at the moment it was given is refused as
    /// a corrupt row.
    #[test]
    fn a_stored_holding_ending_before_it_began_is_refused() {
        let refused = ensure_stored_order("role assignment", now(), Expiry::At(now()));

        assert!(matches!(refused, Err(DomainError::Infrastructure(_))));
    }

    /// Sam gives Bob the viewer role. The holding hands over the record the
    /// assignment raised, once: taking it again finds nothing.
    #[test]
    fn a_holding_hands_over_what_it_raised_once() {
        let viewer = role("viewer", &[], &[]);
        let sam = anyone_holding(&[SystemPermission::Users(UserAction::Update)]);
        let bob = PrincipalRef::User(UserId::new());
        let given = RoleAssignment::assign_until(
            NewHolding::standing(bob, EventLabel::of("bob")),
            &viewer,
            sam,
        )
        .unwrap();
        let mut held = HeldAccess::Role(given);

        let first = raised_names(&mut held);
        let second = raised_names(&mut held);

        assert_eq!(first, ["authorization.role_assigned"]);
        assert!(second.is_empty());
    }
}
