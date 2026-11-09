//! The longest a tenant lets its people ask for access.
//!
//! Nobody may ask for a role or a group for longer than a month. Acme wants
//! less: production access is for a shift, never a week. Ann, who may shape
//! roles, sets the limit to eight hours, and from then on a request for two
//! days is refused when it is made. A tenant that never set one allows the
//! month.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::access_request::{AccessRequestLimits, MAX_ACCESS_LENGTH};
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::access_requests::AccessRequestPolicyChanged;
use crate::domains::authorization::permission::{RoleAction, SystemPermission};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::Lifetime;

/// The right that changes the limit: the right to shape roles, as with the
/// tenant's other access rules.
const SHAPES_ACCESS: SystemPermission = SystemPermission::Roles(RoleAction::Update);

/// One tenant's limit on how long its people may ask for access.
#[derive(Debug)]
pub struct AccessRequestPolicy<T: TenantScope> {
    limits: AccessRequestLimits,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// An [`AccessRequestPolicy`] as storage holds it, read back through
/// [`AccessRequestPolicy::reconstitute`].
#[derive(Clone, Copy)]
pub struct AccessRequestPolicyRow {
    /// The longest a request may ask for.
    pub longest: Lifetime,
    /// When the limit last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> AccessRequestPolicy<T> {
    /// The policy of a tenant that never set one: requests of up to
    /// `MAX_ACCESS_LENGTH`.
    #[must_use]
    pub fn widest() -> Self {
        Self {
            limits: AccessRequestLimits::WIDEST,
            updated_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a policy from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored limit is longer
    ///   than `MAX_ACCESS_LENGTH`.
    pub fn reconstitute(row: AccessRequestPolicyRow) -> Result<Self, DomainError> {
        RowCheck::of("access request policy")
            .holds(
                row.longest.duration() <= MAX_ACCESS_LENGTH,
                "a limit longer than anyone may ask for",
            )
            .finish()?;
        Ok(Self {
            limits: AccessRequestLimits::new(row.longest)?,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// What a request is held to.
    #[must_use]
    pub fn limits(&self) -> AccessRequestLimits {
        self.limits
    }

    /// When the limit last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Holds requests to `limits` from now on, as `by` decides. Raises
    /// `authorization.access_request_policy_changed` with the limit before
    /// and after. Asking for the limit already set changes nothing and
    /// raises nothing.
    ///
    /// Requests already made keep the length they asked for; the next one
    /// is held to the new limit.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update roles.
    pub fn change_limits(
        &mut self,
        limits: AccessRequestLimits,
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        by.ensure_holds(SHAPES_ACCESS)?;
        if limits == self.limits {
            return Ok(());
        }
        let previous = std::mem::replace(&mut self.limits, limits);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(AccessRequestPolicyChanged {
            previous: previous.longest(),
            current: limits.longest(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for AccessRequestPolicy<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::raised_names;

    fn hours(count: i64) -> Lifetime {
        Lifetime::seconds(count.saturating_mul(3600)).unwrap()
    }

    fn eight_hours() -> AccessRequestLimits {
        AccessRequestLimits::new(hours(8)).unwrap()
    }

    /// A tenant that never set a limit allows the month.
    #[test]
    fn a_tenant_without_a_limit_allows_the_longest() {
        let policy = AccessRequestPolicy::<ResolvedTenant>::widest();

        assert_eq!(policy.limits(), AccessRequestLimits::WIDEST);
    }

    /// Ann, who may update roles, sets eight hours. The limit holds and the
    /// change is recorded; setting eight hours again records nothing.
    #[test]
    fn a_limit_change_is_recorded_once() {
        let mut policy = AccessRequestPolicy::<ResolvedTenant>::widest();
        let ann = anyone_holding(&[SHAPES_ACCESS]);

        policy.change_limits(eight_hours(), ann).unwrap();
        let first = raised_names(&mut policy);
        policy.change_limits(eight_hours(), ann).unwrap();

        assert_eq!(policy.limits(), eight_hours());
        assert_eq!(first, ["authorization.access_request_policy_changed"]);
        assert!(raised_names(&mut policy).is_empty());
    }

    /// A role viewer cannot raise the access-request limit, which stays at eight hours.
    #[test]
    fn only_someone_who_may_update_roles_changes_the_limit() {
        let mut policy =
            AccessRequestPolicy::<ResolvedTenant>::reconstitute(AccessRequestPolicyRow {
                longest: hours(8),
                updated_at: crate::shared::clock::now(),
            })
            .unwrap();
        let sam = anyone_holding(&[SystemPermission::Roles(RoleAction::View)]);

        let refused = policy.change_limits(AccessRequestLimits::WIDEST, sam);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(policy.limits(), eight_hours());
    }

    /// A stored forty-day access-request limit exceeds the maximum and is
    /// rejected as corrupt.
    #[test]
    fn a_stored_limit_past_the_longest_is_refused() {
        let stored = AccessRequestPolicy::<ResolvedTenant>::reconstitute(AccessRequestPolicyRow {
            longest: hours(24 * 40),
            updated_at: crate::shared::clock::now(),
        });

        assert!(refused_as_corrupt(&stored));
    }
}
