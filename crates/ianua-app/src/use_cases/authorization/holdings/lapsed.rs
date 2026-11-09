//! A hold that ran out and the sweep has not cleared yet, cleared away and
//! recorded before a fresh one of the same role or group is given.
//!
//! The store lets a fresh grant replace such a hold, so the sweep would
//! never see it and its end would go unrecorded. A path that gives a role
//! or a place again clears the old hold here first and records its end as
//! the sweep does, by the platform. The clearing removes only a hold still
//! run out, so of the sweep and a grant at the same moment exactly one
//! records it.

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises;
use ianua_domain::types::{EventLabel, PrincipalRef};
use time::OffsetDateTime;

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{GroupMembershipStore, RoleAssignmentStore};
use crate::tenancy::ScopedTenant;

/// Whose run-out hold is looked for, how they are named in its record,
/// and the moment it is judged at.
pub(crate) struct RanOut<'a> {
    /// Who held it.
    pub(crate) principal: &'a PrincipalRef,
    /// How the record names them.
    pub(crate) label: EventLabel,
    /// The moment the hold must have ended by.
    pub(crate) now: OffsetDateTime,
}

/// Clears away `ran_out.principal`'s hold of `role` that ended by
/// `ran_out.now` and the sweep has not cleared, and returns the record of
/// its end, the platform's. Empty when there is none, or the sweep cleared
/// it first and recorded it itself.
///
/// # Errors
///
/// - `AppError::Internal` when the holds cannot be read or cleared.
/// - `AppError::Domain` when the hold found cannot be ended.
pub(crate) async fn role_cleared(
    store: &dyn RoleAssignmentStore,
    tenant: &ScopedTenant,
    role: &Role<ResolvedTenant>,
    ran_out: RanOut<'_>,
) -> Result<Vec<DomainEvent>, AppError> {
    let held = store
        .find_by_principal(tenant, ran_out.principal)
        .await
        .or_internal()?;
    let Some(mut ended) = held
        .into_iter()
        .find(|held| held.role_id() == role.id() && !held.is_in_force(ran_out.now))
    else {
        return Ok(Vec::new());
    };
    ended
        .lapse(role, ran_out.now, ran_out.label)
        .map_err(AppError::from_domain)?;
    if !store
        .remove_lapsed(tenant, &ended, ran_out.now)
        .await
        .or_internal()?
    {
        return Ok(Vec::new());
    }
    Ok(by_the_platform(&mut ended, tenant))
}

/// Clears away `ran_out.principal`'s place in `group` that ended by
/// `ran_out.now` and the sweep has not cleared, and returns the record of
/// its end, the platform's. Empty when there is none, or the sweep cleared
/// it first and recorded it itself.
///
/// # Errors
///
/// - `AppError::Internal` when the places cannot be read or cleared.
/// - `AppError::Domain` when the place found cannot be ended.
pub(crate) async fn place_cleared(
    store: &dyn GroupMembershipStore,
    tenant: &ScopedTenant,
    group: &Group<ResolvedTenant>,
    ran_out: RanOut<'_>,
) -> Result<Vec<DomainEvent>, AppError> {
    let held = store
        .find_by_principal(tenant, ran_out.principal)
        .await
        .or_internal()?;
    let Some(mut ended) = held
        .into_iter()
        .find(|held| held.group_id() == group.id() && !held.is_in_force(ran_out.now))
    else {
        return Ok(Vec::new());
    };
    ended
        .lapse(group, ran_out.now, ran_out.label)
        .map_err(AppError::from_domain)?;
    if !store
        .remove_lapsed(tenant, &ended, ran_out.now)
        .await
        .or_internal()?
    {
        return Ok(Vec::new());
    }
    Ok(by_the_platform(&mut ended, tenant))
}

/// What `ended` raised, recorded as the platform's, as the sweep records it.
fn by_the_platform(ended: &mut impl Raises, tenant: &ScopedTenant) -> Vec<DomainEvent> {
    ended
        .take_events(tenant)
        .into_iter()
        .map(DomainEvent::system)
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Expiry, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeRoleAssignmentStore, stored_assignment_until, stored_group,
        stored_membership_until, stored_role,
    };
    use crate::test_support::{block_on, test_ctx};

    fn bob() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    fn ran_out(principal: &PrincipalRef) -> RanOut<'_> {
        RanOut {
            principal,
            label: EventLabel::of("bob"),
            now: clock::now(),
        }
    }

    /// An expired on-call assignment is removed and yields one event.
    /// Repeating cleanup finds nothing and yields no duplicate event.
    #[test]
    fn a_role_that_ran_out_is_cleared_and_its_end_recorded() {
        let on_call = stored_role("on-call", Vec::new(), Vec::new());
        let bob = bob();
        let ended = Expiry::At(clock::now() - Duration::hours(1));
        let store = FakeRoleAssignmentStore::holding(
            test_ctx().tenant_id(),
            [stored_assignment_until(bob, *on_call.id(), ended)],
        );
        let tenant = test_ctx().tenant();

        let first = block_on(role_cleared(&store, &tenant, &on_call, ran_out(&bob))).unwrap();
        let again = block_on(role_cleared(&store, &tenant, &on_call, ran_out(&bob))).unwrap();

        assert_eq!(first.len(), 1);
        assert!(again.is_empty());
        assert_eq!(store.count(), 0);
    }

    /// Bob still holds "on-call" until tomorrow. Nothing is cleared and
    /// nothing recorded.
    #[test]
    fn a_role_still_in_force_is_left() {
        let on_call = stored_role("on-call", Vec::new(), Vec::new());
        let bob = bob();
        let running = Expiry::At(clock::now() + Duration::days(1));
        let store = FakeRoleAssignmentStore::holding(
            test_ctx().tenant_id(),
            [stored_assignment_until(bob, *on_call.id(), running)],
        );

        let cleared = block_on(role_cleared(
            &store,
            &test_ctx().tenant(),
            &on_call,
            ran_out(&bob),
        ))
        .unwrap();

        assert!(cleared.is_empty());
        assert_eq!(store.count(), 1);
    }

    /// An expired Production membership is removed and yields one event.
    #[test]
    fn a_place_that_ran_out_is_cleared_and_its_end_recorded() {
        let production = stored_group("Production", GroupPlace::TopLevel, Vec::new());
        let bob = bob();
        let ended = Expiry::At(clock::now() - Duration::hours(1));
        let store = FakeGroupMembershipStore::holding(
            test_ctx().tenant_id(),
            [stored_membership_until(bob, *production.id(), ended)],
        );

        let cleared = block_on(place_cleared(
            &store,
            &test_ctx().tenant(),
            &production,
            ran_out(&bob),
        ))
        .unwrap();

        assert_eq!(cleared.len(), 1);
        assert_eq!(store.count(), 0);
    }
}
