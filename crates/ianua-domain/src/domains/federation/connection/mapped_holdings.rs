//! What a connection's group mapping gave one person, and taking it back
//! once the provider no longer puts them in the group that brought it.
//!
//! Okta drops Ann from `ops`. Without this, the Ops role the mapping gave
//! her at an earlier sign-in stays hers until an admin notices, though her
//! provider no longer vouches for it. So every sign-in through the
//! connection takes back what its mapping gave and gives no more. Only what
//! the mapping gave is on this record: a role Ann held already when the
//! mapping reached her, or one an admin gave her, is never taken this way.

use std::marker::PhantomData;

use crate::domains::authorization::group::{Group, GroupMembership};
use crate::domains::authorization::role::Role;
use crate::domains::authorization::role_assignment::RoleAssignment;
use crate::domains::federation::connection::group_mapping::{MappedGrants, ProviderGroupName};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{ConnectionId, EventLabel, GroupId, PrincipalRef, RoleId, UserId};

/// A [`MappedHoldings`] as storage holds it, read back through
/// [`MappedHoldings::reconstitute`].
pub struct MappedHoldingsRow {
    /// The connection whose mapping gave them.
    pub connection_id: ConnectionId,
    /// The person they were given to.
    pub user_id: UserId,
    /// The roles the mapping gave.
    pub roles: Vec<RoleId>,
    /// The groups the mapping put them in.
    pub groups: Vec<GroupId>,
}

/// The roles and groups one connection's group mapping gave one person, and
/// that they still hold through it.
#[derive(Debug)]
pub struct MappedHoldings<T: TenantScope> {
    connection_id: ConnectionId,
    user_id: UserId,
    roles: Vec<RoleId>,
    groups: Vec<GroupId>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> MappedHoldings<T> {
    /// Nothing given yet to `user_id` through `connection_id`'s mapping, as
    /// before their first sign-in through it.
    #[must_use]
    pub fn none(connection_id: ConnectionId, user_id: UserId) -> Self {
        Self {
            connection_id,
            user_id,
            roles: Vec::new(),
            groups: Vec::new(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds the record from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row names a role or a
    ///   group twice.
    pub fn reconstitute(row: MappedHoldingsRow) -> Result<Self, DomainError> {
        RowCheck::of("mapped holdings")
            .holds(
                first_repeat(row.roles.iter().copied()).is_none(),
                "names a role twice",
            )
            .holds(
                first_repeat(row.groups.iter().copied()).is_none(),
                "names a group twice",
            )
            .finish()?;
        Ok(Self {
            connection_id: row.connection_id,
            user_id: row.user_id,
            roles: row.roles,
            groups: row.groups,
            _scope: PhantomData,
        })
    }

    /// The connection whose mapping gave them.
    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// The person they were given to.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The roles the mapping gave.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    /// The groups the mapping put the person in.
    #[must_use]
    pub fn groups(&self) -> &[GroupId] {
        &self.groups
    }

    /// Notes that the mapping gave `role`.
    pub(crate) fn gave_role(&mut self, role: RoleId) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    /// Notes that the mapping put the person in `group`.
    pub(crate) fn gave_group(&mut self, group: GroupId) {
        if !self.groups.contains(&group) {
            self.groups.push(group);
        }
    }

    /// Takes off this record every role and group `now` no longer brings,
    /// and returns them as what the mapping takes back from the person,
    /// named `label` in its records.
    pub(crate) fn withdraw(
        &mut self,
        now: &MappedGrants,
        label: EventLabel,
    ) -> MappedWithdrawal<T> {
        let (kept_roles, roles): (Vec<RoleId>, Vec<RoleId>) = std::mem::take(&mut self.roles)
            .into_iter()
            .partition(|role| now.roles().contains(role));
        let (kept_groups, groups): (Vec<GroupId>, Vec<GroupId>) = std::mem::take(&mut self.groups)
            .into_iter()
            .partition(|group| now.groups().contains(group));
        self.roles = kept_roles;
        self.groups = kept_groups;
        MappedWithdrawal {
            user_id: self.user_id,
            label,
            roles,
            groups,
            _scope: PhantomData,
        }
    }
}

/// A person a connection's mapping reaches at sign-in: what it gave them
/// so far, the groups their provider puts them in now, and the name their
/// records show them by.
pub struct MappedPerson<'a, T: TenantScope> {
    /// What the mapping gave them so far. Giving and taking back note it
    /// here.
    pub holdings: &'a mut MappedHoldings<T>,
    /// The groups the provider names for them now.
    pub groups: &'a [ProviderGroupName],
    /// The name their records show them by, their address.
    pub label: EventLabel,
}

/// What a connection's mapping takes back from one person, because the
/// provider no longer puts them in a group that brings it.
///
/// Only a connection's `mapped_withdrawal` makes one, from the person's
/// [`MappedHoldings`], so nothing the mapping did not give, and nothing it
/// still gives, is taken this way.
#[derive(Debug)]
pub struct MappedWithdrawal<T: TenantScope> {
    user_id: UserId,
    label: EventLabel,
    roles: Vec<RoleId>,
    groups: Vec<GroupId>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> MappedWithdrawal<T> {
    /// The roles taken back.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    /// The groups the person leaves.
    #[must_use]
    pub fn groups(&self) -> &[GroupId] {
        &self.groups
    }

    /// Takes `role` back from `assignment`. Raises
    /// `authorization.role_revoked`, naming the person as their records do,
    /// taken once the assignment is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the assignment is someone else's,
    ///   or `role` is not one this takes back.
    /// - [`DomainError::Forbidden`] when `role` is not the role assigned.
    pub fn take_role(
        &self,
        assignment: &mut RoleAssignment<T>,
        role: &Role<T>,
    ) -> Result<(), DomainError> {
        self.ensure_holder(assignment.principal())?;
        if !self.roles.contains(role.id()) {
            return Err(DomainError::forbidden(message!(
                "federation-the-mapping-did-not-give-this",
                "the mapping did not give this role, or still gives it"
            )));
        }
        assignment.withdrawn_by_provider(role, self.label.clone())
    }

    /// Takes the person out of `group`, ending `membership`. Raises
    /// `authorization.group_member_removed`, naming the person as their
    /// records do, taken once the membership is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the membership is someone else's,
    ///   or `group` is not one this takes them out of.
    /// - [`DomainError::Forbidden`] when the membership is of another group.
    pub fn take_group(
        &self,
        membership: &mut GroupMembership<T>,
        group: &Group<T>,
    ) -> Result<(), DomainError> {
        self.ensure_holder(membership.principal())?;
        if !self.groups.contains(group.id()) {
            return Err(DomainError::forbidden(message!(
                "federation-the-mapping-did-not-put-the",
                "the mapping did not put the person in this group, or still does"
            )));
        }
        membership.withdrawn_by_provider(group, self.label.clone())
    }

    /// Refuses a holding that is not the person's.
    fn ensure_holder(&self, principal: &PrincipalRef) -> Result<(), DomainError> {
        if *principal != PrincipalRef::User(self.user_id) {
            return Err(DomainError::forbidden(message!(
                "federation-the-mapping-takes-back-only-what",
                "the mapping takes back only what it gave this person"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::federation::connection::group_mapping::{
        GroupMapping, GroupRule, GroupRules, MappedGrant,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::Label;

    fn group(name: &str) -> ProviderGroupName {
        ProviderGroupName::new(name).unwrap()
    }

    /// A mapping of `ops` to `role` and `engineering` to `team`.
    fn mapping(role: RoleId, team: GroupId) -> GroupMapping {
        GroupMapping::On(
            GroupRules::new(
                Label::new("claim", "groups").unwrap(),
                vec![
                    GroupRule {
                        provider_group: group("ops"),
                        grant: MappedGrant::Role(role),
                    },
                    GroupRule {
                        provider_group: group("engineering"),
                        grant: MappedGrant::Group(team),
                    },
                ],
            )
            .unwrap(),
        )
    }

    fn holding(role: RoleId, team: GroupId) -> MappedHoldings<ResolvedTenant> {
        let mut holdings = MappedHoldings::none(ConnectionId::new(), UserId::new());
        holdings.gave_role(role);
        holdings.gave_group(team);
        holdings
    }

    /// Okta drops Ann from `ops` but keeps her in `engineering`. The Ops
    /// role is taken back; the Engineering group stays, and stays on the
    /// record.
    #[test]
    fn only_what_the_provider_no_longer_brings_is_withdrawn() {
        let (ops, team) = (RoleId::new(), GroupId::new());
        let mut holdings = holding(ops, team);
        let now = mapping(ops, team).grants_for(&[group("engineering")]);

        let withdrawal = holdings.withdraw(&now, EventLabel::of("ann@acme.test"));

        assert_eq!(withdrawal.roles(), [ops]);
        assert!(withdrawal.groups().is_empty());
        assert!(holdings.roles().is_empty());
        assert_eq!(holdings.groups(), [team]);
    }

    /// Disabling a mapping puts its granted role and group in the withdrawal,
    /// even when the provider still names them.
    #[test]
    fn a_mapping_switched_off_takes_back_everything_it_gave() {
        let (ops, team) = (RoleId::new(), GroupId::new());
        let mut holdings = holding(ops, team);
        let now = GroupMapping::Off.grants_for(&[group("ops"), group("engineering")]);

        let withdrawal = holdings.withdraw(&now, EventLabel::of("ann@acme.test"));

        assert_eq!(withdrawal.roles(), [ops]);
        assert_eq!(withdrawal.groups(), [team]);
    }

    /// Giving the same role twice notes it once.
    #[test]
    fn a_role_given_twice_is_noted_once() {
        let ops = RoleId::new();
        let mut holdings =
            MappedHoldings::<ResolvedTenant>::none(ConnectionId::new(), UserId::new());

        holdings.gave_role(ops);
        holdings.gave_role(ops);

        assert_eq!(holdings.roles(), [ops]);
    }

    /// A stored record that names a role twice is refused as corrupt.
    #[test]
    fn a_stored_record_naming_a_role_twice_is_refused() {
        let ops = RoleId::new();

        let stored = MappedHoldings::<ResolvedTenant>::reconstitute(MappedHoldingsRow {
            connection_id: ConnectionId::new(),
            user_id: UserId::new(),
            roles: vec![ops, ops],
            groups: Vec::new(),
        });

        assert!(refused_as_corrupt(&stored));
    }
}
