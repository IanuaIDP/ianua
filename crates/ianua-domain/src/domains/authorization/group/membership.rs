//! Members of a group: who is in it, and the records joining and leaving
//! raise.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::access_request::{AccessRequest, AskedAccess};
use crate::domains::authorization::access_review::ReviewScope;
use crate::domains::authorization::directory::TenantDirectory;
use crate::domains::authorization::events::groups::{
    GroupMemberAdded, GroupMemberRemoved, GroupMembershipExpired,
};
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::group::{Group, GroupPlace};
use crate::domains::authorization::group_tree::Conferred;
use crate::domains::authorization::holding::{
    NewHolding, ensure_ends_later, ensure_lapsed, ensure_stored_order,
};
use crate::domains::authorization::permission::{RoleAction, SystemPermission};
use crate::domains::authorization::review_removals::ReviewRemovals;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{EventLabel, Expiry, GroupId, PrincipalRef, UserId};

/// A [`GroupMembership`] as storage holds it, read back through
/// [`GroupMembership::reconstitute`].
#[derive(Clone, Copy)]
pub struct GroupMembershipRow {
    /// The member.
    pub principal: PrincipalRef,
    /// The container whose permissions this member inherits.
    pub group_id: GroupId,
    /// When the member joined.
    pub joined_at: OffsetDateTime,
    /// When the membership ends, or that it does not.
    pub expires: Expiry,
}

/// Puts a person, an agent or a machine into a group in one tenant.
///
/// A member can belong to many groups. The shared `T: TenantScope` parameter
/// keeps the member and the group in the same tenant.
///
/// A group lets many members share roles without repeating each grant. A
/// tier of partner apps shares roles the same way a team of people does.
///
/// A membership may end at a time. From then on it brings nothing when
/// rights are worked out, and [`lapse`](Self::lapse) sweeps it away.
#[derive(Debug)]
pub struct GroupMembership<T: TenantScope> {
    /// The member.
    principal: PrincipalRef,
    /// The group the member belongs to.
    group_id: GroupId,
    /// When the membership was created.
    joined_at: OffsetDateTime,
    /// When the membership ends, or that it does not.
    expires: Expiry,
    /// What the membership raised since it was last saved.
    raised: Raised<T>,
    /// Which plane this belongs to (see [`crate::isolation`]).
    _scope: PhantomData<T>,
}

impl<T: TenantScope> GroupMembership<T> {
    /// Adds `holding`'s principal to `group` until `holding.until`.
    /// [`NewHolding::standing`] has no expiry. `conferred` includes the group's roles
    /// and its ancestors' roles as computed by [`GroupTree::conferred`].
    /// Raises `authorization.group_member_added` with `holding.label` and expiry.
    ///
    /// # Errors
    /// [`DomainError::Validation`] if expiry is not future.
    /// [`DomainError::Forbidden`] without role-assignment rights, for another group's
    /// `conferred` permissions, or if the granter cannot delegate every gained permission.
    pub fn join_until(
        holding: NewHolding,
        group: &Group<T>,
        conferred: &Conferred,
        granter: &HeldByGranter<'_>,
    ) -> Result<Self, DomainError> {
        ensure_ends_later(holding.until, crate::shared::clock::now())?;
        granter.ensure_holds(SystemPermission::Roles(RoleAction::Assign))?;
        conferred.ensure_for(GroupPlace::Under(group.id))?;
        granter.ensure_may_give(&conferred.handout())?;
        Ok(Self::recorded(holding, group))
    }

    /// Puts the person who asked into the group an approved access request
    /// asked for, until the end the approval set. Raises
    /// `authorization.group_member_added`, naming them `member_label`.
    ///
    /// The approver was checked for the right and what the group brings
    /// when they approved, so no one is checked here.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the request is not approved.
    /// - [`DomainError::Conflict`] when it asked for another group.
    pub fn from_approved_request(
        request: &AccessRequest<T>,
        group: &Group<T>,
        member_label: EventLabel,
    ) -> Result<Self, DomainError> {
        let granted = request.granted(AskedAccess::Group(group.id))?;
        Ok(Self::recorded(
            NewHolding {
                principal: granted.principal,
                label: member_label,
                until: granted.until,
            },
            group,
        ))
    }

    /// Adds a directory user to a directory-owned group through SCIM.
    /// The enabled directory supplies authority; no person's grant is checked. Group roles
    /// were authorized when assigned. Agents and apps instead use [`Self::join_until`].
    /// Raises `authorization.group_member_added`, naming `member_label`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the directory is off or the group is dashboard-owned.
    pub fn from_directory(
        user_id: UserId,
        group: &Group<T>,
        directory: &impl TenantDirectory<T>,
        member_label: EventLabel,
    ) -> Result<Self, DomainError> {
        directory.ensure_speaks()?;
        group.ensure_kept_by_directory()?;
        Ok(Self::recorded(
            NewHolding::standing(PrincipalRef::User(user_id), member_label),
            group,
        ))
    }

    /// Puts `user` into `group` because their sign-in provider puts them in
    /// a group mapped to it. Raises `authorization.group_member_added`,
    /// naming the user `member_label`.
    ///
    /// No granter is checked: the admin who mapped the group was. Nobody
    /// chooses each person a provider names, so the group brings no
    /// built-in permission: checked again here, as `conferred` says now, in
    /// case a role with one was added to it or above it after the mapping.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `conferred` was worked out for
    ///   another group, or brings a built-in permission.
    pub(crate) fn by_group_mapping(
        user: UserId,
        group: &Group<T>,
        conferred: &Conferred,
        member_label: EventLabel,
    ) -> Result<Self, DomainError> {
        conferred.ensure_for(GroupPlace::Under(group.id))?;
        ensure_joined_automatically(conferred)?;
        Ok(Self::recorded(
            NewHolding::standing(PrincipalRef::User(user), member_label),
            group,
        ))
    }

    fn recorded(holding: NewHolding, group: &Group<T>) -> Self {
        let mut membership = Self {
            principal: holding.principal,
            group_id: group.id,
            joined_at: crate::shared::clock::now(),
            expires: holding.until,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        membership.raised.raise(GroupMemberAdded {
            group_id: group.id,
            group_label: group.label(),
            member: holding.principal,
            member_label: holding.label,
            until: holding.until,
            occurred_at: membership.joined_at,
        });
        membership
    }

    /// Sweeps away this membership of `group` once its end has passed by
    /// `now`. Raises `authorization.group_membership_expired`, naming the
    /// member `member_label`, taken once the membership is removed from
    /// storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `group` is another group.
    /// - [`DomainError::Conflict`] when the membership has not ended by
    ///   `now`, or never ends.
    pub fn lapse(
        &mut self,
        group: &Group<T>,
        now: OffsetDateTime,
        member_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.ensure_of(group)?;
        ensure_lapsed(self.expires, now)?;
        self.raised.raise(GroupMembershipExpired {
            group_id: self.group_id,
            group_label: group.label(),
            member: self.principal,
            member_label,
            occurred_at: now,
        });
        Ok(())
    }

    /// When the membership ends, or that it does not.
    #[must_use]
    pub fn expires(&self) -> Expiry {
        self.expires
    }

    /// Whether the membership still counts at `now`: it has no end, or its
    /// end is still to come.
    #[must_use]
    pub fn is_in_force(&self, now: OffsetDateTime) -> bool {
        !self.expires.has_passed(now)
    }

    /// Ends this membership of `group` once `granter` may. Raises
    /// `authorization.group_member_removed`, naming the member
    /// `member_label`, taken once the membership is removed from storage.
    ///
    /// The member loses all the group brings, `conferred`. Only someone who
    /// could have given that takes it away. Sam may assign roles. Without
    /// this, he takes Ann out of "Admins" and she loses the owner role.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `group` is another group.
    /// - [`DomainError::Forbidden`] when `conferred` was worked out for
    ///   another group.
    /// - [`DomainError::Forbidden`] when `granter` may not assign roles, or
    ///   may not hand out what the group brings.
    pub fn end(
        &mut self,
        group: &Group<T>,
        conferred: &Conferred,
        granter: &HeldByGranter<'_>,
        member_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.ensure_of(group)?;
        conferred.ensure_for(GroupPlace::Under(self.group_id))?;
        granter.ensure_controls(
            SystemPermission::Roles(RoleAction::Assign),
            &conferred.handout(),
        )?;
        self.raise_ended(group, member_label);
        Ok(())
    }

    /// Ends membership in a group controlled by the tenant's enabled directory.
    /// Raises `authorization.group_member_removed` with `member_label`, to be taken
    /// after storage removes the membership.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the directory is off, `group` differs from the
    /// membership's group, or the group is dashboard-owned.
    pub fn end_by_directory(
        &mut self,
        group: &Group<T>,
        directory: &impl TenantDirectory<T>,
        member_label: EventLabel,
    ) -> Result<(), DomainError> {
        directory.ensure_speaks()?;
        self.ensure_of(group)?;
        group.ensure_kept_by_directory()?;
        self.raise_ended(group, member_label);
        Ok(())
    }

    /// Ends membership as directed by a completed overdue review.
    /// The review's removal proof supplies authority without checking a person's rights.
    /// Raises `authorization.group_member_removed` with `member_label`, taken after deletion.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another group, a review of another role or group,
    /// or removals that do not name this member.
    pub fn withdraw_by_review(
        &mut self,
        group: &Group<T>,
        removals: &ReviewRemovals,
        member_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.ensure_of(group)?;
        removals.ensure_names(&self.principal, ReviewScope::Group(self.group_id))?;
        self.raise_ended(group, member_label);
        Ok(())
    }

    /// Ends this membership of `group` because the sign-in provider no
    /// longer puts the member in a group mapped to it. Raises
    /// `authorization.group_member_removed`, naming the member
    /// `member_label`, taken once the membership is removed from storage.
    ///
    /// No granter is checked: the provider's word put them in, and its word
    /// takes them out. Only a connection's withdrawal calls this, for a
    /// membership its mapping gave.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `group` is another group.
    pub(crate) fn withdrawn_by_provider(
        &mut self,
        group: &Group<T>,
        member_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.ensure_of(group)?;
        self.raise_ended(group, member_label);
        Ok(())
    }

    /// Refuses `group` when this membership is of another one.
    fn ensure_of(&self, group: &Group<T>) -> Result<(), DomainError> {
        if group.id != self.group_id {
            return Err(DomainError::forbidden(message!(
                "authorization-the-membership-belongs-to-another-group",
                "the membership belongs to another group"
            )));
        }
        Ok(())
    }

    /// Raises the member leaving `group`, named `member_label`.
    fn raise_ended(&mut self, group: &Group<T>, member_label: EventLabel) {
        self.raised.raise(GroupMemberRemoved {
            group_id: self.group_id,
            group_label: group.label(),
            member: self.principal,
            member_label,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Rebuilds a group membership from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it ends before it began.
    pub fn reconstitute(row: GroupMembershipRow) -> Result<Self, DomainError> {
        ensure_stored_order("group membership", row.joined_at, row.expires)?;
        Ok(Self {
            principal: row.principal,
            group_id: row.group_id,
            joined_at: row.joined_at,
            expires: row.expires,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The member.
    #[must_use]
    pub fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    /// The group the member belongs to.
    #[must_use]
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// When the member joined the group.
    #[must_use]
    pub fn joined_at(&self) -> OffsetDateTime {
        self.joined_at
    }
}

impl<T: TenantScope> Raises for GroupMembership<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a group given automatically, by a provider's group mapping,
/// when sitting in it brings a built-in permission that gives power, as
/// `conferred` says. The metrics overview gives none.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `conferred` brings a built-in
///   permission that gives power.
pub(crate) fn ensure_joined_automatically(conferred: &Conferred) -> Result<(), DomainError> {
    let gives_power = conferred
        .handout()
        .system
        .iter()
        .any(SystemPermission::gives_power);
    if gives_power {
        return Err(DomainError::forbidden(message!(
            "authorization-a-group-given-automatically-brings-no",
            "a group given automatically brings no built-in permission; a person gives admin rights"
        )));
    }
    Ok(())
}
