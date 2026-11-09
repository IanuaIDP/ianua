//! Giving a role to a person, an agent or an app, and taking it back.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::access_request::{AccessRequest, AskedAccess};
use crate::domains::authorization::access_review::ReviewScope;
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::roles::{
    RoleAssigned, RoleAssignmentExpired, RoleRevoked,
};
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::holding::{
    NewHolding, ensure_ends_later, ensure_lapsed, ensure_stored_order,
};
use crate::domains::authorization::permission::{
    AgentAction, ConsumersAction, SystemPermission, UserAction,
};
use crate::domains::authorization::review_removals::ReviewRemovals;
use crate::domains::authorization::role::Role;
use crate::domains::identity::account::user::User;
use crate::domains::identity::invitations::invitation::Invitation;
use crate::domains::identity::invitations::status::InvitationStatus;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{ActorRef, EventLabel, Expiry, PrincipalRef, RoleId, UserId};

/// A [`RoleAssignment`] as storage holds it, read back through
/// [`RoleAssignment::reconstitute`].
pub struct RoleAssignmentRow {
    /// The principal who holds this role.
    pub principal: PrincipalRef,
    /// The role assigned.
    pub role_id: RoleId,
    /// Who made the assignment.
    pub assigned_by: ActorRef,
    /// When assigned.
    pub assigned_at: OffsetDateTime,
    /// When the role is taken away again, or that it is not.
    pub expires: Expiry,
}

/// Gives a role to a person, an agent or a machine in one tenant.
///
/// The shared `T: TenantScope` parameter keeps the principal and the role in
/// the same tenant.
///
/// Every kind of caller gets its rights the same way, through a role. So
/// "what may this caller do" has one answer for all of them.
///
/// A role may be given until a time. From that moment it counts for
/// nothing when rights are worked out, and [`lapse`](Self::lapse) sweeps
/// the record away.
#[derive(Debug)]
pub struct RoleAssignment<T: TenantScope> {
    principal: PrincipalRef,
    role_id: RoleId,
    assigned_by: ActorRef,
    assigned_at: OffsetDateTime,
    expires: Expiry,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// The right that changes which roles `principal` holds.
///
/// A person's roles are part of their record, so giving or taking one needs
/// the right to update users. An organization member acting in the tenant
/// counts as one of its users. An agent's roles need the right to update
/// agents, and an app's the right to update consumers.
#[must_use]
pub fn assignment_right(principal: &PrincipalRef) -> SystemPermission {
    match principal {
        PrincipalRef::User(_) | PrincipalRef::OrgUser(_) => {
            SystemPermission::Users(UserAction::Update)
        }
        PrincipalRef::Agent(_) => SystemPermission::Agents(AgentAction::Update),
        PrincipalRef::Consumer(_) => SystemPermission::Consumers(ConsumersAction::Update),
    }
}

impl<T: TenantScope> RoleAssignment<T> {
    /// Assigns `role` to `principal`, given by `granter`, who is recorded
    /// as the one who assigned it.
    ///
    /// The principal gains all the role grants. So `granter` must have the
    /// right to change that principal's roles, and be able to hand out all
    /// the role grants, through their standing rights. A break-glass grant
    /// is for the emergency, not for handing on.
    ///
    /// The record names whoever the proof is for. Sam gives Bob a role and
    /// cannot record it as given by Ann, or by the system.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `granter` lacks the right
    ///   [`assignment_right`] names for `principal`.
    /// - [`DomainError::Forbidden`] when `granter` may not hand out everything
    ///   the role grants.
    pub fn create(
        principal: PrincipalRef,
        role: &Role<T>,
        granter: &TenantAuthority,
    ) -> Result<Self, DomainError> {
        let held = granter.standing();
        held.ensure_holds(assignment_right(&principal))?;
        held.ensure_may_give(&role.grants())?;
        Ok(Self::recorded(
            principal,
            role,
            granter.actor(),
            Expiry::Never,
        ))
    }

    /// Assigns `role` to `holding`'s principal until `holding.until`, as
    /// [`create`](Self::create) does, as a change of its own that the audit
    /// trail records. Raises `authorization.role_assigned`, naming the
    /// holder by `holding.label`, with when it ends.
    /// [`NewHolding::standing`] is an assignment with no end.
    ///
    /// # Errors
    ///
    /// - As [`create`](Self::create).
    /// - [`DomainError::Validation`] when the end is not in the future.
    pub fn assign_until(
        holding: NewHolding,
        role: &Role<T>,
        granter: &TenantAuthority,
    ) -> Result<Self, DomainError> {
        ensure_ends_later(holding.until, crate::shared::clock::now())?;
        let mut assignment = Self::create(holding.principal, role, granter)?;
        assignment.expires = holding.until;
        assignment.raise_assigned(role, holding.label, None);
        Ok(assignment)
    }

    /// Assigns the role an approved access request asked for, to the person
    /// who asked, until the end the approval set. Raises
    /// `authorization.role_assigned`, naming the holder by `holder_label`.
    ///
    /// The approver was checked for the right and the role when they
    /// approved, so no one is checked here. The record names the approver
    /// as the one who assigned it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the request is not approved.
    /// - [`DomainError::Conflict`] when it asked for another role.
    pub fn from_approved_request(
        request: &AccessRequest<T>,
        role: &Role<T>,
        holder_label: EventLabel,
    ) -> Result<Self, DomainError> {
        let granted = request.granted(AskedAccess::Role(*role.id()))?;
        let mut assignment =
            Self::recorded(granted.principal, role, granted.approver, granted.until);
        assignment.raise_assigned(role, holder_label, None);
        Ok(assignment)
    }

    /// Assigns a role every new user gets, on behalf of [`ActorRef::System`].
    ///
    /// Whoever made the role a default was checked for all it grants at that
    /// time. So no one is checked here.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not given to new users.
    pub fn by_default(principal: PrincipalRef, role: &Role<T>) -> Result<Self, DomainError> {
        if !role.is_default() {
            return Err(DomainError::forbidden(message!(
                "authorization-only-a-role-every-new-user",
                "only a role every new user gets is assigned without someone granting it"
            )));
        }
        Ok(Self::recorded(
            principal,
            role,
            ActorRef::System,
            Expiry::Never,
        ))
    }

    /// Assigns the default role a sign-in provider or a directory gives the
    /// users it creates, on behalf of [`ActorRef::System`].
    ///
    /// Only federation calls this: a sign-in connection and a SCIM endpoint,
    /// each for the default role it is configured with, and each refusing
    /// any other role before it gets here. Nobody else may record a role no
    /// granter was checked for. Without that, any code gives Sam a role
    /// carrying `billing:admin` with no one asked.
    ///
    /// Nobody chooses each of those people, so the role carries no built-in
    /// permission that gives power. Admin rights are always given by a
    /// person. The rule is checked again here, in case the role was widened
    /// after it was named the default.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` carries a built-in
    ///   permission that gives power.
    pub(crate) fn by_provider(user: UserId, role: &Role<T>) -> Result<Self, DomainError> {
        ensure_given_automatically(role)?;
        Ok(Self::recorded(
            PrincipalRef::User(user),
            role,
            ActorRef::System,
            Expiry::Never,
        ))
    }

    /// Assigns `role` to `user` because their sign-in provider puts them in
    /// a group mapped to it, on behalf of [`ActorRef::System`]. Raises
    /// `authorization.role_assigned`, naming the holder by `holder_label`,
    /// so a role a provider hands out is in the audit trail like one a
    /// person gives.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` carries a built-in
    ///   permission.
    pub(crate) fn by_group_mapping(
        user: UserId,
        role: &Role<T>,
        holder_label: EventLabel,
    ) -> Result<Self, DomainError> {
        let mut assignment = Self::by_provider(user, role)?;
        assignment.raise_assigned(role, holder_label, None);
        Ok(assignment)
    }

    /// Takes this assignment of `role` away because the sign-in provider no
    /// longer puts its holder in a group mapped to it. Raises
    /// `authorization.role_revoked`, naming the holder by `holder_label`,
    /// taken once the assignment is removed from storage.
    ///
    /// No granter is checked: the provider's word gave the role, and its
    /// word takes it back. Only a connection's withdrawal calls this, for a
    /// role its mapping gave.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not the role assigned.
    pub(crate) fn withdrawn_by_provider(
        &mut self,
        role: &Role<T>,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        if *role.id() != self.role_id {
            return Err(DomainError::forbidden(message!(
                "authorization-this-assignment-is-of-another-role",
                "this assignment is of another role"
            )));
        }
        self.raise_revoked(role, holder_label);
        Ok(())
    }

    /// Assigns the role an accepted invitation gives `invitee`, on behalf of
    /// whoever sent it. Raises `authorization.role_assigned`, naming the
    /// invitee and the sender by `sender_label`.
    ///
    /// Accepting checked the role again against what the inviter holds now,
    /// so no one is checked here. Ann invited Bob as an editor with the
    /// right to invite users, but not to update them. Without this, Bob's
    /// role could only be given by someone who may update users.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the invitation was not accepted.
    /// - [`DomainError::Conflict`] when `role` is not the role it gives.
    /// - [`DomainError::Conflict`] when `invitee` is not the account it
    ///   invited.
    pub fn from_accepted_invitation(
        invitation: &Invitation<T>,
        role: &Role<T>,
        invitee: &User<T>,
        sender_label: EventLabel,
    ) -> Result<Self, DomainError> {
        if invitation.status() != InvitationStatus::Accepted {
            return Err(DomainError::conflict(message!(
                "authorization-a-role-comes-with-an-invitation",
                "a role comes with an invitation only once it is accepted"
            )));
        }
        if invitation.role_id() != role.id() {
            return Err(DomainError::conflict(message!(
                "authorization-the-invitation-gives-another-role",
                "the invitation gives another role"
            )));
        }
        if invitee.id() != invitation.user_id() {
            return Err(DomainError::conflict(message!(
                "authorization-the-invitation-was-for-another-account",
                "the invitation was for another account"
            )));
        }
        let mut assignment = Self::recorded(
            PrincipalRef::User(*invitee.id()),
            role,
            invitation.invited_by().clone(),
            Expiry::Never,
        );
        assignment.raise_assigned(role, invitee.label(), Some(sender_label));
        Ok(assignment)
    }

    fn recorded(
        principal: PrincipalRef,
        role: &Role<T>,
        assigned_by: ActorRef,
        expires: Expiry,
    ) -> Self {
        Self {
            principal,
            role_id: *role.id(),
            assigned_by,
            assigned_at: crate::shared::clock::now(),
            expires,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Records that the holder was given `role`.
    fn raise_assigned(
        &mut self,
        role: &Role<T>,
        holder_label: EventLabel,
        granted_by_label: Option<EventLabel>,
    ) {
        self.raised.raise(RoleAssigned {
            holder: self.principal,
            holder_label,
            role_id: self.role_id,
            role_label: role.label(),
            assigned_by: self.assigned_by.clone(),
            granted_by_label,
            until: self.expires,
            occurred_at: self.assigned_at,
        });
    }

    /// Takes this assignment away, once `granter` may. Raises
    /// `authorization.role_revoked`, naming the holder by `holder_label`,
    /// taken once the assignment is removed from storage.
    ///
    /// The holder loses all `role` grants. Only someone who could have given
    /// it takes it away. Sam may update users and view them. Without this,
    /// he takes the admin role from Ann and she can no longer run the
    /// tenant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not the role assigned.
    /// - [`DomainError::Forbidden`] when `granter` lacks the right
    ///   [`assignment_right`] names, or may not hand out all `role` grants.
    pub fn revoke(
        &mut self,
        role: &Role<T>,
        granter: &HeldByGranter<'_>,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        if *role.id() != self.role_id {
            return Err(DomainError::forbidden(message!(
                "authorization-this-assignment-is-of-another-role",
                "this assignment is of another role"
            )));
        }
        granter.ensure_controls(assignment_right(&self.principal), &role.grants())?;
        self.raise_revoked(role, holder_label);
        Ok(())
    }

    /// Takes this assignment away because an overdue review the platform
    /// completed says it goes. Raises `authorization.role_revoked`, naming
    /// the holder by `holder_label`, taken once the assignment is removed
    /// from storage.
    ///
    /// Nobody's rights are checked: the review decided. Only its own
    /// removals say so, and only of the role it covered.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not the role assigned.
    /// - [`DomainError::Forbidden`] when `removals` covered another role or
    ///   group, or do not name this holder.
    pub fn withdraw_by_review(
        &mut self,
        role: &Role<T>,
        removals: &ReviewRemovals,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        if *role.id() != self.role_id {
            return Err(DomainError::forbidden(message!(
                "authorization-this-assignment-is-of-another-role",
                "this assignment is of another role"
            )));
        }
        removals.ensure_names(&self.principal, ReviewScope::Role(self.role_id))?;
        self.raise_revoked(role, holder_label);
        Ok(())
    }

    /// Records that the holder lost `role`, named `holder_label`.
    fn raise_revoked(&mut self, role: &Role<T>, holder_label: EventLabel) {
        self.raised.raise(RoleRevoked {
            holder: self.principal,
            holder_label,
            role_id: self.role_id,
            role_label: role.label(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Sweeps away this assignment once its end has passed by `now`. Raises
    /// `authorization.role_assignment_expired`, naming the holder by
    /// `holder_label`, taken once the assignment is removed from storage.
    ///
    /// The role already counted for nothing from its end on; this only
    /// clears the record and says so in the audit trail.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not the role assigned.
    /// - [`DomainError::Conflict`] when the assignment has not ended by
    ///   `now`, or never ends.
    pub fn lapse(
        &mut self,
        role: &Role<T>,
        now: OffsetDateTime,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        if *role.id() != self.role_id {
            return Err(DomainError::forbidden(message!(
                "authorization-this-assignment-is-of-another-role",
                "this assignment is of another role"
            )));
        }
        ensure_lapsed(self.expires, now)?;
        self.raised.raise(RoleAssignmentExpired {
            holder: self.principal,
            holder_label,
            role_id: self.role_id,
            role_label: role.label(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Rebuilds a role assignment from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it ends before it was made.
    pub fn reconstitute(row: RoleAssignmentRow) -> Result<Self, DomainError> {
        ensure_stored_order("role assignment", row.assigned_at, row.expires)?;
        Ok(Self {
            principal: row.principal,
            role_id: row.role_id,
            assigned_by: row.assigned_by,
            assigned_at: row.assigned_at,
            expires: row.expires,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// When the role is taken away again, or that it is not.
    #[must_use]
    pub fn expires(&self) -> Expiry {
        self.expires
    }

    /// Whether the role still counts at `now`: it has no end, or its end is
    /// still to come.
    #[must_use]
    pub fn is_in_force(&self, now: OffsetDateTime) -> bool {
        !self.expires.has_passed(now)
    }

    /// The principal who holds this role.
    #[must_use]
    pub fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    /// The role that was assigned.
    #[must_use]
    pub fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// Who made the assignment. [`ActorRef::System`] for a role every new
    /// user gets.
    #[must_use]
    pub fn assigned_by(&self) -> &ActorRef {
        &self.assigned_by
    }

    /// When the assignment was made.
    #[must_use]
    pub fn assigned_at(&self) -> OffsetDateTime {
        self.assigned_at
    }
}

impl<T: TenantScope> Raises for RoleAssignment<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a role given automatically, by a provider or a directory, when
/// it carries a built-in permission that gives power. The metrics overview
/// the Member role carries gives none.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `role` carries a built-in permission
///   that gives power.
pub(crate) fn ensure_given_automatically<T: TenantScope>(
    role: &Role<T>,
) -> Result<(), DomainError> {
    let gives_power = role
        .system_permissions()
        .iter()
        .any(SystemPermission::gives_power);
    if gives_power {
        return Err(DomainError::forbidden(message!(
            "authorization-a-role-given-automatically-carries-no",
            "a role given automatically carries no built-in permission; a person gives admin rights"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{CustomPermission, RoleAction};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole};
    use crate::domains::identity::invitations::invitation::InvitationRow;
    use crate::domains::identity::invitations::offer::OfferState;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::{anyone_holding, assumed_authority};
    use crate::test_support::builders::{label, user};
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{
        AgentId, ConsumerId, Email, Human, HumanAccount, InvitationId, OrgUserId, PersonKey,
        TenantId, TokenHash,
    };

    fn admin_role() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("admin"),
            system_permissions: vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            custom_permissions: vec![CustomPermission::new("billing", "admin").unwrap()],
            assignment: DefaultAssignment::Manual,
        })
    }

    fn viewer_role() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("viewer"),
            system_permissions: vec![SystemPermission::Users(UserAction::View)],
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::NewUsers,
        })
    }

    fn owner() -> HeldByGranter<'static> {
        HeldByGranter::assumed(SystemPermission::all(), &[])
    }

    /// Someone signed in who holds everything.
    fn signed_in_owner() -> &'static TenantAuthority {
        anyone_holding(SystemPermission::all())
    }

    /// Ann, an admin signed in through her organization account, gives a
    /// user the admin role. The assignment names that user as holder and
    /// Ann's organization account as the one who assigned it, read from her
    /// proof.
    #[test]
    fn an_assignment_records_its_granter_from_the_proof() {
        let ann = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("ann@acme.test").unwrap(),
        );
        let by_ann = assumed_authority(&ann, TenantId::new(), SystemPermission::all(), &[]);
        let user = PrincipalRef::User(UserId::new());

        let assignment =
            RoleAssignment::<ResolvedTenant>::create(user, &admin_role(), by_ann).unwrap();

        assert_eq!(*assignment.principal(), user);
        assert_eq!(
            assignment.assigned_by().audit_label(),
            by_ann.actor().audit_label()
        );
        assert!(matches!(assignment.assigned_by(), ActorRef::OrgUser(_)));
    }

    /// A user gives an agent the admin role. The assignment keeps the holder
    /// as an agent, the same way it keeps a person.
    #[test]
    fn a_role_is_assignable_to_an_agent() {
        let agent = PrincipalRef::Agent(AgentId::new());

        let assignment =
            RoleAssignment::<ResolvedTenant>::create(agent, &admin_role(), signed_in_owner())
                .unwrap();

        assert_eq!(*assignment.principal(), agent);
        assert_eq!(assignment.principal().kind(), "agent");
    }

    /// Sam's role-assignment and user-update rights cannot grant himself an
    /// admin role with wider rights.
    #[test]
    fn assigning_a_role_takes_holding_all_it_grants() {
        let sam = anyone_holding(&[
            SystemPermission::Roles(RoleAction::Assign),
            SystemPermission::Users(UserAction::Update),
        ]);

        let result =
            RoleAssignment::<ResolvedTenant>::create(sam.who().principal(), &admin_role(), sam);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Emergency rights alone cannot authorize giving Ann a standing admin role.
    #[test]
    fn a_break_glass_grant_gives_no_role() {
        let ann = TenantAuthority::in_emergency(SystemPermission::all());

        let result =
            RoleAssignment::<ResolvedTenant>::create(ann.who().principal(), &admin_role(), ann);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// User-viewing rights cannot assign the viewer role to a user, agent or consumer.
    #[test]
    fn assigning_a_role_needs_the_right_for_the_holder() {
        let bob = anyone_holding(&[SystemPermission::Users(UserAction::View)]);

        for holder in [
            PrincipalRef::User(UserId::new()),
            PrincipalRef::Agent(AgentId::new()),
            PrincipalRef::Consumer(ConsumerId::new()),
        ] {
            let result = RoleAssignment::<ResolvedTenant>::create(holder, &viewer_role(), bob);
            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
    }

    /// Sam cannot revoke Ann's admin role with only user-update and viewing
    /// rights, while an owner can revoke it.
    #[test]
    fn only_someone_who_could_give_a_role_takes_it_back() {
        let admin = admin_role();
        let mut ann = RoleAssignment::<ResolvedTenant>::create(
            PrincipalRef::User(UserId::new()),
            &admin,
            signed_in_owner(),
        )
        .unwrap();
        let sam = HeldByGranter::assumed(
            &[
                SystemPermission::Users(UserAction::Update),
                SystemPermission::Users(UserAction::View),
            ],
            &[],
        );

        assert!(matches!(
            ann.revoke(&admin, &sam, EventLabel::of("ann@acme.test")),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            ann.revoke(&admin, &owner(), EventLabel::of("ann@acme.test"))
                .is_ok()
        );
    }

    /// Revoking an admin assignment using a different viewer role is refused.
    #[test]
    fn a_revoke_is_checked_against_the_role_assigned() {
        let mut ann = RoleAssignment::<ResolvedTenant>::create(
            PrincipalRef::User(UserId::new()),
            &admin_role(),
            signed_in_owner(),
        )
        .unwrap();

        let result = ann.revoke(&viewer_role(), &owner(), EventLabel::of("ann@acme.test"));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A stored assignment is read back. Its holder, assigner and time come
    /// back as stored.
    #[test]
    fn reconstitute_assignment_preserves_all_fields() {
        let user = PrincipalRef::User(UserId::new());
        let role = RoleId::new();
        let admin = UserId::new();
        let now = crate::shared::clock::now();
        let assignment = RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
            principal: user,
            role_id: role,
            assigned_by: ActorRef::User(admin),
            assigned_at: now,
            expires: Expiry::At(now + time::Duration::days(1)),
        })
        .unwrap();
        assert_eq!(*assignment.principal(), user);
        assert_eq!(
            assignment.assigned_by().audit_label(),
            ActorRef::User(admin).audit_label()
        );
        assert_eq!(assignment.assigned_at(), now);
        assert_eq!(
            assignment.expires(),
            Expiry::At(now + time::Duration::days(1))
        );
    }

    /// A stored assignment expiring when it was made is rejected as corrupt.
    #[test]
    fn a_stored_assignment_ending_before_it_was_made_is_refused() {
        let now = crate::shared::clock::now();

        let stored = RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id: RoleId::new(),
            assigned_by: ActorRef::System,
            assigned_at: now,
            expires: Expiry::At(now),
        });

        assert!(refused_as_corrupt(&stored));
    }

    /// Ann gives Carol the admin role for a week. It counts until the week
    /// is over and not a moment after, and the record says when it ends.
    #[test]
    fn a_role_given_until_a_time_counts_until_then() {
        let week = crate::shared::clock::now() + time::Duration::days(7);
        let mut carol = RoleAssignment::<ResolvedTenant>::assign_until(
            NewHolding {
                principal: PrincipalRef::User(UserId::new()),
                label: EventLabel::of("carol@acme.test"),
                until: Expiry::At(week),
            },
            &admin_role(),
            signed_in_owner(),
        )
        .unwrap();

        assert!(carol.is_in_force(week - time::Duration::seconds(1)));
        assert!(!carol.is_in_force(week));
        let events = raised(&mut carol);
        assert_eq!(
            events[0].payload().get("expires_at"),
            Some(week.to_string().as_str())
        );
    }

    /// Assigning a role with an expiry in the past is rejected as invalid.
    #[test]
    fn a_role_cannot_be_given_until_a_time_already_past() {
        let yesterday = crate::shared::clock::now() - time::Duration::days(1);

        let refused = RoleAssignment::<ResolvedTenant>::assign_until(
            NewHolding {
                principal: PrincipalRef::User(UserId::new()),
                label: EventLabel::of("bob@acme.test"),
                until: Expiry::At(yesterday),
            },
            &admin_role(),
            signed_in_owner(),
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Carol's week with the admin role is over. The sweep takes it away
    /// and records it. Sweeping a role with no end, or one still running,
    /// is refused.
    #[test]
    fn only_an_ended_role_is_swept() {
        let admin = admin_role();
        let now = crate::shared::clock::now();
        let stored = |expires| {
            RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
                principal: PrincipalRef::User(UserId::new()),
                role_id: *admin.id(),
                assigned_by: ActorRef::System,
                assigned_at: now - time::Duration::days(7),
                expires,
            })
            .unwrap()
        };
        let mut ended = stored(Expiry::At(now - time::Duration::hours(1)));
        let mut running = stored(Expiry::At(now + time::Duration::hours(1)));
        let mut standing = stored(Expiry::Never);
        let carol = || EventLabel::of("carol@acme.test");

        ended.lapse(&admin, now, carol()).unwrap();
        let early = running.lapse(&admin, now, carol());
        let never = standing.lapse(&admin, now, carol());

        assert_eq!(
            raised_names(&mut ended),
            ["authorization.role_assignment_expired"]
        );
        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert!(matches!(never, Err(DomainError::Conflict(_))));
    }

    /// Sweeping an expired admin assignment with a different viewer role is refused.
    #[test]
    fn a_sweep_is_checked_against_the_role_assigned() {
        let now = crate::shared::clock::now();
        let mut ended = RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id: *admin_role().id(),
            assigned_by: ActorRef::System,
            assigned_at: now - time::Duration::days(7),
            expires: Expiry::At(now - time::Duration::hours(1)),
        })
        .unwrap();

        let refused = ended.lapse(&viewer_role(), now, EventLabel::of("carol"));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A new user gets the viewer role by default. The assignment names the
    /// viewer role and the system as the one who assigned it.
    #[test]
    fn an_assignment_names_the_role_it_grants() {
        let role = viewer_role();

        let assignment =
            RoleAssignment::<ResolvedTenant>::by_default(PrincipalRef::User(UserId::new()), &role)
                .unwrap();

        assert_eq!(assignment.role_id(), role.id());
        assert!(matches!(assignment.assigned_by(), ActorRef::System));
    }

    /// Bob, whom the invitations below invite.
    fn bob() -> User<ResolvedTenant> {
        user(UserId::new(), "bob@example.com")
    }

    fn invitation(
        role: &Role<ResolvedTenant>,
        invitee: &User<ResolvedTenant>,
        state: OfferState,
    ) -> Invitation<ResolvedTenant> {
        let now = crate::shared::clock::now();
        Invitation::reconstitute(InvitationRow {
            id: InvitationId::new(),
            user_id: *invitee.id(),
            email: Email::new("bob@example.com").unwrap(),
            invited_by: ActorRef::User(UserId::new()),
            role_id: *role.id(),
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            state,
            message: None,
            expires_at: now + time::Duration::days(7),
            created_at: now - time::Duration::days(1),
        })
        .unwrap()
    }

    /// Bob accepted Ann's invitation as a viewer. He is given the viewer
    /// role, recorded as given by Ann, with no one else checked.
    #[test]
    fn an_accepted_invitation_gives_its_role() {
        let viewer = viewer_role();
        let accepted = OfferState::Accepted {
            at: crate::shared::clock::now(),
        };
        let bob = bob();
        let invited = invitation(&viewer, &bob, accepted);

        let assignment = RoleAssignment::from_accepted_invitation(
            &invited,
            &viewer,
            &bob,
            EventLabel::of("Ann"),
        )
        .unwrap();

        assert_eq!(
            *assignment.principal(),
            PrincipalRef::User(*invited.user_id())
        );
        assert_eq!(
            assignment.assigned_by().audit_label(),
            invited.invited_by().audit_label()
        );
    }

    /// An invitation cannot produce a role assignment while pending, for a
    /// different role or for another account.
    #[test]
    fn only_an_accepted_invitation_gives_only_its_own_role() {
        let viewer = viewer_role();
        let bob = bob();
        let pending = invitation(&viewer, &bob, OfferState::Pending);
        let accepted = invitation(
            &viewer,
            &bob,
            OfferState::Accepted {
                at: crate::shared::clock::now(),
            },
        );
        let sender = || EventLabel::of("Ann");

        let early = RoleAssignment::from_accepted_invitation(&pending, &viewer, &bob, sender());
        let swapped =
            RoleAssignment::from_accepted_invitation(&accepted, &admin_role(), &bob, sender());
        let stranger = RoleAssignment::from_accepted_invitation(
            &accepted,
            &viewer,
            &user(UserId::new(), "mallory@example.com"),
            sender(),
        );

        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert!(matches!(swapped, Err(DomainError::Conflict(_))));
        assert!(matches!(stranger, Err(DomainError::Conflict(_))));
    }

    /// A sign-in provider creates Bob and gives him its default role, which
    /// holds only `billing:read`. He holds it, recorded as given by the
    /// system.
    #[test]
    fn a_provider_gives_the_user_it_creates_its_default_role() {
        let reader = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("billing reader"),
            system_permissions: Vec::new(),
            custom_permissions: vec![CustomPermission::new("billing", "read").unwrap()],
            assignment: DefaultAssignment::Manual,
        });
        let bob = UserId::new();

        let assignment = RoleAssignment::by_provider(bob, &reader).unwrap();

        assert_eq!(*assignment.principal(), PrincipalRef::User(bob));
        assert_eq!(assignment.role_id(), reader.id());
        assert!(matches!(assignment.assigned_by(), ActorRef::System));
    }

    /// Automatic provider assignment rejects a role carrying user and role management.
    #[test]
    fn a_provider_never_gives_a_role_with_built_in_permissions() {
        let result = RoleAssignment::<ResolvedTenant>::by_provider(UserId::new(), &admin_role());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A provider gives Bob a role carrying only the metrics overview, as
    /// the Member role does: it gives no power, so it is given.
    #[test]
    fn a_provider_gives_a_role_carrying_only_the_metrics_overview() {
        let member = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("member"),
            system_permissions: vec![SystemPermission::ViewMetrics],
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });

        let assignment = RoleAssignment::by_provider(UserId::new(), &member);

        assert!(assignment.is_ok());
    }

    /// A manually assigned admin role cannot be granted through default assignment.
    #[test]
    fn a_manual_role_is_not_assigned_by_default() {
        let result = RoleAssignment::<ResolvedTenant>::by_default(
            PrincipalRef::User(UserId::new()),
            &admin_role(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The label a role event links `key` under.
    fn label_at(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("{key} is not a reference: {other:?}"),
        }
    }

    /// Ann gives Carol the admin role. The assignment is raised, naming
    /// Carol by the label she is known by and the role by its name, with no
    /// granter label.
    #[test]
    fn assigning_raises_authorization_role_assigned() {
        let mut assignment = RoleAssignment::<ResolvedTenant>::assign_until(
            NewHolding::standing(
                PrincipalRef::User(UserId::new()),
                EventLabel::of("Carol (carol@acme.test)"),
            ),
            &admin_role(),
            signed_in_owner(),
        )
        .unwrap();

        let events = raised(&mut assignment);

        assert_eq!(
            events[0].event_type().to_string(),
            "authorization.role_assigned"
        );
        assert_eq!(label_at(&events[0], "holder"), "Carol (carol@acme.test)");
        assert_eq!(label_at(&events[0], "role"), "admin");
    }

    /// An assignment made for another context's own record, as a sign-in
    /// provider or a workflow makes one, raises nothing.
    #[test]
    fn creating_an_assignment_raises_nothing() {
        let mut assignment = RoleAssignment::<ResolvedTenant>::create(
            PrincipalRef::User(UserId::new()),
            &admin_role(),
            signed_in_owner(),
        )
        .unwrap();

        assert!(raised_names(&mut assignment).is_empty());
    }

    /// Bob accepts Ann's invitation as a viewer. The assignment is raised,
    /// naming Bob and Ann, the sender, as the one who granted it.
    #[test]
    fn an_accepted_invitation_raises_the_role_given_by_its_sender() {
        let viewer = viewer_role();
        let bob = bob();
        let invited = invitation(
            &viewer,
            &bob,
            OfferState::Accepted {
                at: crate::shared::clock::now(),
            },
        );

        let mut assignment = RoleAssignment::from_accepted_invitation(
            &invited,
            &viewer,
            &bob,
            EventLabel::of("Ann"),
        )
        .unwrap();
        let events = raised(&mut assignment);

        assert_eq!(label_at(&events[0], "holder"), bob.label().as_str());
        assert_eq!(label_at(&events[0], "granted_by"), "Ann");
    }

    /// An owner takes the admin role from Ann. The revocation is raised,
    /// naming Ann and the role.
    #[test]
    fn revoking_raises_authorization_role_revoked() {
        let admin = admin_role();
        let mut ann = RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id: *admin.id(),
            assigned_by: ActorRef::System,
            assigned_at: crate::shared::clock::now(),
            expires: Expiry::Never,
        })
        .unwrap();

        ann.revoke(&admin, &owner(), EventLabel::of("ann@acme.test"))
            .unwrap();
        let events = raised(&mut ann);

        assert_eq!(
            events[0].event_type().to_string(),
            "authorization.role_revoked"
        );
        assert_eq!(label_at(&events[0], "holder"), "ann@acme.test");
        assert_eq!(label_at(&events[0], "role"), "admin");
    }

    /// A user viewer cannot revoke Ann's admin role, and the refused attempt raises no event.
    #[test]
    fn a_refused_revoke_raises_nothing() {
        let admin = admin_role();
        let mut ann = RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id: *admin.id(),
            assigned_by: ActorRef::System,
            assigned_at: crate::shared::clock::now(),
            expires: Expiry::Never,
        })
        .unwrap();
        let sam = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);

        let result = ann.revoke(&admin, &sam, EventLabel::of("ann@acme.test"));

        assert!(result.is_err());
        assert!(raised_names(&mut ann).is_empty());
    }

    /// A review naming Bob's viewer role cannot revoke Ann's admin role or raise
    /// an event for it. Bob's matching assignment raises a revocation event.
    #[test]
    fn a_review_withdraws_only_the_role_it_covered_from_whom_it_named() {
        let (admin, viewer) = (admin_role(), viewer_role());
        let given = |role: &Role<ResolvedTenant>| {
            RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
                principal: PrincipalRef::User(UserId::new()),
                role_id: *role.id(),
                assigned_by: ActorRef::System,
                assigned_at: crate::shared::clock::now(),
                expires: Expiry::Never,
            })
            .unwrap()
        };
        let (mut anns_admin, mut bobs_viewer) = (given(&admin), given(&viewer));
        let removals = ReviewRemovals::of(
            crate::types::AccessReviewId::new(),
            ReviewScope::Role(*viewer.id()),
            vec![*bobs_viewer.principal()],
        );

        let refused = anns_admin.withdraw_by_review(&admin, &removals, EventLabel::of("ann"));
        bobs_viewer
            .withdraw_by_review(&viewer, &removals, EventLabel::of("bob"))
            .unwrap();

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut anns_admin).is_empty());
        assert_eq!(
            raised_names(&mut bobs_viewer),
            ["authorization.role_revoked"]
        );
    }

    /// Ann's admin role is read back from storage. Reading it raises
    /// nothing.
    #[test]
    fn an_assignment_read_back_from_storage_has_raised_nothing() {
        let mut ann = RoleAssignment::<ResolvedTenant>::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(UserId::new()),
            role_id: RoleId::new(),
            assigned_by: ActorRef::System,
            assigned_at: crate::shared::clock::now(),
            expires: Expiry::Never,
        })
        .unwrap();

        assert!(raised_names(&mut ann).is_empty());
    }
}
