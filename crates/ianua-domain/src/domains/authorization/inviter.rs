//! What the person who sent an invitation holds when it is accepted,
//! worked out from the tenant's records.
//!
//! Accepting an invitation gives its role. Sam invited Bob as an editor,
//! then lost his rights. Checked against what Sam held when he sent it, or
//! against a list the use case wrote, Bob would still gain the role. So
//! what Sam holds is worked out here, at the moment Bob accepts.

use crate::domains::authorization::authority::{Holdings, TenantAccess};
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::role::Role;
use crate::domains::identity::account::user::User;
use crate::domains::identity::invitations::invited_role::{CurrentInviter, InvitedRole};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, PrincipalRef, RoleId};

/// The person who sent an invitation, with what they hold in its tenant
/// now.
///
/// Only [`InviterNow::tenant_user`] makes one for a user of the tenant, and
/// the organization for one of its members. Its fields are private, so no
/// caller adds a right to it, or moves it to another sender.
#[derive(Debug)]
pub struct InviterNow {
    inviter: ActorRef,
    held: Holdings,
}

impl InviterNow {
    /// `inviter`, a user of the tenant `access` was read from, with the
    /// rights their roles and groups give them there now.
    ///
    /// What a break-glass grant adds is for the emergency, not for handing
    /// on, so it does not count. An inviter whose account may no longer
    /// sign in holds nothing: Sam was switched off after inviting Mallory's
    /// second mailbox as an admin, and the invitation must die with him.
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists, for records that
    ///   name a role or group that is not there.
    ///
    /// [`TenantGrants::administrators`]: crate::domains::authorization::stewardship::TenantGrants::administrators
    pub fn tenant_user<T: TenantScope>(
        access: &TenantAccess<'_, T>,
        inviter: &User<T>,
    ) -> Result<Self, DomainError> {
        let sender = ActorRef::User(*inviter.id());
        if !inviter.can_authenticate() {
            return Ok(Self::holding(sender, Holdings::default()));
        }
        let held = access.standing_of(PrincipalRef::User(*inviter.id()))?;
        Ok(Self::holding(sender, held))
    }

    /// `inviter`, holding `held` in the tenant now, as this crate worked it
    /// out from the records. The organization makes one this way for a
    /// member who sent an invitation.
    pub(crate) fn holding(inviter: ActorRef, held: Holdings) -> Self {
        Self { inviter, held }
    }

    /// `inviter`, holding `system`, as a test says, without the records
    /// behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(
        inviter: ActorRef,
        system: &[crate::domains::authorization::permission::SystemPermission],
    ) -> Self {
        Self::holding(inviter, Holdings::of(system.to_vec(), Vec::new()))
    }

    /// Who sent the invitation.
    #[must_use]
    pub fn inviter(&self) -> &ActorRef {
        &self.inviter
    }

    /// What they hold now, to hand out.
    #[must_use]
    pub fn held(&self) -> HeldByGranter<'_> {
        let handout = self.held.handout();
        HeldByGranter::new(handout.system, handout.custom)
    }
}

impl Sealed for InviterNow {}

impl CurrentInviter for InviterNow {
    fn is_inviter(&self, invited_by: &ActorRef) -> bool {
        match (&self.inviter, invited_by) {
            (ActorRef::User(held), ActorRef::User(sent)) => held == sent,
            (ActorRef::OrgUser(held), ActorRef::OrgUser(sent)) => held == sent,
            _ => false,
        }
    }
}

/// A role offered by an invitation is checked against what its sender
/// holds now, as for the one they hold when they send it.
impl<T: TenantScope> InvitedRole<T, InviterNow> for Role<T> {
    fn invited_role_id(&self) -> RoleId {
        *self.id()
    }

    fn ensure_offered_by(&self, inviter: &InviterNow) -> Result<(), DomainError> {
        <Self as InvitedRole<T, HeldByGranter<'_>>>::ensure_offered_by(self, &inviter.held())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::identity::invitations::invitation::{CreateInvitationParams, Invitation};
    use crate::domains::identity::invitations::route::InvitationRoute;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::test_support::authority::{anyone_holding, user_adder};
    use crate::test_support::builders::{label, user};
    use crate::types::{DisplayName, Email, Lifetime, TenantId, TokenHash, UserId};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const ADD_USERS: SystemPermission = SystemPermission::Users(UserAction::Create);

    fn role_granting(system: &[SystemPermission]) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("team"),
            system_permissions: system.to_vec(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// Acme's records: Sam may view and add users, and the viewer role
    /// lets its holders view them.
    struct Acme {
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
        sam: User<ResolvedTenant>,
    }

    impl Acme {
        fn new() -> Self {
            let mut sam = user(UserId::new(), "sam@acme.test");
            sam.verify_email(&proof_of(sam.email())).unwrap();
            let adder = role_granting(&[VIEW_USERS, ADD_USERS]);
            let given = RoleAssignment::create(
                PrincipalRef::User(*sam.id()),
                &adder,
                anyone_holding(SystemPermission::all()),
            )
            .unwrap();
            Self {
                roles: vec![adder, role_granting(&[VIEW_USERS])],
                assignments: vec![given],
                sam,
            }
        }

        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: TenantId::new(),
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &[],
                break_glass: &[],
            }
        }

        fn viewer(&self) -> &Role<ResolvedTenant> {
            &self.roles[1]
        }

        /// Bob's invited account, and Sam's invitation to it as a viewer.
        fn bob_invited_by_sam(&self) -> (User<ResolvedTenant>, Invitation<ResolvedTenant>) {
            let bob = User::invite(
                UserId::new(),
                Email::new("bob@acme.test").unwrap(),
                DisplayName::new("Bob", &DisplayNameLimits::default()).unwrap(),
                &user_adder(),
            )
            .unwrap();
            let invitation = Invitation::create(
                CreateInvitationParams {
                    user_id: *bob.id(),
                    email: bob.email().clone(),
                    invited_by: ActorRef::User(*self.sam.id()),
                    token_hash: TokenHash::from_stored("invite".to_owned()),
                    message: None,
                    lifetime: Lifetime::seconds(3600).unwrap(),
                },
                self.viewer(),
                &self.sam_now(),
            )
            .unwrap();
            (bob, invitation)
        }

        fn sam_now(&self) -> InviterNow {
            InviterNow::tenant_user(&self.access(), &self.sam).unwrap()
        }
    }

    /// Sam may add users and invited Bob as a viewer. Bob accepts, and the
    /// role is checked against what Sam holds now, from Acme's records.
    #[test]
    fn an_invitation_is_accepted_against_what_its_sender_holds_now() {
        let acme = Acme::new();
        let (mut bob, mut invitation) = acme.bob_invited_by_sam();

        invitation
            .accept(
                &mut bob,
                acme.viewer(),
                &acme.sam_now(),
                InvitationRoute::Mailed,
            )
            .unwrap();

        assert_eq!(bob.status(), UserStatus::Active);
    }

    /// Locking Sam after he invites Bob prevents acceptance, leaving Bob's
    /// account invited.
    #[test]
    fn an_inviter_who_was_shut_out_hands_out_nothing() {
        let mut acme = Acme::new();
        let (mut bob, mut invitation) = acme.bob_invited_by_sam();
        let control = control_over(&acme.sam);
        acme.sam.lock(&control).unwrap();

        let result = invitation.accept(
            &mut bob,
            acme.viewer(),
            &acme.sam_now(),
            InvitationRoute::Mailed,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(bob.status(), UserStatus::Invited);
    }

    /// Another admin's rights cannot authorize acceptance of Sam's invitation;
    /// Bob's account remains invited.
    #[test]
    fn what_someone_else_holds_accepts_no_invitation() {
        let acme = Acme::new();
        let (mut bob, mut invitation) = acme.bob_invited_by_sam();
        let ann = InviterNow::assumed(ActorRef::User(UserId::new()), SystemPermission::all());

        let result = invitation.accept(&mut bob, acme.viewer(), &ann, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(bob.status(), UserStatus::Invited);
    }
}
