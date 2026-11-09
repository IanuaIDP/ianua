use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::user_status::UserStatus;
use crate::domains::identity::events::invitations::{
    InvitationAccepted, InvitationDeclined, InvitationExpired, InvitationResent, InvitationRevoked,
};
use crate::domains::identity::invitations::invited_role::{CurrentInviter, InvitedRole};
use crate::domains::identity::invitations::offer::{InvitationOffer, OfferRow, OfferState};
use crate::domains::identity::invitations::route::InvitationRoute;
use crate::domains::identity::invitations::status::{InvitationLifecycle, InvitationStatus};
use crate::domains::identity::tokens::renewal::RenewedLink;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{ActorRef, Email, InvitationId, Lifetime, RoleId, Text, TokenHash, UserId};

/// The longest an invitation's link may live.
///
/// A link that lives for months is a way into the tenant lying in a mailbox
/// for months.
pub(crate) const MAX_INVITATION_LIFETIME: time::Duration = time::Duration::days(30);

/// An invitation to join a tenant, sent to an email address.
///
/// It belongs to an invited user account that waits to join. The email
/// holds a link with a single-use token. Following it accepts the
/// invitation for that account.
///
/// It is read and written only through stores opened for its tenant. See
/// [`crate::isolation`].
#[derive(Debug)]
pub struct Invitation<T: TenantScope> {
    id: InvitationId,
    user_id: UserId,
    email: Email,
    invited_by: ActorRef,
    role_id: RoleId,
    offer: InvitationOffer,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a new invitation is made from.
pub struct CreateInvitationParams {
    /// The invited user account this invitation belongs to.
    ///
    /// It stays the same, while the email can change after the invitation
    /// is sent.
    pub user_id: UserId,
    /// The email address to invite.
    pub email: Email,
    /// Who sent the invitation: a tenant user or an org admin.
    pub invited_by: ActorRef,
    /// The hash of the link's token. The raw token goes to the invitee.
    pub token_hash: TokenHash,
    /// A personal message for the invitation email, when given.
    pub message: Option<Text>,
    /// How long the link works from now, at most
    /// `MAX_INVITATION_LIFETIME`.
    pub lifetime: Lifetime,
}

/// An invitation as storage keeps it, checked again by
/// [`Invitation::reconstitute`].
pub struct InvitationRow {
    /// The invitation's id.
    pub id: InvitationId,
    /// The invited user account this invitation belongs to.
    pub user_id: UserId,
    /// The email address that was invited.
    pub email: Email,
    /// Who sent the invitation.
    pub invited_by: ActorRef,
    /// The role given when it is accepted.
    pub role_id: RoleId,
    /// The hash of the link's token.
    pub token_hash: TokenHash,
    /// Where the invitation stands. See [`OfferState::from_stored`].
    pub state: OfferState,
    /// The personal message, when given.
    pub message: Option<Text>,
    /// When the invitation expires.
    pub expires_at: OffsetDateTime,
    /// When the invitation was created.
    pub created_at: OffsetDateTime,
}

impl<T: TenantScope> Invitation<T> {
    /// Creates a pending invitation that gives `role` when accepted.
    ///
    /// Whoever accepts gains all the role grants. So `granter`, which is
    /// what the inviter holds, must be able to hand out all of it, as in
    /// [`RoleAssignment::create`](crate::domains::authorization::role::RoleAssignment::create).
    /// Sam may view users. Without this check, Sam invites a second mailbox
    /// of his own with the admin role, accepts and holds it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `granter` may not create users.
    /// - [`DomainError::Forbidden`] when `granter` may not hand out everything
    ///   the role grants.
    /// - [`DomainError::Validation`] when the lifetime is longer than
    ///   `MAX_INVITATION_LIFETIME`.
    pub fn create<G>(
        params: CreateInvitationParams,
        role: &impl InvitedRole<T, G>,
        granter: &G,
    ) -> Result<Self, DomainError> {
        role.ensure_offered_by(granter)?;
        params
            .lifetime
            .ensure_at_most(MAX_INVITATION_LIFETIME, "an invitation")?;
        let now = crate::shared::clock::now();
        let expires_at = params.lifetime.ends_after(now);
        Ok(Self {
            id: InvitationId::new(),
            user_id: params.user_id,
            email: params.email,
            invited_by: params.invited_by,
            role_id: role.invited_role_id(),
            offer: InvitationOffer::open(params.token_hash, params.message, expires_at),
            created_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds an invitation from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the invitation was
    ///   accepted before it was sent, or once its link had run out.
    pub fn reconstitute(row: InvitationRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            email: row.email,
            invited_by: row.invited_by,
            role_id: row.role_id,
            offer: InvitationOffer::reconstitute(OfferRow {
                token_hash: row.token_hash,
                state: row.state,
                message: row.message,
                expires_at: row.expires_at,
            })?,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &InvitationRow) -> Result<(), DomainError> {
        RowCheck::of("invitation")
            .in_order_if(
                row.created_at,
                row.state.accepted_at(),
                "accepted before it was sent",
            )
            .finish()
    }

    /// The invitation's id.
    #[must_use]
    pub fn id(&self) -> &InvitationId {
        &self.id
    }

    /// The invited user account this invitation belongs to.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The email address that was invited.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// Who sent the invitation.
    #[must_use]
    pub fn invited_by(&self) -> &ActorRef {
        &self.invited_by
    }

    /// The role given when the invitation is accepted.
    #[must_use]
    pub fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// The hash a presented link token is checked against.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        self.offer.token_hash()
    }

    /// The status as stored.
    #[must_use]
    pub fn status(&self) -> InvitationStatus {
        self.offer.status()
    }

    /// The personal message, when given.
    #[must_use]
    pub fn message(&self) -> Option<&Text> {
        self.offer.message()
    }

    /// When the invitation expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.offer.expires_at()
    }

    /// When the invitation was accepted, if at all.
    #[must_use]
    pub fn accepted_at(&self) -> Option<OffsetDateTime> {
        self.offer.accepted_at()
    }

    /// When the invitation was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether this invitation can still be accepted at `now`.
    #[must_use]
    pub fn is_pending(&self, now: OffsetDateTime) -> bool {
        self.offer.is_pending(now)
    }

    /// What following this invitation's link at `now` gets you.
    #[must_use]
    pub fn state(&self, now: OffsetDateTime) -> InvitationLifecycle {
        self.offer.state(now)
    }

    /// Marks the invitation as accepted by `invitee`, and lets the invitee's
    /// account in.
    ///
    /// The account becomes active. Its address is verified when the link
    /// reached the invitee by `route` [`InvitationRoute::Mailed`]: it was
    /// mailed there, so whoever followed it holds that mailbox. A link
    /// handed to the inviter on a deployment with no mail server proves no
    /// mailbox, and the address stays as it was. This is the invitee's own
    /// way in. An admin letting an account in uses [`User::activate`],
    /// which checks who acts.
    ///
    /// Only the account it was sent for may accept it. That account must
    /// still have the invited address and still wait to join. Say Ann's
    /// address changes after the invite. Without the address check, whoever
    /// reads her old mailbox would get her account. A deactivated account
    /// is not switched back on by an old link either.
    ///
    /// The role is checked again against what the inviter holds now,
    /// `inviter`, worked out from the tenant's records for the person who
    /// sent it. Sam invited Bob as an editor, then lost his rights, or the
    /// editor role was given the right to manage roles. Without this, Bob
    /// would still gain the role as it stands today.
    ///
    /// Raises `identity.invitation_accepted`, and the invitee raises
    /// `identity.user_status_changed` on becoming active.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Conflict`] for a different role, an invitee not waiting
    /// to join, or an expired link; [`DomainError::Forbidden`] for a different sender,
    /// insufficient current grant rights, or a different invitee account or address;
    /// or [`DomainError::InvalidTransition`] unless pending.
    pub fn accept<G: CurrentInviter>(
        &mut self,
        invitee: &mut User<T>,
        role: &impl InvitedRole<T, G>,
        inviter: &G,
        route: InvitationRoute,
    ) -> Result<(), DomainError> {
        if role.invited_role_id() != self.role_id {
            return Err(DomainError::conflict(message!(
                "identity-this-is-not-the-role-the",
                "this is not the role the invitation offers"
            )));
        }
        if !inviter.is_inviter(&self.invited_by) {
            return Err(DomainError::forbidden(message!(
                "identity-what-the-inviter-holds-was-worked",
                "what the inviter holds was worked out for someone else"
            )));
        }
        role.ensure_offered_by(inviter)?;
        self.ensure_still_for(invitee)?;
        if invitee.status() != UserStatus::Invited {
            return Err(DomainError::conflict(message!(
                "identity-the-invited-account-is-no-longer",
                "the invited account is no longer waiting to join"
            )));
        }
        self.offer.accept()?;
        invitee.join_by_invitation(&route.accepted_address(self.email.clone()))?;
        self.raised.raise(InvitationAccepted {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `invitee` unless the invitation was sent for it, to the
    /// address it still has.
    fn ensure_still_for(&self, invitee: &User<T>) -> Result<(), DomainError> {
        self.ensure_sent_for(invitee)?;
        if *invitee.email() != self.email {
            return Err(DomainError::forbidden(message!(
                "identity-the-invitation-was-sent-to-an",
                "the invitation was sent to an address the account no longer has"
            )));
        }
        Ok(())
    }

    /// Withdraws the invitation sent for `invitee` before it is accepted,
    /// as `control` allows. Raises `identity.invitation_revoked`, naming
    /// the invitee by name and address.
    ///
    /// Withdrawing it shuts the invited account out, so it needs what
    /// shutting out another account needs.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `invitee` is another account.
    /// - [`DomainError::Forbidden`] when `control` refuses shutting out the
    ///   invited account.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn revoke(
        &mut self,
        invitee: &User<T>,
        control: &impl AccountControlCheck,
    ) -> Result<(), DomainError> {
        self.ensure_sent_for(invitee)?;
        control.ensure_allowed(&self.user_id, AccountAction::ShutOut)?;
        self.offer.revoke()?;
        self.raised.raise(InvitationRevoked {
            user_id: self.user_id,
            user_label: invitee.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Marks the invitation expired once its link has run out at `now`.
    ///
    /// A link past its expiry already does nothing. Marking it says so on
    /// the record, so the invited account can be closed.
    ///
    /// Raises `identity.invitation_expired` at `now`, naming `invitee`, the
    /// account it was sent for, by name and address.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `invitee` is another account.
    /// - [`DomainError::Conflict`] when the link has not run out yet.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn lapse(&mut self, invitee: &User<T>, now: OffsetDateTime) -> Result<(), DomainError> {
        self.ensure_sent_for(invitee)?;
        self.offer.lapse(now)?;
        self.raised.raise(InvitationExpired {
            user_id: self.user_id,
            user_label: invitee.label(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Closes `invitee`'s account once this invitation ended without being
    /// accepted: it expired, was declined or was revoked.
    ///
    /// An account nobody claimed would otherwise wait in the user list as
    /// invited for good. It is deactivated, so its history stays and an
    /// admin may still let it in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `invitee` is another account.
    /// - [`DomainError::Conflict`] when the invitation is still pending, or
    ///   was accepted.
    pub fn close_unanswered(&self, invitee: &mut User<T>) -> Result<(), DomainError> {
        self.ensure_sent_for(invitee)?;
        match self.status() {
            InvitationStatus::Expired | InvitationStatus::Declined | InvitationStatus::Revoked => {
                Ok(invitee.close_unanswered_invite()?)
            }
            InvitationStatus::Pending | InvitationStatus::Accepted => {
                Err(DomainError::conflict(message!(
                    "identity-only-an-invitation-nobody-accepted-closes",
                    "only an invitation nobody accepted closes its account"
                )))
            }
        }
    }

    /// Turns the invitation down, for the invitee who followed its link.
    /// Raises `identity.invitation_declined`, naming the invitee by name and
    /// address.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `invitee` is another account, or
    ///   has moved off the invited address.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn decline(&mut self, invitee: &User<T>) -> Result<(), DomainError> {
        self.ensure_still_for(invitee)?;
        self.offer.decline()?;
        self.raised.raise(InvitationDeclined {
            user_id: self.user_id,
            user_label: invitee.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Replaces the pending invitation's token and expiry for a resend to its current invitee.
    /// Raises `identity.invitation_resent`, naming the invitee and address.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without invitation rights, for another invitee or a changed address.
    /// [`DomainError::Validation`] for a lifetime above `MAX_INVITATION_LIFETIME`.
    /// [`DomainError::InvalidTransition`] unless pending.
    pub fn rotate_token(
        &mut self,
        invitee: &User<T>,
        by: &impl AccountCreator<T>,
        new_token_hash: TokenHash,
        new_lifetime: Lifetime,
    ) -> Result<(), DomainError> {
        by.ensure_may_open(AccountOpening::Invitation)?;
        self.ensure_still_for(invitee)?;
        new_lifetime.ensure_at_most(MAX_INVITATION_LIFETIME, "an invitation")?;
        let expires_at = new_lifetime.ends_after(crate::shared::clock::now());
        self.offer.rotate_token(new_token_hash, expires_at)?;
        self.resent(invitee);
        Ok(())
    }

    /// Sends the invitation again from its own link, which ran out before
    /// `invitee` followed it. Raises `identity.invitation_resent`, as
    /// [`rotate_token`](Self::rotate_token) does.
    ///
    /// Ann opens her invitation a week late. The page offers her a new link
    /// instead of sending her to an admin. Nobody in the tenant decides
    /// this, so the invitation must stand as it was sent: the dead link is
    /// its own, nobody withdrew it, and the account still waits to join at
    /// the invited address without having changed how it signs in. The new
    /// link goes to that same address, so only its mailbox gains anything.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] for a different link, account or address;
    /// [`DomainError::Conflict`] if the invitee no longer waits to join, changed sign-in
    /// credentials since sending, or the link still works; [`DomainError::Validation`]
    /// for a lifetime beyond `MAX_INVITATION_LIFETIME`; or
    /// [`DomainError::InvalidTransition`] if accepted, declined, revoked or marked expired.
    pub fn renew_from_link(
        &mut self,
        invitee: &User<T>,
        presented: &TokenHash,
        renewed: RenewedLink,
    ) -> Result<(), DomainError> {
        if presented != self.offer.token_hash() {
            return Err(DomainError::forbidden(message!(
                "identity-the-link-is-not-this-invitation",
                "the link is not this invitation's"
            )));
        }
        self.ensure_still_for(invitee)?;
        self.ensure_unchanged_since_sent(invitee)?;
        let now = crate::shared::clock::now();
        if self.offer.state(now) == InvitationLifecycle::Pending {
            return Err(DomainError::conflict(message!(
                "identity-the-invitation-s-link-still-works",
                "the invitation's link still works"
            )));
        }
        renewed
            .lifetime
            .ensure_at_most(MAX_INVITATION_LIFETIME, "an invitation")?;
        let expires_at = renewed.lifetime.ends_after(now);
        self.offer.rotate_token(renewed.token_hash, expires_at)?;
        self.resent(invitee);
        Ok(())
    }

    /// Raises the invitation going out again to `invitee`.
    fn resent(&mut self, invitee: &User<T>) {
        self.raised.raise(InvitationResent {
            user_id: self.user_id,
            user_label: invitee.label(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Refuses `invitee` unless the invitation was sent for that account.
    fn ensure_sent_for(&self, invitee: &User<T>) -> Result<(), DomainError> {
        if *invitee.id() != self.user_id {
            return Err(DomainError::forbidden(message!(
                "identity-the-invitation-is-for-another-account",
                "the invitation is for another account"
            )));
        }
        Ok(())
    }

    /// Refuses `invitee` once it stopped waiting to join, or changed how it
    /// signs in after the invitation was sent.
    fn ensure_unchanged_since_sent(&self, invitee: &User<T>) -> Result<(), DomainError> {
        if invitee.status() != UserStatus::Invited {
            return Err(DomainError::conflict(message!(
                "identity-the-invited-account-is-no-longer",
                "the invited account is no longer waiting to join"
            )));
        }
        if invitee.credentials_changed_at().since(self.created_at) {
            return Err(DomainError::conflict(message!(
                "identity-the-invited-account-changed-how-it",
                "the invited account changed how it signs in since it was invited"
            )));
        }
        Ok(())
    }
}

impl<T: TenantScope> Raises for Invitation<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::authorization::granter::{AccountControl, Handout, HeldByGranter};
    use crate::domains::authorization::inviter::InviterNow;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::identity::account::vouching::Vouching;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::CredentialChange;

    fn text(s: &str) -> Text {
        Text::new("message", s).unwrap()
    }

    /// The id of the role every test invitation offers.
    const OFFERED: uuid::Uuid = uuid::Uuid::from_u128(7);

    fn role_granting(system: &[SystemPermission]) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::from_uuid(OFFERED),
            name: label("Invited role"),
            system_permissions: system.to_vec(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// What Sam may do: view and add users.
    const SAMS_RIGHTS: [SystemPermission; 2] = [
        SystemPermission::Users(UserAction::View),
        SystemPermission::Users(UserAction::Create),
    ];

    /// Sam, who may view and add users.
    fn sam() -> HeldByGranter<'static> {
        HeldByGranter::assumed(&SAMS_RIGHTS, &[])
    }

    /// Sam, who sends every test invitation.
    fn sams_account() -> ActorRef {
        ActorRef::User(UserId::from_uuid(uuid::Uuid::from_u128(5)))
    }

    /// What Sam holds when an invitation he sent is accepted.
    fn sam_now() -> InviterNow {
        InviterNow::assumed(sams_account(), &SAMS_RIGHTS)
    }

    fn params_for(invitee: &User<ResolvedTenant>) -> CreateInvitationParams {
        CreateInvitationParams {
            user_id: *invitee.id(),
            email: invitee.email().clone(),
            invited_by: sams_account(),
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            message: None,
            lifetime: week(),
        }
    }

    fn week() -> Lifetime {
        Lifetime::new(Duration::days(7)).unwrap()
    }

    fn viewer() -> Role<ResolvedTenant> {
        role_granting(&[SystemPermission::Users(UserAction::View)])
    }

    fn invitation_for(invitee: &User<ResolvedTenant>) -> Invitation<ResolvedTenant> {
        let params = CreateInvitationParams {
            message: Some(text("Welcome to Acme!")),
            ..params_for(invitee)
        };
        Invitation::create(params, &viewer(), &sam()).unwrap()
    }

    /// `invitee` accepts the mailed link, with the viewer role and what Sam
    /// holds now.
    fn accept(
        inv: &mut Invitation<ResolvedTenant>,
        invitee: &mut User<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        inv.accept(invitee, &viewer(), &sam_now(), InvitationRoute::Mailed)
    }

    /// Alice accepts the invitation Sam mailed her. She is in, and her
    /// address is verified: following the link proved her mailbox.
    #[test]
    fn a_mailed_invitation_proves_the_address() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        accept(&mut inv, &mut alice).unwrap();

        assert_eq!(alice.status(), UserStatus::Active);
        assert!(alice.email_verified());
    }

    /// Accepting a handed-over invitation activates Alice's account while leaving
    /// its email address unverified because the link did not prove mailbox access.
    #[test]
    fn a_handed_over_invitation_leaves_the_address_unverified() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        inv.accept(
            &mut alice,
            &viewer(),
            &sam_now(),
            InvitationRoute::HandedOver,
        )
        .unwrap();

        assert_eq!(alice.status(), UserStatus::Active);
        assert!(!alice.email_verified());
    }

    /// Alice accepts the link Sam handed her. The invitation vouches for
    /// her first sign-in, and that sign-in spends it.
    #[test]
    fn accepting_vouches_for_the_first_sign_in_only() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        assert_eq!(alice.vouching(), Vouching::Absent);

        inv.accept(
            &mut alice,
            &viewer(),
            &sam_now(),
            InvitationRoute::HandedOver,
        )
        .unwrap();
        assert_eq!(alice.vouching(), Vouching::Fresh);

        alice.record_login();
        assert_eq!(alice.vouching(), Vouching::Absent);
    }

    fn invitee() -> User<ResolvedTenant> {
        User::invite(
            UserId::new(),
            Email::new("alice@example.com").unwrap(),
            crate::types::DisplayName::new(
                "Alice",
                &crate::shared::config::DisplayNameLimits::default(),
            )
            .unwrap(),
            &sam(),
        )
        .unwrap()
    }

    fn test_invitation() -> Invitation<ResolvedTenant> {
        invitation_for(&invitee())
    }

    /// Alice is invited with the message "Welcome to Acme!". The invitation
    /// is pending, not accepted, and keeps the message.
    #[test]
    fn create_pending_invitation() {
        let inv = test_invitation();

        assert_eq!(inv.status(), InvitationStatus::Pending);
        assert!(inv.is_pending(crate::shared::clock::now()));
        assert!(inv.accepted_at().is_none());
        assert_eq!(inv.message().map(Text::as_str), Some("Welcome to Acme!"));
    }

    /// Alice accepts her invitation. Its link is closed afterwards.
    #[test]
    fn accepting_closes_the_invitation() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        accept(&mut inv, &mut alice).unwrap();

        assert_eq!(
            inv.state(crate::shared::clock::now()),
            InvitationLifecycle::Closed
        );
    }

    /// Alice accepts her invitation. Her account becomes active with a join
    /// time, and the address it was mailed to is verified, since following
    /// the link shows she reads that mailbox.
    #[test]
    fn accepting_lets_the_invitee_in_with_the_invited_address_proven() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        accept(&mut inv, &mut alice).unwrap();

        assert_eq!(alice.status(), UserStatus::Active);
        assert!(alice.joined_at().is_some());
        assert_eq!(alice.email(), inv.email());
        assert!(alice.email_verified());
    }

    /// Alice cannot accept an invitation sent before her address changed. The
    /// invitation remains pending and her account remains invited.
    #[test]
    fn a_link_to_an_address_the_account_has_left_is_refused() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        alice
            .change_email(
                Email::new("alice@new.example").unwrap(),
                &control_over(&alice),
            )
            .unwrap();

        let result = accept(&mut inv, &mut alice);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(inv.status(), InvitationStatus::Pending);
        assert_eq!(alice.status(), UserStatus::Invited);
    }

    /// Alice's invitation cannot activate another account with the same address;
    /// that account remains invited.
    #[test]
    fn a_link_is_refused_for_another_account() {
        let mut inv = invitation_for(&invitee());
        let mut mallory = invitee();

        let result = accept(&mut inv, &mut mallory);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(mallory.status(), UserStatus::Invited);
    }

    /// Alice's old invitation cannot reactivate her deactivated account. The
    /// invitation remains pending and the account remains deactivated.
    #[test]
    fn a_link_does_not_bring_back_a_deactivated_account() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        alice.deactivate(&control_over(&alice)).unwrap();

        let result = accept(&mut inv, &mut alice);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(inv.status(), InvitationStatus::Pending);
        assert_eq!(alice.status(), UserStatus::Deactivated);
    }

    /// An invitation cannot be resent after Alice leaves the invited address.
    #[test]
    fn a_link_is_not_resent_to_an_address_the_account_has_left() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        alice
            .change_email(
                Email::new("alice@new.example").unwrap(),
                &control_over(&alice),
            )
            .unwrap();

        let result = inv.rotate_token(
            &alice,
            &sam(),
            TokenHash::from_stored("fresh".to_owned()),
            week(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Rita's view-only rights cannot renew Alice's invitation, and its token
    /// stays unchanged. Sam's right to add users allows the resend.
    #[test]
    fn only_someone_who_may_invite_sends_an_invitation_again() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);
        let rita = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);
        let fresh = || TokenHash::from_stored("fresh".to_owned());

        let by_rita = inv.rotate_token(&alice, &rita, fresh(), week());
        let unchanged = inv.token_hash().clone();
        let by_sam = inv.rotate_token(&alice, &sam(), fresh(), week());

        assert!(matches!(by_rita, Err(DomainError::Forbidden(_))));
        assert_eq!(unchanged, TokenHash::from_stored("hashed_token".to_owned()));
        assert!(by_sam.is_ok());
    }

    /// An invitation keeps the user and the role it was made with, and gets
    /// its own id. A nil role would let the person in with no access, or with
    /// whatever a nil id points at.
    #[test]
    fn an_invitation_names_the_user_and_the_role_it_grants() {
        let alice = invitee();
        let viewer = role_granting(&[SystemPermission::Users(UserAction::View)]);

        let invitation =
            Invitation::<ResolvedTenant>::create(params_for(&alice), &viewer, &sam()).unwrap();

        assert_eq!(invitation.user_id(), alice.id());
        assert_eq!(invitation.role_id(), viewer.id());
        assert!(!invitation.id().as_uuid().is_nil());
        assert!(invitation.message().is_none());
    }

    /// Sam cannot invite someone with a user-management role beyond his own rights.
    #[test]
    fn an_invitation_to_a_role_the_inviter_may_not_hand_out_is_refused() {
        let mallory = invitee();
        let manager = role_granting(&[SystemPermission::ManageUsers]);

        let result = Invitation::<ResolvedTenant>::create(params_for(&mallory), &manager, &sam());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Rita cannot invite Alice even as a viewer without permission to add users.
    #[test]
    fn inviting_needs_the_right_to_add_people() {
        let alice = invitee();
        let rita = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);

        let result = Invitation::<ResolvedTenant>::create(params_for(&alice), &viewer(), &rita);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Alice cannot accept after Sam loses the rights needed to grant her role;
    /// her account remains invited.
    #[test]
    fn accepting_checks_the_role_against_the_inviter_now() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        let sam_now = InviterNow::assumed(sams_account(), &[]);

        let result = inv.accept(&mut alice, &viewer(), &sam_now, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(alice.status(), UserStatus::Invited);
    }

    /// Accepting Alice's invitation with a different role is a conflict.
    #[test]
    fn accepting_with_another_role_is_refused() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        let other = Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("Other role"),
            system_permissions: Vec::new(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });

        let result = inv.accept(&mut alice, &other, &sam_now(), InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// Another admin's rights cannot substitute for the sender's when Alice
    /// accepts; her account remains invited.
    #[test]
    fn accepting_is_checked_against_the_sender_only() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        let ann = InviterNow::assumed(ActorRef::User(UserId::new()), SystemPermission::all());

        let result = inv.accept(&mut alice, &viewer(), &ann, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(alice.status(), UserStatus::Invited);
    }

    /// Alice turns the invitation down from its link. It is declined and
    /// can no longer be accepted.
    #[test]
    fn an_invitee_declines_from_the_link() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        inv.decline(&alice).unwrap();

        assert_eq!(inv.status(), InvitationStatus::Declined);
        assert!(accept(&mut inv, &mut alice).is_err());
    }

    /// A sixty-day invitation exceeds the thirty-day maximum and is rejected.
    #[test]
    fn an_invitation_lives_at_most_thirty_days() {
        let alice = invitee();
        let params = CreateInvitationParams {
            lifetime: Lifetime::new(Duration::days(60)).unwrap(),
            ..params_for(&alice)
        };

        let made = Invitation::create(params, &viewer(), &sam());

        assert!(matches!(made, Err(DomainError::Validation(_))));
    }

    /// An invitation sent for a week runs out a week after it was sent, so
    /// no expiry already past can be given to it.
    #[test]
    fn an_invitation_runs_out_its_lifetime_after_it_was_sent() {
        let inv = test_invitation();

        assert_eq!(inv.expires_at(), inv.created_at() + Duration::days(7));
    }

    /// Sam sends Alice's invitation again for a week. The new link runs out
    /// a week from the resend.
    #[test]
    fn a_resent_link_runs_out_its_lifetime_after_the_resend() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);
        let resent_at = inv.created_at() + Duration::days(1);
        let fresh = TokenHash::from_stored("fresh".to_owned());
        let _later = crate::shared::clock::freeze(resent_at);

        inv.rotate_token(&alice, &sam(), fresh, week()).unwrap();

        assert_eq!(inv.expires_at(), resent_at + Duration::days(7));
    }

    /// A week's new link for a dead one.
    fn renewal() -> RenewedLink {
        RenewedLink {
            token_hash: TokenHash::from_stored("renewed".to_owned()),
            lifetime: week(),
        }
    }

    /// The hash of the link every test invitation is sent with.
    fn sent_link() -> TokenHash {
        TokenHash::from_stored("hashed_token".to_owned())
    }

    /// Alice opens her invitation a day after its link ran out. Her dead
    /// link renews it: a new link for a week, and the invitation pending.
    #[test]
    fn a_dead_link_renews_its_invitation() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);
        let opened_at = inv.expires_at() + Duration::days(1);
        let _later = crate::shared::clock::freeze(opened_at);

        inv.renew_from_link(&alice, &sent_link(), renewal())
            .unwrap();

        assert_eq!(inv.token_hash().as_str(), "renewed");
        assert_eq!(inv.expires_at(), opened_at + Duration::days(7));
        assert!(inv.is_pending(opened_at));
    }

    /// A working invitation link cannot renew itself, and its token stays unchanged.
    #[test]
    fn a_working_link_is_not_renewed() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);

        let result = inv.renew_from_link(&alice, &sent_link(), renewal());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(inv.token_hash(), &sent_link());
    }

    /// A revoked invitation rejects renewal from its expired link.
    #[test]
    fn a_revoked_invitation_is_not_renewed() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);
        inv.revoke(&alice, &control_over(&alice)).unwrap();
        let _later = crate::shared::clock::freeze(inv.expires_at());

        let result = inv.renew_from_link(&alice, &sent_link(), renewal());

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A different token cannot renew Alice's expired invitation.
    #[test]
    fn only_the_invitations_own_link_renews_it() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);
        let _later = crate::shared::clock::freeze(inv.expires_at());

        let result = inv.renew_from_link(
            &alice,
            &TokenHash::from_stored("mallorys".to_owned()),
            renewal(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An expired invitation cannot renew from its link after Alice changes address.
    #[test]
    fn a_dead_link_to_an_address_the_account_has_left_is_not_renewed() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        alice
            .change_email(
                Email::new("alice@new.example").unwrap(),
                &control_over(&alice),
            )
            .unwrap();
        let _later = crate::shared::clock::freeze(inv.expires_at());

        let result = inv.renew_from_link(&alice, &sent_link(), renewal());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An expired invitation cannot renew after Alice's credentials change.
    #[test]
    fn a_dead_link_is_not_renewed_once_the_account_changed_how_it_signs_in() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);
        let _later = crate::shared::clock::freeze(inv.expires_at());
        alice.record_credential_change();

        let result = inv.renew_from_link(&alice, &sent_link(), renewal());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// A stored invitation says it was accepted at the instant its link ran
    /// out. No link is taken up once it runs out, so loading it is refused
    /// as corrupt.
    #[test]
    fn a_stored_invitation_accepted_once_its_link_ran_out_is_refused() {
        let now = crate::shared::clock::now();
        let expires_at = now + Duration::days(7);

        let stored = Invitation::<ResolvedTenant>::reconstitute(InvitationRow {
            id: InvitationId::new(),
            user_id: UserId::new(),
            email: Email::new("alice@example.com").unwrap(),
            invited_by: ActorRef::User(UserId::new()),
            role_id: RoleId::from_uuid(OFFERED),
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            state: OfferState::Accepted { at: expires_at },
            message: None,
            expires_at,
            created_at: now,
        });

        assert!(refused_as_corrupt(&stored));
    }

    /// Bob cannot revoke Alice's invitation without user rights. An admin can
    /// revoke it afterward, leaving the invitation revoked.
    #[test]
    fn revoking_an_invitation_needs_the_right_to_shut_the_account_out() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);
        let bob = AccountControl::assumed(
            anyone_holding(&[]),
            *alice.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        let by_bob = inv.revoke(&alice, &bob);
        let by_admin = inv.revoke(&alice, &control_over(&alice));

        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
        assert!(by_admin.is_ok());
        assert_eq!(inv.status(), InvitationStatus::Revoked);
    }

    /// Alice never answers. Her link runs out, the invitation is marked
    /// expired, and her invited account is closed. Marking it before the
    /// link ran out is refused.
    #[test]
    fn an_unanswered_invitation_expires_and_closes_its_account() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        let too_soon = inv.lapse(&alice, crate::shared::clock::now());
        inv.lapse(&alice, inv.expires_at()).unwrap();
        inv.close_unanswered(&mut alice).unwrap();

        assert!(matches!(too_soon, Err(DomainError::Conflict(_))));
        assert_eq!(inv.status(), InvitationStatus::Expired);
        assert_eq!(alice.status(), UserStatus::Deactivated);
    }

    /// A pending invitation cannot close its account, which remains invited.
    #[test]
    fn a_pending_invitation_does_not_close_its_account() {
        let mut alice = invitee();
        let inv = invitation_for(&alice);

        let closed = inv.close_unanswered(&mut alice);

        assert!(matches!(closed, Err(DomainError::Conflict(_))));
        assert_eq!(alice.status(), UserStatus::Invited);
    }

    /// The label an invitation event names the invitee under.
    fn invitee_label_of(event: &DomainEvent) -> String {
        match event.payload().value("user") {
            Some(crate::shared::events::data::FieldValue::Reference(reference)) => {
                reference.label().to_owned()
            }
            other => panic!("user is not a reference: {other:?}"),
        }
    }

    /// Alice accepts her invitation. The acceptance is raised.
    #[test]
    fn accepting_raises_identity_invitation_accepted() {
        let mut alice = invitee();
        let mut inv = invitation_for(&alice);

        accept(&mut inv, &mut alice).unwrap();

        assert_eq!(raised_names(&mut inv), ["identity.invitation_accepted"]);
    }

    /// Ann's invited account was read back from storage, and she accepts.
    /// Her move from invited to active is raised once, on her account, as
    /// every other status change is.
    #[test]
    fn accepting_raises_the_invitees_status_change() {
        let mut ann = account_with(UserId::new(), UserStatus::Invited, CredentialChange::Never);
        let mut inv = invitation_for(&ann);

        accept(&mut inv, &mut ann).unwrap();

        assert_eq!(raised_names(&mut ann), ["identity.user_status_changed"]);
    }

    /// An admin revokes Alice's invitation. The record names her by name and
    /// address, so it stays readable once her account is gone.
    #[test]
    fn revoking_raises_identity_invitation_revoked_naming_the_invitee() {
        let alice = invitee();
        let mut inv = invitation_for(&alice);

        inv.revoke(&alice, &control_over(&alice)).unwrap();

        let events = raised(&mut inv);
        assert_eq!(
            events[0].event_type().to_string(),
            "identity.invitation_revoked"
        );
        assert_eq!(
            invitee_label_of(&events[0]),
            format!(
                "{} ({})",
                alice.display_name().as_str(),
                alice.email().as_str()
            )
        );
    }

    /// Alice declines; another invitation runs out unanswered. Each is
    /// raised.
    #[test]
    fn declining_and_lapsing_are_raised() {
        let alice = invitee();
        let mut declined = invitation_for(&alice);
        let mut lapsed = invitation_for(&alice);

        declined.decline(&alice).unwrap();
        lapsed.lapse(&alice, lapsed.expires_at()).unwrap();

        assert_eq!(
            raised_names(&mut declined),
            ["identity.invitation_declined"]
        );
        assert_eq!(raised_names(&mut lapsed), ["identity.invitation_expired"]);
    }

    /// Sam sends Alice's invitation again; later her dead link gets a new
    /// one. Each sending is raised.
    #[test]
    fn sending_again_raises_identity_invitation_resent() {
        let alice = invitee();
        let mut resent = invitation_for(&alice);
        let mut renewed = invitation_for(&alice);

        resent
            .rotate_token(
                &alice,
                &sam(),
                TokenHash::from_stored("new".to_owned()),
                week(),
            )
            .unwrap();
        let _later = crate::shared::clock::freeze(renewed.expires_at());
        renewed
            .renew_from_link(&alice, &sent_link(), renewal())
            .unwrap();

        assert_eq!(raised_names(&mut resent), ["identity.invitation_resent"]);
        assert_eq!(raised_names(&mut renewed), ["identity.invitation_resent"]);
    }

    /// Revocation without user rights or against another account is refused,
    /// and neither attempt raises an event.
    #[test]
    fn a_refused_invitation_change_raises_nothing() {
        let alice = invitee();
        let mallory = invitee();
        let mut inv = invitation_for(&alice);
        let bob = AccountControl::assumed(
            anyone_holding(&[]),
            *alice.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        let by_bob = inv.revoke(&alice, &bob);
        let for_mallory = inv.revoke(&mallory, &control_over(&alice));

        assert!(by_bob.is_err());
        assert!(matches!(for_mallory, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut inv).is_empty());
    }

    /// Alice's invitation is read back from storage. Loading it raises
    /// nothing.
    #[test]
    fn an_invitation_read_back_from_storage_has_raised_nothing() {
        let now = crate::shared::clock::now();
        let mut stored = Invitation::<ResolvedTenant>::reconstitute(InvitationRow {
            id: InvitationId::new(),
            user_id: UserId::new(),
            email: Email::new("alice@example.com").unwrap(),
            invited_by: ActorRef::User(UserId::new()),
            role_id: RoleId::from_uuid(OFFERED),
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            state: OfferState::Pending,
            message: None,
            expires_at: now + Duration::days(7),
            created_at: now,
        })
        .unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }
}
