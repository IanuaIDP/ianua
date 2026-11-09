use time::OffsetDateTime;

use crate::domains::identity::invitations::invitation::MAX_INVITATION_LIFETIME;
use crate::domains::identity::invitations::offer::{InvitationOffer, OfferRow, OfferState};
use crate::domains::identity::invitations::route::{AcceptedAddress, InvitationRoute};
use crate::domains::identity::invitations::status::{InvitationLifecycle, InvitationStatus};
use crate::domains::identity::tokens::renewal::RenewedLink;
use crate::domains::organization::events::invitations::{
    OrgUserInvitationAccepted, OrgUserInvitationDeclined, OrgUserInvitationExpired,
    OrgUserInvitationResent, OrgUserInvitationRevoked, OrgUserInvited,
};
use crate::domains::organization::members::control::{OrgControl, ensure_platform_or_may};
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_authority::ensure_may_hand_out;
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::domains::organization::members::permission::{MemberAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    ActedBy, Email, Lifetime, OrgInvitationId, OrgUserId, OrganizationId, Text, TokenHash,
};

/// The right that sends, resends and withdraws invitations.
const INVITE: OrgPermission = OrgPermission::Members(MemberAction::Invite);

/// A magic-link invitation sending an org user a token to join an organization.
///
/// A tenant [`Invitation`](crate::domains::identity::invitations::invitation::Invitation)
/// is typed by its tenant. An org invitation is a plain struct that carries
/// its `organization_id` as a value, like [`OrgUser`] does. The offer and its
/// rules are the same [`InvitationOffer`], and so is the longest a link may
/// live.
#[derive(Debug)]
pub struct OrgInvitation {
    id: OrgInvitationId,
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    email: Email,
    invited_by: OrgUserId,
    offer: InvitationOffer,
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// What a new org invitation is made from, beside the invited account and
/// who sends it.
pub struct CreateOrgInvitationParams {
    /// Hash of the magic-link token. The raw token is emailed to the invitee.
    pub token_hash: TokenHash,
    /// Optional personal message included in the invitation email.
    pub message: Option<Text>,
    /// How long the link works from now, at most
    /// `MAX_INVITATION_LIFETIME`.
    pub lifetime: Lifetime,
}

/// An invitation as stored, for rebuilding it with
/// [`OrgInvitation::reconstitute`].
pub struct OrgInvitationRow {
    /// Unique invitation identifier.
    pub id: OrgInvitationId,
    /// The organization the invitation belongs to.
    pub organization_id: OrganizationId,
    /// The org user the invitation is for.
    pub org_user_id: OrgUserId,
    /// The email address that was invited.
    pub email: Email,
    /// The admin who sent the invitation.
    pub invited_by: OrgUserId,
    /// Hash of the magic-link token.
    pub token_hash: TokenHash,
    /// Where the invitation stands. See [`OfferState::from_stored`].
    pub state: OfferState,
    /// Optional personal message.
    pub message: Option<Text>,
    /// When the invitation expires.
    pub expires_at: OffsetDateTime,
    /// When the invitation was created.
    pub created_at: OffsetDateTime,
}

impl OrgInvitation {
    /// Creates a pending invitation for `invitee`, sent by `by`.
    ///
    /// The organization, the member and the address all come from the
    /// invited account, so the link always goes to the account's own
    /// address. Sam may only view members. Without the right check he
    /// invites a second mailbox of his own. And only an owner invites an
    /// owner. Raises `organization.org_user_invited`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not invite members, or
    ///   invites an owner without being one.
    /// - [`DomainError::Conflict`] when `invitee` is no longer waiting to
    ///   join.
    /// - [`DomainError::Validation`] when the lifetime is longer than
    ///   `MAX_INVITATION_LIFETIME`.
    pub fn create(
        params: CreateOrgInvitationParams,
        invitee: &OrgUser,
        by: &OrgControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(invitee.organization_id(), INVITE)?;
        ensure_may_hand_out(invitee.role(), by.by())?;
        ensure_waiting(invitee)?;
        params
            .lifetime
            .ensure_at_most(MAX_INVITATION_LIFETIME, "an invitation")?;
        let now = crate::shared::clock::now();
        let expires_at = params.lifetime.ends_after(now);
        let mut invitation = Self {
            id: OrgInvitationId::new(),
            organization_id: *invitee.organization_id(),
            org_user_id: *invitee.id(),
            email: invitee.email().clone(),
            invited_by: *by.by().id(),
            offer: InvitationOffer::open(params.token_hash, params.message, expires_at),
            created_at: now,
            raised: RaisedEvents::default(),
        };
        invitation.raised.raise_organization(OrgUserInvited {
            organization_id: invitation.organization_id,
            org_user_id: invitation.org_user_id,
            email: invitation.email.clone(),
            occurred_at: now,
        });
        Ok(invitation)
    }

    /// Rebuilds an organization invitation from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the invitation was
    ///   accepted before it was sent, or once its link had run out.
    pub fn reconstitute(row: OrgInvitationRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            org_user_id: row.org_user_id,
            email: row.email,
            invited_by: row.invited_by,
            offer: InvitationOffer::reconstitute(OfferRow {
                token_hash: row.token_hash,
                state: row.state,
                message: row.message,
                expires_at: row.expires_at,
            })?,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OrgInvitationRow) -> Result<(), DomainError> {
        RowCheck::of("organization invitation")
            .in_order_if(
                row.created_at,
                row.state.accepted_at(),
                "accepted before it was sent",
            )
            .finish()
    }

    /// Unique invitation identifier.
    #[must_use]
    pub fn id(&self) -> &OrgInvitationId {
        &self.id
    }

    /// The organization the invitee will join.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The org user the invitation is for.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// The email address that was invited.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// The admin who sent the invitation.
    #[must_use]
    pub fn invited_by(&self) -> &OrgUserId {
        &self.invited_by
    }

    /// Hash of the magic-link token for verification.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        self.offer.token_hash()
    }

    /// Current invitation status.
    #[must_use]
    pub fn status(&self) -> InvitationStatus {
        self.offer.status()
    }

    /// Optional personal message.
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

    /// Whether this invitation can still be accepted.
    #[must_use]
    pub fn is_pending(&self, now: OffsetDateTime) -> bool {
        self.offer.is_pending(now)
    }

    /// What presenting this invitation's link gets you.
    #[must_use]
    pub fn state(&self, now: OffsetDateTime) -> InvitationLifecycle {
        self.offer.state(now)
    }

    /// Accepts a pending invitation for its waiting member and returns address proof.
    /// A mailed link proves mailbox control; a link handed to the inviter proves nothing.
    /// The inviter must still have authority to invite this member.
    /// Raises `organization.org_user_invitation_accepted`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another member, organization or address, or an inviter
    /// who did not send the invitation or lacks current authority.
    /// [`DomainError::Conflict`] for an expired link or a member not waiting to join.
    /// [`DomainError::InvalidTransition`] unless pending.
    pub fn accept(
        &mut self,
        invitee: &OrgUser,
        inviter: &OrgUser,
        route: InvitationRoute,
    ) -> Result<AcceptedAddress, DomainError> {
        self.ensure_still_for(invitee)?;
        self.ensure_inviter_still_may(inviter, invitee.role())?;
        ensure_waiting(invitee)?;
        self.offer.accept()?;
        self.raised.raise_organization(OrgUserInvitationAccepted {
            organization_id: self.organization_id,
            email: self.email.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(route.accepted_address(self.email.clone()))
    }

    /// Refuses `invitee` unless the invitation was sent for it, in this
    /// organization, to the address it still has.
    fn ensure_still_for(&self, invitee: &OrgUser) -> Result<(), DomainError> {
        if *invitee.id() != self.org_user_id || *invitee.organization_id() != self.organization_id {
            return Err(DomainError::forbidden(message!(
                "organization-the-invitation-is-for-another-member",
                "the invitation is for another member"
            )));
        }
        if *invitee.email() != self.email {
            return Err(DomainError::forbidden(message!(
                "organization-the-invitation-was-sent-to-an",
                "the invitation was sent to an address the member no longer has"
            )));
        }
        Ok(())
    }

    /// Refuses `inviter` unless they sent this invitation and are still an
    /// active member of its organization whose role may invite `role`.
    fn ensure_inviter_still_may(
        &self,
        inviter: &OrgUser,
        role: OrgRole,
    ) -> Result<(), DomainError> {
        let still_may = *inviter.id() == self.invited_by
            && *inviter.organization_id() == self.organization_id
            && inviter.status() == OrgUserStatus::Active
            && inviter.role().grants(&INVITE);
        if !still_may {
            return Err(DomainError::forbidden(message!(
                "organization-whoever-sent-the-invitation-may-no",
                "whoever sent the invitation may no longer invite"
            )));
        }
        ensure_may_hand_out(role, inviter)
    }

    /// Withdraws the invitation before it is accepted, as `by` decides. The
    /// platform withdraws one when the invited account is removed. Raises
    /// `organization.org_user_invitation_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a member withdraws it without the
    ///   right to invite.
    /// - [`DomainError::InvalidTransition`] unless it is pending.
    pub fn revoke(&mut self, by: ActedBy<OrgControl<'_>>) -> Result<(), DomainError> {
        ensure_platform_or_may(by, &self.organization_id, INVITE)?;
        self.offer.revoke()?;
        self.raised.raise_organization(OrgUserInvitationRevoked {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            email: self.email.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Turns the invitation down, for the invitee who followed its link.
    /// Raises `organization.org_user_invitation_declined`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `invitee` is another member, or has
    ///   moved off the invited address.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn decline(&mut self, invitee: &OrgUser) -> Result<(), DomainError> {
        self.ensure_still_for(invitee)?;
        self.offer.decline()?;
        self.raised.raise_organization(OrgUserInvitationDeclined {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            email: self.email.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Marks the invitation expired once its link has run out at `now`.
    /// Raises `organization.org_user_invitation_expired`, at `now`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the link has not run out yet.
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    pub fn lapse(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        self.offer.lapse(now)?;
        self.raised.raise_organization(OrgUserInvitationExpired {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            email: self.email.clone(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Closes `invitee`'s account once this invitation ended without being
    /// accepted: it expired, was declined or was revoked.
    ///
    /// An account nobody claimed would otherwise wait in the member list as
    /// invited for good. It is deactivated, so its history stays and an
    /// owner may still let it in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `invitee` is another member.
    /// - [`DomainError::Conflict`] when the invitation is still pending, or
    ///   was accepted, or `invitee` is no longer waiting to join.
    pub fn close_unanswered(&self, invitee: &mut OrgUser) -> Result<(), DomainError> {
        if *invitee.id() != self.org_user_id {
            return Err(DomainError::forbidden(message!(
                "organization-the-invitation-is-for-another-member",
                "the invitation is for another member"
            )));
        }
        match self.status() {
            InvitationStatus::Expired | InvitationStatus::Declined | InvitationStatus::Revoked => {
                invitee.close_unanswered_invite()
            }
            InvitationStatus::Pending | InvitationStatus::Accepted => {
                Err(DomainError::conflict(message!(
                    "identity-only-an-invitation-nobody-accepted-closes",
                    "only an invitation nobody accepted closes its account"
                )))
            }
        }
    }

    /// Replaces the magic-link token and sets a new expiry, as `by` decides.
    /// The invitation stays pending. Resend uses this and mails the invited
    /// address, so it is refused once `invitee` has left that address.
    /// Otherwise the new link would go to the old mailbox. Raises
    /// `organization.org_user_invitation_resent`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `invitee` is another member, in
    ///   another organization, or no longer has the invited address.
    /// - [`DomainError::Forbidden`] if `by` may not invite members.
    /// - [`DomainError::Validation`] when the new lifetime is longer than
    ///   `MAX_INVITATION_LIFETIME`.
    /// - [`DomainError::InvalidTransition`] unless it is pending.
    pub fn rotate_token(
        &mut self,
        invitee: &OrgUser,
        by: &OrgControl<'_>,
        new_token_hash: TokenHash,
        new_lifetime: Lifetime,
    ) -> Result<(), DomainError> {
        self.ensure_still_for(invitee)?;
        by.ensure_may(&self.organization_id, INVITE)?;
        new_lifetime.ensure_at_most(MAX_INVITATION_LIFETIME, "an invitation")?;
        let now = crate::shared::clock::now();
        self.offer
            .rotate_token(new_token_hash, new_lifetime.ends_after(now))?;
        self.resent(now);
        Ok(())
    }

    /// Sends the invitation again from its own link, which ran out before
    /// `invitee` followed it. Raises `organization.org_user_invitation_resent`,
    /// as [`rotate_token`](Self::rotate_token) does.
    ///
    /// Ann opens her invitation a week late. The page offers her a new link
    /// instead of sending her to an owner. Nobody in the organization
    /// decides this, so the invitation must stand as it was sent: the dead
    /// link is its own, nobody withdrew it, and the account still waits to
    /// join at the invited address without having changed how it signs in.
    /// The new link goes to that same address, so only its mailbox gains
    /// anything.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `presented` is not this
    ///   invitation's link, `invitee` is another member, or has moved off
    ///   the invited address.
    /// - [`DomainError::Conflict`] when `invitee` no longer waits to join,
    ///   or changed how it signs in after the invitation was sent, or the
    ///   link still works.
    /// - [`DomainError::Validation`] when the new lifetime is longer than
    ///   `MAX_INVITATION_LIFETIME`.
    /// - [`DomainError::InvalidTransition`] when it was accepted, declined,
    ///   revoked or marked expired.
    pub fn renew_from_link(
        &mut self,
        invitee: &OrgUser,
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
        self.offer
            .rotate_token(renewed.token_hash, renewed.lifetime.ends_after(now))?;
        self.resent(now);
        Ok(())
    }

    /// Refuses `invitee` once it stopped waiting to join, or changed how it
    /// signs in after the invitation was sent.
    fn ensure_unchanged_since_sent(&self, invitee: &OrgUser) -> Result<(), DomainError> {
        ensure_waiting(invitee)?;
        if invitee.credentials_changed_at().since(self.created_at) {
            return Err(DomainError::conflict(message!(
                "organization-the-invited-member-changed-how-they",
                "the invited member changed how they sign in since they were invited"
            )));
        }
        Ok(())
    }

    /// Raises the invitation going out again at `now`.
    fn resent(&mut self, now: OffsetDateTime) {
        self.raised.raise_organization(OrgUserInvitationResent {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            email: self.email.clone(),
            occurred_at: now,
        });
    }
}

impl RaisesComplete for OrgInvitation {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses `invitee` unless it still waits to join.
fn ensure_waiting(invitee: &OrgUser) -> Result<(), DomainError> {
    if invitee.status() != OrgUserStatus::Invited {
        return Err(DomainError::conflict(message!(
            "organization-the-invited-member-is-no-longer",
            "the invited member is no longer waiting to join"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::organization::lifecycle::tests::founding_of;
    use crate::domains::organization::members::control::tests::{acting, session_of};
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword,
    };
    use crate::domains::organization::members::owners::Owners;
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{DisplayName, PasswordHash};

    fn text(s: &str) -> Text {
        Text::new("message", s).unwrap()
    }

    fn week() -> Lifetime {
        Lifetime::new(Duration::days(7)).unwrap()
    }

    fn params() -> CreateOrgInvitationParams {
        CreateOrgInvitationParams {
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            message: Some(text("Welcome to Acme!")),
            lifetime: week(),
        }
    }

    fn user_params(
        organization_id: OrganizationId,
        email: &str,
        role: OrgRole,
    ) -> CreateOrgUserParams {
        CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id,
            email: Email::new(email).unwrap(),
            display_name: DisplayName::new("Alice", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        }
    }

    /// Alice, invited with `role`, and the founder who invited her.
    fn invited_with(role: OrgRole) -> (OrgUser, OrgUser) {
        let organization_id = OrganizationId::new();
        let founder = OrgUser::create(
            user_params(organization_id, "founder@example.com", OrgRole::Owner),
            AddedBy::Founding(founding_of(organization_id)),
        )
        .unwrap();
        let session = session_of(&founder);
        let alice = OrgUser::invite(
            user_params(organization_id, "alice@example.com", role),
            &acting(&founder, &session),
        )
        .unwrap();
        (alice, founder)
    }

    /// Alice, invited as a member, and the founder who invited her.
    fn invited_member_and_owner() -> (OrgUser, OrgUser) {
        invited_with(OrgRole::Member)
    }

    /// An invitation for `member`, sent by `owner`.
    fn invitation_for(member: &OrgUser, owner: &OrgUser) -> OrgInvitation {
        let session = session_of(owner);
        OrgInvitation::create(params(), member, &acting(owner, &session)).unwrap()
    }

    /// `owner` moves `member` to `to`, keeping themselves as the owner.
    fn moved(member: &mut OrgUser, to: OrgUserStatus, owner: &OrgUser) {
        let session = session_of(owner);
        member
            .change_status(
                to,
                &acting(owner, &session),
                Owners::of(std::slice::from_ref(owner)),
            )
            .unwrap();
    }

    /// `owner` corrects `member`'s address to `email`.
    fn readdressed(member: &mut OrgUser, email: &str, owner: &OrgUser) {
        let session = session_of(owner);
        member
            .change_email(Email::new(email).unwrap(), &acting(owner, &session))
            .unwrap();
    }

    /// A fresh link for a dead one, good for a week.
    fn renewal() -> RenewedLink {
        RenewedLink {
            token_hash: TokenHash::from_stored("fresh_token".to_owned()),
            lifetime: week(),
        }
    }

    /// The link Alice's invitation was sent with.
    fn sent_link() -> TokenHash {
        TokenHash::from_stored("hashed_token".to_owned())
    }

    /// Alice opens her invitation a week late. Her own dead link gets her a
    /// new one, the invitation waits again, and the resend is raised.
    #[test]
    fn a_dead_link_is_renewed_from_itself() {
        let (alice, founder) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &founder);
        let _ = inv.take_events();
        let _later = crate::shared::clock::freeze(inv.expires_at() + Duration::days(1));

        inv.renew_from_link(&alice, &sent_link(), renewal())
            .unwrap();

        assert!(inv.is_pending(crate::shared::clock::now()));
        assert_eq!(inv.token_hash().as_str(), "fresh_token");
        assert_eq!(inv.take_events().len(), 1);
    }

    /// Renewal from Alice's own link is refused while that link still works.
    #[test]
    fn a_link_that_still_works_is_not_renewed() {
        let (alice, founder) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &founder);

        let refused = inv.renew_from_link(&alice, &sent_link(), renewal());

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// An unrelated token cannot renew Alice's expired invitation link.
    #[test]
    fn another_link_renews_nothing() {
        let (alice, founder) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &founder);
        let _later = crate::shared::clock::freeze(inv.expires_at() + Duration::days(1));
        let mallorys = TokenHash::from_stored("mallorys_token".to_owned());

        let refused = inv.renew_from_link(&alice, &mallorys, renewal());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Alice is invited with the note "Welcome to Acme!". The invitation is
    /// pending, not accepted, keeps the note and names Alice, her address
    /// and the founder who sent it.
    #[test]
    fn create_sets_pending_status() {
        let (alice, founder) = invited_member_and_owner();

        let inv = invitation_for(&alice, &founder);

        assert_eq!(inv.status(), InvitationStatus::Pending);
        assert!(inv.is_pending(crate::shared::clock::now()));
        assert!(inv.accepted_at().is_none());
        assert_eq!(inv.message().map(Text::as_str), Some("Welcome to Acme!"));
        assert_eq!(inv.org_user_id(), alice.id());
        assert_eq!(inv.email(), alice.email());
        assert_eq!(inv.invited_by(), founder.id());
        assert_eq!(inv.organization_id(), alice.organization_id());
    }

    /// Sam's member session cannot create an invitation for Alice.
    #[test]
    fn a_plain_member_sends_no_invitation() {
        let (alice, founder) = invited_member_and_owner();
        let session = session_of(&founder);
        let sam = OrgUser::create(
            user_params(
                *founder.organization_id(),
                "sam@example.com",
                OrgRole::Member,
            ),
            AddedBy::Member(acting(&founder, &session)),
        )
        .unwrap();
        let sams = session_of(&sam);

        let result = OrgInvitation::create(params(), &alice, &acting(&sam, &sams));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A year-long invitation fails validation even when an owner sends it.
    #[test]
    fn an_invitation_lives_at_most_thirty_days() {
        let (alice, founder) = invited_member_and_owner();
        let session = session_of(&founder);

        let result = OrgInvitation::create(
            CreateOrgInvitationParams {
                lifetime: Lifetime::new(Duration::days(365)).unwrap(),
                ..params()
            },
            &alice,
            &acting(&founder, &session),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Alice follows her invitation link. It is no longer pending, records
    /// when it was accepted, and gives back her invited address as proven.
    #[test]
    fn accepting_closes_the_invitation() {
        let (alice, founder) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &founder);

        let proven = inv
            .accept(&alice, &founder, InvitationRoute::Mailed)
            .unwrap();

        assert!(inv.accepted_at().is_some());
        assert!(!inv.is_pending(crate::shared::clock::now()));
        assert!(proven.is_proven());
        assert_eq!(proven.email(), inv.email());
    }

    /// Accepting a handed-over link records acceptance while returning the
    /// invited address as unproven.
    #[test]
    fn a_handed_over_link_gives_back_the_address_unproven() {
        let (alice, founder) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &founder);

        let accepted = inv
            .accept(&alice, &founder, InvitationRoute::HandedOver)
            .unwrap();

        assert!(inv.accepted_at().is_some());
        assert_eq!(accepted, AcceptedAddress::unproven(inv.email().clone()));
    }

    /// Alice joined, left and her account was closed. The founder invites
    /// her address again. The same account gets the new invitation, and
    /// accepting it lets her in again as active, joined when she first did.
    #[test]
    fn a_reopened_account_is_invited_and_joins_again() {
        let (mut alice, founder) = invited_member_and_owner();
        let mut first = invitation_for(&alice, &founder);
        let proof = first
            .accept(&alice, &founder, InvitationRoute::Mailed)
            .unwrap();
        alice
            .accept_invitation(PasswordHash::from_stored("first".to_owned()), proof)
            .unwrap();
        let joined = alice.joined_at();
        moved(&mut alice, OrgUserStatus::Deactivated, &founder);
        let session = session_of(&founder);
        alice
            .reopen_for_invitation(
                DisplayName::new("Alice", &DisplayNameLimits::default()).unwrap(),
                OrgRole::Member,
                &acting(&founder, &session),
            )
            .unwrap();

        let mut again = invitation_for(&alice, &founder);
        let proof = again
            .accept(&alice, &founder, InvitationRoute::Mailed)
            .unwrap();
        alice
            .accept_invitation(PasswordHash::from_stored("second".to_owned()), proof)
            .unwrap();

        assert_eq!(again.org_user_id(), alice.id());
        assert_eq!(alice.status(), OrgUserStatus::Active);
        assert_eq!(alice.joined_at(), joined);
    }

    /// Locking the inviter prevents accepting their owner invitation;
    /// the invitation remains pending.
    #[test]
    fn an_invitation_from_someone_who_lost_the_right_is_refused() {
        let (alice, mut founder) = invited_with(OrgRole::Owner);
        let mut inv = invitation_for(&alice, &founder);
        let session = session_of(&founder);
        let co_owner = OrgUser::create(
            user_params(*founder.organization_id(), "co@example.com", OrgRole::Owner),
            AddedBy::Member(acting(&founder, &session)),
        )
        .unwrap();
        moved(&mut founder, OrgUserStatus::Locked, &co_owner);

        let result = inv.accept(&alice, &founder, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(inv.status(), InvitationStatus::Pending);
    }

    /// A deactivated invitee cannot accept her link; the invitation remains
    /// pending after the refusal.
    #[test]
    fn a_link_does_not_bring_back_a_deactivated_member() {
        let (mut alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);
        moved(&mut alice, OrgUserStatus::Deactivated, &owner);

        let result = inv.accept(&alice, &owner, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(inv.status(), InvitationStatus::Pending);
    }

    /// Changing Alice's address prevents accepting the link sent to her old
    /// address, leaving the invitation pending.
    #[test]
    fn a_link_to_an_address_the_member_has_left_is_refused() {
        let (mut alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);
        readdressed(&mut alice, "alice@new.example", &owner);

        let result = inv.accept(&alice, &owner, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(inv.status(), InvitationStatus::Pending);
    }

    /// Alice's invitation cannot be accepted for another organization's
    /// invited member.
    #[test]
    fn a_link_is_refused_for_another_member() {
        let (alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);
        let (mallory, _) = invited_member_and_owner();

        let result = inv.accept(&mallory, &owner, InvitationRoute::Mailed);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// After Alice's address changes, even the owner cannot rotate the
    /// invitation token for her old address.
    #[test]
    fn a_link_is_not_resent_to_an_address_the_member_has_left() {
        let (mut alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);
        readdressed(&mut alice, "alice@new.example", &owner);
        let session = session_of(&owner);

        let result = inv.rotate_token(
            &alice,
            &acting(&owner, &session),
            TokenHash::from_stored("fresh".to_owned()),
            week(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Alice turns her invitation down. It reads as declined, and closing it
    /// deactivates her waiting account.
    #[test]
    fn a_declined_invitation_closes_its_account() {
        let (mut alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);

        inv.decline(&alice).unwrap();
        inv.close_unanswered(&mut alice).unwrap();

        assert_eq!(inv.status(), InvitationStatus::Declined);
        assert_eq!(alice.status(), OrgUserStatus::Deactivated);
    }

    /// Alice never answers. A week later the invitation is marked expired,
    /// and her waiting account is closed.
    #[test]
    fn an_unanswered_invitation_expires_and_closes_its_account() {
        let (mut alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);

        inv.lapse(inv.expires_at() + Duration::SECOND).unwrap();
        inv.close_unanswered(&mut alice).unwrap();

        assert_eq!(inv.status(), InvitationStatus::Expired);
        assert_eq!(alice.status(), OrgUserStatus::Deactivated);
    }

    /// A pending invitation cannot close Alice's account; she remains
    /// invited.
    #[test]
    fn a_pending_invitation_closes_nothing() {
        let (mut alice, owner) = invited_member_and_owner();
        let inv = invitation_for(&alice, &owner);

        let result = inv.close_unanswered(&mut alice);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(alice.status(), OrgUserStatus::Invited);
    }

    /// The platform withdraws Alice's invitation when her account is
    /// removed. It reads as revoked.
    #[test]
    fn the_platform_withdraws_an_invitation() {
        let (alice, owner) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &owner);

        inv.revoke(ActedBy::Platform).unwrap();

        assert_eq!(inv.status(), InvitationStatus::Revoked);
    }

    /// An invitation sent for a week runs out a week after it was sent, so
    /// no expiry already past can be given to it.
    #[test]
    fn an_invitation_runs_out_its_lifetime_after_it_was_sent() {
        let (alice, owner) = invited_member_and_owner();

        let inv = invitation_for(&alice, &owner);

        assert_eq!(inv.expires_at(), inv.created_at() + Duration::days(7));
    }

    /// A stored invitation says it was accepted at the instant its link ran
    /// out. No link is taken up once it runs out, so loading it is refused
    /// as corrupt.
    #[test]
    fn a_stored_invitation_accepted_once_its_link_ran_out_is_refused() {
        let now = crate::shared::clock::now();
        let expires_at = now + Duration::days(7);

        let stored = OrgInvitation::reconstitute(OrgInvitationRow {
            id: OrgInvitationId::new(),
            organization_id: OrganizationId::new(),
            org_user_id: OrgUserId::new(),
            email: Email::new("alice@example.com").unwrap(),
            invited_by: OrgUserId::new(),
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            state: OfferState::Accepted { at: expires_at },
            message: None,
            expires_at,
            created_at: now,
        });

        assert!(refused_as_corrupt(&stored));
    }

    /// The founder invites Alice, resends the link, and Alice accepts. Each
    /// step is raised, in order, naming her address.
    #[test]
    fn sending_resending_and_accepting_raise_their_records() {
        let (alice, founder) = invited_member_and_owner();
        let mut inv = invitation_for(&alice, &founder);
        let session = session_of(&founder);
        inv.rotate_token(
            &alice,
            &acting(&founder, &session),
            TokenHash::from_stored("rotated".to_owned()),
            week(),
        )
        .unwrap();
        inv.accept(&alice, &founder, InvitationRoute::Mailed)
            .unwrap();

        let events = inv.take_events();
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "organization.org_user_invited",
                "organization.org_user_invitation_resent",
                "organization.org_user_invitation_accepted",
            ]
        );
        assert_eq!(events[2].payload().get("email"), Some("alice@example.com"));
    }

    /// Alice declines one invitation, the founder revokes a second, and a
    /// third runs out. Each ending is raised.
    #[test]
    fn every_ending_raises_its_record() {
        let (alice, founder) = invited_member_and_owner();
        let session = session_of(&founder);
        let (mut declined, mut revoked, mut lapsed) = (
            invitation_for(&alice, &founder),
            invitation_for(&alice, &founder),
            invitation_for(&alice, &founder),
        );
        for inv in [&mut declined, &mut revoked, &mut lapsed] {
            let _ = inv.take_events();
        }

        declined.decline(&alice).unwrap();
        revoked
            .revoke(ActedBy::By(acting(&founder, &session)))
            .unwrap();
        lapsed
            .lapse(crate::shared::clock::now() + Duration::days(8))
            .unwrap();

        assert_eq!(
            event_names(&mut declined),
            ["organization.org_user_invitation_declined"]
        );
        assert_eq!(
            event_names(&mut revoked),
            ["organization.org_user_invitation_revoked"]
        );
        assert_eq!(
            event_names(&mut lapsed),
            ["organization.org_user_invitation_expired"]
        );
    }

    /// Drains an invitation's records so each ending can assert its exact event sequence.
    fn event_names(inv: &mut OrgInvitation) -> Vec<String> {
        inv.take_events()
            .iter()
            .map(|event| event.event_type().to_string())
            .collect()
    }

    /// Expiring a current invitation and declining an accepted one are
    /// both refused, and neither raises an event.
    #[test]
    fn a_refused_step_raises_nothing() {
        let (alice, founder) = invited_member_and_owner();
        let mut current = invitation_for(&alice, &founder);
        let mut accepted = invitation_for(&alice, &founder);
        accepted
            .accept(&alice, &founder, InvitationRoute::Mailed)
            .unwrap();
        let _ = (current.take_events(), accepted.take_events());

        let lapsed = current.lapse(crate::shared::clock::now());
        let declined = accepted.decline(&alice);

        assert!(lapsed.is_err() && declined.is_err());
        assert!(current.take_events().is_empty());
        assert!(accepted.take_events().is_empty());
    }

    /// An invitation is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn an_invitation_read_back_from_storage_has_raised_nothing() {
        let now = crate::shared::clock::now();
        let mut stored = OrgInvitation::reconstitute(OrgInvitationRow {
            id: OrgInvitationId::new(),
            organization_id: OrganizationId::new(),
            org_user_id: OrgUserId::new(),
            email: Email::new("alice@example.com").unwrap(),
            invited_by: OrgUserId::new(),
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            state: OfferState::Pending,
            message: None,
            expires_at: now + Duration::days(7),
            created_at: now,
        })
        .unwrap();

        assert!(stored.take_events().is_empty());
    }
}
