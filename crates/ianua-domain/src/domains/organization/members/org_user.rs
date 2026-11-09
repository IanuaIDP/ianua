//! Org users, the people who sign in to the management plane.
//!
//! Org users manage the IdP: tenants, users, policies and routes. They are
//! separate from tenant users, the end users whose identity the IdP manages.

use time::OffsetDateTime;

use crate::domains::identity::account::address::{AccountAddress, AddressStanding, MailReach};
use crate::domains::identity::account::vouching::Vouching;
use crate::domains::identity::invitations::route::AcceptedAddress;
use crate::domains::organization::events::members::{
    OrgUserCreated, OrgUserDeleted, OrgUserRoleChanged, OrgUserStatusChanged,
};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::membership::OrgRole;
pub use crate::domains::organization::members::org_password::OrgPassword;
pub use crate::domains::organization::members::org_user_authority::AddedBy;
use crate::domains::organization::members::org_user_authority::{
    ensure_may_act_on, ensure_may_bring_in, ensure_may_hand_out,
};
use crate::domains::organization::members::org_user_row::ensure_consistent;
use crate::domains::organization::members::org_user_status::{
    InvalidOrgUserTransition, OrgUserStatus,
};
use crate::domains::organization::members::owners::Owners;
use crate::domains::organization::members::permission::MemberAction;
use crate::domains::organization::members::reach::{MemberReach, MemberReachParts};
use crate::domains::organization::members::reopened::ReopenedAccount;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::types::{
    CredentialChange, DisplayName, Email, EventLabel, Joining, Locale, OrgUserId, OrganizationId,
    PasswordHash, Preference, Timezone,
};

mod closing;
mod credentials;
mod ownership;
mod profile;

/// Parameters for creating a new org user.
pub struct CreateOrgUserParams {
    /// Globally unique identifier.
    pub id: OrgUserId,
    /// The organization this user belongs to.
    pub organization_id: OrganizationId,
    /// Email address, unique within the organization.
    pub email: Email,
    /// Display name shown in admin UIs.
    pub display_name: DisplayName,
    /// The password, or that none is set yet. An invited user sets theirs
    /// when accepting a magic-link invitation.
    pub password_hash: OrgPassword,
    /// Authority within the organization. It has no default, so making
    /// someone an owner is always a choice the caller writes down.
    pub role: OrgRole,
}

/// A member as stored, for rebuilding it with [`OrgUser::reconstitute`].
pub struct OrgUserRow {
    /// Unique identifier.
    pub id: OrgUserId,
    /// The organization this user belongs to.
    pub organization_id: OrganizationId,
    /// Email address.
    pub email: Email,
    /// The persisted person label shown in membership lists and audit references.
    pub display_name: DisplayName,
    /// The password, or that none is set yet.
    pub password_hash: OrgPassword,
    /// Current lifecycle status.
    pub status: OrgUserStatus,
    /// Authority within the organization.
    pub role: OrgRole,
    /// Whether the user was shown to hold `email`.
    pub email_standing: AddressStanding,
    /// The locale they chose, or that they follow the organization's.
    pub locale: Preference<Locale>,
    /// The timezone they chose, or that they follow the organization's.
    pub timezone: Preference<Timezone>,
    /// When this user was created.
    pub created_at: OffsetDateTime,
    /// When this user was last modified.
    pub updated_at: OffsetDateTime,
    /// Whether it has joined, and when it first did.
    pub joining: Joining,
    /// When this user last changed how they sign in, or that they never have.
    pub credentials_changed_at: CredentialChange,
    /// Whether the setup token or an accepted invitation still vouches for
    /// the next sign-in.
    pub vouching: Vouching,
}

/// An org-level user identity.
///
/// Org users manage the IdP through the dashboard. They have their own
/// credentials, sessions, MFA and device trust, separate from tenant users.
///
/// An org user is one person's account in one organization. Their address
/// is unique within that organization, not across the platform: the same
/// person may hold an account in several organizations under one address,
/// each with its own credentials.
#[derive(Debug)]
pub struct OrgUser {
    id: OrgUserId,
    organization_id: OrganizationId,
    address: AccountAddress,
    display_name: DisplayName,
    password_hash: OrgPassword,
    status: OrgUserStatus,
    role: OrgRole,
    locale: Preference<Locale>,
    timezone: Preference<Timezone>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    /// Whether it has joined, and when it first did.
    joining: Joining,
    credentials_changed_at: CredentialChange,
    vouching: Vouching,
    raised: RaisedEvents,
}

impl OrgUser {
    /// Creates an org user with a known password. This is the founder of a
    /// new organization, or a member an admin adds. Raises
    /// `organization.org_user_created`.
    ///
    /// The account is `Active` and joined at once, but its address is
    /// unverified. Nobody creating an account can vouch for a mailbox they
    /// do not hold. So the address counts as verified only once the person
    /// follows an emailed link and [`verify_email`](Self::verify_email) gets
    /// the proof.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `added_by` is a member without the
    ///   right to create members, or brings in an owner without being one.
    ///   See [`AddedBy`].
    /// - [`DomainError::Forbidden`] when `added_by` is the founding of
    ///   another organization than `params.organization_id`.
    /// - [`DomainError::Validation`] when a founder is not made an owner.
    pub fn create(params: CreateOrgUserParams, added_by: AddedBy<'_>) -> Result<Self, DomainError> {
        ensure_may_bring_in(
            params.role,
            &params.organization_id,
            added_by,
            MemberAction::Create,
        )?;
        let mut member = Self::opened(params, OrgUserStatus::Active);
        member.raised.raise_organization(OrgUserCreated {
            organization_id: member.organization_id,
            org_user_id: member.id,
            email: member.email().clone(),
            occurred_at: member.created_at,
        });
        Ok(member)
    }

    /// Creates an org user in status `Invited`, invited by `by`.
    ///
    /// Invited users start unverified. Accepting the emailed invitation is
    /// what proves their address. It raises nothing: the invitation sent
    /// for the account records it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not invite members to the
    ///   organization. See [`OrgControl::ensure_may`].
    /// - [`DomainError::Forbidden`] when `by` invites an owner without being
    ///   one.
    pub fn invite(params: CreateOrgUserParams, by: &OrgControl<'_>) -> Result<Self, DomainError> {
        ensure_may_bring_in(
            params.role,
            &params.organization_id,
            AddedBy::Member(*by),
            MemberAction::Invite,
        )?;
        Ok(Self::opened(params, OrgUserStatus::Invited))
    }

    /// A new member from `params`, starting at `status` with an unverified
    /// address. Only an active member has joined.
    fn opened(params: CreateOrgUserParams, status: OrgUserStatus) -> Self {
        let now = crate::shared::clock::now();
        let joining = if status == OrgUserStatus::Active {
            Joining::Joined { at: now }
        } else {
            Joining::NotYet
        };
        Self {
            id: params.id,
            organization_id: params.organization_id,
            address: AccountAddress::unverified(params.email),
            display_name: params.display_name,
            password_hash: params.password_hash,
            status,
            role: params.role,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining,
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
            raised: RaisedEvents::default(),
        }
    }

    /// Rebuilds an organization member from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has joined while still
    ///   unverified, or is active or locked with no join date.
    /// - [`DomainError::Infrastructure`] when the row says the member changed,
    ///   joined or changed how they sign in before they were created.
    /// - [`DomainError::Infrastructure`] when a route vouches for the row's
    ///   next sign-in while it never joined.
    pub fn reconstitute(row: OrgUserRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            address: AccountAddress::stored(row.email, row.email_standing),
            display_name: row.display_name,
            password_hash: row.password_hash,
            status: row.status,
            role: row.role,
            locale: row.locale,
            timezone: row.timezone,
            created_at: row.created_at,
            updated_at: row.updated_at,
            joining: row.joining,
            credentials_changed_at: row.credentials_changed_at,
            vouching: row.vouching,
            raised: RaisedEvents::default(),
        })
    }

    /// Unique org user identifier.
    #[must_use]
    pub fn id(&self) -> &OrgUserId {
        &self.id
    }

    /// The organization this user belongs to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Email address.
    #[must_use]
    pub fn email(&self) -> &Email {
        self.address.email()
    }

    /// The address with its standing.
    #[must_use]
    pub fn address(&self) -> &AccountAddress {
        &self.address
    }

    /// The person label shown in membership lists and audit references.
    #[must_use]
    pub fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    /// The password, or that none is set. An invited user who has not
    /// accepted yet has none.
    #[must_use]
    pub fn password_hash(&self) -> &OrgPassword {
        &self.password_hash
    }

    /// Current lifecycle status.
    #[must_use]
    pub fn status(&self) -> OrgUserStatus {
        self.status
    }

    /// Authority within the organization.
    #[must_use]
    pub fn role(&self) -> OrgRole {
        self.role
    }

    /// Who the member is, whose member, in what role and status: what a
    /// check of their reach into a tenant reads.
    #[must_use]
    pub fn reach(&self) -> MemberReach {
        MemberReach::new(MemberReachParts {
            id: self.id,
            organization_id: self.organization_id,
            role: self.role,
            status: self.status,
        })
    }

    /// Whether the user's email address has been verified.
    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.address.is_verified()
    }

    /// Whether the member's address lets a sign-in finish, where `mail`
    /// says whether a link confirming it could reach them. See
    /// [`AddressStanding::admits_sign_in`]: the address is never marked
    /// verified by this.
    #[must_use]
    pub fn address_admits_sign_in(&self, mail: MailReach) -> bool {
        self.address.standing().admits_sign_in(mail)
    }

    /// The locale they chose, or that they follow the organization's.
    #[must_use]
    pub fn locale(&self) -> &Preference<Locale> {
        &self.locale
    }

    /// The timezone they chose, or that they follow the organization's.
    #[must_use]
    pub fn timezone(&self) -> &Preference<Timezone> {
        &self.timezone
    }

    /// When this user was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this user was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// When this user joined, meaning first became `Active`. `None` until then.
    #[must_use]
    pub fn joined_at(&self) -> Option<OffsetDateTime> {
        self.joining.joined_at()
    }

    /// When this user last changed how they sign in, such as by setting a
    /// password or adding or removing a second factor.
    /// [`CredentialChange::Never`] if they never have.
    ///
    /// A device remembered before this no longer skips the second factor.
    /// See `DeviceTrustRules`.
    #[must_use]
    pub fn credentials_changed_at(&self) -> CredentialChange {
        self.credentials_changed_at
    }

    /// Whether the installation's setup token or an accepted invitation
    /// still vouches for the next sign-in. It does from that route until
    /// the first sign-in after it.
    #[must_use]
    pub fn vouching(&self) -> Vouching {
        self.vouching
    }

    /// Records that the member signed in. The sign-in spends whatever the
    /// setup token or an accepted invitation vouched for.
    pub fn record_sign_in(&mut self) {
        self.vouching = Vouching::Absent;
        self.touch();
    }

    /// Moves to a new status, as `by` decides. `owners` is every member of
    /// the organization as it stands now.
    ///
    /// Locking or deactivating someone shuts them out. So `by` needs the
    /// right to update members, only an owner moves an owner, and the last
    /// active owner is never shut out. Without that last rule, Ann, the only
    /// owner, deactivates herself by mistake and nobody can run the
    /// organization again.
    ///
    /// Reaching `Active` is joining, however it happened. That may be
    /// accepting an invitation, verifying an email, an admin activating the
    /// account, or bringing back one deactivated before it ever joined. So
    /// the join time is recorded on every move to `Active`, and no route
    /// there is left without a join date. Only the first join is kept.
    ///
    /// Raises `organization.org_user_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update members, or
    ///   this account is an owner and `by` is not one.
    /// - [`DomainError::Conflict`] when it would shut out the last active
    ///   owner.
    /// - [`DomainError::InvalidTransition`] when the current status cannot
    ///   move to `to`, or `to` is `Invited`, which only a new invitation
    ///   reaches. See [`reopen_for_invitation`](Self::reopen_for_invitation).
    /// - [`DomainError::InvalidTransition`] when the member is closing, or
    ///   `to` is `Closing`: only their erasure closes them, and only its
    ///   cancelling brings them back. See
    ///   [`OrgErasureRequest`](crate::domains::organization::members::privacy::erasure::OrgErasureRequest).
    pub fn change_status(
        &mut self,
        to: OrgUserStatus,
        by: &OrgControl<'_>,
        owners: Owners<'_>,
    ) -> Result<(), DomainError> {
        ensure_may_act_on(self, by, MemberAction::Update)?;
        if to == OrgUserStatus::Invited {
            return Err(DomainError::invalid_transition(message!(
                "organization-a-member-waits-to-join-again",
                "a member waits to join again only through a new invitation"
            )));
        }
        if to == OrgUserStatus::Closing || self.status == OrgUserStatus::Closing {
            return Err(DomainError::invalid_transition(message!(
                "organization-a-member-closes-and-comes-back",
                "a member closes, and comes back, only through their erasure"
            )));
        }
        if to != OrgUserStatus::Active {
            self.ensure_an_owner_stays(owners)?;
        }
        let from = self.status;
        self.move_to(to)?;
        self.status_moved(from);
        Ok(())
    }

    /// Raises `organization.org_user_status_changed`, from `from` to the
    /// status the member has now.
    fn status_moved(&mut self, from: OrgUserStatus) {
        self.raised.raise_organization(OrgUserStatusChanged {
            organization_id: self.organization_id,
            org_user_id: self.id,
            org_user_label: self.label(),
            from,
            to: self.status,
            occurred_at: self.updated_at,
        });
    }

    /// Reopens a deactivated account for invitation, keeping its identity and history.
    /// Clears the password, email proof and remembered-device trust. The caller must use
    /// [`ReopenedAccount`] to remove factors and passkeys, withdraw tenant grants, and
    /// ensure no invitation remains pending. The invited mailbox may have a new holder.
    /// Only an owner may reopen an owner's account or assign the owner role.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without invitation rights or required owner authority.
    /// [`DomainError::InvalidTransition`] unless the account is closed.
    pub fn reopen_for_invitation(
        &mut self,
        display_name: DisplayName,
        role: OrgRole,
        by: &OrgControl<'_>,
    ) -> Result<ReopenedAccount, DomainError> {
        ensure_may_act_on(self, by, MemberAction::Invite)?;
        ensure_may_hand_out(role, by.by())?;
        self.move_to(OrgUserStatus::Invited)?;
        self.display_name = display_name;
        self.role = role;
        self.address = AccountAddress::unverified(self.address.email().clone());
        self.password_hash = OrgPassword::NotSet;
        self.record_credential_change();
        Ok(ReopenedAccount::of(self))
    }

    /// Removes this member from the organization, as `by` decides, once
    /// the caller has taken away what they held. `owners` is every member
    /// as it stands now. Raises `organization.org_user_deleted`; the caller
    /// takes it once the account is deleted.
    ///
    /// Nobody removes themselves. Leaving takes another member's decision.
    /// Mallory steals Ann's session. Without this check, she erases the
    /// account she holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not remove members, or
    ///   this account is an owner and `by` is not one.
    /// - [`DomainError::Conflict`] when this is the last active owner.
    /// - [`DomainError::Forbidden`] when `by` is this member.
    pub fn remove(&mut self, by: &OrgControl<'_>, owners: Owners<'_>) -> Result<(), DomainError> {
        ensure_may_act_on(self, by, MemberAction::Remove)?;
        self.ensure_an_owner_stays(owners)?;
        if by.is_member(&self.id) {
            return Err(DomainError::forbidden(message!(
                "organization-a-member-cannot-remove-themselves-ask",
                "a member cannot remove themselves; ask another owner"
            )));
        }
        self.raised.raise_organization(OrgUserDeleted {
            organization_id: self.organization_id,
            org_user_id: self.id,
            org_user_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Closes an account whose invitation ended unanswered: it expired, was
    /// declined or was revoked. Only
    /// [`OrgInvitation::close_unanswered`](crate::domains::organization::members::invitation::OrgInvitation::close_unanswered)
    /// calls this, once it has checked the invitation.
    pub(crate) fn close_unanswered_invite(&mut self) -> Result<(), DomainError> {
        if self.status != OrgUserStatus::Invited {
            return Err(DomainError::conflict(message!(
                "organization-the-member-is-no-longer-waiting",
                "the member is no longer waiting to join"
            )));
        }
        Ok(self.move_to(OrgUserStatus::Deactivated)?)
    }

    /// Refuses taking this account away as an active owner unless another
    /// active owner stays.
    pub(crate) fn ensure_an_owner_stays(&self, owners: Owners<'_>) -> Result<(), DomainError> {
        if self.role != OrgRole::Owner || self.status != OrgUserStatus::Active {
            return Ok(());
        }
        owners.ensure_another_besides(self)
    }

    /// Moves to `to` and records the join on a move to `Active`.
    fn move_to(&mut self, to: OrgUserStatus) -> Result<(), InvalidOrgUserTransition> {
        self.status = self.status.try_transition(to)?;
        if to == OrgUserStatus::Active {
            self.joining = self.joining.join_at(crate::shared::clock::now());
        }
        self.touch();
        Ok(())
    }

    /// Replaces the organization role, as `by` decides. `owners` is every
    /// member of the organization as it stands now.
    ///
    /// Only an owner makes someone an owner or takes an owner's role away.
    /// An owner reaches every tenant, so this is the widest grant there is.
    /// The last active owner keeps the role. Raises
    /// `organization.org_user_role_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update members.
    /// - [`DomainError::Forbidden`] when the change makes or unmakes an owner
    ///   and `by` is not an owner.
    /// - [`DomainError::Conflict`] when it would demote the last active
    ///   owner.
    pub fn change_role(
        &mut self,
        role: OrgRole,
        by: &OrgControl<'_>,
        owners: Owners<'_>,
    ) -> Result<(), DomainError> {
        ensure_may_act_on(self, by, MemberAction::Update)?;
        ensure_may_hand_out(role, by.by())?;
        if role != OrgRole::Owner {
            self.ensure_an_owner_stays(owners)?;
        }
        let from = std::mem::replace(&mut self.role, role);
        self.touch();
        self.raised.raise_organization(OrgUserRoleChanged {
            organization_id: self.organization_id,
            org_user_id: self.id,
            org_user_label: self.label(),
            from,
            to: self.role,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Lets an invited member in: sets the password they chose, marks the
    /// invited address verified when the invitation proved it, and moves
    /// them to `Active`. `accepted` is what [`OrgInvitation::accept`] gives
    /// back: a handed over invitation proved no mailbox, and the address
    /// keeps its standing.
    ///
    /// Following the invitation link proves the person, so nobody else
    /// acts here, and it vouches for their first sign-in: a risky one may
    /// set a second factor up there and then, even where no mail could
    /// confirm it. Only someone still waiting to join is let in. An owner
    /// deactivated Alice before she accepted. Without this check, her old
    /// link switches her back on. Raises
    /// `organization.org_user_status_changed`, from `Invited` to `Active`,
    /// as every other move of a member's status does.
    ///
    /// [`OrgInvitation::accept`]: crate::domains::organization::members::invitation::OrgInvitation::accept
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the account is no longer invited.
    /// - [`DomainError::Forbidden`] when `accepted` is for another address
    ///   than the account has.
    pub fn accept_invitation(
        &mut self,
        password: PasswordHash,
        accepted: AcceptedAddress,
    ) -> Result<(), DomainError> {
        if self.status != OrgUserStatus::Invited {
            return Err(DomainError::conflict(message!(
                "organization-the-member-is-no-longer-waiting",
                "the member is no longer waiting to join"
            )));
        }
        if accepted.email() != self.email() {
            return Err(DomainError::forbidden(message!(
                "organization-the-invitation-was-for-another-address",
                "the invitation was for another address than the member has"
            )));
        }
        let from = self.status;
        self.move_to(OrgUserStatus::Active)?;
        if let Some(proof) = accepted.into_proof() {
            self.address = AccountAddress::verified(proof);
        }
        self.replace_password(password);
        self.vouching = Vouching::Fresh;
        self.status_moved(from);
        Ok(())
    }

    /// How an audit record names this member: their name and address
    /// together, so the record still reads after they are renamed or
    /// removed, such as "Ann (ann@acme.test)".
    pub(crate) fn label(&self) -> EventLabel {
        EventLabel::of(&format!("{} ({})", self.display_name, self.email()))
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl RaisesComplete for OrgUser {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::credentials::password::PasswordHasher;
    use crate::domains::authentication::sessions::sign_in_progress::finished_sign_in_of;
    use crate::domains::identity::account::verified_email::{VerifiedEmail, proof_of};
    use crate::domains::identity::tokens::installation_setup::InstallerProof;
    use crate::domains::organization::lifecycle::tests::founding_of;
    use crate::domains::organization::members::control::tests::{acting, session_of};
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::test_support::fakes::FakeHasher;
    use crate::types::PrincipalId;

    /// What `f` gives back when `member` acts through a fresh session of
    /// their own.
    fn by<R>(member: &OrgUser, f: impl FnOnce(&OrgControl<'_>) -> R) -> R {
        let session = session_of(member);
        f(&acting(member, &session))
    }

    /// `member` alone, as the owners the organization keeps.
    fn only(member: &OrgUser) -> Owners<'_> {
        Owners::of(std::slice::from_ref(member))
    }

    /// `user` moved to `to` by `owner`, who stays an owner beside them.
    fn moved(user: &mut OrgUser, to: OrgUserStatus, owner: &OrgUser) -> Result<(), DomainError> {
        by(owner, |c| user.change_status(to, c, only(owner)))
    }

    /// `user`'s password set to `hash` by `actor`.
    fn repassed(user: &mut OrgUser, hash: &str, actor: &OrgUser) -> Result<(), DomainError> {
        let hash = PasswordHash::from_stored(hash.to_owned());
        by(actor, |c| user.change_password(hash, c))
    }

    /// `user`'s address set to `email` by `actor`.
    fn readdressed(user: &mut OrgUser, email: &str, actor: &OrgUser) -> Result<(), DomainError> {
        let email = Email::new(email).unwrap();
        by(actor, |c| user.change_email(email, c))
    }

    fn params() -> CreateOrgUserParams {
        CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: OrganizationId::new(),
            email: Email::new("alice@acme.com").unwrap(),
            display_name: DisplayName::new("Alice", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::Set(PasswordHash::from_stored("hash".to_owned())),
            role: OrgRole::Owner,
        }
    }

    /// Someone made an owner of `params.organization_id` by founding it.
    fn found(params: CreateOrgUserParams) -> Result<OrgUser, DomainError> {
        let founding = founding_of(params.organization_id);
        OrgUser::create(params, AddedBy::Founding(founding))
    }

    /// The founder of a fresh organization, its first owner.
    fn founded() -> OrgUser {
        found(params()).unwrap()
    }

    /// Someone `by` adds to its organization with `role`.
    fn added(owner: &OrgUser, role: OrgRole) -> OrgUser {
        by(owner, |control| {
            OrgUser::create(
                CreateOrgUserParams {
                    id: OrgUserId::new(),
                    organization_id: owner.organization_id,
                    role,
                    ..params()
                },
                AddedBy::Member(*control),
            )
        })
        .unwrap()
    }

    /// An active owner of `member`'s organization, who may act on anyone
    /// in it.
    fn owner_of(member: &OrgUser) -> OrgUser {
        found(CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: member.organization_id,
            ..params()
        })
        .unwrap()
    }

    /// The founder of a fresh organization whose password is `raw`.
    fn founded_with_password(raw: &str) -> OrgUser {
        found(CreateOrgUserParams {
            password_hash: OrgPassword::Set(FakeHasher.hash(raw).unwrap()),
            ..params()
        })
        .unwrap()
    }

    /// The password `user` has now, as stored.
    fn password_of(user: &OrgUser) -> Option<&str> {
        user.password_hash().hash().map(PasswordHash::as_str)
    }

    /// An owner its organization's founder invited.
    fn invited() -> OrgUser {
        let founder = founded();
        by(&founder, |control| {
            OrgUser::invite(
                CreateOrgUserParams {
                    organization_id: founder.organization_id,
                    ..params()
                },
                control,
            )
        })
        .unwrap()
    }

    /// Sam's member role cannot promote, add or invite an owner. Each attempt
    /// is forbidden, and the existing member keeps their role.
    #[test]
    fn only_an_owner_makes_an_owner() {
        let founder = founded();
        let mut member = added(&founder, OrgRole::Member);
        let sam = added(&founder, OrgRole::Member);
        let as_owner = || CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: founder.organization_id,
            ..params()
        };

        let promoted = by(&sam, |c| {
            member.change_role(OrgRole::Owner, c, only(&founder))
        });
        let added_owner = by(&sam, |c| OrgUser::create(as_owner(), AddedBy::Member(*c)));
        let invited_owner = by(&sam, |c| OrgUser::invite(as_owner(), c));

        assert!(matches!(promoted, Err(DomainError::Forbidden(_))));
        assert!(matches!(added_owner, Err(DomainError::Forbidden(_))));
        assert!(matches!(invited_owner, Err(DomainError::Forbidden(_))));
        assert_eq!(member.role(), OrgRole::Member);
    }

    /// Sam cannot add or invite another member with his member role. Both
    /// operations are forbidden.
    #[test]
    fn a_plain_member_brings_nobody_in() {
        let founder = founded();
        let sam = added(&founder, OrgRole::Member);
        let as_member = || CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: founder.organization_id,
            role: OrgRole::Member,
            ..params()
        };

        let added_member = by(&sam, |c| OrgUser::create(as_member(), AddedBy::Member(*c)));
        let invited_member = by(&sam, |c| OrgUser::invite(as_member(), c));

        assert!(matches!(added_member, Err(DomainError::Forbidden(_))));
        assert!(matches!(invited_member, Err(DomainError::Forbidden(_))));
    }

    /// A member cannot demote a co-owner. The forbidden change leaves the
    /// co-owner's role intact.
    #[test]
    fn only_an_owner_unmakes_an_owner() {
        let founder = founded();
        let mut co_owner = added(&founder, OrgRole::Owner);
        let member = added(&founder, OrgRole::Member);

        let demoted = by(&member, |c| {
            co_owner.change_role(OrgRole::Member, c, only(&founder))
        });

        assert!(matches!(demoted, Err(DomainError::Forbidden(_))));
        assert_eq!(co_owner.role(), OrgRole::Owner);
    }

    /// Owning Globex gives Mallory no authority to promote a member of Acme.
    /// Her attempt is forbidden.
    #[test]
    fn an_owner_of_another_organization_makes_no_owner_here() {
        let founder = founded();
        let mut member = added(&founder, OrgRole::Member);
        let stranger = founded();

        let promoted = by(&stranger, |c| {
            member.change_role(OrgRole::Owner, c, only(&founder))
        });

        assert!(matches!(promoted, Err(DomainError::Forbidden(_))));
    }

    /// Acme's last owner cannot be deactivated, locked, demoted or removed.
    /// Each attempt conflicts, leaving Ann active and an owner.
    #[test]
    fn the_last_active_owner_is_never_taken_away() {
        let mut ann = founded();
        let members = [
            OrgUser::reconstitute(row_of(&ann)).unwrap(),
            added(&ann, OrgRole::Member),
        ];
        let owners = Owners::of(&members);
        let session = session_of(&ann);
        let by_ann = acting(&members[0], &session);

        let deactivated = ann.change_status(OrgUserStatus::Deactivated, &by_ann, owners);
        let locked = ann.change_status(OrgUserStatus::Locked, &by_ann, owners);
        let demoted = ann.change_role(OrgRole::Member, &by_ann, owners);
        let removed = ann.remove(&by_ann, owners);

        assert!(matches!(deactivated, Err(DomainError::Conflict(_))));
        assert!(matches!(locked, Err(DomainError::Conflict(_))));
        assert!(matches!(demoted, Err(DomainError::Conflict(_))));
        assert!(matches!(removed, Err(DomainError::Conflict(_))));
        assert_eq!(ann.status(), OrgUserStatus::Active);
        assert_eq!(ann.role(), OrgRole::Owner);
    }

    /// Ann and Bob both own Acme. Ann steps down to member, since Bob still
    /// runs the organization.
    #[test]
    fn an_owner_steps_down_while_another_stays() {
        let mut ann = founded();
        let bob = added(&ann, OrgRole::Owner);

        by(&bob, |c| ann.change_role(OrgRole::Member, c, only(&bob))).unwrap();

        assert_eq!(ann.role(), OrgRole::Member);
    }

    /// Ann cannot remove herself even when Acme has another owner. Bob can
    /// remove her using his own owner authority.
    #[test]
    fn a_member_never_removes_themselves() {
        let mut ann = founded();
        let bob = added(&ann, OrgRole::Owner);
        let members = [OrgUser::reconstitute(row_of(&ann)).unwrap(), bob];
        let owners = Owners::of(&members);

        let by_ann = by(&members[0], |c| ann.remove(c, owners));
        let by_bob = by(&members[1], |c| ann.remove(c, owners));

        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert!(by_bob.is_ok());
    }

    /// The row `member` would be stored as, to load a second copy of it.
    pub(super) fn row_of(member: &OrgUser) -> OrgUserRow {
        OrgUserRow {
            id: member.id,
            organization_id: member.organization_id,
            email: member.email().clone(),
            display_name: member.display_name.clone(),
            password_hash: member.password_hash.clone(),
            status: member.status,
            role: member.role,
            email_standing: AddressStanding::Unverified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: member.created_at,
            updated_at: member.updated_at,
            joining: member.joining,
            credentials_changed_at: member.credentials_changed_at,
            vouching: member.vouching,
        }
    }

    /// Someone founding an organization is created as a plain member. It is
    /// refused, since an organization starts with its founder as owner.
    #[test]
    fn a_founder_is_always_an_owner() {
        let result = found(CreateOrgUserParams {
            role: OrgRole::Member,
            ..params()
        });

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An account still waiting on its address, as storage can hold one.
    fn pending_verification() -> OrgUser {
        let now = crate::shared::clock::now();
        OrgUser::reconstitute(OrgUserRow {
            id: OrgUserId::new(),
            organization_id: OrganizationId::new(),
            email: Email::new("alice@acme.com").unwrap(),
            display_name: DisplayName::new("Alice", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::Set(PasswordHash::from_stored("hash".to_owned())),
            status: OrgUserStatus::PendingVerification,
            role: OrgRole::Member,
            email_standing: AddressStanding::Unverified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining: Joining::NotYet,
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        })
        .unwrap()
    }

    /// Alice's address is not confirmed. Where a link could confirm it her
    /// sign-in waits for that; where no mail server is set up it goes on,
    /// and the address stays unverified.
    #[test]
    fn an_unconfirmed_address_admits_a_sign_in_only_without_mail() {
        let alice = founded();

        assert!(!alice.address_admits_sign_in(MailReach::Available));
        assert!(alice.address_admits_sign_in(MailReach::NotSetUp));
        assert!(!alice.email_verified());
    }

    /// Alice founds Acme. Her account is active and keeps her address and
    /// display name.
    #[test]
    fn create_produces_active_user() {
        let user = founded();

        assert_eq!(user.status(), OrgUserStatus::Active);
        assert_eq!(user.email().as_str(), "alice@acme.com");
        assert_eq!(user.display_name().as_str(), "Alice");
    }

    /// Alice founds Acme with `alice@acme.com`. Her address starts
    /// unverified, since nobody has followed a link sent to it yet.
    #[test]
    fn a_created_account_starts_with_its_address_unverified() {
        let user = founded();

        assert!(!user.email_verified());
    }

    /// Alice founds Acme. She can sign in at once and has a join date.
    #[test]
    fn a_created_account_is_joined_immediately() {
        let user = founded();

        assert!(user.status().can_authenticate());
        assert!(user.joined_at().is_some());
    }

    /// Alice's account waits on her address, and she follows the link. Her
    /// address is verified, her account turns active, and she has joined.
    #[test]
    fn verifying_email_activates_a_pending_account() {
        let mut user = pending_verification();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert_eq!(user.status(), OrgUserStatus::Active);
        assert!(user.email_verified());
        assert!(user.joined_at().is_some());
    }

    /// Confirming Alice's address after deactivation succeeds without
    /// reactivating her account.
    #[test]
    fn verifying_email_does_not_revive_a_deactivated_account() {
        let mut user = founded();
        let owner = owner_of(&user);
        moved(&mut user, OrgUserStatus::Deactivated, &owner).unwrap();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert_eq!(user.status(), OrgUserStatus::Deactivated);
    }

    /// Alice is invited and starts with an unverified address. Once she
    /// proves it, it reads as verified.
    #[test]
    fn invite_starts_unverified_and_verify_email_flips_it() {
        let mut user = invited();
        assert!(!user.email_verified());

        user.verify_email(&proof_of(user.email())).unwrap();

        assert!(user.email_verified());
    }

    /// Alice's address is verified, and she founds another organization
    /// while signed in. Her own sign-in vouches for her address.
    #[test]
    fn a_members_own_sign_in_vouches_for_their_verified_address() {
        let mut alice = founded();
        alice.verify_email(&proof_of(alice.email())).unwrap();
        let hers = finished_sign_in_of(PrincipalId::from(*alice.id()));

        let vouched = alice.vouched_address(&hers).unwrap();

        assert_eq!(vouched.as_email(), alice.email());
    }

    /// Mallory's completed sign-in cannot vouch for Alice's address. The
    /// request is forbidden even though Alice's address is verified.
    #[test]
    fn another_members_sign_in_vouches_for_nothing() {
        let mut alice = founded();
        alice.verify_email(&proof_of(alice.email())).unwrap();
        let mallorys = finished_sign_in_of(PrincipalId::from(OrgUserId::new()));

        let refused = alice.vouched_address(&mallorys);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Alice's completed sign-in cannot vouch for her unverified address.
    /// Requesting that proof is forbidden.
    #[test]
    fn an_unverified_address_is_vouched_for_by_nobody() {
        let alice = founded();
        let hers = finished_sign_in_of(PrincipalId::from(*alice.id()));

        let refused = alice.vouched_address(&hers);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An active member is locked. Their status reads as locked.
    #[test]
    fn can_lock_active_user() {
        let mut user = founded();
        let owner = owner_of(&user);

        moved(&mut user, OrgUserStatus::Locked, &owner).unwrap();

        assert_eq!(user.status(), OrgUserStatus::Locked);
    }

    /// An active member is deactivated. Their status reads as deactivated.
    #[test]
    fn can_deactivate_active_user() {
        let mut user = founded();
        let owner = owner_of(&user);

        moved(&mut user, OrgUserStatus::Deactivated, &owner).unwrap();

        assert_eq!(user.status(), OrgUserStatus::Deactivated);
    }

    /// A deactivated member is made active again. Their status reads as
    /// active.
    #[test]
    fn deactivated_can_reactivate() {
        let mut user = founded();
        let owner = owner_of(&user);
        moved(&mut user, OrgUserStatus::Deactivated, &owner).unwrap();

        assert!(moved(&mut user, OrgUserStatus::Active, &owner).is_ok());
        assert_eq!(user.status(), OrgUserStatus::Active);
    }

    /// The founder invites someone as a member. The invitee is a member and
    /// the founder stays an owner.
    #[test]
    fn factories_carry_the_requested_role() {
        let founder = founded();
        let member = by(&founder, |c| {
            OrgUser::invite(
                CreateOrgUserParams {
                    organization_id: founder.organization_id,
                    role: OrgRole::Member,
                    ..params()
                },
                c,
            )
        })
        .unwrap();
        assert_eq!(member.role(), OrgRole::Member);
        assert_eq!(founder.role(), OrgRole::Owner);
    }

    /// The founder demotes a co-owner to member. The co-owner is now a
    /// member.
    #[test]
    fn change_role_replaces_the_role() {
        let founder = founded();
        let mut user = added(&founder, OrgRole::Owner);

        by(&founder, |c| {
            user.change_role(OrgRole::Member, c, only(&founder))
        })
        .unwrap();

        assert_eq!(user.role(), OrgRole::Member);
    }

    /// An owner sets a new password for Alice. The account keeps the new
    /// hash.
    #[test]
    fn change_password_updates_hash() {
        let mut user = founded();
        let owner = owner_of(&user);

        repassed(&mut user, "new_hash", &owner).unwrap();

        assert_eq!(password_of(&user), Some("new_hash"));
    }

    /// An owner resets Alice's password at a frozen time. That time is
    /// recorded as a credential change, so every device she remembered
    /// before must ask for a second factor again.
    #[test]
    fn changing_the_password_records_a_credential_change() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut user = founded();
        let owner = owner_of(&user);
        assert!(user.credentials_changed_at() == CredentialChange::Never);

        let _frozen = crate::shared::clock::freeze(now);
        repassed(&mut user, "new_hash", &owner).unwrap();

        assert_eq!(user.credentials_changed_at().changed_at(), Some(now));
    }

    /// Sam's member role cannot lock Ann or change her password or address.
    /// Ann remains active with her original address and password, and her
    /// credential-change marker stays unset.
    #[test]
    fn a_member_cannot_act_on_an_owners_sign_in() {
        let founder = founded();
        let mut ann = added(&founder, OrgRole::Owner);
        let sam = added(&founder, OrgRole::Member);

        let locked = moved(&mut ann, OrgUserStatus::Locked, &sam);
        let reset = repassed(&mut ann, "sams", &sam);
        let readdress = readdressed(&mut ann, "sam@acme.com", &sam);

        assert!(matches!(locked, Err(DomainError::Forbidden(_))));
        assert!(matches!(reset, Err(DomainError::Forbidden(_))));
        assert!(matches!(readdress, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.status(), OrgUserStatus::Active);
        assert_eq!(password_of(&ann), Some("hash"));
        assert_eq!(ann.credentials_changed_at(), CredentialChange::Never);
        assert_eq!(ann.email().as_str(), "alice@acme.com");
    }

    /// The founder locks Ann, a co-owner, and resets her password. Both
    /// are allowed, since an owner may act on another owner.
    #[test]
    fn an_owner_acts_on_a_co_owners_sign_in() {
        let founder = founded();
        let mut ann = added(&founder, OrgRole::Owner);

        moved(&mut ann, OrgUserStatus::Locked, &founder).unwrap();
        repassed(&mut ann, "reset", &founder).unwrap();

        assert_eq!(ann.status(), OrgUserStatus::Locked);
        assert_eq!(password_of(&ann), Some("reset"));
    }

    /// An owner cannot use administrative authority to reset her own password.
    /// The refusal preserves her password and credential-change marker.
    #[test]
    fn a_member_does_not_set_their_own_password_as_an_admin() {
        let mut ann = founded();
        let as_ann = OrgUser::reconstitute(row_of(&ann)).unwrap();

        let reset = repassed(&mut ann, "mallorys", &as_ann);

        assert!(matches!(reset, Err(DomainError::Forbidden(_))));
        assert_eq!(password_of(&ann), Some("hash"));
        assert_eq!(ann.credentials_changed_at(), CredentialChange::Never);
    }

    /// An owner's administrative authority cannot change her own address.
    /// The forbidden attempt leaves her original address in place.
    #[test]
    fn a_member_does_not_move_their_own_address_as_an_admin() {
        let mut ann = founded();
        let as_ann = OrgUser::reconstitute(row_of(&ann)).unwrap();

        let readdress = readdressed(&mut ann, "mallory@evil.example", &as_ann);

        assert!(matches!(readdress, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.email().as_str(), "alice@acme.com");
    }

    /// Sam cannot deactivate or remove another member using his member role.
    /// Both attempts are forbidden, and Bob stays active.
    #[test]
    fn a_member_cannot_act_on_another_member() {
        let founder = founded();
        let mut bob = added(&founder, OrgRole::Member);
        let sam = added(&founder, OrgRole::Member);

        let deactivated = moved(&mut bob, OrgUserStatus::Deactivated, &sam);
        let removed = by(&sam, |c| bob.remove(c, only(&founder)));

        assert!(matches!(deactivated, Err(DomainError::Forbidden(_))));
        assert!(matches!(removed, Err(DomainError::Forbidden(_))));
        assert_eq!(bob.status(), OrgUserStatus::Active);
    }

    /// A member cannot reset another member's password. Bob keeps his original
    /// password and unchanged credential marker after Sam's forbidden attempt.
    #[test]
    fn a_member_cannot_set_another_members_password() {
        let founder = founded();
        let mut bob = added(&founder, OrgRole::Member);
        let sam = added(&founder, OrgRole::Member);
        let sams = PasswordHash::from_stored("sams".to_owned());

        let result = by(&sam, |c| bob.change_password(sams, c));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(password_of(&bob), Some("hash"));
        assert_eq!(bob.credentials_changed_at(), CredentialChange::Never);
    }

    /// A Globex owner cannot reset an Acme member's password. Mallory's
    /// forbidden attempt leaves Bob's password unchanged.
    #[test]
    fn an_owner_of_another_organization_cannot_act_on_a_member_here() {
        let founder = founded();
        let mut bob = added(&founder, OrgRole::Member);
        let mallory = founded();

        let reset = repassed(&mut bob, "m", &mallory);

        assert!(matches!(reset, Err(DomainError::Forbidden(_))));
        assert_eq!(password_of(&bob), Some("hash"));
    }

    /// A locked owner's attempt to change another member's address is
    /// forbidden. Bob keeps his original address.
    #[test]
    fn a_locked_member_cannot_act_on_anyone() {
        let founder = founded();
        let mut bob = added(&founder, OrgRole::Member);
        let mut ann = added(&founder, OrgRole::Owner);
        moved(&mut ann, OrgUserStatus::Locked, &founder).unwrap();

        let readdress = readdressed(&mut bob, "ann@acme.com", &ann);

        assert!(matches!(readdress, Err(DomainError::Forbidden(_))));
        assert_eq!(bob.email().as_str(), "alice@acme.com");
    }

    /// Alice changes her own password and gives her current one. The new
    /// one is kept and recorded as a credential change.
    #[test]
    fn the_own_password_changes_with_the_current_one() {
        let hasher = FakeHasher;
        let mut alice = founded_with_password("old");

        alice
            .change_own_password("old", hasher.hash("new").unwrap(), &hasher)
            .unwrap();

        assert_eq!(password_of(&alice), Some("fake$new"));
        assert!(alice.credentials_changed_at().changed_at().is_some());
    }

    /// Giving the wrong current password forbids Alice's password change.
    /// Her original password remains in place.
    #[test]
    fn the_own_password_does_not_change_without_the_current_one() {
        let hasher = FakeHasher;
        let mut alice = founded_with_password("old");

        let changed = alice.change_own_password("guess", hasher.hash("mallorys").unwrap(), &hasher);

        assert!(matches!(changed, Err(DomainError::Forbidden(_))));
        assert_eq!(password_of(&alice), Some("fake$old"));
    }

    /// An account with no password cannot change it by supplying an empty
    /// current password. The forbidden attempt leaves the password unset.
    #[test]
    fn an_account_without_a_password_cannot_prove_one() {
        let hasher = FakeHasher;
        let mut alice = found(CreateOrgUserParams {
            password_hash: OrgPassword::NotSet,
            ..params()
        })
        .unwrap();

        let changed = alice.change_own_password("", hasher.hash("mallorys").unwrap(), &hasher);

        assert!(matches!(changed, Err(DomainError::Forbidden(_))));
        assert_eq!(alice.password_hash(), &OrgPassword::NotSet);
    }

    /// Alice follows a reset link mailed to her address. Her new password
    /// is kept.
    #[test]
    fn a_reset_link_to_the_current_address_sets_the_password() {
        let mut alice = founded();

        alice
            .reset_password(
                PasswordHash::from_stored("new".to_owned()),
                &proof_of(alice.email()),
            )
            .unwrap();

        assert_eq!(password_of(&alice), Some("new"));
    }

    /// After Alice's address changes, proof of her old mailbox cannot reset
    /// her password. The forbidden reset preserves her original password.
    #[test]
    fn a_reset_link_to_a_former_address_is_refused() {
        let mut alice = founded();
        let old = proof_of(alice.email());
        alice.change_verified_email(proof_of(&Email::new("alice@new.acme.com").unwrap()));

        let reset = alice.reset_password(PasswordHash::from_stored("mallorys".to_owned()), &old);

        assert!(matches!(reset, Err(DomainError::Forbidden(_))));
        assert_eq!(password_of(&alice), Some("hash"));
    }

    /// Alice accepts her invitation and picks a password. She is active,
    /// joined, holds a verified address and has the password she chose.
    #[test]
    fn accepting_an_invitation_lets_the_member_in() {
        let mut alice = invited();
        let proof = AcceptedAddress::proven(proof_of(alice.email()));

        alice
            .accept_invitation(PasswordHash::from_stored("chosen".to_owned()), proof)
            .unwrap();

        assert_eq!(alice.status(), OrgUserStatus::Active);
        assert!(alice.joined_at().is_some());
        assert!(alice.email_verified());
        assert_eq!(password_of(&alice), Some("chosen"));
    }

    /// Alice accepts her invitation. Her move from invited to active is
    /// raised once, as every other status change is.
    #[test]
    fn accepting_an_invitation_raises_the_status_change() {
        let mut alice = invited();
        raised_complete_names(&mut alice);
        let proof = AcceptedAddress::proven(proof_of(alice.email()));

        alice
            .accept_invitation(PasswordHash::from_stored("chosen".to_owned()), proof)
            .unwrap();

        let events = alice.take_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "organization.org_user_status_changed"
        );
        let payload = events[0].payload();
        let Some(FieldValue::Change(status)) = payload.value("status") else {
            panic!("the status change is missing");
        };
        assert_eq!(status.from(), Some("Invited"));
        assert_eq!(status.to(), Some("Active"));
    }

    /// Alice accepts an invitation that was handed over, on a deployment
    /// with no mail server. She is active with the password she chose, and
    /// her address stays unverified.
    #[test]
    fn accepting_a_handed_over_invitation_leaves_the_address_unverified() {
        let mut alice = invited();
        let unproven = AcceptedAddress::unproven(alice.email().clone());

        alice
            .accept_invitation(PasswordHash::from_stored("chosen".to_owned()), unproven)
            .unwrap();

        assert_eq!(alice.status(), OrgUserStatus::Active);
        assert!(!alice.email_verified());
        assert_eq!(password_of(&alice), Some("chosen"));
    }

    /// Alice accepts the link an owner handed her. The invitation vouches
    /// for her first sign-in, and that sign-in spends it.
    #[test]
    fn accepting_vouches_for_the_first_sign_in_only() {
        let mut alice = invited();
        let unproven = AcceptedAddress::unproven(alice.email().clone());
        assert_eq!(alice.vouching(), Vouching::Absent);

        alice
            .accept_invitation(PasswordHash::from_stored("chosen".to_owned()), unproven)
            .unwrap();
        assert_eq!(alice.vouching(), Vouching::Fresh);

        alice.record_sign_in();
        assert_eq!(alice.vouching(), Vouching::Absent);
    }

    /// Olive ran the install and presents its setup token. Her address is
    /// verified, and the token vouches for her first sign-in.
    #[test]
    fn the_setup_token_confirms_the_owner_and_vouches_for_her() {
        let mut olive = founded();
        let proof = InstallerProof::spent_for(proof_of(olive.email()));

        olive.confirm_as_installer(&proof).unwrap();

        assert!(olive.email_verified());
        assert_eq!(olive.vouching(), Vouching::Fresh);
    }

    /// An invited member cannot be vouched for with an installer proof.
    /// The attempt conflicts and leaves the member without vouching.
    #[test]
    fn the_setup_token_confirms_no_member_who_never_joined() {
        let mut alice = invited();
        let proof = InstallerProof::spent_for(proof_of(alice.email()));

        let confirmed = alice.confirm_as_installer(&proof);

        assert!(matches!(confirmed, Err(DomainError::Conflict(_))));
        assert_eq!(alice.vouching(), Vouching::Absent);
    }

    /// A stored member is still invited, yet a route vouches for their next
    /// sign-in. Every route that vouches also joins, so the row is refused
    /// as corrupt.
    #[test]
    fn a_stored_member_vouched_for_before_joining_is_refused() {
        let row = OrgUserRow {
            vouching: Vouching::Fresh,
            ..row_of(&invited())
        };

        assert!(refused_as_corrupt(&OrgUser::reconstitute(row)));
    }

    /// Accepting Alice's invitation after an owner deactivates her conflicts.
    /// Her account remains deactivated.
    #[test]
    fn an_invitation_does_not_bring_back_a_deactivated_member() {
        let mut alice = invited();
        let owner = owner_of(&alice);
        moved(&mut alice, OrgUserStatus::Deactivated, &owner).unwrap();
        let proof = AcceptedAddress::proven(proof_of(alice.email()));

        let accepted = alice.accept_invitation(PasswordHash::from_stored("p".to_owned()), proof);

        assert!(matches!(accepted, Err(DomainError::Conflict(_))));
        assert_eq!(alice.status(), OrgUserStatus::Deactivated);
    }

    /// Proof of the old mailbox cannot accept an invitation after Alice's
    /// address changes. She stays invited with her original password.
    #[test]
    fn an_invitation_for_a_former_address_is_refused() {
        let mut alice = invited();
        let old = AcceptedAddress::proven(proof_of(alice.email()));
        let owner = owner_of(&alice);
        readdressed(&mut alice, "alice@new.acme.com", &owner).unwrap();

        let accepted = alice.accept_invitation(PasswordHash::from_stored("m".to_owned()), old);

        assert!(matches!(accepted, Err(DomainError::Forbidden(_))));
        assert_eq!(alice.status(), OrgUserStatus::Invited);
        assert_eq!(password_of(&alice), Some("hash"));
    }

    /// Alice adds a second factor at a frozen time. That exact time is
    /// recorded as her last credential change.
    #[test]
    fn a_factor_change_is_recorded_at_the_moment_it_happens() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut user = founded();

        let _frozen = crate::shared::clock::freeze(now);
        user.record_credential_change();

        assert_eq!(user.credentials_changed_at().changed_at(), Some(now));
    }

    /// Bob's locked, verified member account is loaded from storage. Its ids,
    /// address, status, role, password, join and credential times come back
    /// as stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let id = OrgUserId::new();
        let org_id = OrganizationId::new();
        let now = crate::shared::clock::now();

        let user = OrgUser::reconstitute(locked_member_row(id, org_id, now)).unwrap();

        assert_eq!(user.credentials_changed_at().changed_at(), Some(now));
        assert_eq!(*user.id(), id);
        assert_eq!(*user.organization_id(), org_id);
        assert_eq!(user.email().as_str(), "bob@acme.com");
        assert_eq!(user.status(), OrgUserStatus::Locked);
        assert_eq!(user.role(), OrgRole::Member);
        assert_eq!(
            user.password_hash().hash().map(PasswordHash::as_str),
            Some("stored_hash")
        );
        assert_eq!(user.joined_at(), Some(now));
    }

    /// Stores Bob after joining with a verified address, a password and a locked account.
    fn locked_member_row(id: OrgUserId, org_id: OrganizationId, now: OffsetDateTime) -> OrgUserRow {
        OrgUserRow {
            id,
            organization_id: org_id,
            email: Email::new("bob@acme.com").unwrap(),
            display_name: DisplayName::new("Bob", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::Set(PasswordHash::from_stored("stored_hash".to_owned())),
            status: OrgUserStatus::Locked,
            role: OrgRole::Member,
            email_standing: AddressStanding::Verified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining: Joining::Joined { at: now },
            credentials_changed_at: CredentialChange::from_stored(Some(now)),
            vouching: Vouching::Absent,
        }
    }

    /// Alice is invited but has not accepted. She has no join date.
    #[test]
    fn an_invited_account_has_not_joined() {
        assert!(invited().joined_at().is_none());
    }

    /// An owner activates Alice's invited account directly, without her
    /// following the link. She still gets a join date.
    #[test]
    fn activating_an_invited_member_stamps_the_join() {
        let mut user = invited();
        let owner = owner_of(&user);
        assert!(user.joined_at().is_none());

        moved(&mut user, OrgUserStatus::Active, &owner).unwrap();

        assert!(user.joined_at().is_some());
    }

    /// An owner activates an account still waiting on its address. It gets a
    /// join date at that moment.
    #[test]
    fn activating_a_pending_verification_member_stamps_the_join() {
        let mut user = pending_verification();
        let owner = owner_of(&user);
        assert_eq!(user.status(), OrgUserStatus::PendingVerification);
        assert!(user.joined_at().is_none());

        moved(&mut user, OrgUserStatus::Active, &owner).unwrap();

        assert!(user.joined_at().is_some());
    }

    /// Alice confirms her address while her account waits on it. She turns
    /// active and gets a join date.
    #[test]
    fn verifying_an_email_stamps_the_join() {
        let mut user = pending_verification();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert_eq!(user.status(), OrgUserStatus::Active);
        assert!(user.joined_at().is_some());
    }

    /// Alice joins, is locked out, and is let back in. Her join date stays
    /// the first one.
    #[test]
    fn returning_to_active_keeps_the_original_join() {
        let mut user = invited();
        let owner = owner_of(&user);
        moved(&mut user, OrgUserStatus::Active, &owner).unwrap();
        let first = user.joined_at().expect("joined on activation");

        moved(&mut user, OrgUserStatus::Locked, &owner).unwrap();
        moved(&mut user, OrgUserStatus::Active, &owner).unwrap();

        assert_eq!(user.joined_at(), Some(first));
    }

    /// Alice is invited and then deactivated before she accepts. She has no
    /// join date.
    #[test]
    fn a_member_who_never_reached_active_has_not_joined() {
        let mut user = invited();
        let owner = owner_of(&user);

        moved(&mut user, OrgUserStatus::Deactivated, &owner).unwrap();

        assert!(user.joined_at().is_none());
    }

    /// Alice changes her display name to "Alice Smith" and her address to
    /// `alice.smith@acme.com`. Both changes are kept.
    #[test]
    fn changing_the_display_name_or_email_takes_effect() {
        let mut user = founded();
        let owner = owner_of(&user);
        let herself = OrgUser::reconstitute(row_of(&user)).unwrap();
        let name = DisplayName::new("Alice Smith", &DisplayNameLimits::default()).unwrap();

        by(&herself, |c| user.change_display_name(name, c)).unwrap();
        readdressed(&mut user, "alice.smith@acme.com", &owner).unwrap();

        assert_eq!(user.display_name().as_str(), "Alice Smith");
        assert_eq!(user.email().as_str(), "alice.smith@acme.com");
    }

    /// An administrative change from Alice's verified address to an unproven
    /// address clears her account's verified-email status.
    #[test]
    fn an_unproven_address_is_not_verified() {
        let mut user = founded();
        let owner = owner_of(&user);
        user.verify_email(&proof_of(user.email())).unwrap();
        assert!(user.email_verified());

        readdressed(&mut user, "someone.else@acme.com", &owner).unwrap();

        assert!(!user.email_verified());
    }

    /// Alice confirms a change to `alice.smith@acme.com`. The account takes
    /// that address and reads as verified.
    #[test]
    fn a_proven_address_stays_verified() {
        let mut user = founded();
        let owner = owner_of(&user);
        readdressed(&mut user, "interim@acme.com", &owner).unwrap();

        user.change_verified_email(VerifiedEmail::proven(
            Email::new("alice.smith@acme.com").unwrap(),
        ));

        assert_eq!(user.email().as_str(), "alice.smith@acme.com");
        assert!(user.email_verified());
    }

    /// Alice starts with the organization's locale and timezone, then picks
    /// German and Berlin. Her own choices are the ones kept.
    #[test]
    fn a_member_keeps_the_locale_and_timezone_they_chose() {
        let mut user = founded();
        let herself = OrgUser::reconstitute(row_of(&user)).unwrap();

        assert_eq!(user.locale(), &Preference::Inherited);
        assert_eq!(user.timezone(), &Preference::Inherited);

        by(&herself, |c| {
            user.change_preferences(
                Preference::Own(Locale::new("de-DE").unwrap()),
                Preference::Own(Timezone::new("Europe/Berlin").unwrap()),
                c,
            )
        })
        .unwrap();

        assert_eq!(user.locale().value().unwrap().as_str(), "de-DE");
        assert_eq!(user.timezone().value().unwrap().as_str(), "Europe/Berlin");
    }

    /// Sam cannot rename an owner or change her preferences with his member
    /// role, and her name stays unchanged. The owner can rename Sam, who can
    /// then rename himself.
    #[test]
    fn only_the_member_or_someone_who_may_update_members_edits_a_profile() {
        let mut ann = founded();
        let mut sam = added(&ann, OrgRole::Member);
        let sam_himself = OrgUser::reconstitute(row_of(&sam)).unwrap();
        let name = |text: &str| DisplayName::new(text, &DisplayNameLimits::default()).unwrap();

        let renamed = by(&sam, |c| {
            ann.change_display_name(name("Former employee"), c)
        });
        let moved = by(&sam, |c| {
            ann.change_preferences(Preference::Inherited, Preference::Inherited, c)
        });
        let by_owner = by(&ann, |c| sam.change_display_name(name("Samuel"), c));
        let by_himself = by(&sam_himself, |c| sam.change_display_name(name("Sam"), c));

        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.display_name().as_str(), "Alice");
        assert!(by_owner.is_ok() && by_himself.is_ok());
        assert_eq!(sam.display_name().as_str(), "Sam");
    }

    /// A member's role changes five minutes after they were added.
    /// `updated_at` moves to that moment and `created_at` stays, so caches
    /// see the change.
    #[test]
    fn editing_a_member_moves_the_timestamp_readers_watch() {
        let founder = founded();
        let mut user = added(&founder, OrgRole::Owner);
        let created = user.updated_at();
        let later = created + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        by(&founder, |c| {
            user.change_role(OrgRole::Member, c, only(&founder))
        })
        .unwrap();

        assert_eq!(user.updated_at(), later);
        assert_eq!(user.created_at(), created);
    }

    /// A stored member still waits on their address but has a join date.
    /// Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_member_joined_while_still_unverified_is_refused() {
        let member = pending_verification();
        let row = OrgUserRow {
            id: member.id,
            organization_id: member.organization_id,
            email: member.email().clone(),
            display_name: member.display_name.clone(),
            password_hash: member.password_hash.clone(),
            status: OrgUserStatus::PendingVerification,
            role: member.role,
            email_standing: AddressStanding::Unverified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: member.created_at,
            updated_at: member.updated_at,
            joining: Joining::Joined {
                at: member.created_at,
            },
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        };

        assert!(refused_as_corrupt(&OrgUser::reconstitute(row)));
    }

    /// Reactivating a member deactivated before accepting her invitation sets
    /// a join date.
    #[test]
    fn reactivating_a_member_who_never_joined_stamps_the_join() {
        let mut user = invited();
        let owner = owner_of(&user);
        moved(&mut user, OrgUserStatus::Deactivated, &owner).unwrap();

        moved(&mut user, OrgUserStatus::Active, &owner).unwrap();

        assert!(user.joined_at().is_some());
    }

    /// Stored active and locked members require a join date. Loading either
    /// status without one reports corrupt storage.
    #[test]
    fn a_stored_active_or_locked_member_with_no_join_date_is_refused() {
        for status in [OrgUserStatus::Active, OrgUserStatus::Locked] {
            let member = founded();
            let row = OrgUserRow {
                id: member.id,
                organization_id: member.organization_id,
                email: member.email().clone(),
                display_name: member.display_name.clone(),
                password_hash: member.password_hash.clone(),
                status,
                role: member.role,
                email_standing: AddressStanding::Unverified,
                locale: Preference::Inherited,
                timezone: Preference::Inherited,
                created_at: member.created_at,
                updated_at: member.updated_at,
                joining: Joining::NotYet,
                credentials_changed_at: CredentialChange::Never,
                vouching: Vouching::Absent,
            };

            assert!(
                refused_as_corrupt(&OrgUser::reconstitute(row)),
                "{status:?}"
            );
        }
    }

    /// Bob joined, signed in with a password, and was deactivated when he
    /// left. The account of `owner`'s organization he holds now.
    fn closed_member(owner: &OrgUser, role: OrgRole) -> OrgUser {
        let mut bob = added(owner, role);
        bob.verify_email(&proof_of(bob.email())).unwrap();
        moved(&mut bob, OrgUserStatus::Deactivated, owner).unwrap();
        bob
    }

    fn named(text: &str) -> DisplayName {
        DisplayName::new(text, &DisplayNameLimits::default()).unwrap()
    }

    /// Bob left Acme and his account was closed. Ann invites his address
    /// again as "Bob Again". The same account waits to join, with no
    /// password, an unproven address and a credential change that ends
    /// every device he remembered. His first join date stays with it.
    #[test]
    fn a_closed_account_is_reopened_for_a_new_invitation() {
        let ann = founded();
        let mut bob = closed_member(&ann, OrgRole::Member);
        let first_join = bob.joined_at();

        by(&ann, |c| {
            bob.reopen_for_invitation(named("Bob Again"), OrgRole::Member, c)
        })
        .unwrap();

        assert_eq!(bob.status(), OrgUserStatus::Invited);
        assert_eq!(bob.display_name().as_str(), "Bob Again");
        assert_eq!(bob.password_hash(), &OrgPassword::NotSet);
        assert!(!bob.email_verified());
        assert_ne!(bob.credentials_changed_at(), CredentialChange::Never);
        assert_eq!(bob.joined_at(), first_join);
        assert!(OrgUser::reconstitute(row_of(&bob)).is_ok());
    }

    /// Reopening an active or locked account is an invalid transition. Both
    /// accounts retain their passwords.
    #[test]
    fn only_a_closed_account_is_reopened() {
        let ann = founded();
        let mut active = added(&ann, OrgRole::Member);
        let mut locked = added(&ann, OrgRole::Member);
        moved(&mut locked, OrgUserStatus::Locked, &ann).unwrap();

        for bob in [&mut active, &mut locked] {
            let result = by(&ann, |c| {
                bob.reopen_for_invitation(named("Bob"), OrgRole::Member, c)
            });

            assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
            assert!(bob.password_hash().hash().is_some());
        }
    }

    /// Sam's member role cannot reopen Bob's closed account for an invitation.
    /// The forbidden attempt leaves Bob deactivated.
    #[test]
    fn a_member_who_may_not_invite_reopens_nothing() {
        let ann = founded();
        let sam = added(&ann, OrgRole::Member);
        let mut bob = closed_member(&ann, OrgRole::Member);

        let result = by(&sam, |c| {
            bob.reopen_for_invitation(named("Bob"), OrgRole::Member, c)
        });

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(bob.status(), OrgUserStatus::Deactivated);
    }

    /// Changing a deactivated account's status directly to invited is an
    /// invalid transition. Bob remains deactivated.
    #[test]
    fn a_status_change_does_not_reopen_an_account() {
        let ann = founded();
        let mut bob = closed_member(&ann, OrgRole::Member);

        let result = moved(&mut bob, OrgUserStatus::Invited, &ann);

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(bob.status(), OrgUserStatus::Deactivated);
    }

    /// Alice founds Acme and adds Bob. Each creation is raised; inviting
    /// Carol raises nothing, since her invitation records it.
    #[test]
    fn creating_raises_org_user_created_and_inviting_raises_nothing() {
        let mut alice = founded();
        let mut bob = added(&alice, OrgRole::Member);
        let mut carol = invited();

        assert_eq!(
            raised_complete_names(&mut alice),
            ["organization.org_user_created"]
        );
        assert_eq!(
            raised_complete_names(&mut bob),
            ["organization.org_user_created"]
        );
        assert!(raised_complete_names(&mut carol).is_empty());
    }

    /// Ann changes Bob's role, display name, address and password, and
    /// locks him. Each change is raised, in order.
    #[test]
    fn every_change_by_an_owner_raises_its_record() {
        let ann = founded();
        let mut bob = added(&ann, OrgRole::Member);
        raised_complete_names(&mut bob);

        by(&ann, |c| bob.change_role(OrgRole::Owner, c, only(&ann))).unwrap();
        by(&ann, |c| bob.change_display_name(named("Robert"), c)).unwrap();
        readdressed(&mut bob, "robert@acme.com", &ann).unwrap();
        repassed(&mut bob, "new-hash", &ann).unwrap();
        moved(&mut bob, OrgUserStatus::Locked, &ann).unwrap();

        assert_eq!(
            raised_complete_names(&mut bob),
            [
                "organization.org_user_role_changed",
                "organization.org_user_display_name_changed",
                "organization.org_user_email_changed",
                "organization.org_user_password_reset",
                "organization.org_user_status_changed",
            ]
        );
    }

    /// Ann locks Bob. The record names Bob by his name and address, and
    /// holds the status he left and the one he has now.
    #[test]
    fn a_status_change_names_the_member_and_both_statuses() {
        let ann = founded();
        let mut bob = added(&ann, OrgRole::Member);
        raised_complete_names(&mut bob);

        moved(&mut bob, OrgUserStatus::Locked, &ann).unwrap();

        let payload = bob.take_events()[0].payload();
        let Some(FieldValue::Reference(named)) = payload.value("org_user") else {
            panic!("the member is not referenced");
        };
        assert_eq!(named.label(), "Alice (alice@acme.com)");
        let Some(FieldValue::Change(status)) = payload.value("status") else {
            panic!("the status change is missing");
        };
        assert_eq!(status.from(), Some("Active"));
        assert_eq!(status.to(), Some("Locked"));
    }

    /// Alice changes her own password, confirms her address, sets her
    /// preferences, and sets up, then switches off, an authenticator app.
    /// Each is raised, in order.
    #[test]
    fn the_members_own_changes_raise_their_records() {
        let mut alice = founded_with_password("current");
        let herself = OrgUser::reconstitute(row_of(&alice)).unwrap();
        raised_complete_names(&mut alice);

        alice
            .change_own_password("current", FakeHasher.hash("next").unwrap(), &FakeHasher)
            .unwrap();
        alice.verify_email(&proof_of(alice.email())).unwrap();
        by(&herself, |c| {
            alice.change_preferences(Preference::Inherited, Preference::Inherited, c)
        })
        .unwrap();
        alice.record_mfa_enrolled();
        alice.record_mfa_turned_off();

        assert_eq!(
            raised_complete_names(&mut alice),
            [
                "organization.org_user_password_changed",
                "organization.org_user_email_verified",
                "organization.org_user_preferences_updated",
                "organization.org_mfa_enrolled",
                "organization.org_mfa_unenrolled",
            ]
        );
    }

    /// Ann removes Bob, then resets the factor of Carol, who lost hers.
    /// Each is raised.
    #[test]
    fn removing_and_resetting_a_factor_raise_their_records() {
        let ann = founded();
        let mut bob = added(&ann, OrgRole::Member);
        let mut carol = added(&ann, OrgRole::Member);
        raised_complete_names(&mut bob);
        raised_complete_names(&mut carol);

        by(&ann, |c| bob.remove(c, only(&ann))).unwrap();
        carol.record_mfa_reset();

        assert_eq!(
            raised_complete_names(&mut bob),
            ["organization.org_user_deleted"]
        );
        assert_eq!(
            raised_complete_names(&mut carol),
            ["organization.org_member_mfa_reset"]
        );
    }

    /// Refused locking, renaming and removal by a member raise no events.
    /// Alice's password change with the wrong current password also raises none.
    #[test]
    fn a_refused_change_raises_nothing() {
        let ann = founded();
        let mut bob = added(&ann, OrgRole::Member);
        let sam = added(&ann, OrgRole::Member);
        let mut alice = founded_with_password("current");
        raised_complete_names(&mut bob);
        raised_complete_names(&mut alice);

        let locked = moved(&mut bob, OrgUserStatus::Locked, &sam);
        let renamed = by(&sam, |c| bob.change_display_name(named("Mallory"), c));
        let removed = by(&sam, |c| bob.remove(c, only(&ann)));
        let repassed =
            alice.change_own_password("wrong", FakeHasher.hash("next").unwrap(), &FakeHasher);

        assert!(locked.is_err() && renamed.is_err() && removed.is_err() && repassed.is_err());
        assert!(raised_complete_names(&mut bob).is_empty());
        assert!(raised_complete_names(&mut alice).is_empty());
    }

    /// Alice's account is read back from storage. Loading it is no change,
    /// so it has raised nothing.
    #[test]
    fn a_member_read_back_from_storage_has_raised_nothing() {
        let mut alice = OrgUser::reconstitute(row_of(&founded())).unwrap();

        assert!(raised_complete_names(&mut alice).is_empty());
    }
}
