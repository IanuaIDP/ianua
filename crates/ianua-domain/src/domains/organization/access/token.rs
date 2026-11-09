//! Single-use tokens issued to org users.
//!
//! The tenant plane's [`SecureToken`](crate::domains::identity::tokens::secure::SecureToken)
//! belongs to one tenant and is keyed by `UserId`. Org users sit above every
//! tenant and are keyed by `OrgUserId`, so they get their own token type. The
//! rules are the same: a hashed value, an expiry, and one use only. The
//! `Purpose` markers are shared with the tenant tokens, so an
//! email-verification token can never be used as a password reset.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::domains::identity::tokens::email_verification::EmailVerification;
use crate::domains::identity::tokens::installation_setup::{InstallationSetup, InstallerProof};
use crate::domains::identity::tokens::magic_link::MagicLink;
use crate::domains::identity::tokens::password_reset::PasswordReset;
use crate::domains::identity::tokens::purpose::{LinkEffect, MailedPurpose, TokenPurpose};
use crate::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use crate::domains::identity::tokens::single_use::{LinkHolder, SingleUse, StoredSingleUse};
use crate::domains::organization::lifecycle::Founding;
use crate::domains::organization::members::org_user::OrgUser;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    Email, Lifetime, OrgUserId, PrincipalId, TokenHash, TokenRefused, TokenState, Usage,
};

/// A token as stored, for rebuilding it with [`OrgToken::reconstitute`].
pub struct OrgTokenRow {
    /// One-way hash of the raw token.
    pub token_hash: TokenHash,
    /// The org user the token was issued to.
    pub org_user_id: OrgUserId,
    /// The address the link was mailed to.
    pub sent_to: Email,
    /// When it was issued.
    pub created_at: OffsetDateTime,
    /// When it stops being usable.
    pub expires_at: OffsetDateTime,
    /// Whether it was used, and when.
    pub usage: Usage,
}

/// An org token about to be mailed.
pub struct NewOrgToken {
    /// One-way hash of the raw value the link carries.
    pub token_hash: TokenHash,
    /// Who it is for.
    pub org_user_id: OrgUserId,
    /// The address it is mailed to, which the account must still have when
    /// the link is followed.
    pub sent_to: Email,
    /// How long it stays usable from now.
    pub lifetime: Lifetime,
}

/// A single-use token issued to an org user for `Purpose`.
#[derive(Debug)]
pub struct OrgToken<Purpose: TokenPurpose> {
    org_user_id: OrgUserId,
    token: SingleUse,
    _purpose: PhantomData<Purpose>,
}

/// Confirms an org user's email address.
pub type OrgVerificationToken = OrgToken<EmailVerification>;

/// Lets an org user set a new password without their old one.
pub type OrgPasswordResetToken = OrgToken<PasswordReset>;

/// Lets the person who installed the platform prove the first owner's
/// address with the setup token the install showed them.
pub type OrgInstallationToken = OrgToken<InstallationSetup>;

/// Finishes a member's sign-in that waits for them to confirm it from their
/// mailbox.
pub type OrgSignInConfirmationToken = OrgToken<SignInConfirmation>;

/// Signs a member in to the dashboard without a password, from their
/// mailbox.
pub type OrgMagicLinkToken = OrgToken<MagicLink>;

impl<Purpose: MailedPurpose> OrgToken<Purpose> {
    /// Issues a token from its hash, to be mailed to `new.sent_to`.
    ///
    /// The infrastructure layer makes and hashes the raw value. The domain
    /// never sees it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the lifetime is longer than a link
    ///   of this kind may live.
    pub fn issue(new: NewOrgToken) -> Result<Self, DomainError> {
        Self::issued(new)
    }
}

impl OrgToken<InstallationSetup> {
    /// Issues the setup token for an installation's first owner, while the
    /// `founding` that makes them is still held.
    ///
    /// Making the owner uses the founding up, so no setup token can be
    /// issued once the installation has an owner. The token proves the
    /// address without the mailbox, which is why only this issues it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `founding` made an ordinary
    ///   organization rather than an installation's own one.
    /// - [`DomainError::Validation`] when the lifetime is longer than a day.
    pub fn for_installer(founding: &Founding, new: NewOrgToken) -> Result<Self, DomainError> {
        founding.ensure_installation()?;
        Self::issued(new)
    }

    /// Spends this setup token for `owner`, who presented it just now, and
    /// gives back what it proves: the owner's address, and that they are
    /// the person who ran the install.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] when the token is another member's, spent, out of
    ///   date, or issued for an address the owner has left. The token is
    ///   left as it was.
    pub fn confirm_installer(
        &mut self,
        owner: &OrgUser,
        now: OffsetDateTime,
    ) -> Result<InstallerProof, TokenRefused> {
        let address = self.redeem(owner, now)?;
        Ok(InstallerProof::spent_for(address))
    }
}

impl OrgToken<SignInConfirmation> {
    /// Consumes a sign-in confirmation link for the member's current mailbox.
    /// It proves mailbox access, not a factor; an address-verification link cannot confirm sign-in.
    ///
    /// # Errors
    /// [`TokenRefused`] for another member, a spent or expired link, a changed address,
    /// or a member unable to sign in. Refusal leaves the link unchanged.
    pub fn confirm(
        &mut self,
        member: &OrgUser,
        now: OffsetDateTime,
    ) -> Result<ProvedFactor, TokenRefused> {
        self.redeem(member, now)?;
        Ok(ProvedFactor::by_mailbox(PrincipalId::from(*member.id())))
    }
}

impl OrgToken<MagicLink> {
    /// Consumes a mailed link to sign in the member and prove their current mailbox.
    /// The caller first checks mail/location admission through
    /// [`OrganizationAuthConfig::admits`](crate::domains::organization::access::auth_config::OrganizationAuthConfig::admits)
    /// and single-sign-on requirements when beginning sign-in.
    ///
    /// # Errors
    /// [`TokenRefused`] for another member, a spent or expired link, a changed address,
    /// or a member unable to sign in. Refusal leaves the link unchanged.
    pub fn sign_in(
        &mut self,
        member: &OrgUser,
        now: OffsetDateTime,
    ) -> Result<WayIn, TokenRefused> {
        self.redeem(member, now)?;
        Ok(WayIn::by_mailed_link(PrincipalId::from(*member.id())))
    }
}

impl<Purpose: TokenPurpose> OrgToken<Purpose> {
    fn issued(new: NewOrgToken) -> Result<Self, DomainError> {
        Ok(Self {
            org_user_id: new.org_user_id,
            token: SingleUse::issue(new.token_hash, new.sent_to, new.lifetime, Purpose::LONGEST)?,
            _purpose: PhantomData,
        })
    }

    /// Rebuilds an organization token from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the token was used
    ///   before it was issued, or once it had expired.
    pub fn reconstitute(row: OrgTokenRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            org_user_id: row.org_user_id,
            token: SingleUse::stored(StoredSingleUse {
                token_hash: row.token_hash,
                sent_to: row.sent_to,
                created_at: row.created_at,
                expires_at: row.expires_at,
                usage: row.usage,
            }),
            _purpose: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OrgTokenRow) -> Result<(), DomainError> {
        RowCheck::of("organization token")
            .in_order_if(
                row.created_at,
                row.usage.used_at(),
                "used before it was issued",
            )
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "used after it expired",
            )
            .finish()
    }

    /// The one-way hash of the raw token value.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        self.token.token_hash()
    }

    /// The org user this token was issued for.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// The address the link was mailed to.
    #[must_use]
    pub fn sent_to(&self) -> &Email {
        self.token.sent_to()
    }

    /// When this token was issued.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.token.created_at()
    }

    /// When this token becomes invalid if unused.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.token.expires_at()
    }

    /// When this token was used. `None` if unused.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.token.usage().used_at()
    }

    /// What following this link would do for `holder`, answered without
    /// spending it.
    ///
    /// Each way of being unusable means something different. A link that ran
    /// out of time, or went to an address the account no longer has, can be
    /// replaced with a new one. A spent link means the account is confirmed,
    /// so there is nothing to reissue. A link issued to another account is no
    /// token at all to this one.
    ///
    /// A link that finishes a sign-in does nothing for a member who may not
    /// sign in now. Olivia is locked after a break-in. The confirmation
    /// mailed before must not finish the sign-in it was sent for.
    #[must_use]
    pub fn state_for(&self, holder: &OrgUser, now: OffsetDateTime) -> TokenState {
        if *holder.id() != self.org_user_id {
            return TokenState::ForAnotherAccount;
        }
        let state = self.token.state_for(link_holder(holder), now);
        if state == TokenState::Usable
            && Purpose::EFFECT == LinkEffect::SignsIn
            && !holder.status().can_authenticate()
        {
            return TokenState::AccountShut;
        }
        state
    }

    /// Spends the link for `holder`. This is the only way it is ever used.
    ///
    /// Refused unless the link was issued to this account, mailed to the
    /// address it has now, unspent and in date. Gives back the address as
    /// proven, because following the link shows its reader holds it.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] naming why, with the token left as it was.
    pub fn redeem(
        &mut self,
        holder: &OrgUser,
        now: OffsetDateTime,
    ) -> Result<VerifiedEmail, TokenRefused> {
        if let Some(refused) = TokenRefused::of(self.state_for(holder, now)) {
            return Err(refused);
        }
        self.token.redeem(link_holder(holder), now)
    }
}

/// `member` as a link sees it: its address and its last sign-in change.
fn link_holder(member: &OrgUser) -> LinkHolder<'_> {
    LinkHolder {
        email: member.email(),
        credentials_changed_at: member.credentials_changed_at(),
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::identity::account::address::AddressStanding;
    use crate::domains::identity::account::vouching::Vouching;
    use crate::domains::organization::billing::plan::OrganizationPlan;
    use crate::domains::organization::lifecycle::{
        CreateOrganizationParams, InstallationParams, Organization,
    };
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword, OrgUserRow,
    };
    use crate::domains::organization::members::org_user_status::OrgUserStatus;
    use crate::shared::config::DomainLimits;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::org_user;
    use crate::types::{
        CredentialChange, DisplayName, Joining, Label, OrganizationId, Preference, TenantSlug,
        TokenStatus,
    };

    const ALICE: &str = "alice@corp.test";

    fn alice() -> Email {
        Email::new(ALICE).unwrap()
    }

    fn holder() -> OrgUser {
        org_user(OrgUserId::new(), ALICE)
    }

    fn an_hour() -> Lifetime {
        Lifetime::seconds(3600).unwrap()
    }

    fn token_for(holder: &OrgUser) -> OrgVerificationToken {
        OrgVerificationToken::issue(NewOrgToken {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            org_user_id: *holder.id(),
            sent_to: holder.email().clone(),
            lifetime: an_hour(),
        })
        .unwrap()
    }

    /// The organization Ann's install makes, with its founding.
    fn installation() -> (Organization, Founding) {
        Organization::create_installation(InstallationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &DomainLimits::default().slug).unwrap(),
            name: Label::new("name", "Acme").unwrap(),
            contact_email: Email::new("ann@acme.test").unwrap(),
            display_name: DisplayName::new("Acme", &DomainLimits::default().display_name).unwrap(),
        })
        .unwrap()
    }

    /// The first owner `founding` makes, with `id`, without a confirmed
    /// address.
    fn first_owner(organization: &Organization, founding: Founding, id: OrgUserId) -> OrgUser {
        OrgUser::create(
            CreateOrgUserParams {
                id,
                organization_id: *organization.id(),
                email: Email::new("ann@acme.test").unwrap(),
                display_name: DisplayName::new("Ann", &DomainLimits::default().display_name)
                    .unwrap(),
                password_hash: OrgPassword::NotSet,
                role: OrgRole::Owner,
            },
            AddedBy::Founding(founding),
        )
        .unwrap()
    }

    fn setup_for(owner: OrgUserId, lifetime: Lifetime) -> NewOrgToken {
        NewOrgToken {
            token_hash: TokenHash::from_stored("setup".to_owned()),
            org_user_id: owner,
            sent_to: Email::new("ann@acme.test").unwrap(),
            lifetime,
        }
    }

    /// Ann installs ianua on her own server, with no mail server. The
    /// install shows her a setup token; using it proves her address and
    /// vouches for her first sign-in, so she can sign in and set up her
    /// second factor.
    #[test]
    fn the_setup_token_proves_the_first_owners_address() {
        let (organization, founding) = installation();
        let owner = OrgUserId::new();
        let mut token =
            OrgInstallationToken::for_installer(&founding, setup_for(owner, an_hour())).unwrap();
        let mut ann = first_owner(&organization, founding, owner);

        let proof = token
            .confirm_installer(&ann, crate::shared::clock::now())
            .unwrap();
        ann.confirm_as_installer(&proof).unwrap();

        assert!(ann.email_verified());
        assert_eq!(ann.vouching(), Vouching::Fresh);
    }

    /// An ordinary organization cannot issue an installation setup token.
    #[test]
    fn an_ordinary_organization_gets_no_setup_token() {
        let (_, founding) = Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("evil", &DomainLimits::default().slug).unwrap(),
            name: Label::new("name", "Evil").unwrap(),
            contact_email: Email::new("mallory@evil.test").unwrap(),
            display_name: DisplayName::new("Evil", &DomainLimits::default().display_name).unwrap(),
            plan: OrganizationPlan::Free,
        })
        .unwrap();

        let refused =
            OrgInstallationToken::for_installer(&founding, setup_for(OrgUserId::new(), an_hour()));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann's setup token cannot establish proof for another member.
    #[test]
    fn a_setup_token_proves_nothing_for_another_member() {
        let (organization, founding) = installation();
        let mut token =
            OrgInstallationToken::for_installer(&founding, setup_for(OrgUserId::new(), an_hour()))
                .unwrap();
        let mallory = first_owner(&organization, founding, OrgUserId::new());

        let refused = token.redeem(&mallory, crate::shared::clock::now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::ForAnotherAccount)
        );
    }

    /// A setup token lives a day at most: one asked for two days is refused,
    /// so a token left in an install log stops working.
    #[test]
    fn a_setup_token_lives_a_day_at_most() {
        let (_, founding) = installation();
        let two_days = Lifetime::seconds(2 * 86_400).unwrap();

        let refused =
            OrgInstallationToken::for_installer(&founding, setup_for(OrgUserId::new(), two_days));

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Alice is mailed a confirmation link that lasts an hour. Checked right
    /// away, it is usable.
    #[test]
    fn a_fresh_token_is_usable() {
        let alice = holder();

        assert_eq!(
            token_for(&alice).state_for(&alice, crate::shared::clock::now()),
            TokenState::Usable
        );
    }

    /// Alice follows her link one second after it expired. It is refused as
    /// expired.
    #[test]
    fn an_expired_token_is_refused() {
        let alice = holder();
        let mut token = token_for(&alice);
        let later = token.expires_at() + Duration::seconds(1);

        let refused = token.redeem(&alice, later);

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Expired)
        );
    }

    /// Replaying a redeemed token is refused as spent and preserves its first-use time.
    #[test]
    fn a_redeemed_token_cannot_be_replayed() {
        let alice = holder();
        let mut token = token_for(&alice);
        let now = crate::shared::clock::now();
        token.redeem(&alice, now).unwrap();

        let replay = token.redeem(&alice, now + Duration::seconds(1));

        assert_eq!(
            replay.map_err(TokenRefused::state),
            Err(TokenState::Consumed)
        );
        assert_eq!(token.consumed_at(), Some(now));
    }

    /// Alice holds one unspent link and one she already used. The unspent one
    /// reads as usable, then expired after its time. The used one reads as
    /// spent, so only the first is worth reissuing.
    #[test]
    fn running_out_of_time_is_told_apart_from_being_spent() {
        let alice = holder();
        let unspent = token_for(&alice);
        let mut spent = token_for(&alice);
        let now = crate::shared::clock::now();
        spent.redeem(&alice, now).unwrap();

        assert_eq!(unspent.state_for(&alice, now), TokenState::Usable);
        assert_eq!(
            unspent.state_for(&alice, unspent.expires_at() + Duration::seconds(1)),
            TokenState::Expired
        );
        assert_eq!(spent.state_for(&alice, now), TokenState::Consumed);
    }

    /// Alice used her link, and it is checked again after its expiry. It
    /// still reads as spent, not expired, so she is not offered a new one.
    #[test]
    fn a_spent_token_does_not_become_expired_later() {
        let alice = holder();
        let mut token = token_for(&alice);
        token.redeem(&alice, crate::shared::clock::now()).unwrap();

        let later = token.expires_at() + Duration::seconds(1);

        assert_eq!(token.state_for(&alice, later), TokenState::Consumed);
    }

    /// A second account with Alice's email cannot redeem her token, which remains unspent.
    #[test]
    fn a_link_cannot_be_redeemed_for_another_account() {
        let alice = holder();
        let other = org_user(OrgUserId::new(), ALICE);
        let mut token = token_for(&alice);

        let refused = token.redeem(&other, crate::shared::clock::now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::ForAnotherAccount)
        );
        assert!(token.consumed_at().is_none());
    }

    /// A token is issued with hash `hashed_token` for one org user. It gives
    /// back that hash, which a link is looked up by, and that user.
    #[test]
    fn a_token_names_the_hash_it_is_found_by_and_the_user_it_verifies() {
        let org_user = OrgUserId::new();

        let token = OrgVerificationToken::issue(NewOrgToken {
            token_hash: TokenHash::from_stored("hashed_token".to_owned()),
            org_user_id: org_user,
            sent_to: alice(),
            lifetime: an_hour(),
        })
        .unwrap();

        assert_eq!(token.token_hash().as_str(), "hashed_token");
        assert_eq!(*token.org_user_id(), org_user);
    }

    /// Changing the member's address supersedes the old link and maps its refusal to expired.
    #[test]
    fn a_link_to_a_former_address_is_superseded() {
        let mut alice = holder();
        let mut token = token_for(&alice);
        alice.change_verified_email(VerifiedEmail::proven(
            Email::new("alice@newcorp.test").unwrap(),
        ));
        let now = crate::shared::clock::now();

        assert_eq!(
            token.redeem(&alice, now).map_err(TokenRefused::state),
            Err(TokenState::Superseded)
        );
        assert_eq!(
            TokenStatus::from(token.state_for(&alice, now)),
            TokenStatus::Expired
        );
    }

    /// A stored token says it was used at the instant it expired. No link
    /// is let through once it expires, so loading it is refused as corrupt.
    #[test]
    fn a_stored_token_used_once_it_expired_is_refused() {
        let now = crate::shared::clock::now();
        let expires = now + Duration::hours(1);

        let token = OrgVerificationToken::reconstitute(OrgTokenRow {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            org_user_id: OrgUserId::new(),
            sent_to: alice(),
            created_at: now,
            expires_at: expires,
            usage: Usage::Used { at: expires },
        });

        assert!(refused_as_corrupt(&token));
    }

    fn confirmation_for(holder: &OrgUser) -> OrgSignInConfirmationToken {
        OrgSignInConfirmationToken::issue(NewOrgToken {
            token_hash: TokenHash::from_stored("confirm".to_owned()),
            org_user_id: *holder.id(),
            sent_to: holder.email().clone(),
            lifetime: an_hour(),
        })
        .unwrap()
    }

    /// Alice, locked after a break-in, as storage keeps her.
    fn locked(alice: &OrgUser) -> OrgUser {
        let now = crate::shared::clock::now();
        OrgUser::reconstitute(OrgUserRow {
            id: *alice.id(),
            organization_id: *alice.organization_id(),
            email: alice.email().clone(),
            display_name: alice.display_name().clone(),
            password_hash: OrgPassword::NotSet,
            status: OrgUserStatus::Locked,
            role: OrgRole::Member,
            email_standing: AddressStanding::Verified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining: Joining::Joined { at: now },
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        })
        .unwrap()
    }

    /// Alice follows the link confirming her sign-in. It proves her
    /// mailbox to the sign-in, and is spent.
    #[test]
    fn a_confirmation_link_proves_the_mailbox_of_a_member_who_may_sign_in() {
        let alice = holder();
        let mut link = confirmation_for(&alice);

        let proof = link.confirm(&alice, crate::shared::clock::now()).unwrap();

        assert_eq!(proof.factor(), MfaFactor::EmailConfirmation);
        assert_eq!(proof.account(), PrincipalId::from(*alice.id()));
        assert!(link.consumed_at().is_some());
    }

    /// A confirmation link for Mallory cannot prove Alice's sign-in.
    #[test]
    fn a_confirmation_link_for_another_member_proves_nothing() {
        let mut mallorys = confirmation_for(&org_user(OrgUserId::new(), "mallory@corp.test"));

        let refused = mallorys
            .confirm(&holder(), crate::shared::clock::now())
            .map_err(TokenRefused::state);

        assert_eq!(refused, Err(TokenState::ForAnotherAccount));
    }

    /// A locked member cannot use a confirmation link, which remains unspent.
    #[test]
    fn a_confirmation_link_does_nothing_for_a_locked_member() {
        let alice = locked(&holder());
        let mut link = confirmation_for(&alice);
        let now = crate::shared::clock::now();

        let refused = link.confirm(&alice, now).map_err(TokenRefused::state);

        assert_eq!(refused, Err(TokenState::AccountShut));
        assert!(link.consumed_at().is_none());
    }

    /// A verification link only proves an address, so a locked member may
    /// still follow it.
    #[test]
    fn a_verification_link_still_proves_a_locked_members_address() {
        let alice = locked(&holder());

        let state = token_for(&alice).state_for(&alice, crate::shared::clock::now());

        assert_eq!(state, TokenState::Usable);
    }

    fn magic_link_for(holder: &OrgUser) -> OrgMagicLinkToken {
        OrgMagicLinkToken::issue(NewOrgToken {
            token_hash: TokenHash::from_stored("magic".to_owned()),
            org_user_id: *holder.id(),
            sent_to: holder.email().clone(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    /// Alice follows the sign-in link mailed to her. It makes a mailed-link
    /// way into her account, and is spent.
    #[test]
    fn a_magic_link_signs_its_member_in() {
        let alice = holder();
        let mut link = magic_link_for(&alice);

        let way_in = link.sign_in(&alice, crate::shared::clock::now()).unwrap();

        assert_eq!(way_in.account(), PrincipalId::from(*alice.id()));
        assert_eq!(
            way_in.method(),
            crate::domains::authentication::sessions::sign_in_progress::LocalMethod::MagicLink
        );
        assert!(link.consumed_at().is_some());
    }

    /// A magic link for another member cannot sign Alice in and remains unspent.
    #[test]
    fn a_magic_link_for_another_member_signs_nobody_in() {
        let alice = holder();
        let mallory = org_user(OrgUserId::new(), "mallory@corp.test");
        let mut mallorys = magic_link_for(&mallory);

        let refused = mallorys
            .sign_in(&alice, crate::shared::clock::now())
            .map_err(TokenRefused::state);

        assert_eq!(refused.err(), Some(TokenState::ForAnotherAccount));
        assert!(mallorys.consumed_at().is_none());
    }

    /// A magic link cannot authenticate a locked member.
    #[test]
    fn a_magic_link_does_nothing_for_a_locked_member() {
        let alice = locked(&holder());
        let mut link = magic_link_for(&alice);

        let refused = link
            .sign_in(&alice, crate::shared::clock::now())
            .map_err(TokenRefused::state);

        assert_eq!(refused.err(), Some(TokenState::AccountShut));
    }

    /// Alice's sign-in link is followed twice. The second time signs
    /// nobody in.
    #[test]
    fn a_magic_link_signs_in_once() {
        let alice = holder();
        let mut link = magic_link_for(&alice);
        let now = crate::shared::clock::now();
        link.sign_in(&alice, now).unwrap();

        let replayed = link.sign_in(&alice, now).map_err(TokenRefused::state);

        assert_eq!(replayed.err(), Some(TokenState::Consumed));
    }
}
