//! A pending email change, confirmed by a link sent to the new address.
//!
//! Org users and tenant users both use it to change their address. The
//! change lands only on the account that asked for it. That account must
//! also still be as it was when it asked.
//!
//! Asking needs a fresh proof of the person, not only an open session. The
//! old address is told, and may cancel the change until it lands.

use time::OffsetDateTime;

use crate::domains::identity::account::control::RecentProof;
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::domains::identity::events::account::{
    EmailChangeCancelled, EmailChangeLinkResent, EmailChangeRequested,
    ManagementEmailChangeCancelled, ManagementEmailChangeConfirmed,
    ManagementEmailChangeLinkResent, ManagementEmailChangeRequested,
};
use crate::domains::identity::tokens::renewal::RenewedLink;
use crate::isolation::scope::{ResolvedTenant, TenantScope};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::{DomainEvent, PlatformDomainEvent};
use crate::shared::events::raised::{
    Raised, RaisedEvents, Raises, RaisesComplete, SavedFor, TenantEventBody,
};
use crate::shared::model::row_check::RowCheck;
use crate::types::{CredentialChange, Email, PrincipalId, TokenHash, TokenRefused, TokenState};

/// Where an email change stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeState {
    /// Waiting for the link sent to the new address.
    Waiting,
    /// Confirmed from the new address, at this instant.
    Confirmed {
        /// When.
        at: OffsetDateTime,
    },
    /// Cancelled from the old address, at this instant.
    Cancelled {
        /// When.
        at: OffsetDateTime,
    },
}

impl ChangeState {
    /// When it was confirmed or cancelled, if it was.
    #[must_use]
    pub fn settled_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Waiting => None,
            Self::Confirmed { at } | Self::Cancelled { at } => Some(at),
        }
    }
}

/// An account asking to change its address, as it stands now.
///
/// It is made only from a loaded account. So a change is checked against
/// the account's real state, never values a caller typed in.
#[derive(Debug, Clone, Copy)]
pub struct ChangingAccount<'a> {
    id: PrincipalId,
    email: &'a Email,
    credentials_changed_at: CredentialChange,
    holder: Holder,
}

/// Whose account is changing its address, which decides what the change
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holder {
    /// A user of one tenant. The change raises the tenant's events.
    TenantUser,
    /// An organization member or an operator. The change raises platform
    /// events, recorded apart from any tenant's.
    ManagementAccount,
}

impl<'a> ChangingAccount<'a> {
    /// The account as loaded: who it is, its address now, and when it last
    /// changed how it signs in.
    ///
    /// Only a loaded account's own accessors feed it, through the `From`
    /// conversions next to each account type. An account made this way is a
    /// management account, an organization member's or an operator's; a
    /// tenant user's comes from its own conversion below.
    pub(crate) fn of(
        id: PrincipalId,
        email: &'a Email,
        credentials_changed_at: CredentialChange,
    ) -> Self {
        Self {
            id,
            email,
            credentials_changed_at,
            holder: Holder::ManagementAccount,
        }
    }
}

impl<'a, T: TenantScope> From<&'a User<T>> for ChangingAccount<'a> {
    fn from(user: &'a User<T>) -> Self {
        Self {
            holder: Holder::TenantUser,
            ..Self::of(
                (*user.id()).into(),
                user.email(),
                user.credentials_changed_at(),
            )
        }
    }
}

/// An email change waiting for its link to be followed.
#[derive(Debug, Clone)]
pub struct PendingEmailChange {
    /// Who is changing their email.
    principal_id: PrincipalId,
    /// The address the account had when it asked.
    from_email: Email,
    /// The new address asked for.
    new_email: Email,
    /// The hash of the confirmation token.
    token_hash: TokenHash,
    /// The hash of the token in the cancel link sent to the old address.
    cancel_token_hash: TokenHash,
    /// When the change was asked for.
    created_at: OffsetDateTime,
    /// When the confirmation link stops working.
    expires_at: OffsetDateTime,
    /// Whether the change is waiting, confirmed or cancelled.
    state: ChangeState,
    /// The tenant events a tenant user's change raised and has not handed
    /// over. A change is not typed by the tenant it belongs to, since
    /// management accounts change their address the same way; its events
    /// take the tenant they are saved for, as every tenant event does.
    raised: Raised<ResolvedTenant>,
    /// The platform events a management account's change raised and has
    /// not handed over.
    management: RaisedEvents,
}

/// What a new pending email change is made from.
pub struct CreateEmailChangeParams {
    /// The new address.
    pub new_email: Email,
    /// The hash of the confirmation token.
    pub token_hash: TokenHash,
    /// The hash of the token in the cancel link sent to the old address.
    pub cancel_token_hash: TokenHash,
    /// How long the confirmation link works.
    pub lifetime: crate::types::Lifetime,
}

/// A pending email change as storage keeps it, checked again by
/// [`PendingEmailChange::reconstitute`].
pub struct EmailChangeRow {
    /// Who is changing their email.
    pub principal_id: PrincipalId,
    /// The address the account had when it asked.
    pub from_email: Email,
    /// The new address asked for.
    pub new_email: Email,
    /// The hash of the confirmation token.
    pub token_hash: TokenHash,
    /// The hash of the token in the cancel link sent to the old address.
    pub cancel_token_hash: TokenHash,
    /// When the change was asked for.
    pub created_at: OffsetDateTime,
    /// When the confirmation link stops working.
    pub expires_at: OffsetDateTime,
    /// Whether it is waiting, confirmed or cancelled.
    pub state: ChangeState,
}

impl PendingEmailChange {
    /// Starts a change of `account`'s address, for its holder who proved
    /// who they are again just now. Raises `identity.email_change_requested`
    /// when `account` is a tenant user's, and
    /// `identity.management_email_change_requested` when it is a management
    /// account's.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is not a fresh proof of the
    ///   account's holder.
    /// - [`DomainError::Validation`] when the new address is the one the
    ///   account already has.
    pub fn create(
        account: ChangingAccount<'_>,
        params: CreateEmailChangeParams,
        proof: &impl RecentProof,
    ) -> Result<Self, DomainError> {
        if !proof.proves_recently(&account.id) {
            return Err(DomainError::forbidden(message!(
                "identity-changing-the-address-needs-the-person",
                "changing the address needs the person to prove who they are again"
            )));
        }
        Self::asked_for(account, params)
    }

    /// Starts a change of `account`'s address, once whoever asks for it
    /// was checked. Only an account's own rules for who may ask call this,
    /// as [`create`](Self::create) and `Operator::ask_email_change` do.
    /// Raises what [`create`](Self::create) raises.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the new address is the one the
    ///   account already has.
    pub(crate) fn asked_for(
        account: ChangingAccount<'_>,
        params: CreateEmailChangeParams,
    ) -> Result<Self, DomainError> {
        if params.new_email == *account.email {
            return Err(DomainError::invalid(message!(
                "identity-the-new-address-is-the-one",
                "the new address is the one the account already has"
            )));
        }
        let now = crate::shared::clock::now();
        let mut change = Self {
            principal_id: account.id,
            from_email: account.email.clone(),
            new_email: params.new_email,
            token_hash: params.token_hash,
            cancel_token_hash: params.cancel_token_hash,
            created_at: now,
            expires_at: params.lifetime.ends_after(now),
            state: ChangeState::Waiting,
            raised: Raised::default(),
            management: RaisedEvents::default(),
        };
        change.raise_requested(account, now);
        Ok(change)
    }

    /// Raises that a change of `account`'s address was asked for at `now`.
    fn raise_requested(&mut self, account: ChangingAccount<'_>, now: OffsetDateTime) {
        self.raise_for(
            account,
            |principal| EmailChangeRequested {
                principal,
                occurred_at: now,
            },
            |principal| ManagementEmailChangeRequested {
                principal,
                occurred_at: now,
            },
        );
    }

    /// Rebuilds an email change from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row changes to the address
    ///   the account already had.
    /// - [`DomainError::Infrastructure`] when the row expires before it was
    ///   asked for.
    /// - [`DomainError::Infrastructure`] when the row was confirmed or
    ///   cancelled before it was asked for.
    /// - [`DomainError::Infrastructure`] when the row was confirmed at or
    ///   after its link expired.
    pub fn reconstitute(row: EmailChangeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            principal_id: row.principal_id,
            from_email: row.from_email,
            new_email: row.new_email,
            token_hash: row.token_hash,
            cancel_token_hash: row.cancel_token_hash,
            created_at: row.created_at,
            expires_at: row.expires_at,
            state: row.state,
            raised: Raised::default(),
            management: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &EmailChangeRow) -> Result<(), DomainError> {
        RowCheck::of("email change")
            .holds(
                row.new_email != row.from_email,
                "a change to the address the account already had",
            )
            .holds(
                row.created_at < row.expires_at,
                "expires before it was asked for",
            )
            .in_order_if(
                row.created_at,
                row.state.settled_at(),
                "confirmed or cancelled before it was asked for",
            )
            .holds(
                Self::confirmed_in(row.state).is_none_or(|at| at < row.expires_at),
                "confirmed after its link expired",
            )
            .finish()
    }

    /// When `state` says the change was confirmed, if it does.
    fn confirmed_in(state: ChangeState) -> Option<OffsetDateTime> {
        let ChangeState::Confirmed { at } = state else {
            return None;
        };
        Some(at)
    }

    /// Who is changing their email.
    #[must_use]
    pub fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// The address the account had when it asked.
    #[must_use]
    pub fn from_email(&self) -> &Email {
        &self.from_email
    }

    /// The new address asked for.
    #[must_use]
    pub fn new_email(&self) -> &Email {
        &self.new_email
    }

    /// The hash of the confirmation token.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// The hash of the token in the cancel link sent to the old address.
    #[must_use]
    pub fn cancel_token_hash(&self) -> &TokenHash {
        &self.cancel_token_hash
    }

    /// Whether the change is waiting, confirmed or cancelled, as storage
    /// keeps it.
    #[must_use]
    pub fn stage(&self) -> ChangeState {
        self.state
    }

    /// When the change was asked for.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the confirmation link stops working.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the change was confirmed, if it was.
    #[must_use]
    pub fn confirmed_at(&self) -> Option<OffsetDateTime> {
        Self::confirmed_in(self.state)
    }

    /// What following this link would do for `account`, without spending
    /// it.
    ///
    /// Confirmed and expired are told apart because they mean opposite
    /// things. Confirmed means the address already changed. Expired means it
    /// never did, and the change must be asked for again.
    ///
    /// A change is superseded once the account's address moved some other
    /// way, or was cancelled from the old address. It is also superseded
    /// when the password or second factor changed
    /// after the request. Say someone stole Ann's session and asked to move
    /// her account to their address. Ann resets her password, and the
    /// change does not go through.
    #[must_use]
    pub fn state_for(&self, account: ChangingAccount<'_>, now: OffsetDateTime) -> TokenState {
        if account.id != self.principal_id {
            return TokenState::ForAnotherAccount;
        }
        match self.state {
            ChangeState::Confirmed { .. } => return TokenState::Consumed,
            ChangeState::Cancelled { .. } => return TokenState::Superseded,
            ChangeState::Waiting => {}
        }
        if *account.email != self.from_email || self.credentials_changed_since(account) {
            return TokenState::Superseded;
        }
        if now >= self.expires_at {
            return TokenState::Expired;
        }
        TokenState::Usable
    }

    fn credentials_changed_since(&self, account: ChangingAccount<'_>) -> bool {
        account.credentials_changed_at.since(self.created_at)
    }

    /// Confirms the change for `account`. This is the only way it is used.
    /// Raises `identity.management_email_change_confirmed` when `account`
    /// is a management account's; a tenant user's move is raised by the
    /// user when it takes the new address.
    ///
    /// It gives back the new address as proven. Moving the account onto it
    /// as a verified address needs that proof.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] when [`Self::state_for`] says the link is not
    ///   usable for `account`. The change is left as it was.
    pub fn confirm(
        &mut self,
        account: ChangingAccount<'_>,
        now: OffsetDateTime,
    ) -> Result<VerifiedEmail, TokenRefused> {
        if let Some(refused) = TokenRefused::of(self.state_for(account, now)) {
            return Err(refused);
        }
        self.state = ChangeState::Confirmed { at: now };
        self.raise_for_management(account, |principal| ManagementEmailChangeConfirmed {
            principal,
            occurred_at: now,
        });
        Ok(VerifiedEmail::proven(self.new_email.clone()))
    }

    /// Cancels the change from the link sent to the old address, for
    /// `account` as it stands now. Raises `identity.email_change_cancelled`
    /// when `account` is a tenant user's, and
    /// `identity.management_email_change_cancelled` when it is a management
    /// account's.
    ///
    /// The old address is told about every change, so a person whose
    /// session was stolen can stop it. Following the link proves the reader
    /// holds the old mailbox. It works until the change lands, even after
    /// its own link expired.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not the one that
    ///   asked, or no longer has the old address.
    /// - [`DomainError::InvalidTransition`] when the change was already
    ///   confirmed or cancelled.
    pub fn cancel_from_old_address(
        &mut self,
        account: ChangingAccount<'_>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if account.id != self.principal_id || *account.email != self.from_email {
            return Err(DomainError::forbidden(message!(
                "identity-the-cancel-link-is-for-another",
                "the cancel link is for another account or an address it no longer has"
            )));
        }
        if self.state != ChangeState::Waiting {
            return Err(DomainError::invalid_transition(message!(
                "identity-the-change-was-already-confirmed-or",
                "the change was already confirmed or cancelled"
            )));
        }
        self.state = ChangeState::Cancelled { at: now };
        self.raise_for(
            account,
            |principal| EmailChangeCancelled {
                principal,
                occurred_at: now,
            },
            |principal| ManagementEmailChangeCancelled {
                principal,
                occurred_at: now,
            },
        );
        Ok(())
    }

    /// Sends the confirmation again from its own link, which ran out before
    /// it was followed, with a new token and lifetime. Raises
    /// `identity.email_change_link_resent` when `account` is a tenant
    /// user's, and `identity.management_email_change_link_resent` when it is
    /// a management account's.
    ///
    /// Ann asks for a new address on Friday and opens the link on Monday.
    /// The page offers her a new link instead of a fresh sign-in. That holds
    /// only while the change stands as it was asked: the dead link is its
    /// own, it was not cancelled, and the account kept its address and how
    /// it signs in. Once Ann resets her password after a stolen session,
    /// the change stays dead. The new link goes to the same new address,
    /// and the cancel link to the old one keeps working.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `presented` is not the pending change's
    ///   link, or `account` is not the one that asked.
    /// - [`DomainError::Conflict`] when the link still works.
    /// - [`DomainError::Conflict`] when the change landed or was cancelled,
    ///   or the account changed its address or how it signs in since.
    pub fn reissue(
        &mut self,
        account: ChangingAccount<'_>,
        presented: &TokenHash,
        renewed: RenewedLink,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if *presented != self.token_hash {
            return Err(DomainError::forbidden(message!(
                "identity-the-link-is-not-this-change",
                "the link is not this change's"
            )));
        }
        ensure_only_ran_out(self.state_for(account, now))?;
        self.token_hash = renewed.token_hash;
        self.expires_at = renewed.lifetime.ends_after(now);
        self.raise_for(
            account,
            |principal| EmailChangeLinkResent {
                principal,
                occurred_at: now,
            },
            |principal| ManagementEmailChangeLinkResent {
                principal,
                occurred_at: now,
            },
        );
        Ok(())
    }

    /// Raises the event for the affected account: the tenant's that
    /// `tenant_user` makes for a tenant user, the platform's that
    /// `management` makes for an organization member or an operator.
    fn raise_for<E: TenantEventBody + 'static, M: PlatformDomainEvent + 'static>(
        &mut self,
        account: ChangingAccount<'_>,
        tenant_user: impl FnOnce(PrincipalId) -> E,
        management: impl FnOnce(PrincipalId) -> M,
    ) {
        match account.holder {
            Holder::TenantUser => self.raised.raise(tenant_user(self.principal_id)),
            Holder::ManagementAccount => self
                .management
                .raise_platform(management(self.principal_id)),
        }
    }

    /// Raises the platform event `management` makes when the affected
    /// account is a management account's, and nothing for a tenant user's.
    fn raise_for_management<M: PlatformDomainEvent + 'static>(
        &mut self,
        account: ChangingAccount<'_>,
        management: impl FnOnce(PrincipalId) -> M,
    ) {
        if account.holder == Holder::TenantUser {
            return;
        }
        self.management
            .raise_platform(management(self.principal_id));
    }
}

/// A tenant user's change: its events are stamped with the tenant it was
/// saved for.
impl Raises for PendingEmailChange {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// An organization member's or an operator's change: its events are the
/// platform's and complete when raised.
impl RaisesComplete for PendingEmailChange {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.management.take()
    }
}

/// Refuses renewing a link in `state`, unless all that is wrong with it is
/// that its time ran out.
fn ensure_only_ran_out(state: TokenState) -> Result<(), DomainError> {
    match state {
        TokenState::Expired => Ok(()),
        TokenState::ForAnotherAccount => Err(DomainError::forbidden(message!(
            "identity-the-change-was-asked-for-another",
            "the change was asked for another account"
        ))),
        TokenState::Usable => Err(DomainError::conflict(message!(
            "identity-the-change-s-link-still-works",
            "the change's link still works"
        ))),
        TokenState::Consumed | TokenState::Superseded | TokenState::AccountShut => {
            Err(DomainError::conflict(message!(
                "identity-the-change-landed-was-cancelled-or",
                "the change landed, was cancelled, or the account changed since"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::{org_user, user};
    use crate::test_support::events::{raised_complete_names, raised_names};
    use crate::types::{OrgUserId, UserId};

    const ALICE: &str = "alice@example.com";

    fn alice() -> User<ResolvedTenant> {
        let mut alice = user(UserId::new(), ALICE);
        alice
            .verify_email(
                &crate::domains::identity::account::verified_email::proof_of(alice.email()),
            )
            .unwrap();
        alice
    }

    fn params() -> CreateEmailChangeParams {
        CreateEmailChangeParams {
            new_email: Email::new("new@example.com").unwrap(),
            token_hash: TokenHash::from_stored("abc123hash".to_owned()),
            cancel_token_hash: TokenHash::from_stored("cancelhash".to_owned()),
            lifetime: crate::types::Lifetime::seconds(3600).unwrap(),
        }
    }

    /// The holder of one account, who proved who they are again just now.
    struct ProvedJustNow(PrincipalId);

    impl crate::domains::identity::sealed::Sealed for ProvedJustNow {}

    impl RecentProof for ProvedJustNow {
        fn proves_recently(&self, account: &PrincipalId) -> bool {
            *account == self.0
        }
    }

    fn proof_by(account: ChangingAccount<'_>) -> ProvedJustNow {
        ProvedJustNow(account.id)
    }

    fn change_for(account: &User<ResolvedTenant>) -> PendingEmailChange {
        PendingEmailChange::create(account.into(), params(), &proof_by(account.into())).unwrap()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn refusal(result: Result<VerifiedEmail, TokenRefused>) -> Option<TokenState> {
        result.err().map(TokenRefused::state)
    }

    /// Alice asks to move from alice@example.com to new@example.com. The
    /// change keeps both addresses and its link is usable straight away.
    #[test]
    fn a_change_records_the_address_it_was_asked_from() {
        let alice = alice();

        let change = change_for(&alice);

        assert_eq!(change.from_email().as_str(), ALICE);
        assert_eq!(change.new_email().as_str(), "new@example.com");
        assert_eq!(change.state_for((&alice).into(), now()), TokenState::Usable);
    }

    /// Alice asks to change to alice@example.com, the address she already
    /// has. No change is started.
    #[test]
    fn changing_to_the_same_address_is_refused() {
        let alice = alice();

        let same = PendingEmailChange::create(
            (&alice).into(),
            CreateEmailChangeParams {
                new_email: Email::new(ALICE).unwrap(),
                ..params()
            },
            &proof_by((&alice).into()),
        );

        assert!(same.is_err());
    }

    /// Alice follows her link. She gets a proof for new@example.com and the
    /// change records when it was confirmed.
    #[test]
    fn confirming_proves_the_new_address() {
        let alice = alice();
        let mut change = change_for(&alice);
        let at = now();

        let proven = change.confirm((&alice).into(), at).unwrap();

        assert_eq!(proven.as_email().as_str(), "new@example.com");
        assert_eq!(change.confirmed_at(), Some(at));
    }

    /// Alice follows her link a second time. It is refused as already used,
    /// so one link gives one proof.
    #[test]
    fn double_confirm_fails() {
        let alice = alice();
        let mut change = change_for(&alice);
        change.confirm((&alice).into(), now()).unwrap();

        assert_eq!(
            refusal(change.confirm((&alice).into(), now())),
            Some(TokenState::Consumed)
        );
    }

    /// Alice follows her link at its expiry time. It is refused as expired
    /// and the change stays unconfirmed.
    #[test]
    fn expired_change_cannot_confirm() {
        let alice = alice();
        let mut change = change_for(&alice);
        let at = change.expires_at();

        assert_eq!(
            refusal(change.confirm((&alice).into(), at)),
            Some(TokenState::Expired)
        );
        assert_eq!(change.confirmed_at(), None);
    }

    /// One second before expiry the link is usable. At the expiry instant it
    /// is expired, the same as every other link and token here.
    #[test]
    fn a_change_expires_at_the_instant_its_window_ends() {
        let alice = alice();
        let change = change_for(&alice);

        assert_eq!(
            change.state_for((&alice).into(), change.expires_at() - Duration::seconds(1)),
            TokenState::Usable
        );
        assert_eq!(
            change.state_for((&alice).into(), change.expires_at()),
            TokenState::Expired
        );
    }

    /// Alice's email change cannot be confirmed for Mallory's account and remains
    /// unconfirmed after the attempt.
    #[test]
    fn a_change_cannot_be_confirmed_for_another_account() {
        let alice = alice();
        let mallory = user(UserId::new(), "mallory@example.com");
        let mut change = change_for(&alice);

        assert_eq!(
            refusal(change.confirm((&mallory).into(), now())),
            Some(TokenState::ForAnotherAccount)
        );
        assert_eq!(change.confirmed_at(), None);
    }

    /// A credential change after Alice requests a new address supersedes the
    /// pending change, so its confirmation is refused.
    #[test]
    fn a_change_asked_before_the_password_was_reset_is_void() {
        let mut alice = alice();
        let mut change = change_for(&alice);
        let _later = crate::shared::clock::freeze(change.created_at() + Duration::seconds(1));
        alice.record_credential_change();

        assert_eq!(
            refusal(change.confirm((&alice).into(), now())),
            Some(TokenState::Superseded)
        );
    }

    /// Alice resets her password and then asks for a new address. The reset
    /// came first, so the change still goes through.
    #[test]
    fn a_change_asked_after_the_password_was_reset_stands() {
        let mut alice = alice();
        alice.record_credential_change();
        let _later = crate::shared::clock::freeze(now() + Duration::seconds(1));
        let mut change = change_for(&alice);

        assert!(change.confirm((&alice).into(), now()).is_ok());
    }

    /// Alice asks for new@example.com, then an admin sets her address to
    /// elsewhere@example.com. The old link is refused as superseded.
    #[test]
    fn a_change_is_void_once_the_address_moved_some_other_way() {
        let mut alice = alice();
        let mut change = change_for(&alice);
        alice
            .change_email(
                Email::new("elsewhere@example.com").unwrap(),
                &control_over(&alice),
            )
            .unwrap();

        assert_eq!(
            refusal(change.confirm((&alice).into(), now())),
            Some(TokenState::Superseded)
        );
    }

    /// An organization member asks for a new address and follows the link.
    /// It goes through the same way as for a tenant user.
    #[test]
    fn an_org_member_confirms_their_own_change() {
        let member = org_user(OrgUserId::new(), ALICE);
        let mut change =
            PendingEmailChange::create((&member).into(), params(), &proof_by((&member).into()))
                .unwrap();

        assert!(change.confirm((&member).into(), now()).is_ok());
    }

    /// Alice has a tenant account and an organization account with the same
    /// address. A link for the tenant account is refused when followed from
    /// the organization one.
    #[test]
    fn a_tenant_change_is_not_confirmed_by_an_org_account() {
        let alice = alice();
        let member = org_user(OrgUserId::new(), ALICE);
        let mut change = change_for(&alice);

        assert_eq!(
            refusal(change.confirm((&member).into(), now())),
            Some(TokenState::ForAnotherAccount)
        );
    }

    fn stored(change: &PendingEmailChange) -> EmailChangeRow {
        EmailChangeRow {
            principal_id: change.principal_id,
            from_email: change.from_email.clone(),
            new_email: change.new_email.clone(),
            token_hash: change.token_hash.clone(),
            cancel_token_hash: change.cancel_token_hash.clone(),
            created_at: change.created_at,
            expires_at: change.expires_at,
            state: change.state,
        }
    }

    /// A stored change whose new address equals the old one is refused as a
    /// corrupt row.
    #[test]
    fn a_stored_change_to_the_address_the_account_had_is_refused() {
        let mut row = stored(&change_for(&alice()));
        row.new_email = row.from_email.clone();

        assert!(refused_as_corrupt(&PendingEmailChange::reconstitute(row)));
    }

    /// A stored change says it was confirmed one second before it was asked
    /// for. It is refused as a corrupt row.
    #[test]
    fn a_stored_change_confirmed_before_it_was_asked_for_is_refused() {
        let mut row = stored(&change_for(&alice()));
        row.state = ChangeState::Confirmed {
            at: row.created_at - time::Duration::SECOND,
        };

        assert!(refused_as_corrupt(&PendingEmailChange::reconstitute(row)));
    }

    /// A stored change says it was confirmed at the instant its link
    /// expired. No link is let through once it expires, so loading it is
    /// refused as corrupt.
    #[test]
    fn a_stored_change_confirmed_once_its_link_expired_is_refused() {
        let mut row = stored(&change_for(&alice()));
        row.state = ChangeState::Confirmed { at: row.expires_at };

        assert!(refused_as_corrupt(&PendingEmailChange::reconstitute(row)));
    }

    /// A stored change was cancelled from the old address after its link
    /// expired. The cancel link works until the change lands, so it loads.
    #[test]
    fn a_stored_change_cancelled_after_its_link_expired_loads() {
        let mut row = stored(&change_for(&alice()));
        row.state = ChangeState::Cancelled {
            at: row.expires_at + Duration::SECOND,
        };

        assert!(PendingEmailChange::reconstitute(row).is_ok());
    }

    /// Fresh proof for Mallory's account cannot authorize Alice's email change.
    #[test]
    fn a_change_needs_a_fresh_proof_of_the_holder() {
        let alice = alice();
        let mallory = user(UserId::new(), "mallory@example.com");

        let with_mallorys_proof =
            PendingEmailChange::create((&alice).into(), params(), &proof_by((&mallory).into()));

        assert!(matches!(
            with_mallorys_proof,
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Alice's session was stolen and a change to Mallory's address was
    /// asked for. Alice follows the cancel link sent to her old address. The
    /// change is cancelled, and Mallory's confirmation link is refused.
    #[test]
    fn the_old_address_cancels_a_change() {
        let alice = alice();
        let mut change = change_for(&alice);

        change
            .cancel_from_old_address((&alice).into(), now())
            .unwrap();

        assert!(matches!(change.stage(), ChangeState::Cancelled { .. }));
        assert_eq!(
            refusal(change.confirm((&alice).into(), now())),
            Some(TokenState::Superseded)
        );
    }

    /// Cancellation is refused for another account and after the email change
    /// has been confirmed.
    #[test]
    fn a_cancel_link_works_only_until_the_change_lands_and_only_for_its_account() {
        let alice = alice();
        let mallory = user(UserId::new(), "mallory@example.com");
        let mut change = change_for(&alice);

        let for_mallory = change.cancel_from_old_address((&mallory).into(), now());
        change.confirm((&alice).into(), now()).unwrap();
        let too_late = change.cancel_from_old_address((&alice).into(), now());

        assert!(matches!(for_mallory, Err(DomainError::Forbidden(_))));
        assert!(matches!(too_late, Err(DomainError::InvalidTransition(_))));
    }

    /// A day's new link for a dead one.
    fn renewal() -> RenewedLink {
        RenewedLink {
            token_hash: TokenHash::from_stored("renewed".to_owned()),
            lifetime: crate::types::Lifetime::seconds(86_400).unwrap(),
        }
    }

    /// The hash of the link every test change is sent with.
    fn sent_link() -> TokenHash {
        params().token_hash
    }

    /// Alice opens her confirmation link after it ran out. The dead link
    /// gets her a new one for a day, which then confirms the change.
    #[test]
    fn a_dead_link_reissues_its_change() {
        let alice = alice();
        let mut change = change_for(&alice);
        let opened_at = change.expires_at() + Duration::hours(1);

        change
            .reissue((&alice).into(), &sent_link(), renewal(), opened_at)
            .unwrap();

        assert_eq!(change.token_hash().as_str(), "renewed");
        assert_eq!(change.expires_at(), opened_at + Duration::days(1));
        assert_eq!(
            change.state_for((&alice).into(), opened_at),
            TokenState::Usable
        );
    }

    /// A working email-change link cannot be reissued before it expires.
    #[test]
    fn a_working_link_is_not_reissued() {
        let alice = alice();
        let mut change = change_for(&alice);

        let result = change.reissue((&alice).into(), &sent_link(), renewal(), now());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// An email-change link cannot be reissued after a credential change
    /// supersedes the request, even when the link expires.
    #[test]
    fn a_change_voided_by_a_password_reset_is_not_reissued() {
        let mut alice = alice();
        let mut change = change_for(&alice);
        let _later = crate::shared::clock::freeze(change.created_at() + Duration::seconds(1));
        alice.record_credential_change();

        let result = change.reissue(
            (&alice).into(),
            &sent_link(),
            renewal(),
            change.expires_at(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// A cancelled email change cannot reissue its expired confirmation link.
    #[test]
    fn a_cancelled_change_is_not_reissued() {
        let alice = alice();
        let mut change = change_for(&alice);
        change
            .cancel_from_old_address((&alice).into(), now())
            .unwrap();

        let result = change.reissue(
            (&alice).into(),
            &sent_link(),
            renewal(),
            change.expires_at(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// Neither a different token nor a different account can reissue Alice's
    /// expired email-change link.
    #[test]
    fn only_the_changes_own_link_and_account_reissue_it() {
        let alice = alice();
        let mallory = user(UserId::new(), "mallory@example.com");
        let mut change = change_for(&alice);
        let dead = change.expires_at();

        let other_token = change.reissue(
            (&alice).into(),
            &TokenHash::from_stored("mallorys".to_owned()),
            renewal(),
            dead,
        );
        let other_account = change.reissue((&mallory).into(), &sent_link(), renewal(), dead);

        assert!(matches!(other_token, Err(DomainError::Forbidden(_))));
        assert!(matches!(other_account, Err(DomainError::Forbidden(_))));
    }

    /// Alice asks for a new address, follows her dead link for another, and
    /// cancels from her old address. Each step is raised, in order.
    #[test]
    fn a_tenant_users_change_raises_each_step() {
        let alice = alice();
        let mut change = change_for(&alice);
        let opened_at = change.expires_at() + Duration::hours(1);

        change
            .reissue((&alice).into(), &sent_link(), renewal(), opened_at)
            .unwrap();
        change
            .cancel_from_old_address((&alice).into(), opened_at)
            .unwrap();

        assert_eq!(
            raised_names(&mut change),
            [
                "identity.email_change_requested",
                "identity.email_change_link_resent",
                "identity.email_change_cancelled",
            ]
        );
    }

    /// An organization member asks for a new address and cancels it. Their
    /// records are the platform's, so the change raises no tenant event.
    #[test]
    fn a_management_accounts_change_raises_no_tenant_event() {
        let member = org_user(OrgUserId::new(), ALICE);
        let mut change =
            PendingEmailChange::create((&member).into(), params(), &proof_by((&member).into()))
                .unwrap();

        change
            .cancel_from_old_address((&member).into(), now())
            .unwrap();

        assert!(raised_names(&mut change).is_empty());
    }

    /// An organization member asks for a new address, follows the dead
    /// link for another, and cancels from the old address. Each step is
    /// raised as the platform's, in order.
    #[test]
    fn a_management_accounts_change_raises_each_step_on_the_platform() {
        let member = org_user(OrgUserId::new(), ALICE);
        let mut change =
            PendingEmailChange::create((&member).into(), params(), &proof_by((&member).into()))
                .unwrap();
        let opened_at = change.expires_at() + Duration::hours(1);

        change
            .reissue((&member).into(), &sent_link(), renewal(), opened_at)
            .unwrap();
        change
            .cancel_from_old_address((&member).into(), opened_at)
            .unwrap();

        assert_eq!(
            raised_complete_names(&mut change),
            [
                "identity.management_email_change_requested",
                "identity.management_email_change_link_resent",
                "identity.management_email_change_cancelled",
            ]
        );
    }

    /// An organization member follows the link to their new address. The
    /// confirmation is raised as the platform's.
    #[test]
    fn confirming_a_management_accounts_change_raises_its_confirmation() {
        let member = org_user(OrgUserId::new(), ALICE);
        let mut change =
            PendingEmailChange::create((&member).into(), params(), &proof_by((&member).into()))
                .unwrap();
        raised_complete_names(&mut change);

        change.confirm((&member).into(), now()).unwrap();

        assert_eq!(
            raised_complete_names(&mut change),
            ["identity.management_email_change_confirmed"]
        );
    }

    /// Alice follows the link to her new address. Her move is raised by her
    /// account when it takes the address, so the change raises nothing.
    #[test]
    fn confirming_a_tenant_users_change_raises_nothing_of_its_own() {
        let alice = alice();
        let mut change = change_for(&alice);
        raised_names(&mut change);

        change.confirm((&alice).into(), now()).unwrap();

        assert!(raised_names(&mut change).is_empty());
        assert!(raised_complete_names(&mut change).is_empty());
    }

    /// Cancelling Alice's email change for Mallory's account is refused without
    /// raising an event.
    #[test]
    fn a_refused_email_change_step_raises_nothing() {
        let alice = alice();
        let mallory = user(UserId::new(), "mallory@example.com");
        let mut change = change_for(&alice);
        raised_names(&mut change);

        let cancelled = change.cancel_from_old_address((&mallory).into(), now());

        assert!(cancelled.is_err());
        assert!(raised_names(&mut change).is_empty());
    }

    /// Alice's change is read back from storage. Loading it raises nothing.
    #[test]
    fn an_email_change_read_back_from_storage_has_raised_nothing() {
        let row = stored(&change_for(&alice()));

        let mut change = PendingEmailChange::reconstitute(row).unwrap();

        assert!(raised_names(&mut change).is_empty());
    }
}
