//! Password reset requests, started by the user or an admin, for getting
//! back into an account, and the password change a sign-in owes when an
//! admin set the password or it expired.

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::events::recovery::{
    PasswordResetCompleted, PasswordResetRequested,
};
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::isolation::scope::{ResolvedTenant, TenantScope};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{
    Email, EventLabel, Lifetime, PasswordResetId, TokenHash, TokenRefused, TokenState, UserId,
};

/// Who initiated the password reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResetInitiator {
    /// The user asked for a reset through "forgot password".
    User,
    /// A tenant admin started the reset for the user.
    Admin,
    /// The system asked for a new password inside a sign-in that proved the
    /// current one, because an admin set it or it expired. Never mailed: it
    /// is answered only by the sign-in that began it, through
    /// [`PasswordResetRequest::complete_in_sign_in`].
    System,
}

impl ResetInitiator {
    /// The name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::System => "system",
        }
    }
}

/// Status of a password reset request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResetStatus {
    /// The reset link was sent, and the user has not acted yet.
    Pending,
    /// The user completed the reset and set a new password.
    Completed,
    /// The reset link expired without being used.
    Expired,
    /// The reset was cancelled, for example by an admin.
    Cancelled,
}

impl ResetStatus {
    /// Moves to `to` if a reset in this status may. Only a pending reset is
    /// completed, expires or is cancelled.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            from == Self::Pending && to != Self::Pending
        })
    }
}

/// Where a reset stands, with the time it was completed if it was.
///
/// It is one value, not a status beside an optional time. So a reset can
/// never read as completed with no completion time, or pending with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetState {
    /// Waiting for the link to be followed.
    Pending,
    /// A new password was set through it.
    Completed {
        /// When.
        at: OffsetDateTime,
    },
    /// Its link ran out unused.
    Expired,
    /// Called off.
    Cancelled,
}

impl ResetState {
    /// The status label this state carries.
    #[must_use]
    pub fn status(self) -> ResetStatus {
        match self {
            Self::Pending => ResetStatus::Pending,
            Self::Completed { .. } => ResetStatus::Completed,
            Self::Expired => ResetStatus::Expired,
            Self::Cancelled => ResetStatus::Cancelled,
        }
    }

    /// Reads a state back from its stored status and completion time.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a completed reset has no
    ///   completion time.
    /// - [`DomainError::Infrastructure`] when a reset in any other status has
    ///   one.
    pub fn from_stored(
        status: ResetStatus,
        completed_at: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, completed_at) {
            (ResetStatus::Completed, Some(at)) => Ok(Self::Completed { at }),
            (ResetStatus::Pending, None) => Ok(Self::Pending),
            (ResetStatus::Expired, None) => Ok(Self::Expired),
            (ResetStatus::Cancelled, None) => Ok(Self::Cancelled),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} password reset has a completion time that contradicts it"
            ))),
        }
    }

    /// When it was completed, if it was. This is the form storage keeps.
    #[must_use]
    pub fn completed_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Completed { at } => Some(at),
            Self::Pending | Self::Expired | Self::Cancelled => None,
        }
    }
}

/// A password reset request.
///
/// Created when a user forgets their password or an admin sends a link: the
/// app layer generates a secure token, sends it by email and tracks the
/// request here. A sign-in whose password must change first begins one too,
/// started by the system, whose token goes back to that sign-in and is
/// never mailed.
#[derive(Debug)]
pub struct PasswordResetRequest {
    /// Unique request identifier.
    id: PasswordResetId,
    /// The user who needs to reset their password.
    user_id: UserId,
    /// The email the reset link was sent to.
    email: Email,
    /// Who initiated the reset.
    initiator: ResetInitiator,
    /// Where the request stands.
    state: ResetState,
    /// One-way hash of the reset token. The raw token is in the email link.
    token_hash: TokenHash,
    /// When the request was created.
    created_at: OffsetDateTime,
    /// When the reset link expires.
    expires_at: OffsetDateTime,
    /// What the request raised and has not handed over yet. The request is
    /// not typed by its tenant's scope, so the list takes the resolved one;
    /// the tenant stamped on each event is the one the save names either way.
    raised: Raised<ResolvedTenant>,
}

/// Persisted state for repository hydration.
pub struct PasswordResetRow {
    /// Unique request identifier.
    pub id: PasswordResetId,
    /// The user who needs to reset.
    pub user_id: UserId,
    /// The email the link was sent to.
    pub email: Email,
    /// Who initiated the reset.
    pub initiator: ResetInitiator,
    /// Where the request stands. See [`ResetState::from_stored`].
    pub state: ResetState,
    /// One-way hash of the reset token.
    pub token_hash: TokenHash,
    /// When the request was created.
    pub created_at: OffsetDateTime,
    /// When the reset link expires.
    pub expires_at: OffsetDateTime,
}

/// Parameters for creating a password reset request. The account and the
/// address come from the account itself, passed to
/// [`PasswordResetRequest::create`].
pub struct CreateResetParams {
    /// Who initiated the reset.
    pub initiator: ResetInitiator,
    /// One-way hash of the reset token.
    pub token_hash: TokenHash,
    /// How long the reset link works, at most `RESET_LONGEST`.
    pub lifetime: Lifetime,
}

impl PasswordResetRequest {
    /// Creates a new pending reset request for `holder`, to be mailed to the
    /// address the account has now. Raises
    /// `authentication.password_reset_requested`, naming the account by that
    /// address.
    ///
    /// Only an address the account's owner was shown to hold gets a link.
    /// An address an admin or a directory typed in is unverified, so it gets
    /// none. Sam may edit users. Without this check, Sam sets Ann's address
    /// to his own, asks for a reset, follows the link and takes her account.
    /// An owner whose address is still unverified confirms it first.
    ///
    /// A link works for an hour at most. One that lived for weeks would sit
    /// in a mailbox, ready for whoever reads it later.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account may not sign in, such as
    ///   a locked one or one waiting for erasure. A new password would open
    ///   nothing.
    /// - [`DomainError::Forbidden`] when the account's address is
    ///   unverified.
    /// - [`DomainError::Validation`] when the link would live longer than
    ///   `RESET_LONGEST`.
    pub fn create<T: TenantScope>(
        holder: &User<T>,
        params: CreateResetParams,
    ) -> Result<Self, DomainError> {
        if params.initiator == ResetInitiator::System {
            return Err(DomainError::invalid(message!(
                "authentication-a-sign-in-s-password-change",
                "a sign-in's password change is begun inside the sign-in, never mailed"
            )));
        }
        ensure_may_sign_in(holder)?;
        ensure_proved_address(holder)?;
        params
            .lifetime
            .ensure_at_most(RESET_LONGEST, "a reset link")?;
        Ok(Self::pending(holder, params))
    }

    /// Begins the password change a sign-in owes for `holder`, whose
    /// current password the sign-in just proved but which an admin set or
    /// which expired. Raises `authentication.password_reset_requested`
    /// started by the system.
    ///
    /// Nothing is mailed, so the address need not be verified: the token
    /// goes back to the browser that proved the password, and answers only
    /// [`Self::complete_in_sign_in`]. It works for
    /// [`IN_SIGN_IN_LONGEST`] at most, a sign-in's span rather than a
    /// mailbox's.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account may not sign in.
    /// - [`DomainError::Validation`] when the change would stay open longer
    ///   than [`IN_SIGN_IN_LONGEST`].
    pub fn in_sign_in<T: TenantScope>(
        holder: &User<T>,
        token_hash: TokenHash,
        lifetime: Lifetime,
    ) -> Result<Self, DomainError> {
        ensure_may_sign_in(holder)?;
        lifetime.ensure_at_most(IN_SIGN_IN_LONGEST, "a sign-in's password change")?;
        let params = CreateResetParams {
            initiator: ResetInitiator::System,
            token_hash,
            lifetime,
        };
        Ok(Self::pending(holder, params))
    }

    /// A new pending request for `holder` under `params`, its request
    /// raised.
    fn pending<T: TenantScope>(holder: &User<T>, params: CreateResetParams) -> Self {
        let now = crate::shared::clock::now();
        let mut request = Self {
            id: PasswordResetId::new(),
            user_id: *holder.id(),
            email: holder.email().clone(),
            initiator: params.initiator,
            state: ResetState::Pending,
            token_hash: params.token_hash,
            created_at: now,
            expires_at: params.lifetime.ends_after(now),
            raised: Raised::default(),
        };
        request.raised.raise(PasswordResetRequested {
            user_id: request.user_id,
            user_label: EventLabel::of(request.email.as_str()),
            initiator: request.initiator,
            occurred_at: now,
        });
        request
    }

    /// Rebuilds a password reset from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row expires no later than it
    ///   was requested.
    /// - [`DomainError::Infrastructure`] when the row was completed before it
    ///   was requested, or once its link had expired.
    pub fn reconstitute(row: PasswordResetRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            email: row.email,
            initiator: row.initiator,
            state: row.state,
            token_hash: row.token_hash,
            created_at: row.created_at,
            expires_at: row.expires_at,
            raised: Raised::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &PasswordResetRow) -> Result<(), DomainError> {
        RowCheck::of("password reset")
            .holds(
                row.created_at < row.expires_at,
                "expires before it was requested",
            )
            .in_order_if(
                row.created_at,
                row.state.completed_at(),
                "completed before it was requested",
            )
            .holds(
                row.state
                    .completed_at()
                    .is_none_or(|at| at < row.expires_at),
                "completed after its link expired",
            )
            .finish()
    }

    /// Unique request identifier.
    #[must_use]
    pub fn id(&self) -> &PasswordResetId {
        &self.id
    }

    /// The user who needs to reset.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The email the link was sent to.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// Who initiated the reset.
    #[must_use]
    pub fn initiator(&self) -> ResetInitiator {
        self.initiator
    }

    /// Current request status.
    #[must_use]
    pub fn status(&self) -> ResetStatus {
        self.state.status()
    }

    /// Where the request stands, with its completion when it was completed.
    #[must_use]
    pub fn reset_state(&self) -> ResetState {
        self.state
    }

    /// The token hash for verification.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// When the request was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the reset link expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the reset was completed.
    #[must_use]
    pub fn completed_at(&self) -> Option<OffsetDateTime> {
        self.state.completed_at()
    }

    /// What following this link would do for `holder`, answered without
    /// using it.
    ///
    /// Each way a link can be unusable tells the holder something different.
    /// A completed reset means the password was already changed, so the form
    /// must not be offered again. A link mailed to an address the account has
    /// since left belongs to whoever reads that mailbox now, so it does
    /// nothing. Nor does one sent before the account last changed how it
    /// signs in: Ann asked for two links and used the second, so the first
    /// must not set her password again. A link for an account that may not
    /// sign in now does nothing until the account is let in again. Anything
    /// else means the holder can ask for another link. So a cancelled request
    /// reads as expired, because "ask for a new one" is the answer whether
    /// the clock or an admin ended it. A link issued to another account does
    /// nothing for this one.
    #[must_use]
    pub fn state_for<T: TenantScope>(&self, holder: &User<T>, now: OffsetDateTime) -> TokenState {
        if *holder.id() != self.user_id {
            return TokenState::ForAnotherAccount;
        }
        match self.state {
            ResetState::Completed { .. } => TokenState::Consumed,
            ResetState::Expired | ResetState::Cancelled => TokenState::Expired,
            ResetState::Pending => self.pending_state(holder, now),
        }
    }

    fn pending_state<T: TenantScope>(&self, holder: &User<T>, now: OffsetDateTime) -> TokenState {
        if !holder.can_authenticate() {
            return TokenState::AccountShut;
        }
        let replaced =
            self.email != *holder.email() || holder.credentials_changed_at().since(self.created_at);
        if replaced {
            return TokenState::Superseded;
        }
        if now >= self.expires_at {
            return TokenState::Expired;
        }
        TokenState::Usable
    }

    /// Marks the reset as completed for `holder`, who set a new password.
    /// This is the only way a reset link is used. It gives back the address
    /// the link was mailed to as proven, because following the link shows its
    /// reader holds that mailbox.
    ///
    /// Raises `authentication.password_reset_completed`.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] unless [`Self::state_for`] says the link is usable
    ///   for `holder`. A link for another account, already used, past its
    ///   window or mailed to an address the account has left cannot set a
    ///   password.
    pub fn complete<T: TenantScope>(
        &mut self,
        holder: &User<T>,
        now: OffsetDateTime,
    ) -> Result<VerifiedEmail, TokenRefused> {
        if self.initiator == ResetInitiator::System {
            return Err(TokenRefused::other_kind());
        }
        self.finish_reset(holder, now)?;
        Ok(VerifiedEmail::proven(self.email.clone()))
    }

    /// Marks the password change a sign-in owed as done for `holder`, who
    /// set a new password inside that sign-in. It proves no mailbox, so the
    /// address keeps whatever standing it had.
    ///
    /// Raises `authentication.password_reset_completed`.
    ///
    /// # Errors
    ///
    /// - [`TokenRefused`] for a mailed reset link, which only
    ///   [`Self::complete`] answers, and unless [`Self::state_for`] says the
    ///   change is usable for `holder`.
    pub fn complete_in_sign_in<T: TenantScope>(
        &mut self,
        holder: &User<T>,
        now: OffsetDateTime,
    ) -> Result<(), TokenRefused> {
        if self.initiator != ResetInitiator::System {
            return Err(TokenRefused::other_kind());
        }
        self.finish_reset(holder, now)
    }

    /// Moves the request to completed for `holder` at `now`, raising the
    /// record of it.
    fn finish_reset<T: TenantScope>(
        &mut self,
        holder: &User<T>,
        now: OffsetDateTime,
    ) -> Result<(), TokenRefused> {
        if let Some(refused) = TokenRefused::of(self.state_for(holder, now)) {
            return Err(refused);
        }
        if self
            .status()
            .try_transition(ResetStatus::Completed)
            .is_err()
        {
            return Err(TokenRefused::spent());
        }
        self.state = ResetState::Completed { at: now };
        self.raised
            .raise(PasswordResetCompleted { occurred_at: now });
        Ok(())
    }
}

impl Raises for PasswordResetRequest {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// The longest a reset link may live. It matches the tenant's other reset
/// links.
pub(crate) const RESET_LONGEST: Duration = Duration::hours(1);

/// The longest a sign-in's password change stays open: long enough to type
/// a new password, not to come back to later.
pub const IN_SIGN_IN_LONGEST: Duration = Duration::minutes(15);

/// Refuses a reset for an account that may not sign in.
fn ensure_may_sign_in<T: TenantScope>(holder: &User<T>) -> Result<(), DomainError> {
    if holder.can_authenticate() {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "authentication-a-reset-link-goes-only-to-2",
        "a reset link goes only to an account that may sign in"
    )))
}

/// Refuses a reset for an account whose address nobody proved reaches its
/// owner.
fn ensure_proved_address<T: TenantScope>(holder: &User<T>) -> Result<(), DomainError> {
    if holder.address().is_verified() {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "authentication-a-reset-link-goes-only-to",
        "a reset link goes only to an address the account's owner was shown to hold"
    )))
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::CredentialChange;

    const ALICE: &str = "alice@acme.com";

    fn verified(address: &str) -> User<ResolvedTenant> {
        let mut holder = user(UserId::new(), address);
        let proof = proof_of(holder.email());
        holder.verify_email(&proof).unwrap();
        holder
    }

    fn alice() -> User<ResolvedTenant> {
        verified(ALICE)
    }

    fn params(initiator: ResetInitiator, token: &str) -> CreateResetParams {
        CreateResetParams {
            initiator,
            token_hash: TokenHash::from_stored(token.to_owned()),
            lifetime: crate::types::Lifetime::seconds(3600).unwrap(),
        }
    }

    fn reset_for(holder: &User<ResolvedTenant>) -> PasswordResetRequest {
        PasswordResetRequest::create(holder, params(ResetInitiator::User, "hashed_token")).unwrap()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// Alice asks for a reset. The new request is pending with no
    /// completion time.
    #[test]
    fn create_produces_pending_request() {
        let req = reset_for(&alice());
        assert_eq!(req.status(), ResetStatus::Pending);
        assert!(req.completed_at().is_none());
    }

    /// Alice follows her fresh link within the hour. It reads as usable.
    #[test]
    fn usable_when_pending_and_not_expired() {
        let alice = alice();
        assert_eq!(
            reset_for(&alice).state_for(&alice, now()),
            TokenState::Usable
        );
    }

    /// Alice sets a new password through her link. The request is completed
    /// at that moment.
    #[test]
    fn complete_sets_status() {
        let alice = alice();
        let mut req = reset_for(&alice);
        let at = now();

        req.complete(&alice, at).unwrap();

        assert_eq!(req.status(), ResetStatus::Completed);
        assert_eq!(req.completed_at(), Some(at));
    }

    /// A consumed reset link is refused as already used.
    #[test]
    fn cannot_complete_twice() {
        let alice = alice();
        let mut req = reset_for(&alice);
        req.complete(&alice, now()).unwrap();

        assert_eq!(
            req.complete(&alice, now()).map_err(TokenRefused::state),
            Err(TokenState::Consumed)
        );
    }

    /// Alice follows her link at the moment it expires. It is refused as
    /// expired, even though storage still says pending.
    #[test]
    fn a_reset_past_its_window_cannot_be_completed() {
        let alice = alice();
        let mut req = reset_for(&alice);
        let at = req.expires_at();

        assert_eq!(
            req.complete(&alice, at).map_err(TokenRefused::state),
            Err(TokenState::Expired)
        );
        assert_eq!(req.status(), ResetStatus::Pending);
    }

    /// Changing Alice's address supersedes the old reset link, which remains pending after refusal.
    #[test]
    fn a_link_sent_to_an_address_the_account_no_longer_has_does_nothing() {
        let mut alice = alice();
        let mut req = reset_for(&alice);
        alice
            .change_email(
                Email::new("alice@new.test").unwrap(),
                &crate::domains::identity::account::user::tests::control_over(&alice),
            )
            .unwrap();

        let refused = req.complete(&alice, now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Superseded)
        );
        assert_eq!(req.status(), ResetStatus::Pending);
    }

    /// A matching email address does not let another account use Alice's reset
    /// link; refusal leaves the link pending.
    #[test]
    fn a_reset_cannot_set_another_accounts_password() {
        let alice = alice();
        let other = verified(ALICE);
        let mut req = reset_for(&alice);

        let refused = req.complete(&other, now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::ForAnotherAccount)
        );
        assert_eq!(req.status(), ResetStatus::Pending);
    }

    /// An admin starts a reset for Bob. The request records the admin as
    /// its initiator.
    #[test]
    fn admin_initiated_reset() {
        let bob = verified("bob@acme.com");

        let req = PasswordResetRequest::create(&bob, params(ResetInitiator::Admin, "admin_hash"))
            .unwrap();

        assert_eq!(req.initiator(), ResetInitiator::Admin);
    }

    fn in_sign_in_for(holder: &User<ResolvedTenant>) -> PasswordResetRequest {
        PasswordResetRequest::in_sign_in(
            holder,
            TokenHash::from_stored("change_hash".to_owned()),
            crate::types::Lifetime::seconds(600).unwrap(),
        )
        .unwrap()
    }

    /// Bob's account, active, at an address an admin typed in that nobody
    /// confirmed since.
    fn typed_in_by_admin() -> User<ResolvedTenant> {
        let mut bob = verified("bob@old.acme.com");
        bob.change_email(
            Email::new("bob@acme.com").unwrap(),
            &crate::domains::identity::account::user::tests::control_over(&bob),
        )
        .unwrap();
        bob
    }

    /// An admin set Bob's password and his address was typed in, never
    /// confirmed. His sign-in still begins the change it owes, started by
    /// the system: nothing is mailed, so no address is needed.
    #[test]
    fn a_sign_in_begins_a_change_for_an_unconfirmed_address() {
        let bob = typed_in_by_admin();

        let change = in_sign_in_for(&bob);

        assert_eq!(change.initiator(), ResetInitiator::System);
        assert_eq!(change.status(), ResetStatus::Pending);
    }

    /// An account awaiting address verification cannot begin a sign-in password change.
    #[test]
    fn an_account_still_joining_begins_no_sign_in_change() {
        let bob = user(UserId::new(), "bob@acme.com");

        let refused = PasswordResetRequest::in_sign_in(
            &bob,
            TokenHash::from_stored("change_hash".to_owned()),
            crate::types::Lifetime::seconds(600).unwrap(),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A sign-in password change cannot be created with a one-hour lifetime.
    #[test]
    fn a_sign_in_change_lives_fifteen_minutes_at_most() {
        let refused = PasswordResetRequest::in_sign_in(
            &alice(),
            TokenHash::from_stored("change_hash".to_owned()),
            crate::types::Lifetime::seconds(3600).unwrap(),
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// System context cannot begin a mailed password reset.
    #[test]
    fn a_system_reset_is_never_created_for_mailing() {
        let refused = PasswordResetRequest::create(&alice(), params(ResetInitiator::System, "h"));

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Bob sets a new password inside his sign-in. The change completes
    /// once, proves no mailbox, and his address stays unconfirmed.
    #[test]
    fn a_sign_in_change_completes_once_and_proves_no_address() {
        let bob = typed_in_by_admin();
        let mut change = in_sign_in_for(&bob);

        change.complete_in_sign_in(&bob, now()).unwrap();
        let again = change.complete_in_sign_in(&bob, now());

        assert_eq!(change.status(), ResetStatus::Completed);
        assert_eq!(
            again.map_err(TokenRefused::state),
            Err(TokenState::Consumed)
        );
        assert!(!bob.address().is_verified());
    }

    /// Sign-in changes and mailed reset links cannot answer each other's
    /// purposes; both remain pending after the refused attempts.
    #[test]
    fn a_sign_in_change_and_a_mailed_link_never_answer_each_other() {
        let alice = alice();
        let mut change = in_sign_in_for(&alice);
        let mut mailed = reset_for(&alice);

        let as_link = change.complete(&alice, now());
        let as_change = mailed.complete_in_sign_in(&alice, now());

        assert_eq!(
            as_link.map_err(TokenRefused::state),
            Err(TokenState::ForAnotherAccount)
        );
        assert_eq!(
            as_change.map_err(TokenRefused::state),
            Err(TokenState::ForAnotherAccount)
        );
        assert_eq!(change.status(), ResetStatus::Pending);
        assert_eq!(mailed.status(), ResetStatus::Pending);
    }

    /// A reset made for Alice reports Alice's user id and address, the exact
    /// token hash and its own id. A presented link is checked against that
    /// hash, and only Alice's password may change.
    #[test]
    fn a_request_reports_the_account_and_the_token_hash_it_was_created_with() {
        let alice = alice();

        let request = reset_for(&alice);

        assert_eq!(request.user_id(), alice.id());
        assert_eq!(request.email(), alice.email());
        assert_eq!(request.token_hash().as_str(), "hashed_token");
        assert!(!request.id().as_uuid().is_nil());
    }

    /// An administrator-entered email address is unverified and cannot receive a reset link.
    #[test]
    fn no_reset_goes_to_an_address_an_admin_typed_in() {
        let mut alice = alice();
        alice
            .change_email(
                Email::new("sam@evil.test").unwrap(),
                &crate::domains::identity::account::user::tests::control_over(&alice),
            )
            .unwrap();

        let refused = PasswordResetRequest::create(&alice, params(ResetInitiator::User, "hash"));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A credential change supersedes reset links issued before it.
    #[test]
    fn a_link_sent_before_the_password_changed_does_nothing() {
        let mut alice = alice();
        let mut first = reset_for(&alice);
        alice.record_credential_change();

        let refused = first.complete(&alice, now());

        assert_eq!(
            refused.map_err(TokenRefused::state),
            Err(TokenState::Superseded)
        );
    }

    /// A two-day lifetime is invalid for a mailed reset link.
    #[test]
    fn a_reset_link_lives_at_most_an_hour() {
        let long = CreateResetParams {
            lifetime: crate::types::Lifetime::seconds(2 * 86_400).unwrap(),
            ..params(ResetInitiator::User, "hash")
        };

        let refused = PasswordResetRequest::create(&alice(), long);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// A locked account can neither obtain a reset link nor use one issued before the lock.
    #[test]
    fn a_locked_account_gets_no_working_reset_link() {
        let ann = account_with(UserId::new(), UserStatus::Active, CredentialChange::Never);
        let mut sent_before = reset_for(&ann);
        let locked = account_with(*ann.id(), UserStatus::Locked, CredentialChange::Never);

        let new_link = PasswordResetRequest::create(&locked, params(ResetInitiator::User, "hash"));
        let old_link = sent_before.complete(&locked, now());

        assert!(matches!(new_link, Err(DomainError::Forbidden(_))));
        assert_eq!(
            old_link.map_err(TokenRefused::state),
            Err(TokenState::AccountShut)
        );
    }

    /// Bob registered and never confirmed his address. A reset for him is
    /// refused. He confirms the address first.
    #[test]
    fn no_reset_goes_to_an_address_nobody_confirmed() {
        let bob = user(UserId::new(), "bob@acme.com");

        let refused = PasswordResetRequest::create(&bob, params(ResetInitiator::User, "hash"));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Alice's link reads as usable now, expired at its end time and two
    /// hours later, and used once she completes it. Each answer tells her
    /// something different: use it, ask again, or the password already
    /// changed.
    #[test]
    fn a_pending_request_past_its_window_reads_as_expired_not_usable() {
        let alice = alice();
        let request = reset_for(&alice);
        let now = now();

        assert_eq!(request.state_for(&alice, now), TokenState::Usable);
        assert_eq!(
            request.state_for(&alice, request.expires_at()),
            TokenState::Expired,
            "the expiry itself is outside the window"
        );
        assert_eq!(
            request.state_for(&alice, now + Duration::hours(2)),
            TokenState::Expired
        );

        let mut used = reset_for(&alice);
        used.complete(&alice, now).unwrap();
        assert_eq!(
            used.state_for(&alice, now),
            TokenState::Consumed,
            "a completed reset must not offer the form again"
        );
    }

    /// A pending reset may become completed, expired or cancelled. None of
    /// those can go back to pending.
    #[test]
    fn only_a_pending_reset_moves() {
        for to in [
            ResetStatus::Completed,
            ResetStatus::Expired,
            ResetStatus::Cancelled,
        ] {
            assert_eq!(ResetStatus::Pending.try_transition(to), Ok(to));
            assert!(to.try_transition(ResetStatus::Pending).is_err());
        }
    }

    fn stored(reset: &PasswordResetRequest) -> PasswordResetRow {
        PasswordResetRow {
            id: *reset.id(),
            user_id: *reset.user_id(),
            email: reset.email().clone(),
            initiator: reset.initiator(),
            state: reset.reset_state(),
            token_hash: reset.token_hash().clone(),
            created_at: reset.created_at(),
            expires_at: reset.expires_at(),
        }
    }

    /// A stored reset expires one second before it was requested. Loading it
    /// is refused as corrupt.
    #[test]
    fn a_stored_reset_that_expires_before_it_was_requested_is_refused() {
        let mut row = stored(&reset_for(&alice()));
        row.expires_at = row.created_at - Duration::SECOND;

        assert!(refused_as_corrupt(&PasswordResetRequest::reconstitute(row)));
    }

    /// A stored reset was completed one second before it was requested.
    /// Loading it is refused as corrupt.
    #[test]
    fn a_stored_reset_completed_before_it_was_requested_is_refused() {
        let mut row = stored(&reset_for(&alice()));
        row.state = ResetState::Completed {
            at: row.created_at - Duration::SECOND,
        };

        assert!(refused_as_corrupt(&PasswordResetRequest::reconstitute(row)));
    }

    /// A stored reset was completed at the instant its link expired. No
    /// link sets a password once it expires, so loading it is refused as
    /// corrupt.
    #[test]
    fn a_stored_reset_completed_once_its_link_expired_is_refused() {
        let mut row = stored(&reset_for(&alice()));
        row.state = ResetState::Completed { at: row.expires_at };

        assert!(refused_as_corrupt(&PasswordResetRequest::reconstitute(row)));
    }

    /// Alice asks for a reset. The request raises
    /// `authentication.password_reset_requested`, naming her by the address
    /// the link goes to, as asked by herself.
    #[test]
    fn asking_for_a_reset_raises_the_request() {
        let mut req = reset_for(&alice());

        let events = raised(&mut req);

        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.password_reset_requested"
        );
        assert_eq!(events[0].payload().get("initiator"), Some("user"));
        assert_eq!(events.len(), 1);
    }

    /// Alice sets a new password through her link. The request raises
    /// `authentication.password_reset_completed`.
    #[test]
    fn completing_a_reset_raises_its_completion() {
        let alice = alice();
        let mut req = reset_for(&alice);
        raised_names(&mut req);

        req.complete(&alice, now()).unwrap();

        assert_eq!(
            raised_names(&mut req),
            ["authentication.password_reset_completed"]
        );
    }

    /// Replaying a used reset link is refused without raising another event.
    #[test]
    fn a_refused_completion_raises_nothing() {
        let alice = alice();
        let mut req = reset_for(&alice);
        req.complete(&alice, now()).unwrap();
        raised_names(&mut req);

        let refused = req.complete(&alice, now());

        assert!(refused.is_err());
        assert!(raised(&mut req).is_empty());
    }

    /// A request read back from storage has raised nothing.
    #[test]
    fn a_request_read_back_has_raised_nothing() {
        let mut req = PasswordResetRequest::reconstitute(stored(&reset_for(&alice()))).unwrap();

        assert!(raised(&mut req).is_empty());
    }
}
