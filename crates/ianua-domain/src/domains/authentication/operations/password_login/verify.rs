//! The first step of a password sign-in: everything that needs nothing
//! from outside the domain.

use crate::domains::authentication::admission::SignInAdmitted;
use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::authentication::events::login::{
    AccountLockedOut, AccountUnderAttack, LockedAddress, LoginFailed, LoginFailureReason,
};
use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::operations::password_login::{
    LoginCandidate, LoginConfig, LoginFailure, PasswordLogin, PasswordProof, VerifiedLogin,
};
use crate::domains::authentication::risk_engine::attack::AttackBegun;
use crate::domains::authentication::risk_engine::origin::AttemptOrigin;
use crate::domains::authentication::risk_engine::rate_limit::{LoginAttemptTracker, OriginLockout};
use crate::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use crate::domains::identity::account::address::MailReach;
use crate::domains::identity::account::user_status::UserStatus;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{TenantEventBody, scoped};
use crate::types::{Email, EventLabel, Fact, IpAddress, TenantId, UntrustedText, UserAgent};

impl PasswordLogin {
    /// The email being used to log in.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// The address the attempt came from, if known.
    #[must_use]
    pub fn ip_address(&self) -> Fact<&IpAddress> {
        self.ip_address.as_ref()
    }

    /// Where the attempt came from, as its failures are counted.
    #[must_use]
    pub fn origin(&self) -> AttemptOrigin {
        AttemptOrigin::of(self.ip_address.as_ref())
    }

    /// A password login attempt, made now, for an attempt the tenant
    /// admitted.
    ///
    /// The tenant has already decided whether the workspace takes passwords
    /// and whether the caller's address may sign in. It decided that for
    /// every email alike, so nothing here asks again.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the attempt was admitted for another
    ///   method than a password.
    pub fn new(
        tenant_id: TenantId,
        email: Email,
        admitted: SignInAdmitted,
        user_agent: Fact<UserAgent>,
    ) -> Result<Self, DomainError> {
        if admitted.method() != AuthMethod::Password {
            return Err(DomainError::forbidden(message!(
                "authentication-the-sign-in-was-admitted-for",
                "the sign-in was admitted for another way in than a password"
            )));
        }
        Ok(Self {
            tenant_id,
            email,
            ip_address: admitted.into_client_ip(),
            user_agent,
            at: crate::shared::clock::now(),
        })
    }

    /// Checks origin lockout, account standing, password and joining/address requirements.
    /// Admission already checked the caller's location. Unknown, shut and wrongly proven
    /// accounts receive the same hash work and invalid-credential response. Hasher outages
    /// reveal no account standing. Only a proven password reveals joining or email state.
    /// Failures mark `tracker`; a valid password clears it. The caller persists the count.
    ///
    /// # Errors
    /// [`LoginFailure::AccountLocked`] for origin lockout; [`LoginFailure::Unavailable`]
    /// for hasher failure without counting an attempt; [`LoginFailure::InvalidCredentials`]
    /// for a wrong password or locked, deactivated or closing account;
    /// [`LoginFailure::EmailNotVerified`] for an unverified address when mail is available;
    /// [`LoginFailure::AccountNotActive`] if the proven account has not finished joining.
    pub fn verify<'a>(
        &'a self,
        password: &str,
        candidate: &'a LoginCandidate,
        tracker: &mut LoginAttemptTracker,
        config: &LoginConfig<'_, impl PasswordHasher, impl RefreshTokenGenerator>,
    ) -> Result<VerifiedLogin<'a>, LoginFailure> {
        let proof = Self::password_proof(password, candidate, config);
        self.check_rate_limit(tracker)?;
        let proof = proof.map_err(LoginFailure::Unavailable)?;
        self.check_user_status(candidate, tracker)?;
        self.check_password(proof, tracker)?;
        tracker.reset();
        self.ensure_email_verified(candidate, config.rules.mail)?;
        self.ensure_joined(candidate)?;
        Ok(VerifiedLogin {
            login: self,
            candidate,
        })
    }

    /// The refusal for an email that has no account.
    ///
    /// It answers exactly as a real account would. That is locked once its
    /// origin is locked out, and invalid credentials otherwise, counted as a
    /// failure. An address that could never lock would give itself away the
    /// first time a real one did.
    pub fn no_such_user(&self, tracker: &mut LoginAttemptTracker) -> LoginFailure {
        if let Err(locked) = self.check_rate_limit(tracker) {
            return locked;
        }
        let events = self.failure_events(tracker, LoginFailureReason::UserNotFound);
        LoginFailure::InvalidCredentials { events }
    }

    /// The record of `lockout`, which this attempt's failure set on its
    /// origin, against `address`: the account the attempts named, or a note
    /// that it has none. It names the address and the network locked out,
    /// never a password.
    #[must_use]
    pub fn locked_out(&self, lockout: OriginLockout, address: LockedAddress) -> DomainEvent {
        self.recorded(AccountLockedOut {
            user_id: address,
            user_label: EventLabel::of(self.email.as_str()),
            failed_attempts: lockout.failed_attempts(),
            locked_until: lockout.until(),
            origin: self.origin(),
            ip_address: self.ip_address.clone(),
            occurred_at: self.at,
        })
    }

    /// The record of `begun`, the attack this attempt found on the account
    /// its address names: the account, or an address without an account.
    /// It names how many networks failed, never which, and never a password.
    #[must_use]
    pub fn under_attack(&self, begun: AttackBegun, address: LockedAddress) -> DomainEvent {
        self.recorded(AccountUnderAttack {
            user_id: address,
            user_label: EventLabel::of(self.email.as_str()),
            networks: begun.networks().get(),
            until: begun.until(),
            occurred_at: self.at,
        })
    }

    /// Refuses while the origin is locked out. Each attempt still leaves a
    /// [`LoginFailed`], so guessing that goes on during a lockout is on
    /// record. It does not count towards the lock, which is already in force.
    fn check_rate_limit(&self, tracker: &LoginAttemptTracker) -> Result<(), LoginFailure> {
        if tracker.is_locked(self.at) {
            return Err(LoginFailure::AccountLocked {
                until: tracker.locked_until().unwrap_or(self.at),
                events: vec![self.failed_event(LoginFailureReason::AccountLocked)],
            });
        }
        Ok(())
    }

    fn check_user_status(
        &self,
        candidate: &LoginCandidate,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<(), LoginFailure> {
        let reason = match candidate.status {
            UserStatus::Deactivated => LoginFailureReason::AccountDeactivated,
            UserStatus::Closing => LoginFailureReason::AccountClosing,
            UserStatus::Locked => LoginFailureReason::AccountLocked,
            UserStatus::Invited | UserStatus::PendingVerification | UserStatus::Active => {
                return Ok(());
            }
        };
        let events = self.failure_events(tracker, reason);
        Err(LoginFailure::InvalidCredentials { events })
    }

    /// Whether `password` is the account's. It runs before anything else is
    /// decided. So every answer costs the same hash, and none comes back
    /// sooner for an account that is locked out, locked or deactivated.
    ///
    /// A hasher that cannot check gives its error, not a wrong password.
    /// Read as wrong, an outage would count every sign-in towards a lockout
    /// and send people to reset passwords that work.
    fn password_proof(
        password: &str,
        candidate: &LoginCandidate,
        config: &LoginConfig<'_, impl PasswordHasher, impl RefreshTokenGenerator>,
    ) -> Result<PasswordProof, DomainError> {
        if config.hasher.verify(password, &candidate.password_hash)? {
            return Ok(PasswordProof::Matched);
        }
        Ok(PasswordProof::Mismatched)
    }

    fn check_password(
        &self,
        proof: PasswordProof,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<(), LoginFailure> {
        if proof == PasswordProof::Matched {
            return Ok(());
        }
        let events = self.failure_events(tracker, LoginFailureReason::BadPassword);
        Err(LoginFailure::InvalidCredentials { events })
    }

    /// Refuses an unverified address where a link could confirm it. On a
    /// deployment with no mail server the sign-in goes on, the address left
    /// unverified, as [`admits_sign_in`] decides.
    ///
    /// [`admits_sign_in`]: crate::domains::identity::account::address::AddressStanding::admits_sign_in
    fn ensure_email_verified(
        &self,
        candidate: &LoginCandidate,
        mail: MailReach,
    ) -> Result<(), LoginFailure> {
        if candidate.email_standing.admits_sign_in(mail) {
            return Ok(());
        }
        Err(LoginFailure::EmailNotVerified {
            events: vec![self.failed_event(LoginFailureReason::EmailNotVerified)],
        })
    }

    /// Refuses an account that never finished joining. Locked and
    /// deactivated accounts were refused before the password was checked.
    fn ensure_joined(&self, candidate: &LoginCandidate) -> Result<(), LoginFailure> {
        if candidate.status == UserStatus::Active {
            return Ok(());
        }
        Err(LoginFailure::AccountNotActive {
            events: vec![self.failed_event(LoginFailureReason::AccountNotActive)],
        })
    }

    /// Marks the attempt a failure on `tracker` and answers with the record
    /// of it failing for `reason`. Whether the failure locks its origin out
    /// is settled once the caller has counted it.
    pub(super) fn failure_events(
        &self,
        tracker: &mut LoginAttemptTracker,
        reason: LoginFailureReason,
    ) -> Vec<DomainEvent> {
        tracker.record_failure();
        vec![self.failed_event(reason)]
    }

    /// `body` as a record of this attempt, in the tenant that admitted it,
    /// made by the platform. An attempt changes nothing stored, so no save
    /// stamps its tenant.
    pub(super) fn recorded(&self, body: impl TenantEventBody + 'static) -> DomainEvent {
        scoped(self.tenant_id, body).system()
    }

    /// The audit record of this attempt failing for `reason`.
    fn failed_event(&self, reason: LoginFailureReason) -> DomainEvent {
        self.recorded(LoginFailed {
            email: UntrustedText::record(self.email.as_str()),
            reason,
            ip_address: self.ip_address.clone(),
            occurred_at: self.at,
        })
    }
}
