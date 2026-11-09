mod kept_through;
mod records;
mod rotation;
mod suspension;
mod watching;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::device_trust::TrustedDevice;
use crate::domains::authentication::events::session::RevocationReason;
use crate::domains::authentication::keeper::AccountKeeper;
use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::account_check::{MaySignIn, SessionCheck};
use crate::domains::authentication::sessions::channel::SessionChannel;
use crate::domains::authentication::sessions::fresh_sign_in::EnrolmentProof;
use crate::domains::authentication::sessions::last_use::LastUse;
use crate::domains::authentication::sessions::mfa_factor::FactorProved;
use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::domains::authentication::sessions::sign_in_progress::{
    SignInProgress, SignInProgressRow, SignInRefused, SignedIn,
};
use crate::domains::authentication::sessions::status::{InvalidSessionTransition, SessionStatus};
use crate::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use crate::domains::identity::account::control::AccountAction;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    CredentialChange, Fact, IpAddress, PrincipalId, ServiceId, SessionId, TokenHash,
    TrustedDeviceId, UserAgent, UserId,
};

/// Why a session could not be carried on under a new token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotationRefused {
    /// The session is revoked, suspended, expired, idle or has not finished
    /// signing in, or its account may no longer sign in or changed how it
    /// signs in since.
    #[error("the session cannot be refreshed")]
    NotUsable,
    /// The session could not be retired.
    #[error(transparent)]
    Transition(#[from] InvalidSessionTransition),
}

/// How a session began: by signing in, or by rotating an earlier one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOrigin {
    /// A sign-in opened it.
    SignIn,
    /// It replaced this session when that one's refresh token was used.
    RotatedFrom(SessionId),
}

impl SessionOrigin {
    /// The origin a stored parent column records. An empty column means a
    /// sign-in.
    #[must_use]
    pub fn from_stored(parent: Option<SessionId>) -> Self {
        parent.map_or(Self::SignIn, Self::RotatedFrom)
    }

    /// The session it replaced, if it replaced one. This is the form storage
    /// keeps.
    #[must_use]
    pub fn parent(&self) -> Option<&SessionId> {
        match self {
            Self::SignIn => None,
            Self::RotatedFrom(parent) => Some(parent),
        }
    }
}

/// A session that proves a user has signed in within a tenant.
///
/// It is read and written only through stores opened for the resolved
/// tenant. See [`crate::isolation`]. The type does not stop a session from
/// one tenant being presented to another. The request's tenant store finding
/// no such session does.
///
/// Each refresh makes a new session linked to the previous one through
/// `parent_id`. A rotated refresh token that is used again counts as token
/// theft, and the app layer revokes every session the user holds.
#[derive(Debug)]
pub struct Session<T: TenantScope> {
    /// Unique session identifier.
    id: SessionId,
    /// The signed-in user.
    user_id: UserId,
    /// One-way hash of the refresh token.
    refresh_token_hash: TokenHash,
    /// The session this one replaced, if a refresh made it.
    parent_id: SessionOrigin,
    /// The client's IP address at sign-in.
    ip_address: Fact<IpAddress>,
    /// The client's User-Agent at sign-in.
    user_agent: Fact<UserAgent>,
    /// The trusted device the sign-in came from, when the browser
    /// presented the secret of one its holder remembered. Rotation carries
    /// it on unchanged.
    signed_in_from: Fact<TrustedDeviceId>,
    /// The way in, the factor proved and what is still owed.
    progress: SignInProgress,
    /// Current lifecycle status.
    status: SessionStatus,
    /// Where the session was opened.
    channel: SessionChannel,
    /// When the person signed in. Rotation carries it on unchanged.
    signed_in_at: OffsetDateTime,
    /// When this session was created.
    created_at: OffsetDateTime,
    /// When the session was last used for a request.
    last_active_at: OffsetDateTime,
    /// When this session expires. Status does not change it.
    expires_at: OffsetDateTime,
    /// The change of how the account signs in this session was kept
    /// through, because its own holder made it.
    kept_through: CredentialChange,
    /// Where the session was last used, while any use of it could be
    /// placed.
    last_use: Fact<LastUse>,
    /// What the session raised and has not handed over yet.
    raised: Raised<T>,
    /// Which plane this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// Persisted state for repository hydration.
pub struct SessionRow {
    /// Unique session identifier.
    pub id: SessionId,
    /// The signed-in user.
    pub user_id: UserId,
    /// One-way hash of the refresh token.
    pub refresh_token_hash: TokenHash,
    /// The session this one replaced, if a refresh made it.
    pub parent_id: SessionOrigin,
    /// The client's IP address at sign-in.
    pub ip_address: Fact<IpAddress>,
    /// The client's User-Agent at sign-in.
    pub user_agent: Fact<UserAgent>,
    /// The trusted device the sign-in came from, if it presented one.
    pub signed_in_from: Fact<TrustedDeviceId>,
    /// The way in, the factor proved and what is still owed.
    pub progress: SignInProgressRow,
    /// Current lifecycle status.
    pub status: SessionStatus,
    /// Where the session was opened.
    pub channel: SessionChannel,
    /// When the person signed in, the same for every session rotated from
    /// that sign-in. Never after `created_at`.
    pub signed_in_at: OffsetDateTime,
    /// When this session was created.
    pub created_at: OffsetDateTime,
    /// When the session was last used.
    pub last_active_at: OffsetDateTime,
    /// When this session expires.
    pub expires_at: OffsetDateTime,
    /// The change of how the account signs in this session was kept
    /// through, or [`CredentialChange::Never`].
    pub kept_through: CredentialChange,
    /// Where the session was last used, while any use of it could be
    /// placed.
    pub last_use: Fact<LastUse>,
}

/// Parameters for creating a new session, beside the account and its
/// sign-in.
pub struct CreateSessionParams {
    /// Unique session identifier.
    pub id: SessionId,
    /// One-way hash of the refresh token.
    pub refresh_token_hash: TokenHash,
    /// The client's IP address, if known.
    pub ip_address: Fact<IpAddress>,
    /// The client's User-Agent header, if known.
    pub user_agent: Fact<UserAgent>,
    /// The tenant's timeouts. The session lasts their absolute lifetime.
    pub timeout: SessionTimeoutPolicy,
}

impl<T: TenantScope> Session<T> {
    /// A new session for `account` after a successful sign-in, opened on
    /// the dashboard, holding the sign-in begun for that account.
    ///
    /// It starts active and lasts the tenant's absolute lifetime from now.
    /// A session that owes nothing has already met the tenant's baseline.
    /// `refresh_token_hash` is a one-way hash of the refresh token. The raw
    /// token is never stored.
    #[must_use]
    pub fn create(account: MaySignIn<T>, params: CreateSessionParams) -> Self {
        let now = crate::shared::clock::now();
        let (user_id, progress) = account.into_parts();
        Self {
            id: params.id,
            user_id,
            refresh_token_hash: params.refresh_token_hash,
            parent_id: SessionOrigin::SignIn,
            ip_address: params.ip_address,
            user_agent: params.user_agent,
            signed_in_from: Fact::Unknown,
            progress,
            status: SessionStatus::Active,
            channel: SessionChannel::Dashboard,
            signed_in_at: now,
            created_at: now,
            last_active_at: now,
            expires_at: params.timeout.absolute_expiry(now),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a session from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the session was
    ///   rotated from itself.
    /// - [`DomainError::Infrastructure`] when the row says it was used, or
    ///   expires, before it was created.
    /// - [`DomainError::Infrastructure`] when the row says the person signed
    ///   in after the session was created.
    /// - [`DomainError::Infrastructure`] when the stored sign-in progress is
    ///   one no sign-in reaches.
    pub fn reconstitute(row: SessionRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            refresh_token_hash: row.refresh_token_hash,
            parent_id: row.parent_id,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            signed_in_from: row.signed_in_from,
            progress: SignInProgress::reconstitute(row.progress)?,
            status: row.status,
            channel: row.channel,
            signed_in_at: row.signed_in_at,
            created_at: row.created_at,
            last_active_at: row.last_active_at,
            expires_at: row.expires_at,
            kept_through: row.kept_through,
            last_use: row.last_use,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SessionRow) -> Result<(), DomainError> {
        RowCheck::of("session")
            .holds(
                row.parent_id.parent() != Some(&row.id),
                "rotated from itself",
            )
            .in_order(
                row.created_at,
                row.last_active_at,
                "used before it was created",
            )
            .in_order(
                row.created_at,
                row.expires_at,
                "expires before it was created",
            )
            .in_order(
                row.signed_in_at,
                row.created_at,
                "signed in after it was created",
            )
            .finish()
    }

    /// Unique session identifier.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The signed-in user.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// One-way hash of the refresh token.
    #[must_use]
    pub fn refresh_token_hash(&self) -> &TokenHash {
        &self.refresh_token_hash
    }

    /// How this session began, and the session it replaced if a refresh
    /// made it.
    #[must_use]
    pub fn parent_id(&self) -> &SessionOrigin {
        &self.parent_id
    }

    /// The client's IP address at sign-in.
    #[must_use]
    pub fn ip_address(&self) -> Fact<&IpAddress> {
        self.ip_address.as_ref()
    }

    /// The client's User-Agent header at sign-in.
    #[must_use]
    pub fn user_agent(&self) -> Fact<&UserAgent> {
        self.user_agent.as_ref()
    }

    /// The trusted device the sign-in came from, when it presented the
    /// secret of one its holder remembered. Every session carried on from
    /// that sign-in names it too.
    #[must_use]
    pub fn signed_in_from(&self) -> Fact<TrustedDeviceId> {
        self.signed_in_from
    }

    /// Records that this sign-in came from `device`: the browser presented
    /// the secret of a device its holder remembered, and it matched, or the
    /// sign-in's own second-factor step just remembered the device.
    ///
    /// Only the sign-in itself names its device. A session carried on from
    /// it already names the one it came from, and Mallory, holding Ann's
    /// refreshed token, cannot claim her laptop for it afterwards.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `device` is not one the session's
    ///   holder trusts: someone else's, or revoked.
    /// - [`DomainError::InvalidTransition`] when the session was carried on
    ///   from another, or already names a device.
    pub fn record_signed_in_from(&mut self, device: &TrustedDevice<T>) -> Result<(), DomainError> {
        if !device.is_trusted_by(PrincipalId::from(self.user_id)) {
            return Err(DomainError::forbidden(message!(
                "authentication-a-session-names-only-a-device",
                "a session names only a device its own holder trusts"
            )));
        }
        let fresh =
            self.parent_id == SessionOrigin::SignIn && matches!(self.signed_in_from, Fact::Unknown);
        if !fresh {
            return Err(DomainError::invalid_transition(message!(
                "authentication-only-the-sign-in-itself-names",
                "only the sign-in itself names the device it came from"
            )));
        }
        self.signed_in_from = Fact::Known(*device.id());
        Ok(())
    }

    /// How far the sign-in has come.
    #[must_use]
    pub fn progress(&self) -> &SignInProgress {
        &self.progress
    }

    /// How the user signed in, such as a password, SAML or a passkey.
    #[must_use]
    pub fn auth_method(&self) -> AuthMethod {
        self.progress.method()
    }

    /// Whether the sign-in owes nothing more, and so met the baseline.
    #[must_use]
    pub fn mfa_satisfied(&self) -> bool {
        self.progress.is_complete()
    }

    /// The strongest second factor proved, or that none was.
    #[must_use]
    pub fn mfa_method(&self) -> FactorProved {
        self.progress.factor()
    }

    /// What the sign-in still owes.
    #[must_use]
    pub fn owed(&self) -> SecondFactor {
        self.progress.owed()
    }

    /// The assurance level this session reached.
    ///
    /// The mapping is in `mfa_factor::assurance_level_for`. The proxy's
    /// caller lookup uses the same function, so the two always agree.
    #[must_use]
    pub fn assurance_level(&self) -> AssuranceLevel {
        self.progress.assurance_level()
    }

    /// Current lifecycle status.
    #[must_use]
    pub fn status(&self) -> SessionStatus {
        self.status
    }

    /// Where the session was opened.
    #[must_use]
    pub fn channel(&self) -> SessionChannel {
        self.channel
    }

    /// When the person signed in. A refresh keeps it, so it is when the
    /// first session of this sign-in was created.
    #[must_use]
    pub fn signed_in_at(&self) -> OffsetDateTime {
        self.signed_in_at
    }

    /// When this session was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the session was last used for a request.
    #[must_use]
    pub fn last_active_at(&self) -> OffsetDateTime {
        self.last_active_at
    }

    /// When this session expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether this session, on its own, can accept requests. It must be
    /// active, not expired, and owe nothing more to finish signing in.
    ///
    /// It looks at the session only. Whether its account may still sign in,
    /// changed how it signs in, or let the session go idle is asked by
    /// [`SessionCheck::admits`], which [`signed_in`](Self::signed_in) and
    /// [`rotate`](Self::rotate) use.
    #[must_use]
    pub fn is_usable(&self, now: OffsetDateTime) -> bool {
        self.is_open(now) && self.progress.is_complete()
    }

    /// Whether this session is active and in date, finished or not.
    pub(crate) fn is_open(&self, now: OffsetDateTime) -> bool {
        self.status.is_active() && now < self.expires_at
    }

    /// The user and their finished sign-in, while `check` admits this
    /// session.
    #[must_use]
    pub fn signed_in(&self, check: &SessionCheck<'_, T>) -> Option<SignedIn<T>> {
        check
            .admits(self)
            .then(|| SignedIn::of(self.user_id.into(), self.progress.carried()))
    }

    /// Leave to set up the second factor the workspace requires, while this
    /// sign-in waits for it and began moments ago.
    ///
    /// Setting up a factor asks for a fresh proof. Someone who must set one
    /// up before they are let in has just proved what the sign-in asked, so
    /// the sign-in itself lets them set it up for a few minutes. It is not a
    /// full fresh proof, so it does nothing else.
    #[must_use]
    pub fn enrolment_proof(&self, now: OffsetDateTime) -> Option<EnrolmentProof> {
        let waiting = self.status.is_active()
            && now < self.expires_at
            && self.progress.owed() == SecondFactor::Enrol;
        if !waiting {
            return None;
        }
        EnrolmentProof::of_sign_in(self.user_id.into(), self.signed_in_at, now)
    }

    /// Whether this session has been explicitly revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.status.is_revoked()
    }

    /// Whether this session has passed its expiration time.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// Whether this session is suspended until its holder proves a factor
    /// again.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.status.is_suspended()
    }

    /// Whether a refresh made this session from an earlier one.
    #[must_use]
    pub fn is_rotated(&self) -> bool {
        matches!(self.parent_id, SessionOrigin::RotatedFrom(_))
    }

    /// Ends this session for good, as its holder signing out or an admin
    /// acting on their account decides.
    ///
    /// Ending someone's session throws them out, as a lock does, so an admin
    /// needs the right to shut them out. Sam may only edit profiles. Without
    /// this check, he signs Ann out of every device in the middle of an
    /// incident she is handling.
    ///
    /// Raises `authentication.session_revoked`: a logout when the holder
    /// ends it, an admin action otherwise.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases
    ///   [`AccountKeeper::ensure_may`] lists, for shutting the account out.
    /// - [`DomainError::InvalidTransition`] when the session is already
    ///   revoked.
    pub fn revoke(&mut self, by: &impl AccountKeeper<T>) -> Result<(), DomainError> {
        let holder = PrincipalId::from(self.user_id);
        by.ensure_may(&holder, AccountAction::ShutOut)?;
        self.retire()?;
        let reason = if by.is_holder_of(&holder) {
            RevocationReason::Logout
        } else {
            RevocationReason::AdminAction
        };
        self.raise_ended(reason);
        Ok(())
    }

    /// Ends this session for good, for whoever holds its refresh token.
    ///
    /// A sign-in that still owes a factor has no finished sign-in to vouch
    /// for its holder, so [`revoke`](Self::revoke) cannot be asked for it.
    /// Ann types her password and closes the tab before her code. The token
    /// her browser holds shows the session is hers to end. Ending it takes
    /// nothing from anyone, so the token is enough.
    ///
    /// Raises `authentication.session_revoked` as a logout.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `presented` is not this session's
    ///   refresh token.
    /// - [`DomainError::InvalidTransition`] when the session is already
    ///   revoked.
    pub fn sign_out(&mut self, presented: &TokenHash) -> Result<(), DomainError> {
        if *presented != self.refresh_token_hash {
            return Err(DomainError::forbidden(message!(
                "authentication-the-token-is-another-session-s",
                "the token is another session's"
            )));
        }
        self.retire()?;
        self.raise_ended(RevocationReason::Logout);
        Ok(())
    }

    /// Ends this session for good because its holder's account no longer
    /// lets them in: it was locked, switched off or closed for erasure.
    ///
    /// The account, moved out of `Active` by someone allowed to, is the
    /// proof. Whoever shut it out was checked when they moved it. Ann's
    /// account is locked after a break-in. Without this, her laptop session
    /// would end with no record of it, and the trail would not say who
    /// threw out the thief.
    ///
    /// Raises `authentication.session_revoked` for the account's change,
    /// naming the holder by `holder.label()`, since the one who shut the
    /// account out is the record's actor.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `holder` is another account than
    ///   this session's, or still lets its holder sign in.
    /// - [`DomainError::InvalidTransition`] when the session is already
    ///   revoked.
    pub fn end_with_account(&mut self, holder: &User<T>) -> Result<(), DomainError> {
        if *holder.id() != self.user_id {
            return Err(DomainError::forbidden(message!(
                "authentication-the-account-is-not-this-session",
                "the account is not this session's holder"
            )));
        }
        if holder.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "authentication-an-account-that-still-signs-in",
                "an account that still signs in keeps its sessions"
            )));
        }
        self.retire()?;
        self.raise_ended_with_account(holder.label());
        Ok(())
    }

    /// Ends this session because a session carrying it on replaced it.
    fn retire(&mut self) -> Result<(), InvalidSessionTransition> {
        self.status = self.status.try_transition(SessionStatus::Revoked)?;
        Ok(())
    }

    /// Binds a session just opened by signing in on an app's host to the
    /// service whose app sign-in was used.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the session already belongs
    ///   to an app. One app's session is never handed to another.
    pub fn bind_to_app(&mut self, service_id: ServiceId) -> Result<(), DomainError> {
        if let SessionChannel::App(_) = self.channel {
            return Err(DomainError::invalid_transition(message!(
                "authentication-the-session-already-belongs-to-an",
                "the session already belongs to an app"
            )));
        }
        self.channel = SessionChannel::App(service_id);
        Ok(())
    }

    /// Records the factor the person proved, under the tenant's `policy`.
    /// `account` is the session's account, as it stands now.
    ///
    /// The table on [`SignInProgress`] says what each owed step accepts. The
    /// session is unchanged when the answer is refused.
    ///
    /// Setting up a factor is a change of how the account signs in, and such
    /// a change ends every session opened before it. A sign-in that owed a
    /// factor to set up is answered by the factor it just set up. So that
    /// answer keeps the session through the account's latest change, or the
    /// sign-in would end the moment it finished.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::ForAnotherAccount`] when the factor was proved for
    ///   another account, or `account` is not this session's. Mallory's own
    ///   code never finishes Ann's sign-in.
    /// - [`SignInRefused`] when the factor does not answer what is owed.
    /// - [`SignInRefused`] when the factor would not raise a finished
    ///   sign-in.
    /// - [`SignInRefused`] when the factor would finish the sign-in below the
    ///   baseline.
    pub fn answer(
        &mut self,
        account: &User<T>,
        proof: ProvedFactor,
        policy: &StepUpPolicy,
    ) -> Result<(), SignInRefused> {
        let factor = proof.for_account(PrincipalId::from(self.user_id))?;
        if *account.id() != self.user_id {
            return Err(SignInRefused::ForAnotherAccount);
        }
        let was_owed = self.progress.owed();
        self.progress = self.progress.answer(factor, policy)?;
        if was_owed == SecondFactor::Enrol {
            self.kept_through = account.credentials_changed_at();
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::device_status::DeviceStatus;
    use crate::domains::authentication::device_trust::TrustedDeviceRow;
    use crate::domains::authentication::events::session::SuspensionReason;
    use crate::domains::authentication::mfa::enrollment::{
        EnrolledFactor, MfaEnrollment, MfaMethod,
    };
    use crate::domains::authentication::mfa::offer::offered;
    use crate::domains::authentication::risk_engine::assessment::RiskLevel;
    use crate::domains::authentication::risk_engine::step_up::{MfaTrigger, StepUpPolicyParams};
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::authentication::sessions::fresh_sign_in::{FRESH_FOR, fresh_proof_of};
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::proved_factor::proved;
    use crate::domains::authentication::sessions::sign_in_code::{
        CodeHolders, RedeemedSignInCode, SignInCode,
    };
    use crate::domains::authentication::sessions::sign_in_progress::{
        FederatedMethod, LocalMethod, ProviderSignIn, finished_sign_in_of,
    };
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::event::DomainEvent;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{CredentialChange, EventLabel, Label, Lifetime, SealedSecret};

    fn password_owing(owed: SecondFactor) -> SignInProgress {
        SignInProgress::begin(LocalMethod::Password, owed, &StepUpPolicy::relaxed())
            .expect("relaxed admits a password")
    }

    fn session_making(progress: SignInProgress) -> Session<ResolvedTenant> {
        Session::create(
            MaySignIn::active(UserId::new(), progress),
            CreateSessionParams {
                id: SessionId::new(),
                refresh_token_hash: TokenHash::from_stored("hashed_token".to_owned()),
                ip_address: Fact::Known(IpAddress::new("10.0.0.1").unwrap()),
                user_agent: Fact::Known(UserAgent::new("Mozilla/5.0").unwrap()),
                timeout: SessionTimeoutPolicy::STANDARD,
            },
        )
    }

    /// A password sign-in of a new account that still owes its code. Tests
    /// elsewhere in the crate use it.
    pub(crate) fn test_session() -> Session<ResolvedTenant> {
        session_making(password_owing(SecondFactor::Verify))
    }

    /// A finished password sign-in of a new account. Tests elsewhere in the
    /// crate use it.
    pub(crate) fn signed_in_session() -> Session<ResolvedTenant> {
        session_making(password_owing(SecondFactor::NotOwed))
    }

    /// The holder of `session`, signed in. Tests elsewhere in the crate use
    /// it to sign out.
    pub(crate) fn holder_of(session: &Session<ResolvedTenant>) -> SignedIn<ResolvedTenant> {
        finished_sign_in_of((*session.user_id()).into())
    }

    /// `factor`, proved for the account `session` belongs to.
    pub(crate) fn holders(session: &Session<ResolvedTenant>, factor: MfaFactor) -> ProvedFactor {
        proved((*session.user_id()).into(), factor)
    }

    /// The active account `session` belongs to, that last changed how it
    /// signs in at `credentials`.
    fn account_of(
        session: &Session<ResolvedTenant>,
        credentials: CredentialChange,
    ) -> User<ResolvedTenant> {
        account_with(*session.user_id(), UserStatus::Active, credentials)
    }

    /// `session` answered with `factor` proved for its holder, whose account
    /// never changed how it signs in.
    fn answered(
        session: &mut Session<ResolvedTenant>,
        factor: MfaFactor,
        policy: &StepUpPolicy,
    ) -> Result<(), SignInRefused> {
        let account = account_of(session, CredentialChange::Never);
        let proof = holders(session, factor);
        session.answer(&account, proof, policy)
    }

    pub(crate) fn rotated(
        parent: &mut Session<ResolvedTenant>,
    ) -> Result<Session<ResolvedTenant>, RotationRefused> {
        let account = account_of(parent, CredentialChange::Never);
        Session::rotate(
            parent,
            SessionId::new(),
            TokenHash::from_stored("new_hash".to_owned()),
            &SessionCheck {
                account: &account,
                timeout: &SessionTimeoutPolicy::STANDARD,
                now: crate::shared::clock::now(),
            },
        )
    }

    /// A device `owner` remembered, standing as `status` says.
    fn device_of(owner: UserId, status: DeviceStatus) -> TrustedDevice<ResolvedTenant> {
        let now = crate::shared::clock::now();
        TrustedDevice::reconstitute(TrustedDeviceRow {
            id: TrustedDeviceId::new(),
            subject_id: PrincipalId::from(owner),
            secret_hash: TokenHash::from_stored("laptop-digest".to_owned()),
            device_name: Label::new("device_name", "Laptop").unwrap(),
            last_user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            last_ip: IpAddress::new("10.0.0.1").unwrap(),
            status,
            last_seen_at: now,
            created_at: now,
        })
        .unwrap()
    }

    /// Ann signs in from her remembered laptop. Her session names it, and
    /// the session her refresh carries it on to names it too.
    #[test]
    fn a_session_names_the_device_it_was_signed_in_from_through_refreshes() {
        let mut session = signed_in_session();
        let laptop = device_of(*session.user_id(), DeviceStatus::Trusted);

        session.record_signed_in_from(&laptop).unwrap();
        let refreshed = rotated(&mut session).unwrap();

        assert_eq!(session.signed_in_from(), Fact::Known(*laptop.id()));
        assert_eq!(refreshed.signed_in_from(), Fact::Known(*laptop.id()));
    }

    /// A sign-in that presented no remembered device names none.
    #[test]
    fn a_session_signed_in_from_no_remembered_device_names_none() {
        assert_eq!(signed_in_session().signed_in_from(), Fact::Unknown);
    }

    /// Another holder's device and a revoked device are both rejected as the
    /// sign-in source. The session's device remains unknown.
    #[test]
    fn a_session_names_no_device_its_holder_does_not_trust() {
        let mut session = signed_in_session();
        let anns = device_of(UserId::new(), DeviceStatus::Trusted);
        let revoked = device_of(*session.user_id(), DeviceStatus::Revoked);

        let someone_elses = session.record_signed_in_from(&anns);
        let forgotten = session.record_signed_in_from(&revoked);

        assert!(matches!(someone_elses, Err(DomainError::Forbidden(_))));
        assert!(matches!(forgotten, Err(DomainError::Forbidden(_))));
        assert_eq!(session.signed_in_from(), Fact::Unknown);
    }

    /// A refreshed session cannot claim a device, and a session that already
    /// named one cannot replace it. Both changes are invalid transitions.
    #[test]
    fn only_the_sign_in_names_its_device_once() {
        let mut session = signed_in_session();
        let owner = *session.user_id();
        let mut refreshed = rotated(&mut session).unwrap();
        let mut named = signed_in_session();
        let phone = device_of(*named.user_id(), DeviceStatus::Trusted);
        named
            .record_signed_in_from(&device_of(*named.user_id(), DeviceStatus::Trusted))
            .unwrap();

        let claimed = refreshed.record_signed_in_from(&device_of(owner, DeviceStatus::Trusted));
        let swapped = named.record_signed_in_from(&phone);

        assert!(matches!(claimed, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(swapped, Err(DomainError::InvalidTransition(_))));
        assert_eq!(refreshed.signed_in_from(), Fact::Unknown);
    }

    fn session_with(auth_method: AuthMethod, mfa_method: FactorProved) -> Session<ResolvedTenant> {
        session_making(
            SignInProgress::reconstitute(SignInProgressRow {
                method: auth_method,
                factor: mfa_method,
                owed: SecondFactor::NotOwed,
            })
            .unwrap(),
        )
    }

    /// Ann finishes signing in with nothing owed. Her new session is active,
    /// usable, and neither revoked nor suspended.
    #[test]
    fn create_produces_active_session() {
        let now = crate::shared::clock::now();
        let session = signed_in_session();

        assert!(session.is_usable(now));
        assert!(!session.is_revoked());
        assert!(!session.is_suspended());
        assert_eq!(session.status(), SessionStatus::Active);
    }

    /// A session made by signing in has no parent and does not count as
    /// rotated.
    #[test]
    fn create_sets_no_parent() {
        let session = test_session();
        assert_eq!(session.parent_id(), &SessionOrigin::SignIn);
        assert!(!session.is_rotated());
    }

    /// Ann refreshes her session. The new one names the old one as its
    /// parent and is usable, and the old one is revoked.
    #[test]
    fn rotate_links_to_parent_and_retires_it() {
        let now = crate::shared::clock::now();
        let mut parent = signed_in_session();

        let child = rotated(&mut parent).unwrap();

        assert_eq!(child.parent_id().parent(), Some(parent.id()));
        assert!(child.is_rotated());
        assert!(child.is_usable(now));
        assert!(parent.is_revoked());
    }

    /// Two rotations preserve the original session's expiry rather than
    /// extending its lifetime.
    #[test]
    fn a_rotated_session_ends_when_the_original_would_have() {
        let mut parent = signed_in_session();

        let mut child = rotated(&mut parent).unwrap();
        let grandchild = rotated(&mut child).unwrap();

        assert_eq!(grandchild.expires_at(), parent.expires_at());
    }

    /// A suspended session cannot be rotated into a usable replacement.
    #[test]
    fn a_suspended_session_is_not_refreshed() {
        let anchor = crate::shared::clock::now();
        let mut parent = Session::<ResolvedTenant>::reconstitute(SessionRow {
            status: SessionStatus::Suspended,
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ..row_at(anchor, 3600)
        })
        .unwrap();

        assert_eq!(rotated(&mut parent).err(), Some(RotationRefused::NotUsable));
    }

    /// Revoking a session prevents its refresh token from rotating it.
    #[test]
    fn a_revoked_session_is_not_refreshed() {
        let mut parent = signed_in_session();
        parent.revoke(&holder_of(&parent)).unwrap();

        assert_eq!(rotated(&mut parent).err(), Some(RotationRefused::NotUsable));
    }

    /// A session still owing its factor is unusable and cannot be refreshed.
    #[test]
    fn a_session_owing_a_factor_is_not_refreshed_or_used() {
        let mut parent = test_session();

        assert!(!parent.is_usable(crate::shared::clock::now()));
        assert_eq!(rotated(&mut parent).err(), Some(RotationRefused::NotUsable));
    }

    /// The code a single sign-on left in the address bar, spent for
    /// `session`.
    fn code_spent_for(session: &Session<ResolvedTenant>) -> RedeemedSignInCode {
        let dashboard = TokenHash::from_stored("dashboard_hash".to_owned());
        SignInCode::issue(
            session,
            CodeHolders {
                code: TokenHash::from_stored("code_hash".to_owned()),
                dashboard: dashboard.clone(),
            },
            Lifetime::seconds(60).unwrap(),
        )
        .unwrap()
        .redeem(crate::shared::clock::now(), &dashboard)
        .unwrap()
    }

    /// `parent` handed over for `code`, its account held as it is now.
    fn handed_over(
        parent: &mut Session<ResolvedTenant>,
        code: &RedeemedSignInCode,
        account: &User<ResolvedTenant>,
    ) -> Result<Session<ResolvedTenant>, RotationRefused> {
        Session::hand_over(
            parent,
            code,
            SessionId::new(),
            TokenHash::from_stored("handed_hash".to_owned()),
            &check_for(account),
        )
    }

    /// Ann comes back from her identity provider still owing her code. The
    /// dashboard swaps the sign-in code for her session, which goes on
    /// owing the code under the new token. Her code then finishes it.
    #[test]
    fn a_single_sign_on_owing_a_factor_is_handed_over_and_then_finished() {
        let mut provider_session = test_session();
        let code = code_spent_for(&provider_session);
        let ann = account_of(&provider_session, CredentialChange::Never);

        let mut handed = handed_over(&mut provider_session, &code, &ann).unwrap();

        assert!(provider_session.is_revoked());
        assert_eq!(handed.owed(), SecondFactor::Verify);
        assert!(!handed.is_usable(crate::shared::clock::now()));
        answered(&mut handed, MfaFactor::Totp, &StepUpPolicy::relaxed()).unwrap();
        assert!(handed.signed_in(&check_for(&ann)).is_some());
    }

    /// A spent code for another session cannot hand over Ann's session.
    /// The refusal does not revoke it.
    #[test]
    fn a_code_for_another_session_hands_nothing_over() {
        let mut anns = test_session();
        let mallorys = code_spent_for(&test_session());
        let ann = account_of(&anns, CredentialChange::Never);

        let refused = handed_over(&mut anns, &mallorys, &ann);

        assert_eq!(refused.err(), Some(RotationRefused::NotUsable));
        assert!(!anns.is_revoked());
    }

    /// A session already carried forward by rotation cannot be handed over again.
    #[test]
    fn a_session_carried_on_before_is_not_handed_over() {
        let mut parent = signed_in_session();
        let mut child = rotated(&mut parent).unwrap();
        let code = code_spent_for(&child);
        let ann = account_of(&child, CredentialChange::Never);

        let refused = handed_over(&mut child, &code, &ann);

        assert_eq!(refused.err(), Some(RotationRefused::NotUsable));
    }

    /// Locking the account prevents handover of its provider session.
    #[test]
    fn a_locked_accounts_single_sign_on_is_not_handed_over() {
        let mut provider_session = test_session();
        let code = code_spent_for(&provider_session);
        let locked = account_with(
            *provider_session.user_id(),
            UserStatus::Locked,
            CredentialChange::Never,
        );

        let refused = handed_over(&mut provider_session, &code, &locked);

        assert_eq!(refused.err(), Some(RotationRefused::NotUsable));
    }

    /// A session that expired a second ago is expired and not usable.
    #[test]
    fn expired_session_is_not_usable() {
        let now = crate::shared::clock::now();
        let session = Session::<ResolvedTenant>::reconstitute(SessionRow {
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ..row_at(now - Duration::seconds(3601), 3600)
        })
        .unwrap();

        assert!(!session.is_usable(now));
        assert!(session.is_expired(now));
    }

    /// Ann's tenant lets sessions last a day. Her new session ends a day
    /// after it opened, whatever way she signed in.
    #[test]
    fn a_new_session_lasts_the_tenants_lifetime() {
        let session = signed_in_session();

        assert_eq!(
            session.expires_at(),
            SessionTimeoutPolicy::STANDARD.absolute_expiry(session.created_at())
        );
    }

    /// A session that expires in an hour is not expired now.
    #[test]
    fn future_session_is_not_expired() {
        let now = crate::shared::clock::now();
        let session = test_session();
        assert!(!session.is_expired(now));
    }

    /// Ann logs out. Her session is revoked and cannot be used.
    #[test]
    fn revoke_makes_session_unusable() {
        let now = crate::shared::clock::now();
        let mut session = test_session();

        session.revoke(&holder_of(&session)).unwrap();

        assert!(session.is_revoked());
        assert!(!session.is_usable(now));
        assert_eq!(session.status(), SessionStatus::Revoked);
    }

    /// Revoking a session that is already revoked is refused.
    #[test]
    fn revoke_twice_fails() {
        let mut session = test_session();
        let ann = holder_of(&session);

        session.revoke(&ann).unwrap();

        assert!(session.revoke(&ann).is_err());
    }

    /// Ann types her password and closes the tab before her code. The
    /// refresh token her browser holds signs the unfinished session out.
    #[test]
    fn the_refresh_token_signs_out_a_session_still_owing_a_factor() {
        let mut anns = test_session();

        anns.sign_out(&TokenHash::from_stored("hashed_token".to_owned()))
            .unwrap();

        assert!(anns.is_revoked());
    }

    /// A token that does not belong to Ann's session cannot sign it out;
    /// the session remains unrevoked.
    #[test]
    fn another_token_signs_out_nothing() {
        let mut anns = test_session();

        let refused = anns.sign_out(&TokenHash::from_stored("mallorys".to_owned()));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(!anns.is_revoked());
    }

    /// Another account's completed sign-in cannot revoke Ann's session.
    #[test]
    fn someone_else_signed_in_does_not_end_a_session() {
        let mut anns = signed_in_session();
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let refused = anns.revoke(&mallory);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(!anns.is_revoked());
    }

    /// User-editing rights cannot revoke another person's session, which
    /// remains unrevoked. User-deactivation rights can revoke it.
    #[test]
    fn ending_someones_session_needs_the_right_to_shut_them_out() {
        static EDITOR: [SystemPermission; 1] = [SystemPermission::Users(UserAction::Update)];
        static DEACTIVATOR: [SystemPermission; 1] =
            [SystemPermission::Users(UserAction::Deactivate)];
        let mut anns = signed_in_session();
        let ann = *anns.user_id();
        let acting = |rights: &'static [SystemPermission]| {
            AccountControl::assumed(
                anyone_holding(rights),
                ann,
                Stewardship::OthersAdminister,
                Handout::NOTHING,
            )
        };

        let by_sam = anns.revoke(&acting(&EDITOR));
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(!anns.is_revoked());

        anns.revoke(&acting(&DEACTIVATOR)).unwrap();
        assert!(anns.is_revoked());
    }

    /// Ann's session owes TOTP and she types a valid code. The session is
    /// complete, records TOTP and owes nothing.
    #[test]
    fn answering_what_is_owed_completes_the_session() {
        let mut session = test_session();
        assert!(!session.mfa_satisfied());

        answered(&mut session, MfaFactor::Totp, &StepUpPolicy::relaxed()).unwrap();

        assert!(session.mfa_satisfied());
        assert_eq!(session.mfa_method(), FactorProved::Proved(MfaFactor::Totp));
        assert_eq!(session.owed(), SecondFactor::NotOwed);
    }

    /// A factor proved for another account is rejected and leaves Ann's
    /// session owing factor verification.
    #[test]
    fn a_factor_proved_for_another_account_finishes_nothing() {
        let mut anns = test_session();
        let ann = account_of(&anns, CredentialChange::Never);
        let mallorys_code = proved(UserId::new().into(), MfaFactor::Totp);

        let refused = anns.answer(&ann, mallorys_code, &StepUpPolicy::relaxed());

        assert_eq!(refused, Err(SignInRefused::ForAnotherAccount));
        assert_eq!(anns.owed(), SecondFactor::Verify);
    }

    /// Ann proves TOTP and then sends TOTP again. The second proof raises
    /// nothing, so it is refused as already proved.
    #[test]
    fn the_same_factor_twice_is_refused() {
        let mut session = test_session();
        let policy = StepUpPolicy::relaxed();
        answered(&mut session, MfaFactor::Totp, &policy).unwrap();

        assert_eq!(
            answered(&mut session, MfaFactor::Totp, &policy),
            Err(SignInRefused::AlreadyProved)
        );
        assert_eq!(session.mfa_method(), FactorProved::Proved(MfaFactor::Totp));
    }

    /// Email confirmation cannot answer this session's factor requirement.
    /// No factor is recorded, and verification remains owed.
    #[test]
    fn a_refused_answer_leaves_the_session_as_it_was() {
        let mut session = test_session();

        let refused = answered(
            &mut session,
            MfaFactor::EmailConfirmation,
            &StepUpPolicy::relaxed(),
        );

        assert!(refused.is_err());
        assert!(!session.mfa_satisfied());
        assert_eq!(session.mfa_method(), FactorProved::NoneYet);
        assert_eq!(session.owed(), SecondFactor::Verify);
    }

    /// A tenant's baseline is AAL3. Ann answers with TOTP, which reaches only
    /// AAL2, so the answer is refused and the session stays incomplete.
    #[test]
    fn an_answer_below_the_baseline_does_not_complete_the_session() {
        let mut session = test_session();

        let hardware_baseline = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal: AssuranceLevel::Aal3,
            sensitive_aal: AssuranceLevel::Aal3,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .unwrap();

        let refused = answered(&mut session, MfaFactor::Totp, &hardware_baseline);

        assert!(matches!(refused, Err(SignInRefused::BelowBaseline(_))));
        assert!(!session.mfa_satisfied());
    }

    /// Even the session holder's factor proof cannot complete the sign-in when
    /// paired with another account. Verification remains owed.
    #[test]
    fn an_answer_with_another_account_finishes_nothing() {
        let mut anns = test_session();
        let mallory = account_with(UserId::new(), UserStatus::Active, CredentialChange::Never);
        let code = holders(&anns, MfaFactor::Totp);

        let refused = anns.answer(&mallory, code, &StepUpPolicy::relaxed());

        assert_eq!(refused, Err(SignInRefused::ForAnotherAccount));
        assert_eq!(anns.owed(), SecondFactor::Verify);
    }

    /// Ann's workspace requires a second factor and she has none. She signs
    /// in, sets up TOTP, which records a change of how she signs in, and
    /// answers with it. Her session counts, rather than ending the moment
    /// her sign-in finished.
    #[test]
    fn a_sign_in_finished_by_the_factor_it_set_up_still_counts() {
        let mut session = session_making(password_owing(SecondFactor::Enrol));
        let set_up = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_of(&session, CredentialChange::At { at: set_up });
        let code = holders(&session, MfaFactor::Totp);

        session
            .answer(&ann, code, &StepUpPolicy::relaxed())
            .unwrap();

        assert!(check_at(&ann, set_up).admits(&session));
    }

    /// Answering an existing factor completes the sign-in but does not preserve
    /// its session across a credential change made after sign-in began.
    #[test]
    fn a_sign_in_that_set_up_nothing_is_not_kept_through_a_change() {
        let mut session = test_session();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_of(&session, CredentialChange::At { at: changed });
        let code = holders(&session, MfaFactor::Totp);

        session
            .answer(&ann, code, &StepUpPolicy::relaxed())
            .unwrap();

        assert!(!check_at(&ann, changed).admits(&session));
    }

    fn check_for(account: &User<ResolvedTenant>) -> SessionCheck<'_, ResolvedTenant> {
        check_at(account, crate::shared::clock::now())
    }

    fn check_at(
        account: &User<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> SessionCheck<'_, ResolvedTenant> {
        SessionCheck {
            account,
            timeout: &SessionTimeoutPolicy::STANDARD,
            now,
        }
    }

    /// Ann's session is finished and her account active. It names her as
    /// signed in.
    #[test]
    fn a_session_of_an_active_account_names_who_signed_in() {
        let session = signed_in_session();
        let ann = account_with(
            *session.user_id(),
            UserStatus::Active,
            CredentialChange::Never,
        );

        let signed_in = session.signed_in(&check_for(&ann)).unwrap();

        assert_eq!(signed_in.subject(), PrincipalId::from(*ann.id()));
    }

    /// A locked account provides no signed-in identity and cannot refresh its
    /// session. The refused refresh leaves the session unrevoked.
    #[test]
    fn a_locked_account_neither_uses_nor_refreshes_its_session() {
        let mut session = signed_in_session();
        let locked = account_with(
            *session.user_id(),
            UserStatus::Locked,
            CredentialChange::Never,
        );
        let check = check_for(&locked);

        assert!(session.signed_in(&check).is_none());
        assert_eq!(
            Session::rotate(
                &mut session,
                SessionId::new(),
                TokenHash::from_stored("next".to_owned()),
                &check,
            )
            .err(),
            Some(RotationRefused::NotUsable)
        );
        assert!(
            !session.is_revoked(),
            "a refused refresh leaves the session as it was"
        );
    }

    /// A session opened before a credential change cannot be refreshed against
    /// the changed account.
    #[test]
    fn a_session_opened_before_a_new_password_is_not_refreshed() {
        let mut session = signed_in_session();
        let changed = account_with(
            *session.user_id(),
            UserStatus::Active,
            CredentialChange::At {
                at: crate::shared::clock::now(),
            },
        );

        let refused = Session::rotate(
            &mut session,
            SessionId::new(),
            TokenHash::from_stored("next".to_owned()),
            &check_for(&changed),
        );

        assert_eq!(refused.err(), Some(RotationRefused::NotUsable));
    }

    /// Rotation retains the original sign-in time. A credential change between
    /// sign-in and rotation therefore invalidates the resulting session.
    #[test]
    fn a_session_rotated_after_a_change_from_one_opened_before_it_stops_counting() {
        let start = crate::shared::clock::now();
        let mut parent = {
            let _now = crate::shared::clock::freeze(start);
            signed_in_session()
        };
        let refreshed = start + Duration::seconds(10);
        let child = {
            let _now = crate::shared::clock::freeze(refreshed);
            rotated(&mut parent).unwrap()
        };
        let changed = start + Duration::seconds(5);
        let ann = account_of(&child, CredentialChange::At { at: changed });

        assert_eq!(child.signed_in_at(), parent.signed_in_at());
        assert!(!check_at(&ann, refreshed).admits(&child));
    }

    /// Ann changes her password from her laptop session, which is kept, and
    /// then refreshes it. The refreshed session is still kept through that
    /// one change.
    #[test]
    fn a_session_kept_through_a_change_stays_kept_when_refreshed() {
        let mut laptop = signed_in_session();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_of(&laptop, CredentialChange::At { at: changed });
        let proof = fresh_proof_of((*ann.id()).into());
        laptop
            .keep_through_own_password_change(&ann, &proof)
            .unwrap();

        let refreshed = Session::rotate(
            &mut laptop,
            SessionId::new(),
            TokenHash::from_stored("next".to_owned()),
            &check_at(&ann, changed),
        )
        .unwrap();

        assert!(check_at(&ann, changed).admits(&refreshed));
    }

    /// Another account's fresh proof cannot preserve a session across a
    /// password change; its kept-through marker remains unset.
    #[test]
    fn a_session_is_not_kept_through_a_change_on_someone_elses_proof() {
        let mut stolen = signed_in_session();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_of(&stolen, CredentialChange::At { at: changed });
        let mallorys_proof = fresh_proof_of(PrincipalId::from(UserId::new()));

        let result = stolen.keep_through_own_password_change(&ann, &mallorys_proof);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(stolen.kept_through(), CredentialChange::Never);
    }

    /// Ann removes a passkey she lost from her laptop's session. Every
    /// session opened before it ends, but the laptop's stays.
    #[test]
    fn the_session_a_passkey_was_removed_from_is_kept_through_it() {
        let mut laptop = signed_in_session();
        let phone = Session::<ResolvedTenant>::reconstitute(SessionRow {
            user_id: *laptop.user_id(),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ..row_at(crate::shared::clock::now(), 3600)
        })
        .unwrap();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_of(&laptop, CredentialChange::At { at: changed });

        laptop
            .keep_through_own_removal(&ann, &holder_of(&laptop))
            .unwrap();

        assert!(check_at(&ann, changed).admits(&laptop));
        assert!(!check_at(&ann, changed).admits(&phone));
    }

    /// Another account's sign-in cannot preserve Ann's session across removal
    /// of a credential. The changed account no longer admits that session.
    #[test]
    fn a_session_is_not_kept_through_a_removal_on_someone_elses_sign_in() {
        let mut anns = signed_in_session();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_of(&anns, CredentialChange::At { at: changed });
        let mallorys = finished_sign_in_of(PrincipalId::from(UserId::new()));

        let result = anns.keep_through_own_removal(&ann, &mallorys);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!check_at(&ann, changed).admits(&anns));
    }

    /// Pat sets up an authenticator app from her laptop and confirms it
    /// with its code. The laptop session is kept through the change; her
    /// phone's session, opened before it, ends.
    #[test]
    fn the_session_a_factor_was_set_up_from_is_kept_through_it() {
        let mut laptop = signed_in_session();
        let phone = Session::<ResolvedTenant>::reconstitute(SessionRow {
            user_id: *laptop.user_id(),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ..row_at(crate::shared::clock::now(), 3600)
        })
        .unwrap();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let pat = account_of(&laptop, CredentialChange::At { at: changed });
        let code = holders(&laptop, MfaFactor::Totp);

        laptop.keep_through_own_factor_addition(&pat, code).unwrap();

        assert!(check_at(&pat, changed).admits(&laptop));
        assert!(!check_at(&pat, changed).admits(&phone));
    }

    /// A code proved for another account cannot preserve Pat's session across
    /// a factor addition. The changed account rejects the session.
    #[test]
    fn a_session_is_not_kept_through_a_new_factor_on_someone_elses_code() {
        let mut stolen = signed_in_session();
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let pat = account_of(&stolen, CredentialChange::At { at: changed });
        let mallorys = proved(PrincipalId::from(UserId::new()), MfaFactor::Totp);

        let result = stolen.keep_through_own_factor_addition(&pat, mallorys);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!check_at(&pat, changed).admits(&stolen));
    }

    /// A sign-in still owing enrollment cannot be kept through a factor
    /// addition. Its kept-through marker remains unset.
    #[test]
    fn an_unfinished_sign_in_is_not_kept_through_a_new_factor() {
        let mut waiting = session_making(password_owing(SecondFactor::Enrol));
        let changed = crate::shared::clock::now() + Duration::seconds(1);
        let pat = account_of(&waiting, CredentialChange::At { at: changed });
        let code = holders(&waiting, MfaFactor::Totp);

        let result = waiting.keep_through_own_factor_addition(&pat, code);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(waiting.kept_through(), CredentialChange::Never);
    }

    /// Ann's workspace requires a second factor and she has none. Right
    /// after her password, her sign-in lets her set up TOTP.
    #[test]
    fn a_sign_in_owing_a_factor_to_set_up_lets_its_person_set_one_up() {
        let session = session_making(password_owing(SecondFactor::Enrol));
        let ann = PrincipalId::from(*session.user_id());
        let proof = session
            .enrolment_proof(crate::shared::clock::now())
            .unwrap();

        let set_up = MfaEnrollment::<ResolvedTenant>::begin(
            ann,
            EnrolledFactor::Totp(SealedSecret::new("anns_secret").unwrap()),
            &offered(MfaMethod::Totp),
            &proof,
        );

        assert_eq!(proof.account(), ann);
        assert!(set_up.is_ok());
    }

    /// A completed sign-in supplies no proof for enrollment owed during sign-in.
    #[test]
    fn a_finished_sign_in_is_no_fresh_proof() {
        let session = signed_in_session();

        assert!(
            session
                .enrolment_proof(crate::shared::clock::now())
                .is_none()
        );
    }

    /// Ann leaves the setup page open for longer than the fresh window. Her
    /// sign-in no longer stands as a fresh proof, so she proves herself
    /// again.
    #[test]
    fn a_sign_in_owing_a_factor_stops_being_fresh() {
        let session = session_making(password_owing(SecondFactor::Enrol));
        let later = session.created_at() + FRESH_FOR;

        assert!(session.enrolment_proof(later).is_none());
    }

    /// A session from a password alone is at AAL1.
    #[test]
    fn assurance_level_for_password_only_is_aal1() {
        let session = session_with(AuthMethod::Password, FactorProved::NoneYet);
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal1);
    }

    /// A session from a password and TOTP is at AAL2.
    #[test]
    fn assurance_level_for_totp_is_aal2() {
        let session = session_with(AuthMethod::Password, FactorProved::Proved(MfaFactor::Totp));
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal2);
    }

    /// A session from a password and a recovery code stays at AAL1. The code
    /// proves the person holds it, not a live second factor.
    #[test]
    fn assurance_level_for_recovery_code_stays_aal1() {
        let session = session_with(
            AuthMethod::Password,
            FactorProved::Proved(MfaFactor::RecoveryCode),
        );
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal1);
    }

    /// A passkey sign-in without an additional factor has AAL2 assurance.
    #[test]
    fn a_passkey_that_may_be_synced_is_aal2() {
        let session = session_with(AuthMethod::Passkey, FactorProved::NoneYet);
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal2);
    }

    /// A passkey sign-in that recorded an attested hardware key is at AAL3.
    #[test]
    fn an_attested_hardware_key_is_aal3() {
        let session = session_with(
            AuthMethod::Passkey,
            FactorProved::Proved(MfaFactor::HardwareKey),
        );
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal3);
    }

    /// Ann signs in through SAML and the provider reports no second factor.
    /// The session is complete but stays at AAL1, not read as a verified
    /// second factor.
    #[test]
    fn a_complete_provider_sign_in_proving_no_factor_is_aal1() {
        let progress = SignInProgress::begin_through_provider(
            ProviderSignIn::new(FederatedMethod::Saml, FactorProved::NoneYet),
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
        .unwrap();

        let session = session_making(progress);

        assert!(session.mfa_satisfied());
        assert_eq!(session.auth_method(), AuthMethod::Saml);
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal1);
    }

    //
    // The comparison decides whether a session that has run out still answers
    // requests, so it is pinned on the instant rather than a second either
    // side of it.

    fn session_active_at(anchor: OffsetDateTime, lifetime_secs: i64) -> Session<ResolvedTenant> {
        Session::<ResolvedTenant>::reconstitute(SessionRow {
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ..row_at(anchor, lifetime_secs)
        })
        .unwrap()
    }

    fn row_at(anchor: OffsetDateTime, lifetime_secs: i64) -> SessionRow {
        SessionRow {
            id: SessionId::new(),
            user_id: UserId::new(),
            refresh_token_hash: TokenHash::from_stored("hash".to_owned()),
            parent_id: SessionOrigin::SignIn,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            signed_in_from: Fact::Unknown,
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Verify,
            },
            status: SessionStatus::Active,
            channel: SessionChannel::Dashboard,
            signed_in_at: anchor,
            created_at: anchor,
            last_active_at: anchor,
            expires_at: anchor + Duration::seconds(lifetime_secs),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
        }
    }

    /// A one hour session is usable at second 3599 and not at second 3600.
    #[test]
    fn a_session_stops_being_usable_at_the_instant_it_expires() {
        let anchor = crate::shared::clock::now();
        let session = session_active_at(anchor, 3600);

        assert!(session.is_usable(anchor + Duration::seconds(3599)));
        assert!(!session.is_usable(anchor + Duration::seconds(3600)));
    }

    /// A stored suspended SAML session with TOTP and a parent loads back with
    /// the same id, user, parent, method, factor and status.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let row = suspended_provider_session();
        let id = row.id;
        let user_id = row.user_id;
        let parent = row.parent_id.clone();
        let laptop = row.signed_in_from;
        let signed_in_at = row.signed_in_at;
        let session = Session::<ResolvedTenant>::reconstitute(row).unwrap();

        assert_eq!(*session.id(), id);
        assert_eq!(*session.user_id(), user_id);
        assert_eq!(session.parent_id().parent(), parent.parent());
        assert_eq!(session.auth_method(), AuthMethod::Saml);
        assert!(session.mfa_satisfied());
        assert_eq!(session.mfa_method(), FactorProved::Proved(MfaFactor::Totp));
        assert_eq!(session.status(), SessionStatus::Suspended);
        assert!(session.is_suspended());
        assert_eq!(session.signed_in_at(), signed_in_at);
        assert_eq!(session.signed_in_from(), laptop);
    }

    /// A rotated SAML session retains its factor, device and original sign-in time.
    fn suspended_provider_session() -> SessionRow {
        let now = crate::shared::clock::now();
        SessionRow {
            id: SessionId::new(),
            user_id: UserId::new(),
            refresh_token_hash: TokenHash::from_stored("hash".to_owned()),
            parent_id: SessionOrigin::RotatedFrom(SessionId::new()),
            ip_address: Fact::Known(IpAddress::new("192.168.1.1").unwrap()),
            user_agent: Fact::Known(UserAgent::new("TestAgent/1.0").unwrap()),
            signed_in_from: Fact::Known(TrustedDeviceId::new()),
            progress: SignInProgressRow {
                method: AuthMethod::Saml,
                factor: FactorProved::Proved(MfaFactor::Totp),
                owed: SecondFactor::NotOwed,
            },
            status: SessionStatus::Suspended,
            channel: SessionChannel::Dashboard,
            signed_in_at: now - Duration::hours(2),
            created_at: now,
            last_active_at: now,
            expires_at: now + Duration::hours(1),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
        }
    }

    /// A session loaded from storage as suspended is not usable.
    #[test]
    fn a_stored_suspended_session_is_not_usable() {
        let anchor = crate::shared::clock::now();
        let session = Session::<ResolvedTenant>::reconstitute(SessionRow {
            status: SessionStatus::Suspended,
            ..row_at(anchor, 3600)
        })
        .unwrap();

        assert!(!session.is_usable(anchor));
    }

    /// A session opened from `10.0.0.1` with `Mozilla/5.0` reports both. Risk
    /// checks compare the next request against them, and Ann sees them in her
    /// session list.
    #[test]
    fn a_session_reports_the_address_and_client_it_was_opened_from() {
        let session = test_session();

        assert_eq!(session.ip_address().known().unwrap().as_str(), "10.0.0.1");
        assert_eq!(
            session.user_agent().known().unwrap().as_str(),
            "Mozilla/5.0"
        );
    }

    /// A session made by a sign-in starts on the dashboard channel.
    #[test]
    fn a_new_session_belongs_to_the_dashboard() {
        assert_eq!(test_session().channel(), SessionChannel::Dashboard);
    }

    /// Ann's session is bound to one app and then refreshed. The new session
    /// still belongs to that app.
    #[test]
    fn a_session_bound_to_an_app_stays_with_it_through_rotation() {
        let service = ServiceId::new();
        let mut session = signed_in_session();
        session.bind_to_app(service).unwrap();

        let carried_on = rotated(&mut session).unwrap();

        assert_eq!(carried_on.channel(), SessionChannel::App(service));
    }

    /// Once bound to one application, a session cannot be bound to another.
    #[test]
    fn an_app_session_cannot_be_rebound() {
        let mut session = test_session();
        session.bind_to_app(ServiceId::new()).unwrap();

        assert!(session.bind_to_app(ServiceId::new()).is_err());
    }

    /// Ann's session is suspended. It is not usable until it resumes.
    #[test]
    fn a_suspended_session_is_not_usable() {
        let mut session = signed_in_session();

        session
            .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
            .unwrap();

        assert!(session.is_suspended());
        assert!(!session.is_usable(crate::shared::clock::now()));
    }

    /// Recovery-code and email-confirmation proofs leave the session suspended.
    /// A TOTP proof resumes it as usable.
    #[test]
    fn only_a_factor_proved_now_resumes_a_session() {
        let mut session = signed_in_session();
        session
            .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
            .unwrap();

        for factor in [MfaFactor::RecoveryCode, MfaFactor::EmailConfirmation] {
            let offered = holders(&session, factor);
            assert!(matches!(
                session.resume(offered, &StepUpPolicy::relaxed()),
                Err(DomainError::Forbidden(_))
            ));
            assert!(session.is_suspended());
        }

        let code = holders(&session, MfaFactor::Totp);
        session.resume(code, &StepUpPolicy::relaxed()).unwrap();
        assert!(session.is_usable(crate::shared::clock::now()));
    }

    /// Another account's factor proof cannot resume a suspended session.
    #[test]
    fn a_suspended_session_does_not_resume_on_another_accounts_factor() {
        let mut session = signed_in_session();
        session
            .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
            .unwrap();
        let mallorys_code = proved(UserId::new().into(), MfaFactor::Totp);

        let refused = session.resume(mallorys_code, &StepUpPolicy::relaxed());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(session.is_suspended());
    }

    /// Resuming a hardware-key session with TOTP records TOTP as the proved
    /// factor and lowers the session's assurance to AAL2.
    #[test]
    fn a_resumed_session_stands_at_the_factor_proved_now() {
        let mut session = session_with(
            AuthMethod::Password,
            FactorProved::Proved(MfaFactor::HardwareKey),
        );
        session
            .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
            .unwrap();
        let code = holders(&session, MfaFactor::Totp);

        session.resume(code, &StepUpPolicy::relaxed()).unwrap();

        assert_eq!(session.assurance_level(), AssuranceLevel::Aal2);
        assert_eq!(session.mfa_method(), FactorProved::Proved(MfaFactor::Totp));
    }

    /// TOTP cannot resume a session under an AAL3 baseline. The session remains
    /// suspended with its earlier AAL3 assurance unchanged.
    #[test]
    fn a_resume_below_the_baseline_is_refused() {
        let mut session = session_with(
            AuthMethod::Password,
            FactorProved::Proved(MfaFactor::HardwareKey),
        );
        session
            .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
            .unwrap();
        let hardware_baseline = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal: AssuranceLevel::Aal3,
            sensitive_aal: AssuranceLevel::Aal3,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .unwrap();

        let code = holders(&session, MfaFactor::Totp);
        let refused = session.resume(code, &hardware_baseline);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(session.is_suspended());
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal3);
    }

    /// Resuming a session that is active is refused as a wrong transition.
    #[test]
    fn an_active_session_has_nothing_to_resume() {
        let mut session = signed_in_session();
        let code = holders(&session, MfaFactor::Totp);

        assert!(matches!(
            session.resume(code, &StepUpPolicy::relaxed()),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    fn stored_session() -> SessionRow {
        let now = crate::shared::clock::now();
        SessionRow {
            id: SessionId::new(),
            user_id: UserId::new(),
            refresh_token_hash: TokenHash::from_stored("hash".to_owned()),
            parent_id: SessionOrigin::SignIn,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            signed_in_from: Fact::Unknown,
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            status: SessionStatus::Active,
            channel: SessionChannel::Dashboard,
            signed_in_at: now,
            created_at: now,
            last_active_at: now,
            expires_at: now + Duration::hours(1),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
        }
    }

    /// A stored session names itself as its parent. Loading it is refused as
    /// corrupt.
    #[test]
    fn a_stored_session_rotated_from_itself_is_refused() {
        let mut row = stored_session();
        row.parent_id = SessionOrigin::RotatedFrom(row.id);

        assert!(refused_as_corrupt(
            &Session::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored session last used, or expiring, one second before it was
    /// created is refused as corrupt.
    #[test]
    fn a_stored_session_used_or_expiring_before_it_was_created_is_refused() {
        let mut used_early = stored_session();
        used_early.last_active_at = used_early.created_at - Duration::SECOND;
        let mut expired_early = stored_session();
        expired_early.expires_at = expired_early.created_at - Duration::SECOND;

        for row in [used_early, expired_early] {
            assert!(refused_as_corrupt(
                &Session::<ResolvedTenant>::reconstitute(row)
            ));
        }
    }

    /// A stored session says its person signed in a second after it was
    /// created. Read back, a credential change between the two would be
    /// missed, so it is refused as corrupt.
    #[test]
    fn a_stored_session_signed_in_after_it_was_created_is_refused() {
        let mut row = stored_session();
        row.signed_in_at = row.created_at + Duration::SECOND;

        assert!(refused_as_corrupt(
            &Session::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored password session claims a provider's hardware key. It is
    /// refused as corrupt, not read back as AAL3.
    #[test]
    fn a_stored_session_with_an_unreachable_progress_is_refused() {
        let mut row = stored_session();
        row.progress.factor = FactorProved::Proved(MfaFactor::ProviderHardwareKey);

        assert!(refused_as_corrupt(
            &Session::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann signs out from her own session. It raises
    /// `authentication.session_revoked` as a logout, naming nobody else.
    #[test]
    fn signing_out_raises_a_logout() {
        let mut anns = signed_in_session();

        anns.revoke(&holder_of(&anns)).unwrap();

        let events = raised(&mut anns);
        assert_eq!(names(&events), ["authentication.session_revoked"]);
        assert_eq!(events[0].payload().get("reason"), Some("logout"));
        assert!(events[0].payload().value("user").is_none());
    }

    /// Ann's browser presents the session's refresh token to sign out. It
    /// raises a logout too.
    #[test]
    fn signing_out_by_token_raises_a_logout() {
        let mut anns = test_session();

        anns.sign_out(&TokenHash::from_stored("hashed_token".to_owned()))
            .unwrap();

        let events = raised(&mut anns);
        assert_eq!(names(&events), ["authentication.session_revoked"]);
        assert_eq!(events[0].payload().get("reason"), Some("logout"));
    }

    /// Fay, who may deactivate users, ends Ann's session. It raises the end
    /// as an admin action.
    #[test]
    fn an_admin_ending_a_session_raises_an_admin_action() {
        static DEACTIVATOR: [SystemPermission; 1] =
            [SystemPermission::Users(UserAction::Deactivate)];
        let mut anns = signed_in_session();
        let fay = AccountControl::assumed(
            anyone_holding(&DEACTIVATOR),
            *anns.user_id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        anns.revoke(&fay).unwrap();

        let events = raised(&mut anns);
        assert_eq!(events[0].payload().get("reason"), Some("admin_action"));
    }

    /// Ann's refresh token comes back after it was swapped. The session
    /// raises its end for token theft, naming Ann, since the platform ends
    /// it.
    #[test]
    fn a_reused_token_raises_token_theft_naming_the_holder() {
        let mut anns = signed_in_session();

        anns.record_token_theft(EventLabel::of("Ann"));

        let events = raised(&mut anns);
        assert_eq!(names(&events), ["authentication.session_revoked"]);
        assert_eq!(events[0].payload().get("reason"), Some("token_theft"));
        assert!(events[0].payload().value("user").is_some());
    }

    /// Ann's account is locked after a break-in. Her laptop session ends
    /// with it, and the end is raised for the account's change, naming Ann.
    #[test]
    fn a_locked_account_ends_its_session_on_the_record() {
        let mut anns = signed_in_session();
        let locked = account_with(*anns.user_id(), UserStatus::Locked, CredentialChange::Never);

        anns.end_with_account(&locked).unwrap();

        let events = raised(&mut anns);
        assert!(anns.is_revoked());
        assert_eq!(names(&events), ["authentication.session_revoked"]);
        assert_eq!(
            events[0].payload().get("reason"),
            Some("account_state_change")
        );
        assert!(events[0].payload().value("user").is_some());
    }

    /// An active account cannot trigger account-based session termination.
    /// The session remains unrevoked and raises no event.
    #[test]
    fn an_account_still_signing_in_keeps_its_session() {
        let mut anns = signed_in_session();
        let active = account_with(*anns.user_id(), UserStatus::Active, CredentialChange::Never);

        let refused = anns.end_with_account(&active);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(!anns.is_revoked());
        assert!(raised(&mut anns).is_empty());
    }

    /// A lock on Bob's account cannot end Ann's session, which remains unrevoked.
    #[test]
    fn another_accounts_lock_ends_no_session() {
        let mut anns = signed_in_session();
        let bobs = account_with(UserId::new(), UserStatus::Locked, CredentialChange::Never);

        let refused = anns.end_with_account(&bobs);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(!anns.is_revoked());
    }

    /// Ann's session is frozen on a binding violation and resumed with her
    /// live code. It raises the suspension, naming Ann and why, then the
    /// resumption.
    #[test]
    fn suspending_and_resuming_raise_both_in_order() {
        let mut session = signed_in_session();

        session
            .suspend(SuspensionReason::BindingViolation, EventLabel::of("Ann"))
            .unwrap();
        let code = holders(&session, MfaFactor::Totp);
        session.resume(code, &StepUpPolicy::relaxed()).unwrap();

        let events = raised(&mut session);
        assert_eq!(
            names(&events),
            [
                "authentication.session_suspended",
                "authentication.session_resumed"
            ]
        );
        assert_eq!(events[0].payload().get("reason"), Some("binding violation"));
    }

    /// Ann refreshes her session. The new session raises
    /// `authentication.token_refreshed`, naming the one it replaced, and the
    /// retired parent raises nothing.
    #[test]
    fn a_refresh_is_raised_by_the_new_session() {
        let mut parent = signed_in_session();

        let mut child = rotated(&mut parent).unwrap();

        let events = raised(&mut child);
        assert_eq!(names(&events), ["authentication.token_refreshed"]);
        assert_eq!(
            events[0].payload().get("session_id"),
            Some(parent.id().to_string().as_str())
        );
        assert!(raised(&mut parent).is_empty());
    }

    /// Ann's sign-in took 42 ms and her session is kept. It raises
    /// `authentication.login_succeeded` with how she signed in and the time.
    #[test]
    fn a_recorded_sign_in_raises_login_succeeded() {
        let mut session = signed_in_session();

        session.record_sign_in(Fact::Known(42));

        let events = raised(&mut session);
        assert_eq!(names(&events), ["authentication.login_succeeded"]);
        assert_eq!(events[0].payload().get("auth_method"), Some("password"));
        assert_eq!(events[0].payload().get("auth_duration_ms"), Some("42"));
    }

    /// A token for the files service is issued under Ann's session. The
    /// session raises `authentication.app_token_issued`, naming the service.
    #[test]
    fn an_issued_app_token_is_raised_by_its_session() {
        let mut session = signed_in_session();
        let files = Label::new("name", "files-api").unwrap();

        session.record_app_token(&ServiceId::new(), &files, crate::shared::clock::now());

        let events = raised(&mut session);
        assert_eq!(names(&events), ["authentication.app_token_issued"]);
        assert!(events[0].payload().value("service").is_some());
    }

    /// Ann proves her code on a session that owed it. Recording it raises
    /// `authentication.mfa_verified` for the session.
    #[test]
    fn a_recorded_factor_raises_mfa_verified() {
        let mut session = test_session();
        answered(&mut session, MfaFactor::Totp, &StepUpPolicy::relaxed()).unwrap();

        session.record_factor_verified();

        assert_eq!(raised_names(&mut session), ["authentication.mfa_verified"]);
    }

    /// A refused resume using another account's factor raises no session event.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut session = signed_in_session();
        session
            .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
            .unwrap();
        let _ = raised(&mut session);
        let mallorys = proved(UserId::new().into(), MfaFactor::Totp);

        let refused = session.resume(mallorys, &StepUpPolicy::relaxed());

        assert!(refused.is_err());
        assert!(raised(&mut session).is_empty());
    }

    /// Ann's single sign-on is handed over for its code. The new session
    /// raises `authentication.sign_in_code_exchanged`, and the retired one
    /// nothing.
    #[test]
    fn a_handed_over_sign_on_raises_the_exchange() {
        let mut provider_session = test_session();
        let code = code_spent_for(&provider_session);
        let ann = account_of(&provider_session, CredentialChange::Never);

        let mut handed = handed_over(&mut provider_session, &code, &ann).unwrap();

        assert_eq!(
            raised_names(&mut handed),
            ["authentication.sign_in_code_exchanged"]
        );
        assert!(raised(&mut provider_session).is_empty());
    }

    /// A session read back from storage has raised nothing.
    #[test]
    fn a_session_read_back_has_raised_nothing() {
        let mut session = Session::<ResolvedTenant>::reconstitute(stored_session()).unwrap();

        assert!(raised(&mut session).is_empty());
    }

    fn names(events: &[DomainEvent]) -> Vec<&'static str> {
        events
            .iter()
            .map(|event| event.event_type().as_str())
            .collect()
    }
}
