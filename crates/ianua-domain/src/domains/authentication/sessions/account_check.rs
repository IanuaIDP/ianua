//! What a session is held to besides itself: the account it belongs to, as
//! that account stands now, and the tenant's idle timeout.
//!
//! A session says only how its sign-in went. Whether it still counts also
//! depends on the account. An admin locks the account, switches it off, or
//! it waits for erasure. Its holder sets a new password because the old
//! one leaked. Each of these must end every session at once, not when the
//! session happens to expire.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::session::Session;
use crate::domains::authentication::sessions::sign_in_progress::{
    ProviderSignIn, SignInProgress, SignInRefused,
};
use crate::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::types::{PrincipalId, UserId};

/// An account that may sign in now, and the sign-in begun for it.
///
/// The sign-in is bound to the account here, once. A tenant session opens
/// only from one, and takes its progress from it. So no way in opens a
/// session for an account it was not proved for. Mallory's own passkey
/// never opens a session for Ann, whatever address was typed. And no way
/// in opens a session for an account that is locked, switched off, still
/// joining or waiting for erasure.
#[derive(Debug)]
pub struct MaySignIn<T: TenantScope> {
    user_id: UserId,
    progress: SignInProgress,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> MaySignIn<T> {
    /// The sign-in `way_in` begins for `account`, owing `owed`, when the
    /// way in was proved for that account and it may sign in now.
    ///
    /// The way in is spent on it, so one proof opens one session.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::ForAnotherAccount`] when `way_in` was proven for
    ///   another account.
    /// - [`SignInRefused::AccountMayNotSignIn`] when the account is locked,
    ///   switched off, still joining or waiting for erasure.
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   way in alone falls short of the baseline.
    pub fn proven(
        account: &User<T>,
        way_in: WayIn,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        if way_in.account() != PrincipalId::from(*account.id()) {
            return Err(SignInRefused::ForAnotherAccount);
        }
        if !account.can_authenticate() {
            return Err(SignInRefused::AccountMayNotSignIn);
        }
        let progress = SignInProgress::start(way_in, owed, policy)?;
        Ok(Self::active(*account.id(), progress))
    }

    /// The sign-in a provider vouched for, begun for `user_id`, owing
    /// `owed`. Only the link to the provider's account calls this, once it
    /// found the account it names and checked that it may sign in.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   sign-in falls short of the baseline.
    pub(crate) fn through_provider(
        user_id: UserId,
        sign_in: ProviderSignIn,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<Self, SignInRefused> {
        let progress = SignInProgress::begin_through_provider(sign_in, owed, policy)?;
        Ok(Self::active(user_id, progress))
    }

    /// The sign-in `progress` for an account a sign-in in this crate
    /// already found active, on a way in proved for it.
    pub(crate) fn active(user_id: UserId, progress: SignInProgress) -> Self {
        Self {
            user_id,
            progress,
            _scope: PhantomData,
        }
    }

    /// The account.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// How far the sign-in has come.
    #[must_use]
    pub fn progress(&self) -> &SignInProgress {
        &self.progress
    }

    /// The account and its sign-in, taken apart by the session that opens
    /// from them.
    pub(crate) fn into_parts(self) -> (UserId, SignInProgress) {
        (self.user_id, self.progress)
    }
}

/// What a stored session is held to each time it is used or refreshed.
pub struct SessionCheck<'a, T: TenantScope> {
    /// The account the session belongs to, as it is now.
    pub account: &'a User<T>,
    /// The tenant's session timeouts.
    pub timeout: &'a SessionTimeoutPolicy,
    /// When the session is being used.
    pub now: OffsetDateTime,
}

impl<T: TenantScope> SessionCheck<'_, T> {
    /// Whether `session` still counts.
    ///
    /// It must be usable on its own, belong to this account, and the account
    /// must still be able to sign in. The account must not have changed how
    /// it signs in since the person signed in, and the session must not have
    /// gone idle. A new password ends every session opened before it, so
    /// whoever held the old password is out. The one session its holder
    /// kept through that change stays, see
    /// [`Session::keep_through_own_password_change`].
    #[must_use]
    pub fn admits(&self, session: &Session<T>) -> bool {
        session.is_usable(self.now) && self.holds_to_account(session)
    }

    /// Whether `session` still counts as a sign-in under way: open, of this
    /// account, and held to it as [`admits`](Self::admits) holds a finished
    /// one, while it may still owe a step.
    pub(crate) fn admits_unfinished(&self, session: &Session<T>) -> bool {
        session.is_open(self.now) && self.holds_to_account(session)
    }

    /// Whether `session` belongs to this account, the account may still
    /// sign in and has not changed how since, and the session has not sat
    /// idle.
    fn holds_to_account(&self, session: &Session<T>) -> bool {
        self.account.id() == session.user_id()
            && self.account.can_authenticate()
            && self.sign_in_still_current(session)
            && !self.timeout.is_idle(session.last_active_at(), self.now)
    }

    /// Whether the account's last change of how it signs in came before the
    /// person signed in, or is the one change the session was kept through.
    ///
    /// It counts from the sign-in, not from when a refresh made this
    /// session. Mallory refreshes Ann's stolen session the moment Ann sets a
    /// new password. Counted from the refresh, the new session would outlive
    /// the change meant to end it.
    fn sign_in_still_current(&self, session: &Session<T>) -> bool {
        let changed = self.account.credentials_changed_at();
        !changed.since(session.signed_in_at()) || changed == session.kept_through()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::sessions::session::CreateSessionParams;
    use crate::domains::authentication::sessions::sign_in_progress::LocalMethod;
    use crate::domains::identity::account::address::AddressStanding;
    use crate::domains::identity::account::user::UserRow;
    use crate::domains::identity::account::user_profile::UserProfile;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::identity::account::vouching::Vouching;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::types::{
        CredentialChange, DisplayName, Email, Fact, Joining, Preference, SessionId, TokenHash,
    };

    /// A new account in `status` that last changed how it signs in at
    /// `credentials`, made a day ago. Tests elsewhere in the crate use it.
    pub(crate) fn account_in(
        status: UserStatus,
        credentials: CredentialChange,
    ) -> User<ResolvedTenant> {
        account_with(UserId::new(), status, credentials)
    }

    /// The account `id` in `status`, as [`account_in`] makes it.
    pub(crate) fn account_with(
        id: UserId,
        status: UserStatus,
        credentials: CredentialChange,
    ) -> User<ResolvedTenant> {
        let since = crate::shared::clock::now() - Duration::days(1);
        let (joining, email_standing) = match status {
            UserStatus::Invited | UserStatus::PendingVerification => {
                (Joining::NotYet, AddressStanding::Unverified)
            }
            UserStatus::Active
            | UserStatus::Locked
            | UserStatus::Closing
            | UserStatus::Deactivated => (Joining::Joined { at: since }, AddressStanding::Verified),
        };
        User::reconstitute(UserRow {
            profile: UserProfile::default(),
            id,
            email: Email::new("ann@example.com").unwrap(),
            display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
            status,
            email_standing,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: since,
            updated_at: since,
            last_login_at: None,
            joining,
            credentials_changed_at: credentials,
            vouching: Vouching::Absent,
        })
        .unwrap()
    }

    const STATUSES_SHUT: [UserStatus; 5] = [
        UserStatus::Locked,
        UserStatus::Deactivated,
        UserStatus::Closing,
        UserStatus::Invited,
        UserStatus::PendingVerification,
    ];

    fn session_for(account: &User<ResolvedTenant>) -> Session<ResolvedTenant> {
        let progress = SignInProgress::begin(
            LocalMethod::Password,
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
        .expect("relaxed admits a password");
        Session::create(
            MaySignIn::active(*account.id(), progress),
            CreateSessionParams {
                id: SessionId::new(),
                refresh_token_hash: TokenHash::from_stored("hash".to_owned()),
                ip_address: Fact::Unknown,
                user_agent: Fact::Unknown,
                timeout: SessionTimeoutPolicy::STANDARD,
            },
        )
    }

    fn password_way_into(account: &User<ResolvedTenant>) -> WayIn {
        WayIn::by_password((*account.id()).into())
    }

    fn proven(
        account: &User<ResolvedTenant>,
        way_in: WayIn,
    ) -> Result<MaySignIn<ResolvedTenant>, SignInRefused> {
        MaySignIn::proven(
            account,
            way_in,
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
    }

    fn check_of<'a>(
        account: &'a User<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> SessionCheck<'a, ResolvedTenant> {
        SessionCheck {
            account,
            timeout: &SessionTimeoutPolicy::STANDARD,
            now,
        }
    }

    /// Ann's account is active and she typed her password. She may sign in,
    /// and the sign-in names her and began with her password.
    #[test]
    fn an_active_account_may_sign_in() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);

        let may = proven(&ann, password_way_into(&ann)).unwrap();

        assert_eq!(may.user_id(), ann.id());
        assert_eq!(
            may.progress().method(),
            crate::domains::authentication::methods::AuthMethod::Password
        );
    }

    /// A password proof cannot admit an account whose status prevents sign-in.
    #[test]
    fn an_account_that_is_shut_may_not_sign_in() {
        for status in STATUSES_SHUT {
            let ann = account_in(status, CredentialChange::Never);

            assert_eq!(
                proven(&ann, password_way_into(&ann)).err(),
                Some(SignInRefused::AccountMayNotSignIn),
                "{status:?} was let in"
            );
        }
    }

    /// Bob's password proof is rejected when used to admit Ann's account.
    #[test]
    fn bobs_way_in_opens_no_session_for_ann() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);
        let bob = account_in(UserStatus::Active, CredentialChange::Never);

        let refused = proven(&ann, password_way_into(&bob));

        assert_eq!(refused.err(), Some(SignInRefused::ForAnotherAccount));
    }

    /// Ann signed in a minute ago and her account is still active. Her
    /// session counts.
    #[test]
    fn a_session_of_an_active_account_counts() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);
        let session = session_for(&ann);

        assert!(check_of(&ann, crate::shared::clock::now()).admits(&session));
    }

    /// An existing session stops being admitted when its account becomes
    /// locked, deactivated or closing.
    #[test]
    fn a_session_stops_counting_once_its_account_is_shut() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);
        let session = session_for(&ann);

        for status in [
            UserStatus::Locked,
            UserStatus::Deactivated,
            UserStatus::Closing,
        ] {
            let shut = User::<ResolvedTenant>::reconstitute(UserRow {
                profile: UserProfile::default(),
                status,
                ..row_of(&ann)
            })
            .unwrap();

            assert!(
                !check_of(&shut, crate::shared::clock::now()).admits(&session),
                "{status:?} kept the session"
            );
        }
    }

    /// A credential change invalidates a session opened before that change.
    #[test]
    fn a_session_opened_before_a_new_password_stops_counting() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);
        let session = session_for(&ann);
        let after = User::<ResolvedTenant>::reconstitute(UserRow {
            profile: UserProfile::default(),
            credentials_changed_at: CredentialChange::At {
                at: crate::shared::clock::now(),
            },
            ..row_of(&ann)
        })
        .unwrap();

        assert!(!check_of(&after, crate::shared::clock::now()).admits(&session));
    }

    /// Ann's account check rejects a session belonging to Bob.
    #[test]
    fn a_session_counts_only_for_its_own_account() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);
        let bob = account_in(UserStatus::Active, CredentialChange::Never);
        let bobs = session_for(&bob);

        assert!(!check_of(&ann, crate::shared::clock::now()).admits(&bobs));
    }

    /// Ann leaves her laptop for 31 minutes under a 30 minute idle timeout.
    /// Her session no longer counts.
    #[test]
    fn a_session_left_idle_past_the_timeout_stops_counting() {
        let ann = account_in(UserStatus::Active, CredentialChange::Never);
        let session = session_for(&ann);
        let later = crate::shared::clock::now() + Duration::minutes(31);

        assert!(!check_of(&ann, later).admits(&session));
    }

    fn row_of(account: &User<ResolvedTenant>) -> UserRow {
        UserRow {
            profile: UserProfile::default(),
            id: *account.id(),
            email: account.email().clone(),
            display_name: account.display_name().clone(),
            status: account.status(),
            email_standing: AddressStanding::Verified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: account.created_at(),
            updated_at: account.created_at(),
            last_login_at: None,
            joining: Joining::Joined {
                at: account.created_at(),
            },
            credentials_changed_at: account.credentials_changed_at(),
            vouching: account.vouching(),
        }
    }

    /// Ann changes her password from her laptop session, after proving who
    /// she is. The laptop session is kept. Her phone session from before is
    /// ended, so whoever held the old password is out.
    #[test]
    fn a_holder_keeps_the_session_they_changed_their_password_from() {
        let before = account_in(UserStatus::Active, CredentialChange::Never);
        let mut laptop = session_for(&before);
        let phone = session_for(&before);
        let now = crate::shared::clock::now() + Duration::seconds(1);
        let ann = account_with(
            *before.id(),
            UserStatus::Active,
            CredentialChange::At { at: now },
        );
        let proof = crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of(
            (*ann.id()).into(),
        );

        laptop
            .keep_through_own_password_change(&ann, &proof)
            .unwrap();

        assert!(check_of(&ann, now).admits(&laptop));
        assert!(!check_of(&ann, now).admits(&phone));
    }
}
