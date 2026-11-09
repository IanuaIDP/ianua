//! A fresh proof of the person, for changes an open session must not make
//! alone.
//!
//! Someone who steals a session holds it until it ends. Changing the
//! account's address, or adding a way to sign in, would let them keep the
//! account after that. So such a change asks the person to prove who they
//! are again, the way they sign in, and the proof counts for a few minutes
//! only.

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::credentials::passkey::{
    KeyAttestation, PasskeyCredential, PasskeyPlane,
};
use crate::domains::authentication::credentials::passkey_ceremony::{
    CeremonyPurpose, PasskeyChallenge,
};
use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::authentication::mfa::enrollment::AnsweredCode;
use crate::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use crate::domains::authentication::sessions::mfa_factor::FactorProved;
use crate::domains::authentication::sessions::sign_in_progress::{LocalMethod, ProviderSignIn};
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::identity::account::control::RecentProof;
use crate::domains::identity::sealed::Sealed;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{PasswordHash, PrincipalId};

/// How long a fresh proof counts for.
pub(crate) const FRESH_FOR: Duration = Duration::minutes(10);

/// A password typed again, with the account's stored hash to check it
/// against and the lockout of where it was typed.
///
/// The lockout is the one sign-in keeps, for the account and the network
/// the attempt came from. Mallory holds Ann's session but not her password.
/// Without it, she guesses on the "confirm it's you" step as fast as the
/// hasher answers, and the lockout never fires.
pub struct PasswordCheck<'a, H: PasswordHasher> {
    /// The password as typed.
    pub raw: &'a str,
    /// The account's stored hash.
    pub stored: &'a PasswordHash,
    /// What checks the one against the other.
    pub hasher: &'a H,
    /// The lockout of where the password was typed, as sign-in keeps it,
    /// and what this attempt does to its count.
    pub tracker: &'a mut LoginAttemptTracker,
}

impl<H: PasswordHasher> std::fmt::Debug for PasswordCheck<'_, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordCheck(redacted)")
    }
}

impl<H: PasswordHasher> PasswordCheck<'_, H> {
    /// Refuses the typed password while where it was typed is locked out of
    /// the account, or when it is wrong. A wrong one counts towards the
    /// lockout, and a right one clears the count. A hasher that cannot check
    /// counts nothing.
    pub(crate) fn ensure_matches(self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.tracker.is_locked(now) {
            return Err(DomainError::forbidden(message!(
                "authentication-too-many-wrong-passwords-try-again",
                "too many wrong passwords; try again later"
            )));
        }
        if !self.hasher.verify(self.raw, self.stored)? {
            self.tracker.record_failure();
            return Err(DomainError::forbidden(message!(
                "authentication-the-password-is-wrong",
                "the password is wrong"
            )));
        }
        self.tracker.reset();
        Ok(())
    }
}

/// The second factor proved together with a password.
#[derive(Debug, Clone, Copy)]
pub enum WithFactor<'a> {
    /// The account has no second factor, so the password is all it signs
    /// in with.
    NoneOnFile,
    /// A right code from the account's second factor, just now.
    Code(&'a AnsweredCode),
}

impl WithFactor<'_> {
    /// Refuses a code from another account's second factor.
    fn ensure_for(self, account: PrincipalId) -> Result<(), DomainError> {
        match self {
            Self::Code(answer) if answer.subject() != account => {
                Err(DomainError::forbidden(message!(
                    "authentication-the-code-is-from-another-account",
                    "the code is from another account's second factor"
                )))
            }
            Self::NoneOnFile | Self::Code(_) => Ok(()),
        }
    }
}

/// What an account signs in with besides links mailed to it.
#[derive(Debug, Clone, Copy)]
pub enum BesideTheMailbox<'a> {
    /// Nothing: its mailbox is its only way in.
    Nothing,
    /// A second factor and no password or passkey, with a right code from
    /// that factor just now.
    SecondFactor(&'a AnsweredCode),
    /// A password or a passkey, which it proves itself with instead.
    PasswordOrPasskey,
}

/// Which ceremony a passkey answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyAnswer {
    /// A challenge to sign in with a passkey already registered.
    SignIn,
    /// The challenge that registered a new passkey.
    Registration,
}

/// A passkey challenge the account's holder answered just now.
#[derive(Debug, Clone, Copy)]
pub struct SpentPasskey {
    account: PrincipalId,
    spent_at: OffsetDateTime,
    answer: PasskeyAnswer,
    key: KeyAttestation,
}

impl SpentPasskey {
    /// A sign-in challenge opened for `account` and spent at `spent_at`, by
    /// a key nobody attested. Tests use it in place of a real ceremony.
    #[cfg(test)]
    pub(crate) fn new(account: PrincipalId, spent_at: OffsetDateTime) -> Self {
        Self {
            account,
            spent_at,
            answer: PasskeyAnswer::SignIn,
            key: KeyAttestation::Unattested,
        }
    }

    /// A registration challenge opened for `account` and spent at
    /// `spent_at`. Tests use it in place of a real ceremony.
    #[cfg(test)]
    pub(crate) fn registered(account: PrincipalId, spent_at: OffsetDateTime) -> Self {
        Self {
            answer: PasskeyAnswer::Registration,
            ..Self::new(account, spent_at)
        }
    }

    /// A passkey ceremony of plane `S`, spent, and the passkey of that plane
    /// that answered it. A tenant's ceremony is answered by a tenant
    /// user's passkey, and an organization's by a member's.
    ///
    /// The caller spends the ceremony, has the adapter check the
    /// authenticator's answer against the state it gave, and records the
    /// new sign count on the passkey, or registers it. Only then is the
    /// passkey marked as used after the challenge was spent. A challenge
    /// spent but never answered, or answered by another account's key,
    /// proves nothing.
    ///
    /// A discoverable challenge names nobody, so the passkey names its
    /// owner.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the ceremony was not spent.
    /// - [`DomainError::Forbidden`] when the ceremony was opened for another
    ///   account than the passkey's owner.
    /// - [`DomainError::Forbidden`] when the passkey was not used, or
    ///   registered, after the challenge was spent.
    pub fn answered<S: PasskeyPlane>(
        ceremony: &impl PasskeyChallenge<S>,
        passkey: &PasskeyCredential<S>,
    ) -> Result<Self, DomainError> {
        let Some(spent_at) = ceremony.spent_at() else {
            return Err(DomainError::invalid(message!(
                "authentication-only-a-spent-challenge-proves-the",
                "only a spent challenge proves the person"
            )));
        };
        let owner = *passkey.user_id();
        if ceremony
            .opened_for()
            .is_some_and(|opened_for| opened_for != owner)
        {
            return Err(DomainError::forbidden(message!(
                "authentication-the-passkey-belongs-to-another-account",
                "the passkey belongs to another account than the challenge"
            )));
        }
        let answer = answer_to(ceremony.opened_as());
        if !used_since(answer, passkey, spent_at) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-passkey-did-not-answer-this",
                "the passkey did not answer this challenge"
            )));
        }
        Ok(Self {
            account: owner.into(),
            spent_at,
            answer,
            key: passkey.attestation(),
        })
    }

    /// The account whose passkey answered.
    pub(crate) fn account(&self) -> PrincipalId {
        self.account
    }

    /// Which ceremony the passkey answered.
    pub(crate) fn answer(&self) -> PasskeyAnswer {
        self.answer
    }

    /// What the passkey's attestation showed.
    pub(crate) fn key(&self) -> KeyAttestation {
        self.key
    }

    /// Whether the challenge was spent within `FRESH_FOR` before `now`.
    pub(crate) fn is_fresh_at(&self, now: OffsetDateTime) -> bool {
        is_within_fresh(self.spent_at, now)
    }
}

/// The answer a ceremony of `purpose` gets.
fn answer_to(purpose: CeremonyPurpose) -> PasskeyAnswer {
    match purpose {
        CeremonyPurpose::Authentication | CeremonyPurpose::DiscoverableAuthentication => {
            PasskeyAnswer::SignIn
        }
        CeremonyPurpose::Registration => PasskeyAnswer::Registration,
    }
}

/// Whether `passkey` was used to sign in, or was registered, no earlier
/// than the challenge was spent.
fn used_since<S: PasskeyPlane>(
    answer: PasskeyAnswer,
    passkey: &PasskeyCredential<S>,
    spent_at: OffsetDateTime,
) -> bool {
    match answer {
        PasskeyAnswer::SignIn => passkey.last_used_at().is_some_and(|used| used >= spent_at),
        PasskeyAnswer::Registration => passkey.created_at() >= spent_at,
    }
}

/// Whether something done `at` still counts as fresh at `now`.
fn is_within_fresh(at: OffsetDateTime, now: OffsetDateTime) -> bool {
    at <= now && now < at.saturating_add(FRESH_FOR)
}

/// Proof that the holder of an account proved who they are again, as
/// strongly as they sign in, a moment ago.
///
/// It is made only by [`by_password`](Self::by_password),
/// [`by_passkey`](Self::by_passkey), [`by_mailbox`](Self::by_mailbox), a
/// password typed again over a fresh directory bind, which
/// [`DirectoryBind::fresh_sign_in`] checks, or a sign-in through a linked
/// provider made just now, which [`FederatedLink::fresh_sign_in`] checks.
/// It counts for `FRESH_FOR`. A
/// sign-in waiting for a factor to be set up gives an [`EnrolmentProof`]
/// instead, which sets up that factor and nothing else.
///
/// [`FederatedLink::fresh_sign_in`]: crate::domains::federation::link::FederatedLink::fresh_sign_in
/// [`DirectoryBind::fresh_sign_in`]: crate::domains::authentication::ldap_certificate::DirectoryBind::fresh_sign_in
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshSignIn {
    account: PrincipalId,
    at: OffsetDateTime,
}

impl FreshSignIn {
    /// Proves the account holder with their password and their enrolled factor, if any.
    /// The caller supplies enrollment status, claims the code's time step and stores
    /// the tracker, as during sign-in.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] during password lockout, for a wrong password
    /// (which counts toward lockout), or a code belonging to another account.
    /// Propagates hasher errors.
    pub fn by_password<H: PasswordHasher>(
        account: PrincipalId,
        password: PasswordCheck<'_, H>,
        factor: WithFactor<'_>,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        password.ensure_matches(now)?;
        factor.ensure_for(account)?;
        Ok(Self { account, at: now })
    }

    /// The holder of `account` typed their password again beside the
    /// client certificate a directory bind checked at `presented_at`, which
    /// stands in for their second factor while it is fresh. Only
    /// [`DirectoryBind::fresh_sign_in`] calls this, once it has checked the
    /// bind still counts.
    ///
    /// The freshness is checked before the password, so a stale bind tells
    /// nobody whether a guessed password was right.
    ///
    /// [`DirectoryBind::fresh_sign_in`]: crate::domains::authentication::ldap_certificate::DirectoryBind::fresh_sign_in
    pub(crate) fn beside_certificate<H: PasswordHasher>(
        account: PrincipalId,
        password: PasswordCheck<'_, H>,
        presented_at: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        if !is_within_fresh(presented_at, now) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-directory-bind-was-made-too",
                "the directory bind was made too long ago to stand in for a second factor; bind again"
            )));
        }
        password.ensure_matches(now)?;
        Ok(Self { account, at: now })
    }

    /// The holder followed a sign-in link mailed to their account just now,
    /// for an account whose mailbox is how it signs in.
    ///
    /// Ann signed up through her company's magic links and never set a
    /// password. Without this she could never prove herself again, so she
    /// could never change her address or add a passkey. The link is as
    /// strong as her sign-in. An account that also has a second factor
    /// answers it too, as at sign-in. One with a password or a passkey
    /// proves itself with that instead, since a mailbox alone is weaker:
    /// Mallory, holding Ann's session and reading her mail, would otherwise
    /// skip Ann's password.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `way_in` is not a followed sign-in
    ///   link.
    /// - [`DomainError::Forbidden`] when the account has a password or a
    ///   passkey.
    /// - [`DomainError::Forbidden`] when the code is from another account's
    ///   second factor.
    pub fn by_mailbox(way_in: WayIn, besides: BesideTheMailbox<'_>) -> Result<Self, DomainError> {
        let (account, method) = way_in.into_parts();
        if method != LocalMethod::MagicLink {
            return Err(DomainError::forbidden(message!(
                "authentication-only-a-followed-sign-in-link",
                "only a followed sign-in link proves the mailbox"
            )));
        }
        match besides {
            BesideTheMailbox::Nothing => {}
            BesideTheMailbox::SecondFactor(answer) => {
                WithFactor::Code(answer).ensure_for(account)?
            }
            BesideTheMailbox::PasswordOrPasskey => {
                return Err(DomainError::forbidden(message!(
                    "authentication-an-account-with-a-password-or",
                    "an account with a password or a passkey proves itself with it"
                )));
            }
        }
        Ok(Self {
            account,
            at: crate::shared::clock::now(),
        })
    }

    /// The holder of `account` signed in through a provider their account
    /// is linked to, just now, as `sign_in` says. The link checks the
    /// provider vouched for the subject it names, and calls this.
    ///
    /// A provider's word on a second factor counts as it does at sign-in.
    /// Without one, the account's own factor answers, when it has one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the provider proved no factor and
    ///   the code is from another account's second factor.
    pub(crate) fn through_provider(
        account: PrincipalId,
        sign_in: ProviderSignIn,
        factor: WithFactor<'_>,
    ) -> Result<Self, DomainError> {
        if sign_in.factor() == FactorProved::NoneYet {
            factor.ensure_for(account)?;
        }
        Ok(Self {
            account,
            at: crate::shared::clock::now(),
        })
    }

    /// The holder answered a passkey sign-in challenge. A passkey is
    /// something they have and unlock, so it counts on its own, as it does
    /// at sign-in.
    ///
    /// Registering a new passkey proves nothing about who holds the account.
    /// Whoever registers it chose it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the passkey answered a registration,
    ///   not a sign-in challenge.
    /// - [`DomainError::Forbidden`] when the challenge was spent longer ago
    ///   than `FRESH_FOR`.
    pub fn by_passkey(spent: SpentPasskey) -> Result<Self, DomainError> {
        if spent.answer != PasskeyAnswer::SignIn {
            return Err(DomainError::forbidden(message!(
                "authentication-registering-a-passkey-does-not-prove",
                "registering a passkey does not prove who holds the account"
            )));
        }
        if !spent.is_fresh_at(crate::shared::clock::now()) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-passkey-was-used-too-long-2",
                "the passkey was used too long ago to prove the person now"
            )));
        }
        Ok(Self {
            account: spent.account,
            at: spent.spent_at,
        })
    }

    /// The account proved.
    #[must_use]
    pub fn account(&self) -> PrincipalId {
        self.account
    }

    /// When the person proved who they are.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }
}

impl Sealed for FreshSignIn {}

impl RecentProof for FreshSignIn {
    fn proves_recently(&self, account: &PrincipalId) -> bool {
        self.account == *account && is_within_fresh(self.at, crate::shared::clock::now())
    }
}

/// A sign-in that waits for its person to set up the second factor the
/// workspace requires, and began moments ago.
///
/// It sets up that factor and nothing else. It is no [`FreshSignIn`]: the
/// sign-in proved only what it asked so far, so it never changes an address,
/// links a provider or changes settings. Mallory has Ann's password in a
/// workspace that requires a factor Ann has not set up. Her sign-in waits
/// for one. Were this a full proof, she would move Ann's address to her own
/// mailbox from that half-finished sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrolmentProof {
    account: PrincipalId,
    at: OffsetDateTime,
}

impl EnrolmentProof {
    /// The proof a sign-in that began at `began_at` gives at `now`, while it
    /// is fresh. Only a session that owes a factor to set up asks for this.
    pub(crate) fn of_sign_in(
        account: PrincipalId,
        began_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Option<Self> {
        is_within_fresh(began_at, now).then_some(Self {
            account,
            at: began_at,
        })
    }

    /// The account signing in.
    #[must_use]
    pub fn account(&self) -> PrincipalId {
        self.account
    }

    /// When the sign-in began.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }
}

impl Sealed for EnrolmentProof {}

/// What lets someone set up a new way to sign in: a fresh proof of the
/// person, or a sign-in waiting for the factor it owes.
///
/// Only [`FreshSignIn`] and [`EnrolmentProof`] answer it, so no caller
/// writes an answer that always agrees.
pub trait FactorSetupProof: Sealed {
    /// Whether this lets the holder of `account` set up a factor now.
    fn lets_set_up(&self, account: &PrincipalId) -> bool;
}

impl FactorSetupProof for FreshSignIn {
    fn lets_set_up(&self, account: &PrincipalId) -> bool {
        self.proves_recently(account)
    }
}

impl FactorSetupProof for EnrolmentProof {
    fn lets_set_up(&self, account: &PrincipalId) -> bool {
        self.account == *account && is_within_fresh(self.at, crate::shared::clock::now())
    }
}

/// A fresh proof of `account`, made now, for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn fresh_proof_of(account: PrincipalId) -> FreshSignIn {
    FreshSignIn {
        account,
        at: crate::shared::clock::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::credentials::passkey::{
        AuthenticatorType, PasskeyCredentialRow,
    };
    use crate::domains::authentication::credentials::passkey_ceremony::{
        OpenCeremonyParams, PasskeyCeremony, TargetedPurpose,
    };
    use crate::domains::authentication::mfa::enrollment::answer_for;
    use crate::domains::authentication::risk_engine::rate_limit::{AttemptTally, Lockout};
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::sign_in_progress::FederatedMethod;
    use crate::domains::identity::account::email_change::{
        CreateEmailChangeParams, PendingEmailChange,
    };
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::identity::tokens::magic_link::MagicLink;
    use crate::domains::identity::tokens::secure::{NewSecureToken, SecureToken};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::{label, user};
    use crate::types::{
        Email, Lifetime, PasskeyCredentialId, PasskeyId, TenantId, TokenHash, UserId,
    };

    /// Says yes to "right" and no to anything else.
    struct KnowsOnePassword;

    impl PasswordHasher for KnowsOnePassword {
        fn hash(&self, raw: &str) -> Result<PasswordHash, DomainError> {
            Ok(PasswordHash::from_stored(raw.to_owned()))
        }

        fn verify(&self, raw: &str, _hash: &PasswordHash) -> Result<bool, DomainError> {
            Ok(raw == "right")
        }
    }

    fn by(raw: &str, account: PrincipalId) -> Result<FreshSignIn, DomainError> {
        counted_by(raw, account, &mut LoginAttemptTracker::new())
    }

    fn counted_by(
        raw: &str,
        account: PrincipalId,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<FreshSignIn, DomainError> {
        let stored = PasswordHash::from_stored("hash".to_owned());
        FreshSignIn::by_password(
            account,
            PasswordCheck {
                raw,
                stored: &stored,
                hasher: &KnowsOnePassword,
                tracker,
            },
            WithFactor::NoneOnFile,
        )
    }

    fn spent_ceremony(purpose: TargetedPurpose, opened_for: UserId) -> PasskeyCeremony {
        let mut ceremony = PasskeyCeremony::open(OpenCeremonyParams {
            tenant_id: TenantId::new(),
            user_id: opened_for,
            purpose,
            state: b"state".to_vec(),
            ttl: Lifetime::seconds(300).unwrap(),
        });
        ceremony.consume(purpose.into()).unwrap();
        ceremony
    }

    fn passkey_of(
        owner: UserId,
        last_used_at: Option<OffsetDateTime>,
    ) -> PasskeyCredential<ResolvedTenant> {
        let created_at = crate::shared::clock::now() - Duration::days(30);
        PasskeyCredential::reconstitute(PasskeyCredentialRow {
            id: PasskeyId::new(),
            user_id: owner,
            credential_id: PasskeyCredentialId::new(vec![1, 2, 3]).unwrap(),
            public_key: vec![4, 5, 6],
            sign_count: 3,
            authenticator_type: AuthenticatorType::Platform,
            attestation: KeyAttestation::Unattested,
            name: label("Laptop"),
            last_used_at,
            created_at,
        })
        .unwrap()
    }

    /// Ann types her password again. The proof counts for her account for
    /// ten minutes, and never for Bob's.
    #[test]
    fn a_password_typed_again_proves_the_person_for_ten_minutes() {
        let ann = PrincipalId::from(UserId::new());
        let bob = PrincipalId::from(UserId::new());
        let start = crate::shared::clock::now();
        let proof = {
            let _now = crate::shared::clock::freeze(start);
            by("right", ann).unwrap()
        };

        let soon = {
            let _now = crate::shared::clock::freeze(start + Duration::minutes(9));
            (proof.proves_recently(&ann), proof.proves_recently(&bob))
        };
        let later = {
            let _now = crate::shared::clock::freeze(start + FRESH_FOR);
            proof.proves_recently(&ann)
        };

        assert_eq!(soon, (true, false));
        assert!(!later);
    }

    /// A wrong password cannot establish fresh proof of the account.
    #[test]
    fn a_wrong_password_proves_nothing() {
        let ann = PrincipalId::from(UserId::new());

        assert!(matches!(by("guess", ann), Err(DomainError::Forbidden(_))));
    }

    /// An origin under lockout cannot establish fresh proof with the correct
    /// password. The refusal leaves its attempt tally untouched.
    #[test]
    fn a_locked_out_origin_is_refused_even_with_the_right_password() {
        let ann = PrincipalId::from(UserId::new());
        let until = crate::shared::clock::now() + Duration::minutes(10);
        let mut tracker = LoginAttemptTracker::standing(Lockout::Until(until));

        let right = counted_by("right", ann, &mut tracker);

        assert!(matches!(right, Err(DomainError::Forbidden(_))));
        assert_eq!(tracker.tally(), AttemptTally::Untouched);
    }

    /// Mallory guesses wrong on the "confirm it's you" step. The guess
    /// counts towards her network's lockout.
    #[test]
    fn a_wrong_password_counts_as_a_failure() {
        let ann = PrincipalId::from(UserId::new());
        let mut tracker = LoginAttemptTracker::new();

        let _ = counted_by("guess", ann, &mut tracker);

        assert_eq!(tracker.tally(), AttemptTally::Failed);
    }

    /// Ann types her password right. The proof is made and her network's
    /// count of wrong passwords is cleared.
    #[test]
    fn a_right_password_clears_the_count_of_wrong_ones() {
        let ann = PrincipalId::from(UserId::new());
        let mut tracker = LoginAttemptTracker::new();

        let proof = counted_by("right", ann, &mut tracker);

        assert!(proof.is_ok());
        assert_eq!(tracker.tally(), AttemptTally::Cleared);
    }

    /// A passkey answer from twenty minutes ago is too old for fresh proof.
    #[test]
    fn an_old_passkey_answer_proves_nothing_now() {
        let ann = PrincipalId::from(UserId::new());
        let spent = SpentPasskey::new(ann, crate::shared::clock::now() - Duration::minutes(20));

        assert!(matches!(
            FreshSignIn::by_passkey(spent),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Ann answers a sign-in challenge with her own passkey, which records
    /// the use. The proof is for her account.
    #[test]
    fn a_challenge_answered_by_the_accounts_own_passkey_proves_the_person() {
        let ann = UserId::new();
        let ceremony = spent_ceremony(TargetedPurpose::Authentication, ann);
        let passkey = passkey_of(ann, Some(crate::shared::clock::now()));

        let proof =
            FreshSignIn::by_passkey(SpentPasskey::answered(&ceremony, &passkey).unwrap()).unwrap();

        assert_eq!(proof.account(), PrincipalId::from(ann));
    }

    /// A passkey belonging to another account cannot answer Ann's challenge.
    #[test]
    fn a_challenge_answered_by_another_accounts_passkey_proves_nothing() {
        let ann = UserId::new();
        let ceremony = spent_ceremony(TargetedPurpose::Authentication, ann);
        let mallorys = passkey_of(UserId::new(), Some(crate::shared::clock::now()));

        assert!(matches!(
            SpentPasskey::answered(&ceremony, &mallorys),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A spent challenge does not establish a passkey answer when the key's
    /// last use predates that challenge.
    #[test]
    fn a_spent_challenge_the_passkey_never_answered_proves_nothing() {
        let ann = UserId::new();
        let ceremony = spent_ceremony(TargetedPurpose::Authentication, ann);
        let unused_since = passkey_of(ann, Some(crate::shared::clock::now() - Duration::days(2)));

        assert!(matches!(
            SpentPasskey::answered(&ceremony, &unused_since),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Ann signs in with a discoverable passkey, without typing who she is.
    /// The passkey names her, so the proof is for her account.
    #[test]
    fn a_discoverable_challenge_proves_the_passkeys_owner() {
        let ann = UserId::new();
        let mut ceremony = PasskeyCeremony::open_discoverable(
            TenantId::new(),
            b"state".to_vec(),
            Lifetime::seconds(300).unwrap(),
        );
        ceremony
            .consume(CeremonyPurpose::DiscoverableAuthentication)
            .unwrap();
        let passkey = passkey_of(ann, Some(crate::shared::clock::now()));

        let proof =
            FreshSignIn::by_passkey(SpentPasskey::answered(&ceremony, &passkey).unwrap()).unwrap();

        assert_eq!(proof.account(), PrincipalId::from(ann));
    }

    /// A registration answer cannot serve as fresh sign-in proof.
    #[test]
    fn registering_a_passkey_proves_nothing_about_the_account() {
        let ann = UserId::new();
        let spent = SpentPasskey {
            answer: PasskeyAnswer::Registration,
            ..SpentPasskey::new(ann.into(), crate::shared::clock::now())
        };

        assert!(matches!(
            FreshSignIn::by_passkey(spent),
            Err(DomainError::Forbidden(_))
        ));
    }

    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// A sign-in link `account` followed just now.
    fn followed_link(account: &User<ResolvedTenant>) -> WayIn {
        let mut link: SecureToken<_, MagicLink> = SecureToken::create(NewSecureToken {
            token_hash: TokenHash::from_stored("magic".to_owned()),
            user_id: *account.id(),
            sent_to: account.email().clone(),
            lifetime: Lifetime::seconds(600).unwrap(),
        })
        .unwrap();
        WayIn::by_magic_link(&mut link, account, crate::shared::clock::now()).unwrap()
    }

    /// Ann has no password and signs in by links to her mailbox. She
    /// follows one again, and the proof is for her account.
    #[test]
    fn a_followed_link_proves_an_account_whose_mailbox_is_its_way_in() {
        let ann = active("ann@acme.test");

        let proof =
            FreshSignIn::by_mailbox(followed_link(&ann), BesideTheMailbox::Nothing).unwrap();

        assert!(proof.proves_recently(&(*ann.id()).into()));
    }

    /// Ann has a second factor beside her mailbox. A code from it, with the
    /// link, proves her. Mallory, reading Ann's mail, offers a code from
    /// her own factor. It is refused.
    #[test]
    fn a_mailbox_proof_takes_the_accounts_own_second_factor() {
        let ann = active("ann@acme.test");
        let anns_code = answer_for((*ann.id()).into());
        let mallorys_code = answer_for(PrincipalId::from(UserId::new()));

        let with_hers = FreshSignIn::by_mailbox(
            followed_link(&ann),
            BesideTheMailbox::SecondFactor(&anns_code),
        );
        let with_mallorys = FreshSignIn::by_mailbox(
            followed_link(&ann),
            BesideTheMailbox::SecondFactor(&mallorys_code),
        );

        assert!(with_hers.is_ok());
        assert!(matches!(with_mallorys, Err(DomainError::Forbidden(_))));
    }

    /// A followed email link cannot establish fresh proof when the account
    /// has a password or passkey to prove instead.
    #[test]
    fn a_mailbox_does_not_prove_an_account_with_a_password() {
        let ann = active("ann@acme.test");

        let proof =
            FreshSignIn::by_mailbox(followed_link(&ann), BesideTheMailbox::PasswordOrPasskey);

        assert!(matches!(proof, Err(DomainError::Forbidden(_))));
    }

    /// A password proof cannot be presented as proof of a followed mailbox link.
    #[test]
    fn only_a_followed_link_proves_the_mailbox() {
        let ann = PrincipalId::from(UserId::new());

        let proof = FreshSignIn::by_mailbox(WayIn::by_password(ann), BesideTheMailbox::Nothing);

        assert!(matches!(proof, Err(DomainError::Forbidden(_))));
    }

    /// Ann signs in through her linked provider, which proved a second
    /// factor. The proof is for her account, without her own code.
    #[test]
    fn a_provider_sign_in_with_its_factor_proves_the_person() {
        let ann = PrincipalId::from(UserId::new());
        let sign_in = ProviderSignIn::new(
            FederatedMethod::Oidc,
            FactorProved::Proved(MfaFactor::ProviderMultiFactor),
        );

        let proof = FreshSignIn::through_provider(ann, sign_in, WithFactor::NoneOnFile).unwrap();

        assert_eq!(proof.account(), ann);
    }

    /// A provider sign-in with no proved factor cannot be completed by
    /// another account's code answer.
    #[test]
    fn a_provider_sign_in_without_a_factor_takes_the_accounts_own_code() {
        let ann = PrincipalId::from(UserId::new());
        let mallorys = answer_for(PrincipalId::from(UserId::new()));
        let sign_in = ProviderSignIn::new(FederatedMethod::Saml, FactorProved::NoneYet);

        let proof = FreshSignIn::through_provider(ann, sign_in, WithFactor::Code(&mallorys));

        assert!(matches!(proof, Err(DomainError::Forbidden(_))));
    }

    /// Ann types her password again and asks for a new address. The change
    /// starts, so the proof answers identity's rule for a recent proof.
    #[test]
    fn a_fresh_password_lets_an_address_change_start() {
        let mut ann: User<ResolvedTenant> = user(UserId::new(), "ann@example.com");
        ann.verify_email(&proof_of(ann.email())).unwrap();
        let proof = by("right", (*ann.id()).into()).unwrap();

        let change = PendingEmailChange::create(
            (&ann).into(),
            CreateEmailChangeParams {
                new_email: Email::new("ann@new.example").unwrap(),
                token_hash: TokenHash::from_stored("confirm".to_owned()),
                cancel_token_hash: TokenHash::from_stored("cancel".to_owned()),
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
            &proof,
        );

        assert!(change.is_ok());
    }
}
