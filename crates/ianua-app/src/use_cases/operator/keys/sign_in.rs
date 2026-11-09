//! Operator sign-in: an operator gives their address and password and gets
//! a short-lived key of their own, the way onto the operator plane for
//! their CLI and scripts. Nothing on the operator plane takes a password
//! directly; every later call carries the key.
//!
//! Wrong passwords count towards the lockout of the network they came from
//! on the operator's address, under the strict policy operators are held
//! to, and every refusal reads the same: an address no operator holds, a
//! wrong password, a disabled account and a locked-out network are told
//! apart only in the record. An address with no operator, and a disabled
//! account, take as long as a real check, so the time does not tell
//! either.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::events::login::LoginFailureReason;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::rate_limit::{
    LoginAttemptTracker, RateLimitPolicy,
};
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::domains::operator::api_key::OperatorApiKey;
use ianua_domain::domains::operator::control::OperatorSignIn;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::operator::sign_in::OperatorSignInAttempt;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Email, Expiry, Fact, IpAddress, Lifetime};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CountedAccount;
use crate::ports::operator::{OperatorKeyStore, OperatorStore};
use crate::ports::shared::ApiKeyGenerator;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::refused::invalid_credentials;
use crate::services::authentication::sign_in_counts::{CountedAt, SignInCounts};
use crate::use_case::Command;
use crate::use_cases::operator::keys::create::{OperatorKeyCreated, fresh_key};

/// The lockout operators are held to: the platform's most powerful
/// accounts take the strict policy, three failures in five minutes locking
/// the network out for an hour.
const OPERATOR_LOCKOUT: RateLimitPolicy = RateLimitPolicy::STRICT;

/// One operator sign-in. It holds the password, so it has no `Debug`.
pub struct OperatorSignInRequest {
    /// The address the operator signs in with.
    pub email: Email,
    /// The password they typed.
    pub password: Secret,
    /// Where the sign-in came from, or that it could not be told.
    pub ip_address: Fact<IpAddress>,
}

/// The ports [`OperatorSignInUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OperatorSignInPorts {
    /// Finds the operator the address names.
    pub operator_store: Arc<dyn OperatorStore>,
    /// Keeps the key the sign-in makes.
    pub key_store: Arc<dyn OperatorKeyStore>,
    /// Makes the raw key and its hash.
    pub key_generator: Arc<dyn ApiKeyGenerator>,
    /// The failed passwords counted per address and network, as sign-in
    /// keeps them.
    pub attempts: SignInCounts,
    /// Checks the password under the node's cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// What an operator may do once their password is proved.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// What the deployment sets for operator sign-in.
#[derive(Debug, Clone, Copy)]
pub struct OperatorSignInSettings {
    /// How long a key a sign-in makes works.
    pub key_lifetime: Lifetime,
}

/// Signs operators in with their password, handing each a short-lived key.
pub struct OperatorSignInUseCase {
    ports: OperatorSignInPorts,
    settings: OperatorSignInSettings,
}

/// What checking a sign-in came to: the operator and the proof of their
/// password, or why not.
type Checked = Result<(Operator, OperatorSignIn), LoginFailureReason>;

impl OperatorSignInUseCase {
    /// A use case signing in through `ports` under `settings`.
    #[must_use]
    pub fn new(ports: OperatorSignInPorts, settings: OperatorSignInSettings) -> Self {
        Self { ports, settings }
    }

    /// Checks `request` once the address's pace has been waited out, and
    /// counts what it did against the network it came from.
    async fn settled(&self, request: &OperatorSignInRequest) -> Result<Checked, AppError> {
        let at = counted_at(request);
        let attempts = &self.ports.attempts;
        let mut tracker = attempts.held(at, async { Familiarity::New }).await?;
        let checked = self.checked(request, &mut tracker).await;
        attempts.settled(at, &tracker).await?;
        checked
    }

    /// The operator `request` proves, or why it is refused. A locked-out
    /// network is refused before anything is hashed.
    async fn checked(
        &self,
        request: &OperatorSignInRequest,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<Checked, AppError> {
        if tracker.is_locked(clock::now()) {
            return Ok(Err(LoginFailureReason::AccountLocked));
        }
        let found = self
            .ports
            .operator_store
            .find_by_email(&request.email)
            .await
            .or_internal()?;
        let Some(operator) = found else {
            self.spend_a_password_check(request).await?;
            tracker.record_failure();
            return Ok(Err(LoginFailureReason::UserNotFound));
        };
        if !operator.is_active() {
            self.spend_a_password_check(request).await?;
            tracker.record_failure();
            return Ok(Err(LoginFailureReason::AccountDeactivated));
        }
        self.proved(request, operator, tracker).await
    }

    /// Whether the password proves `operator`, the hash running under a
    /// permit; a success clears the network's failures on the address.
    async fn proved(
        &self,
        request: &OperatorSignInRequest,
        operator: Operator,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<Checked, AppError> {
        let hasher = self.ports.hashing.permitted().await?;
        match operator.sign_in_with_password(request.password.expose(), &hasher) {
            Ok(sign_in) => {
                tracker.reset();
                Ok(Ok((operator, sign_in)))
            }
            Err(DomainError::Forbidden(_)) => {
                tracker.record_failure();
                Ok(Err(LoginFailureReason::BadPassword))
            }
            Err(other) => Err(AppError::from_domain(other)),
        }
    }

    /// Hashes the typed password and drops it, taking as long as checking
    /// it would, under a permit like a real check.
    async fn spend_a_password_check(
        &self,
        request: &OperatorSignInRequest,
    ) -> Result<(), AppError> {
        let hasher = self.ports.hashing.permitted().await?;
        let _ = hasher.hash(request.password.expose());
        Ok(())
    }

    /// A key for `operator`, acting on the strength of `sign_in`, working
    /// for the configured lifetime from now. Records its making as done by
    /// the operator.
    async fn key_for(
        &self,
        operator: &Operator,
        sign_in: &OperatorSignIn,
        auditor: &RequestAuditor,
    ) -> Result<OperatorKeyCreated, AppError> {
        let authority = self
            .ports
            .operator_authorities
            .signed_in(operator, sign_in)
            .await?;
        let expires_at = Expiry::At(self.settings.key_lifetime.ends_after(clock::now()));
        let (raw_key, new) = fresh_key(self.ports.key_generator.as_ref(), expires_at).await?;
        let mut key =
            OperatorApiKey::create(new, &authority, operator).map_err(AppError::from_domain)?;
        self.ports.key_store.save(&key).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), key.take_events())
            .await
            .or_internal()?;
        Ok(OperatorKeyCreated {
            raw_key,
            key_prefix: key.key_prefix().clone(),
        })
    }
}

impl Command for OperatorSignInUseCase {
    type Caller = ();
    type Input = OperatorSignInRequest;
    type Output = Result<OperatorKeyCreated, AppError>;

    /// Signs the operator `request` names in with their password and makes
    /// them a key working for the configured lifetime, recording
    /// `operator.operator_api_key_created`. A refusal records
    /// `operator.operator_sign_in_failed` instead, with why.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` for every refusal alike: an address no
    ///   operator holds, a wrong password, a disabled account, or a
    ///   network locked out of the address.
    /// - `AppError::Busy` when no password hash could start on this node in
    ///   time. Nothing is counted or recorded.
    /// - `AppError::Internal` on storage, count, key or audit failure.
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: OperatorSignInRequest,
    ) -> Result<OperatorKeyCreated, AppError> {
        let reason = match self.settled(&request).await? {
            Ok((operator, sign_in)) => return self.key_for(&operator, &sign_in, auditor).await,
            Err(reason) => reason,
        };
        let mut attempt = OperatorSignInAttempt::new(&request.email, request.ip_address);
        attempt.record_refusal(reason);
        auditor
            .dispatch_by(&ActorRef::System, attempt.take_events())
            .await
            .or_internal()?;
        Err(invalid_credentials())
    }
}

/// Where `request` is counted: the address on the operator plane, from the
/// network it came from, under the operators' lockout.
fn counted_at(request: &OperatorSignInRequest) -> CountedAt<'_> {
    CountedAt {
        account: CountedAccount::Operator {
            email: &request.email,
        },
        origin: AttemptOrigin::of(request.ip_address.as_ref()),
        policy: &OPERATOR_LOCKOUT,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::identity::OperatorRow;
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::OperatorId;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::FakeOperatorAuthorities;
    use crate::test_support::authentication::{
        CountingHasher, FakeSignInAttemptCounts, hashing_with,
    };
    use crate::test_support::oauth::FakeApiKeyGenerator;
    use crate::test_support::operator::{FakeOperatorKeyStore, FakeOperatorStore};
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor};

    /// Bob's operator password: a sentence, so no scanner takes it for a
    /// key.
    const PASSWORD: &str = "Operator lantern quarry 5521";

    /// A wrong guess at it.
    const GUESS: &str = "Not the operator password 1234";

    /// Bob's address.
    const BOB: &str = "bob@ianua.dev";

    /// How long the keys a sign-in makes work in these tests: twelve hours.
    const KEY_HOURS: i64 = 12;

    struct Setup {
        uc: OperatorSignInUseCase,
        keys: Arc<FakeOperatorKeyStore>,
        attempts: Arc<FakeSignInAttemptCounts>,
        hasher: Arc<CountingHasher>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(status: OperatorStatus) -> Self {
            let keys = Arc::new(FakeOperatorKeyStore::empty());
            let attempts = Arc::new(FakeSignInAttemptCounts::default());
            let hasher = Arc::new(CountingHasher::default());
            let bob = operator(status);
            Self {
                uc: OperatorSignInUseCase::new(
                    OperatorSignInPorts {
                        operator_store: Arc::new(FakeOperatorStore::holding([bob])),
                        key_store: keys.clone(),
                        key_generator: Arc::new(FakeApiKeyGenerator::new()),
                        attempts: SignInCounts::new(attempts.clone(), Fake::fake()),
                        hashing: hashing_with(hasher.clone()),
                        operator_authorities: Arc::new(FakeOperatorAuthorities::admitting()),
                    },
                    OperatorSignInSettings {
                        key_lifetime: Lifetime::new(Duration::hours(KEY_HOURS)).unwrap(),
                    },
                ),
                keys,
                attempts,
                hasher,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn active() -> Self {
            Self::holding(OperatorStatus::Active)
        }

        fn sign_in(&self, email: &str, password: &str) -> Result<OperatorKeyCreated, AppError> {
            let request = OperatorSignInRequest {
                email: Email::new(email).unwrap(),
                password: Secret::new(password.to_owned()),
                ip_address: Fact::Known(IpAddress::new("192.0.2.7").unwrap()),
            };
            block_on(
                self.uc
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn failures_on_bob(&self) -> u64 {
            let bob = Email::new(BOB).unwrap();
            self.attempts
                .on_account(CountedAccount::Operator { email: &bob })
        }
    }

    /// Bob, an operator whose password `FakeHasher` hashed.
    fn operator(status: OperatorStatus) -> Operator {
        Operator::reconstitute(OperatorRow {
            id: OperatorId::new(),
            email: Email::new(BOB).unwrap(),
            password_hash: FakeHasher.hash(PASSWORD).unwrap(),
            status,
            created_at: clock::now(),
        })
        .unwrap()
    }

    /// Bob signs in with his password: he gets an `opk_` key that works
    /// for twelve hours, it is stored, and its making is recorded.
    #[test]
    fn the_right_password_makes_a_key_that_ends() {
        let setup = Setup::active();

        let made = setup.sign_in(BOB, PASSWORD).unwrap();

        assert!(made.key_prefix.as_str().starts_with("opk_"));
        let stored = block_on(setup.keys.find_by_prefix(&made.key_prefix))
            .unwrap()
            .unwrap();
        let Expiry::At(ends) = stored.expires_at() else {
            panic!("a key a sign-in makes ends");
        };
        assert!(ends <= clock::now() + Duration::hours(KEY_HOURS));
        assert_eq!(setup.recorded(), vec!["operator.operator_api_key_created"]);
    }

    /// A wrong operator password answers not found, creates no key and
    /// increments the failure count while recording the refusal.
    #[test]
    fn a_wrong_password_is_refused_counted_and_recorded() {
        let setup = Setup::active();

        let result = setup.sign_in(BOB, GUESS);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.keys.count(), 0);
        assert_eq!(setup.failures_on_bob(), 1);
        assert_eq!(setup.recorded(), vec!["operator.operator_sign_in_failed"]);
    }

    /// An unknown operator address answers not found after one dummy hash
    /// and records a sign-in failure.
    #[test]
    fn an_unknown_address_answers_like_a_wrong_password() {
        let setup = Setup::active();

        let unknown = setup.sign_in("nobody@ianua.dev", GUESS);

        assert!(matches!(unknown, Err(AppError::NotFound(_))));
        assert_eq!(setup.hasher.hashed(), 1);
        assert_eq!(setup.recorded(), vec!["operator.operator_sign_in_failed"]);
    }

    /// A disabled operator's correct password answers not found after one
    /// dummy hash, and no key is stored.
    #[test]
    fn a_disabled_operator_is_refused_like_a_wrong_password() {
        let setup = Setup::holding(OperatorStatus::Disabled);

        let result = setup.sign_in(BOB, PASSWORD);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.hasher.hashed(), 1);
        assert_eq!(setup.keys.count(), 0);
    }

    /// After the network reaches its failed-password limit, even the
    /// correct operator password is refused and no key is stored.
    #[test]
    fn three_guesses_lock_the_network_out_before_the_right_password() {
        let setup = Setup::active();
        for _ in 0..OPERATOR_LOCKOUT.max_failed_attempts() {
            assert!(setup.sign_in(BOB, GUESS).is_err());
        }

        let after = setup.sign_in(BOB, PASSWORD);

        assert!(matches!(after, Err(AppError::NotFound(_))));
        assert_eq!(setup.keys.count(), 0);
    }

    /// Bob mistypes once, then signs in: the success clears the failure.
    #[test]
    fn a_success_clears_the_networks_failures() {
        let setup = Setup::active();
        assert!(setup.sign_in(BOB, GUESS).is_err());

        assert!(setup.sign_in(BOB, PASSWORD).is_ok());

        assert_eq!(setup.keys.count(), 1);
    }
}
