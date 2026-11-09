//! Signing a user in with an email address and a password.
//!
//! It runs in two steps. [`PasswordLogin::verify`] decides everything that
//! needs nothing from outside the domain. That is the attempt count, the
//! account's status, the password, the address list and a verified email.
//! Only then does the application look up the breach status, the location
//! and the device. [`VerifiedLogin::conclude`] weighs those into the risk,
//! the step-up, the second factor owed, the session and the events.

mod conclude;
mod verify;

use time::OffsetDateTime;

use crate::domains::authentication::credentials::breach::{BreachPolicy, BreachStatus};
use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::authentication::credentials::password_rules::PasswordDue;
use crate::domains::authentication::methods::MfaPolicy;
use crate::domains::authentication::mfa::owed::{Enrolment, SecondFactor};
use crate::domains::authentication::risk_engine::assessment::{IpGeolocation, LoginRiskAssessment};
use crate::domains::authentication::risk_engine::attack::AccountAttack;
use crate::domains::authentication::risk_engine::history::SignInHistory;
use crate::domains::authentication::risk_engine::step_up::{Familiarity, StepUpPolicy};
use crate::domains::authentication::sessions::session::Session;
use crate::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use crate::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use crate::domains::identity::account::address::{AddressStanding, MailReach};
use crate::domains::identity::account::user_status::UserStatus;
use crate::domains::identity::account::vouching::Vouching;
use crate::isolation::scope::ResolvedTenant;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::security::secret::Secret;
use crate::types::{Email, Fact, IpAddress, PasswordHash, TenantId, UserAgent, UserId};

/// What a password sign-in needs to know about the account it names.
pub struct LoginCandidate {
    /// The user's ID.
    pub user_id: UserId,
    /// The stored password hash.
    pub password_hash: PasswordHash,
    /// Current lifecycle status.
    pub status: UserStatus,
    /// Whether the user was shown to hold the address they signed in with.
    pub email_standing: AddressStanding,
    /// Whether the user has a second factor set up.
    pub enrolment: Enrolment,
    /// Whether an accepted invitation still vouches for this sign-in.
    pub vouching: Vouching,
    /// Whether the password must be changed before the sign-in goes on, as
    /// [`CurrentPassword::due`] works it out from the credential store.
    ///
    /// [`CurrentPassword::due`]: crate::domains::authentication::credentials::password_rules::CurrentPassword::due
    pub password_due: PasswordDue,
}

/// One password sign-in attempt, for one tenant and one email address.
pub struct PasswordLogin {
    tenant_id: TenantId,
    email: Email,
    ip_address: Fact<IpAddress>,
    user_agent: Fact<UserAgent>,
    at: OffsetDateTime,
}

/// What a successful password sign-in produces.
pub struct LoginResult {
    /// The new session, ready to store.
    pub session: Session<ResolvedTenant>,
    /// The raw refresh token. It is sent to the client and never stored.
    pub refresh_token: Secret,
    /// What the sign-in still owes in the way of a second factor.
    pub second_factor: SecondFactor,
    /// Whether the password must be replaced before the session is used for
    /// anything else, such as after an admin set it. The caller hands out
    /// nothing but a password change until it is.
    pub password_due: PasswordDue,
    /// The assessed risk level.
    pub risk_assessment: LoginRiskAssessment,
    /// Events the sign-in produced: a breach found and every check that could not
    /// run, each for the tenant that admitted it. The session records the
    /// sign-in itself once it is kept, see [`Session::record_sign_in`].
    pub events: Vec<DomainEvent>,
    /// When the sign-in completed.
    pub occurred_at: OffsetDateTime,
}

/// Why a password sign-in failed.
#[derive(Debug)]
pub enum LoginFailure {
    /// Too many recent failures from where the attempt came, so that origin
    /// is locked out of the account. The caller answers it as invalid
    /// credentials, so the lockout tells a guesser nothing.
    AccountLocked {
        /// When the lockout ends.
        until: OffsetDateTime,
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// Wrong password or unknown email.
    InvalidCredentials {
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// The password was right, but the account never finished joining. It
    /// is still invited or waiting on its address.
    AccountNotActive {
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// The user's email address is not verified.
    EmailNotVerified {
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// The risk was too high, so the sign-in was refused.
    RiskDenied {
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// The sign-in looked risky and the person has nothing to answer it
    /// with: no second factor, no mail that could reach them, and no
    /// invitation vouching for them. An administrator sends a new
    /// invitation, whose acceptance vouches for the next sign-in.
    NothingToProveWith {
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// A password can never meet the tenant's baseline, so it is not a way
    /// in there.
    MethodNotAdmitted {
        /// Events the attempt produced.
        events: Vec<DomainEvent>,
    },
    /// The credentials were good but the session could not be made, such as
    /// when no refresh token could be generated. It is a fault on our side,
    /// never reported to the person as a wrong password.
    Unavailable(DomainError),
}

/// The rules and ports a password sign-in's first step runs with: the rules
/// both steps share, and the hasher that checks the password.
///
/// The hasher is kept apart from the rules so the application can hold it,
/// and whatever limits how many hashes run at once, only for the first
/// step. The second step never hashes.
pub struct LoginConfig<'a, H: PasswordHasher, R: RefreshTokenGenerator> {
    /// The rules both steps run under.
    pub rules: LoginRules<'a, R>,
    /// Checks the typed password against the stored hash.
    pub hasher: &'a H,
}

/// The rules a password sign-in runs under, and the port that makes its
/// session's token.
pub struct LoginRules<'a, R: RefreshTokenGenerator> {
    /// How long the new session may last and sit idle.
    pub timeout_policy: &'a SessionTimeoutPolicy,
    /// Makes the new session's refresh token.
    pub token_generator: &'a R,
    /// Whether the tenant has second factors off, optional or required.
    pub mfa_policy: MfaPolicy,
    /// When the sign-in must ask for a second factor or be refused.
    pub step_up_policy: &'a StepUpPolicy,
    /// What the sign-in does about a breached password.
    pub breach_policy: BreachPolicy,
    /// Whether a confirmation link mailed now would reach the person. On a
    /// deployment with no mail server, a sign-in that would wait for one
    /// owes a second factor instead, or is refused when the person has
    /// none.
    pub mail: MailReach,
}

/// What the application learned about a sign-in whose password was proven,
/// from services and records outside the domain.
pub struct SecurityContext<'a> {
    /// Whether the password appears in known breaches. `Unknown` when the
    /// deployment does not check.
    pub breach: Lookup<BreachStatus>,
    /// Where the request came from. `Unknown` when it has no address or the
    /// address cannot be placed.
    pub location: Lookup<IpGeolocation>,
    /// Whether the device is one the user trusted.
    pub device: Familiarity,
    /// Where the user has signed in from before.
    pub history: &'a SignInHistory,
    /// Whether the account is under attack from many networks, so a device
    /// the user did not trust must prove more than the password.
    pub attack: AccountAttack,
}

/// The answer to a question the application asked outside the domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// The service answered.
    Known(T),
    /// There was nothing to find out, or the answer is "nothing".
    Unknown,
    /// The service could not be reached, so the question went unanswered.
    Unavailable,
}

impl<T> Lookup<T> {
    /// The answer, if there was one.
    #[must_use]
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(answer) => Some(answer),
            Self::Unknown | Self::Unavailable => None,
        }
    }

    /// The answer as a [`Fact`]. It is unknown both when there was nothing
    /// to find and when nobody could be asked.
    #[must_use]
    pub fn fact(&self) -> Fact<&T> {
        match self {
            Self::Known(answer) => Fact::Known(answer),
            Self::Unknown | Self::Unavailable => Fact::Unknown,
        }
    }

    /// Whether the question went unanswered because of an outage.
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// Whether the typed password is the account's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordProof {
    Matched,
    Mismatched,
}

/// A sign-in whose attempt count, account, password and address passed.
///
/// It waits on what the application learns about it from outside the domain.
pub struct VerifiedLogin<'a> {
    login: &'a PasswordLogin,
    candidate: &'a LoginCandidate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::admission::SignInAdmitted;
    use crate::domains::authentication::credentials::password_rules::ChangeReason;
    use crate::domains::authentication::events::login::LockedAddress;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::risk_engine::assessment::{RiskAction, RiskLevel};
    use crate::domains::authentication::risk_engine::origin::AttemptOrigin;
    use crate::domains::authentication::risk_engine::rate_limit::{
        AttemptOutcome, AttemptTally, Lockout, LoginAttemptTracker, RateLimitPolicy,
    };
    use crate::domains::authentication::risk_engine::step_up::{
        MfaTrigger, StepUpPolicy, StepUpPolicyParams,
    };
    use crate::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
    use crate::test_support::fakes::{FakeHasher, FakeRefreshTokenGenerator};
    use crate::types::{CountryCode, TokenHash};

    fn email() -> Email {
        Email::new("alice@acme.com").unwrap()
    }

    fn admitted(method: AuthMethod) -> SignInAdmitted {
        SignInAdmitted::new(method, Fact::Known(&IpAddress::new("10.0.0.1").unwrap()))
    }

    fn login() -> PasswordLogin {
        PasswordLogin::new(
            TenantId::new(),
            email(),
            admitted(AuthMethod::Password),
            Fact::Unknown,
        )
        .unwrap()
    }

    fn candidate(hasher: &FakeHasher, password: &str) -> LoginCandidate {
        LoginCandidate {
            user_id: UserId::new(),
            password_hash: hasher.hash(password).unwrap(),
            status: UserStatus::Active,
            email_standing: AddressStanding::Verified,
            enrolment: Enrolment::NotEnrolled,
            vouching: Vouching::Absent,
            password_due: PasswordDue::Current,
        }
    }

    /// Signing in with an administrator-set password returns a required password change.
    #[test]
    fn a_sign_in_with_an_admin_set_password_says_it_must_change() {
        let tc = TestConfig::standard();
        let set_by_sam = LoginCandidate {
            password_due: PasswordDue::ChangeRequired(ChangeReason::SetByAdmin),
            ..candidate(&tc.hasher, "correct")
        };
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &set_by_sam,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        )
        .unwrap();

        assert_eq!(
            result.password_due,
            PasswordDue::ChangeRequired(ChangeReason::SetByAdmin)
        );
    }

    struct TestConfig {
        timeout_policy: SessionTimeoutPolicy,
        hasher: FakeHasher,
        token_generator: FakeRefreshTokenGenerator,
        step_up_policy: StepUpPolicy,
        breach_policy: BreachPolicy,
        mfa_policy: MfaPolicy,
        mail: MailReach,
    }

    impl TestConfig {
        fn standard() -> Self {
            Self {
                timeout_policy: SessionTimeoutPolicy::STANDARD,
                hasher: FakeHasher,
                token_generator: FakeRefreshTokenGenerator::new(),
                step_up_policy: StepUpPolicy::relaxed(),
                breach_policy: BreachPolicy::Off,
                mfa_policy: MfaPolicy::Optional,
                mail: MailReach::Available,
            }
        }

        fn as_login_config(&self) -> LoginConfig<'_, FakeHasher, FakeRefreshTokenGenerator> {
            self.hashing_with(&self.hasher)
        }

        fn hashing_with<'a, H: PasswordHasher>(
            &'a self,
            hasher: &'a H,
        ) -> LoginConfig<'a, H, FakeRefreshTokenGenerator> {
            LoginConfig {
                rules: self.rules_with(&self.token_generator),
                hasher,
            }
        }

        fn rules_with<'a, R: RefreshTokenGenerator>(
            &'a self,
            token_generator: &'a R,
        ) -> LoginRules<'a, R> {
            LoginRules {
                timeout_policy: &self.timeout_policy,
                token_generator,
                mfa_policy: self.mfa_policy,
                step_up_policy: &self.step_up_policy,
                breach_policy: self.breach_policy,
                mail: self.mail,
            }
        }
    }

    fn security_ctx() -> SecurityContext<'static> {
        security_ctx_with_breach_status(BreachStatus::Clean)
    }

    fn london() -> IpGeolocation {
        IpGeolocation::new(
            51.51,
            -0.13,
            CountryCode::new("GB").unwrap(),
            Some("London".to_owned()),
        )
        .unwrap()
    }

    /// A sign-in placed in London, with a previous one `hours_ago` from the
    /// given coordinates.
    ///
    /// Leaks the history for `'static`, as the other helpers here do.
    fn security_ctx_travelling_from(
        previous: (f64, f64, &str),
        hours_ago: i64,
    ) -> SecurityContext<'static> {
        let (lat, lon, country) = previous;
        let when = crate::shared::clock::now() - time::Duration::hours(hours_ago);
        let history: &'static SignInHistory = Box::leak(Box::new(SignInHistory::new(
            vec![CountryCode::new(country).unwrap()],
            Fact::Known((
                IpGeolocation::new(lat, lon, CountryCode::new(country).unwrap(), None).unwrap(),
                when,
            )),
        )));
        SecurityContext {
            breach: Lookup::Known(BreachStatus::Clean),
            location: Lookup::Known(london()),
            device: Familiarity::Known,
            history,
            attack: AccountAttack::Quiet,
        }
    }

    fn security_ctx_with_breach_status(breach: BreachStatus) -> SecurityContext<'static> {
        SecurityContext {
            breach: Lookup::Known(breach),
            location: Lookup::Unknown,
            device: Familiarity::Known,
            history: Box::leak(Box::new(SignInHistory::default())),
            attack: AccountAttack::Quiet,
        }
    }

    /// Both steps of a sign-in, as the application runs them.
    fn sign_in(
        password: &str,
        candidate: &LoginCandidate,
        tracker: &mut LoginAttemptTracker,
        config: &LoginConfig<'_, FakeHasher, impl RefreshTokenGenerator>,
        security: &SecurityContext<'_>,
    ) -> Result<LoginResult, LoginFailure> {
        login()
            .verify(password, candidate, tracker, config)?
            .conclude(tracker, &config.rules, security)
    }

    /// Alice signs in with the right password and no factor is owed. She
    /// gets a session, a refresh token stored only as a hash, and a
    /// `login_succeeded` event carrying the measured 42 ms.
    #[test]
    fn successful_login_returns_session() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        let output = result.unwrap();
        assert_eq!(output.second_factor, SecondFactor::NotOwed);
        assert!(!output.refresh_token.is_empty());
        assert_eq!(output.session.refresh_token_hash().as_str(), "fake_hash_0");

        let mut session = output.session;
        session.record_sign_in(Fact::Known(42));
        let events = crate::test_support::events::raised(&mut session);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.login_succeeded"
        );
        assert_eq!(events[0].payload().get("auth_duration_ms"), Some("42"));
    }

    struct BrokenTokenGenerator;

    impl RefreshTokenGenerator for BrokenTokenGenerator {
        fn generate(
            &self,
        ) -> Result<crate::domains::authentication::tokens::refresh::RefreshToken, DomainError>
        {
            Err(DomainError::infra_msg("no randomness available"))
        }

        fn hash_raw(&self, raw: &str) -> TokenHash {
            TokenHash::from_stored(raw.to_owned())
        }
    }

    /// Alice types the right password but no refresh token can be made. The
    /// sign-in fails as unavailable, not as wrong credentials, so she is not
    /// sent to reset a password that works.
    #[test]
    fn a_session_that_cannot_be_made_is_not_reported_as_wrong_credentials() {
        let tc = TestConfig::standard();
        let config = LoginConfig {
            rules: tc.rules_with(&BrokenTokenGenerator),
            hasher: &tc.hasher,
        };
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in("correct", &cand, &mut tracker, &config, &security_ctx());

        assert!(matches!(result, Err(LoginFailure::Unavailable(_))));
    }

    /// A hasher that cannot check any password, as during an outage.
    struct BrokenHasher;

    impl PasswordHasher for BrokenHasher {
        fn hash(&self, _raw: &str) -> Result<PasswordHash, DomainError> {
            Err(DomainError::infra_msg("the hasher is down"))
        }

        fn verify(&self, _raw: &str, _hash: &PasswordHash) -> Result<bool, DomainError> {
            Err(DomainError::infra_msg("the hasher is down"))
        }
    }

    /// The hasher is down while Alice signs in. She is told the sign-in is
    /// unavailable, not that her password is wrong, and the attempt does not
    /// count towards locking her out.
    #[test]
    fn a_password_that_could_not_be_checked_is_not_counted_as_wrong() {
        let tc = TestConfig::standard();
        let config = tc.hashing_with(&BrokenHasher);
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let attempt = login();

        let result = attempt.verify("correct", &cand, &mut tracker, &config);

        assert!(matches!(result, Err(LoginFailure::Unavailable(_))));
        assert_eq!(tracker.tally(), AttemptTally::Untouched);
    }

    /// A failed password hasher returns unavailable for both active and locked accounts.
    #[test]
    fn every_account_reads_as_unavailable_while_the_hasher_is_down() {
        let tc = TestConfig::standard();
        let config = tc.hashing_with(&BrokenHasher);
        let attempt = login();
        let unavailable = |account: &LoginCandidate| {
            let mut tracker = LoginAttemptTracker::new();
            let result = attempt.verify("correct", account, &mut tracker, &config);
            matches!(result, Err(LoginFailure::Unavailable(_)))
        };
        let active = candidate(&tc.hasher, "correct");
        let locked = LoginCandidate {
            status: UserStatus::Locked,
            ..candidate(&tc.hasher, "correct")
        };

        assert!(unavailable(&active));
        assert!(unavailable(&locked));
    }

    //
    // `TravelVelocity` has its own tests for the arithmetic. What these pin is
    // the wiring: that a computed impossible travel actually stops the login,
    // rather than being computed and then ignored. Tokyo to London is about
    // 9,560km, so the hours between the two logins set the implied speed.

    fn tokyo() -> (f64, f64, &'static str) {
        (35.68, 139.65, "JP")
    }

    /// A London sign-in one hour after Tokyo is refused for impossible-travel risk.
    #[test]
    fn impossible_travel_denies_the_login() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 1),
        );

        assert!(matches!(result, Err(LoginFailure::RiskDenied { .. })));
    }

    /// Alice signs in from London 20 hours after Tokyo. That is fast but
    /// possible, so the sign-in goes ahead, rated high risk with a second
    /// factor asked.
    #[test]
    fn suspicious_travel_is_allowed_but_recorded_as_high_risk() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 20),
        );

        let output = result.unwrap();
        assert_eq!(output.risk_assessment.risk_level(), RiskLevel::High);
        assert_eq!(output.risk_assessment.action(), RiskAction::StepUpMfa);
        assert!(
            output
                .events
                .iter()
                .any(|event| event.event_type().as_str() == "authentication.risky_sign_in"),
            "the risky sign-in is recorded"
        );
    }

    /// A tenant demands AAL3 for every sign-in. Alice's right password is
    /// refused as a method that cannot get there, instead of being topped up
    /// with a TOTP code that would not reach it either.
    #[test]
    fn a_password_sign_in_that_needs_a_hardware_key_is_refused() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal3,
            sensitive_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal3,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .unwrap();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert!(matches!(
            result,
            Err(LoginFailure::MethodNotAdmitted { .. })
        ));
    }

    /// A tenant refuses sign-ins from risk level High. Alice's London sign-in
    /// 20 hours after Tokyo rates High, so it is refused.
    #[test]
    fn a_tenant_refusing_high_risk_refuses_a_suspicious_jump() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal1,
            sensitive_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal2,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::High,
        })
        .unwrap();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 20),
        );

        assert!(matches!(result, Err(LoginFailure::RiskDenied { .. })));
    }

    /// A tenant asks for a second factor from a new country. Alice has signed
    /// in from Japan before and now signs in from Britain, so a factor is
    /// owed.
    #[test]
    fn a_new_country_asks_for_the_second_factor() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal1,
            sensitive_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal2,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Asks,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .unwrap();
        let mut cand = candidate(&tc.hasher, "correct");
        cand.enrolment = Enrolment::Enrolled;
        let mut tracker = LoginAttemptTracker::new();

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 100),
        )
        .unwrap();

        assert_eq!(output.second_factor, SecondFactor::Verify);
    }

    /// A tenant has second factors off but asks for a check from a new
    /// country. Sam signs in from Britain after Japan. He confirms through
    /// his verified address, instead of being locked out or let in on the
    /// password alone.
    #[test]
    fn a_new_country_is_confirmed_by_email_while_second_factors_are_off() {
        let mut tc = TestConfig::standard();
        tc.mfa_policy = MfaPolicy::Disabled;
        tc.step_up_policy = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal1,
            sensitive_aal:
                crate::domains::authentication::risk_engine::assurance::AssuranceLevel::Aal2,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Asks,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .unwrap();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 100),
        )
        .unwrap();

        assert_eq!(output.second_factor, SecondFactor::ConfirmByEmail);
    }

    /// Alice signs in from London 100 hours after Tokyo. That is an ordinary
    /// trip, so the risk is low and the sign-in is allowed.
    #[test]
    fn unhurried_travel_is_low_risk() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 100),
        );

        let output = result.unwrap();
        assert_eq!(output.risk_assessment.risk_level(), RiskLevel::Low);
        assert_eq!(output.risk_assessment.action(), RiskAction::Allow);
    }

    /// Alice signs in for the first time, with no history and no location.
    /// With nothing to compare, the risk is low.
    #[test]
    fn a_first_login_has_nothing_to_compare_and_is_low_risk() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert_eq!(result.unwrap().risk_assessment.risk_level(), RiskLevel::Low);
    }

    /// Berlin, where Pat signed in before.
    fn berlin() -> (f64, f64, &'static str) {
        (52.52, 13.40, "DE")
    }

    /// What made the sign-in in `output` look risky, as its
    /// `authentication.risky_sign_in` names it; none when it recorded none.
    fn risk_sign(output: &LoginResult) -> Option<String> {
        output
            .events
            .iter()
            .find(|event| event.event_type().as_str() == "authentication.risky_sign_in")
            .and_then(|event| event.payload().get("sign").map(str::to_owned))
    }

    /// Pat's very first sign-in ever is placed in London. With no country
    /// to compare it with, it is no new country and records nothing risky.
    #[test]
    fn a_first_sign_in_ever_records_no_risky_sign_in() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let security = SecurityContext {
            location: Lookup::Known(london()),
            ..security_ctx()
        };

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security,
        )
        .unwrap();

        assert_eq!(risk_sign(&output), None);
    }

    /// Pat signed in from Berlin and, two days later, signs in from London,
    /// a country he never signed in from. The trip is unhurried, so the
    /// risk stays low and nothing more is asked, but the sign-in is
    /// recorded as risky for its new country.
    #[test]
    fn a_new_country_two_days_later_records_a_risky_sign_in() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(berlin(), 48),
        )
        .unwrap();

        assert_eq!(output.risk_assessment.risk_level(), RiskLevel::Low);
        assert_eq!(output.second_factor, SecondFactor::NotOwed);
        assert_eq!(risk_sign(&output).as_deref(), Some("new_country"));
    }

    /// Pat signed in from London two days ago and signs in from London
    /// again: a country he knows, so nothing risky is recorded.
    #[test]
    fn a_known_country_again_records_no_risky_sign_in() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from((51.51, -0.13, "GB"), 48),
        )
        .unwrap();

        assert_eq!(risk_sign(&output), None);
    }

    /// Alice signs in from London 20 hours after Tokyo: fast, and into a
    /// country she never signed in from, so the record names both.
    #[test]
    fn a_fast_journey_into_a_new_country_names_both_signs() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_travelling_from(tokyo(), 20),
        )
        .unwrap();

        assert_eq!(
            risk_sign(&output).as_deref(),
            Some("fast_travel_to_new_country")
        );
    }

    /// An attempt admitted for a passkey cannot start a password login.
    #[test]
    fn a_login_admitted_for_another_way_in_is_refused() {
        let login = PasswordLogin::new(
            TenantId::new(),
            email(),
            admitted(AuthMethod::Passkey),
            Fact::Unknown,
        );

        assert!(matches!(login, Err(DomainError::Forbidden(_))));
    }

    //
    // Each disjunct in the MFA decision is asked for on its own, so that a
    // test only passes because the signal it names actually reached the
    // verdict.

    /// A tenant requires MFA and Alice has a factor. With no other signal,
    /// she must still verify it.
    #[test]
    fn a_tenant_requiring_mfa_demands_it_of_an_enrolled_user() {
        let mut tc = TestConfig::standard();
        tc.mfa_policy = MfaPolicy::Required;
        let mut cand = candidate(&tc.hasher, "correct");
        cand.enrolment = Enrolment::Enrolled;
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::Verify);
    }

    /// A tenant requires MFA and Bob has no factor. He must set one up, and
    /// his session is not complete until he does.
    #[test]
    fn a_tenant_requiring_mfa_makes_a_user_without_one_set_it_up() {
        let mut tc = TestConfig::standard();
        tc.mfa_policy = MfaPolicy::Required;
        let mut cand = candidate(&tc.hasher, "correct");
        cand.enrolment = Enrolment::NotEnrolled;
        let mut tracker = LoginAttemptTracker::new();

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        )
        .unwrap();

        assert_eq!(output.second_factor, SecondFactor::Enrol);
        assert!(!output.session.mfa_satisfied());
    }

    /// Under a relaxed policy with optional MFA, Alice has a factor and
    /// nothing asks for one. She is let in with no factor owed.
    #[test]
    fn an_enrolled_user_is_left_alone_when_nothing_asks_for_mfa() {
        let tc = TestConfig::standard();
        let mut cand = candidate(&tc.hasher, "correct");
        cand.enrolment = Enrolment::Enrolled;
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::NotOwed);
    }

    /// An account under attack requires email confirmation on a new device
    /// even when its policy otherwise asks nothing of new devices.
    #[test]
    fn under_attack_a_new_device_proves_more_than_the_password() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let botnet = SecurityContext {
            device: Familiarity::New,
            attack: AccountAttack::Ongoing,
            ..security_ctx()
        };

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &botnet,
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::ConfirmByEmail);
    }

    /// Alice signs in on her trusted laptop while her account is under
    /// attack. She is asked for nothing more.
    #[test]
    fn under_attack_a_trusted_device_goes_straight_in() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let laptop = SecurityContext {
            device: Familiarity::Known,
            attack: AccountAttack::Ongoing,
            ..security_ctx()
        };

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &laptop,
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::NotOwed);
    }

    /// A new-device sign-in without an enrolled factor requires email confirmation.
    #[test]
    fn a_new_device_without_a_factor_is_confirmed_by_email() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::untrusted_devices();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let new_device = SecurityContext {
            device: Familiarity::New,
            ..security_ctx()
        };

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &new_device,
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::ConfirmByEmail);
    }

    /// A new-device sign-in with neither mail nor an enrolled factor is
    /// refused because no further proof is available, and records an event.
    #[test]
    fn a_new_device_without_a_factor_or_mail_is_refused() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::untrusted_devices();
        tc.mail = MailReach::NotSetUp;
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let new_device = SecurityContext {
            device: Familiarity::New,
            ..security_ctx()
        };

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &new_device,
        );

        assert!(matches!(
            result,
            Err(LoginFailure::NothingToProveWith { events }) if !events.is_empty()
        ));
    }

    /// Alice accepted an invitation an admin handed her, on a deployment
    /// with no mail server. Her first sign-in, from a new device, goes on
    /// owing a factor she sets up there and then: the invitation already
    /// proved her.
    #[test]
    fn the_first_sign_in_an_invitation_vouches_for_sets_up_a_factor() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::untrusted_devices();
        tc.mail = MailReach::NotSetUp;
        let cand = LoginCandidate {
            vouching: Vouching::Fresh,
            ..candidate(&tc.hasher, "correct")
        };
        let mut tracker = LoginAttemptTracker::new();
        let new_device = SecurityContext {
            device: Familiarity::New,
            ..security_ctx()
        };

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &new_device,
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::Enrol);
    }

    /// Ann's address was never confirmed and the deployment can mail a
    /// link. Her right password is refused until she confirms it.
    #[test]
    fn an_unverified_address_is_refused_where_a_link_can_confirm_it() {
        let tc = TestConfig::standard();
        let ann = LoginCandidate {
            email_standing: AddressStanding::Unverified,
            ..candidate(&tc.hasher, "correct")
        };
        let mut tracker = LoginAttemptTracker::new();
        let attempt = login();

        let result = attempt.verify("correct", &ann, &mut tracker, &tc.as_login_config());

        assert!(matches!(result, Err(LoginFailure::EmailNotVerified { .. })));
    }

    /// Ann's address was typed in by an admin on a deployment with no mail
    /// server, so no link could ever confirm it. Her right password lets
    /// her in.
    #[test]
    fn an_unverified_address_signs_in_where_nothing_is_mailed() {
        let mut tc = TestConfig::standard();
        tc.mail = MailReach::NotSetUp;
        let ann = LoginCandidate {
            email_standing: AddressStanding::Unverified,
            ..candidate(&tc.hasher, "correct")
        };
        let mut tracker = LoginAttemptTracker::new();
        let attempt = login();

        let result = attempt.verify("correct", &ann, &mut tracker, &tc.as_login_config());

        assert!(result.is_ok());
    }

    /// Ann registered and still waits to confirm her address, on a
    /// deployment that can mail her the link. Her right password is told to
    /// confirm it first.
    #[test]
    fn a_waiting_account_is_refused_where_a_link_can_confirm_it() {
        let tc = TestConfig::standard();
        let ann = LoginCandidate {
            status: UserStatus::PendingVerification,
            email_standing: AddressStanding::Unverified,
            ..candidate(&tc.hasher, "correct")
        };
        let mut tracker = LoginAttemptTracker::new();
        let attempt = login();

        let result = attempt.verify("correct", &ann, &mut tracker, &tc.as_login_config());

        assert!(matches!(result, Err(LoginFailure::EmailNotVerified { .. })));
    }

    /// An account awaiting verification remains inactive when the deployment has no mail service.
    #[test]
    fn a_waiting_account_is_refused_where_nothing_is_mailed() {
        let mut tc = TestConfig::standard();
        tc.mail = MailReach::NotSetUp;
        let ann = LoginCandidate {
            status: UserStatus::PendingVerification,
            email_standing: AddressStanding::Unverified,
            ..candidate(&tc.hasher, "correct")
        };
        let mut tracker = LoginAttemptTracker::new();
        let attempt = login();

        let result = attempt.verify("correct", &ann, &mut tracker, &tc.as_login_config());

        assert!(matches!(result, Err(LoginFailure::AccountNotActive { .. })));
    }

    /// A strict policy requires email confirmation followed by factor
    /// enrollment when a new-device sign-in has no enrolled factor.
    #[test]
    fn a_signal_under_a_strict_baseline_is_confirmed_by_email_then_enrolled() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::strict();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let new_device = SecurityContext {
            device: Familiarity::New,
            ..security_ctx()
        };

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &new_device,
        );

        assert_eq!(
            result.unwrap().second_factor,
            SecondFactor::ConfirmThenEnrol
        );
    }

    /// A strict step-up policy needs a second factor at every sign-in. Bob
    /// has none and nothing else asks, yet he must still set one up.
    #[test]
    fn a_step_up_policy_asking_for_mfa_is_enough_on_its_own() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::strict();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert_eq!(result.unwrap().second_factor, SecondFactor::Enrol);
    }

    /// A tenant's baseline needs a second factor but second factors are off.
    /// A password can never get there, so Alice's sign-in is refused instead
    /// of opening a session below the baseline.
    #[test]
    fn a_password_below_a_baseline_it_can_never_reach_is_refused() {
        let mut tc = TestConfig::standard();
        tc.step_up_policy = StepUpPolicy::strict();
        tc.mfa_policy = MfaPolicy::Disabled;
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert!(matches!(
            result,
            Err(LoginFailure::MethodNotAdmitted { .. })
        ));
    }

    /// A breached password without an enrolled factor requires email
    /// confirmation and does not mark the session as MFA-verified.
    #[test]
    fn a_breached_password_without_a_factor_asks_for_email_confirmation() {
        let mut tc = TestConfig::standard();
        tc.breach_policy = BreachPolicy::StepUp;
        let mut cand = candidate(&tc.hasher, "correct");
        cand.enrolment = Enrolment::NotEnrolled;
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_with_breach_status(BreachStatus::Breached(3)),
        );

        let output = result.unwrap();
        assert_eq!(output.second_factor, SecondFactor::ConfirmByEmail);
        assert!(!output.session.mfa_satisfied());
    }

    /// Alice signs in with a password found in 3 breaches. She has a factor,
    /// so she must verify it before the session is complete.
    #[test]
    fn breached_password_forces_mfa_when_user_has_mfa_enrolled() {
        let mut tc = TestConfig::standard();
        tc.breach_policy = BreachPolicy::StepUp;
        let mut cand = candidate(&tc.hasher, "correct");
        cand.enrolment = Enrolment::Enrolled;
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx_with_breach_status(BreachStatus::Breached(3)),
        );

        let output = result.unwrap();
        assert_eq!(output.second_factor, SecondFactor::Verify);
        assert!(!output.session.mfa_satisfied());
    }

    /// The breach service and the geolocator are both down. Alice still gets
    /// in, and two events record that the breach and location checks did not
    /// run.
    #[test]
    fn a_check_that_could_not_run_lets_the_sign_in_through_and_is_recorded() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let outage = SecurityContext {
            breach: Lookup::Unavailable,
            location: Lookup::Unavailable,
            device: Familiarity::Known,
            history: &SignInHistory::default(),
            attack: AccountAttack::Quiet,
        };

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &outage,
        )
        .unwrap();

        let unavailable: Vec<_> = output
            .events
            .iter()
            .filter(|e| e.event_type().as_str() == "authentication.sign_in_check_unavailable")
            .map(|e| e.payload().get("check").map(str::to_owned))
            .collect();
        assert_eq!(
            unavailable,
            vec![Some("breach".to_owned()), Some("location".to_owned())]
        );
    }

    /// The deployment does not check breaches and the address cannot be
    /// placed. That is not an outage, so no event is recorded.
    #[test]
    fn a_check_with_nothing_to_find_records_nothing() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();
        let quiet = SecurityContext {
            breach: Lookup::Unknown,
            location: Lookup::Unknown,
            device: Familiarity::Known,
            history: &SignInHistory::default(),
            attack: AccountAttack::Quiet,
        };

        let output = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &quiet,
        )
        .unwrap();

        assert!(output.events.is_empty());
    }

    /// Alice types the wrong password. The sign-in fails as invalid
    /// credentials and the attempt counts toward a lockout.
    #[test]
    fn wrong_password_returns_invalid_credentials() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "wrong",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert!(matches!(
            result,
            Err(LoginFailure::InvalidCredentials { .. })
        ));
        assert_eq!(tracker.tally(), AttemptTally::Failed);
    }

    /// Alice types her password right. The attempt clears her network's
    /// count of failures.
    #[test]
    fn a_right_password_clears_the_origins_count() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert!(result.is_ok());
        assert_eq!(tracker.tally(), AttemptTally::Cleared);
    }

    /// Someone signs in with an address that has no account. It fails the
    /// same way as a wrong password and still counts toward a lockout, so the
    /// answer does not reveal which addresses exist.
    #[test]
    fn no_such_user_returns_invalid_credentials() {
        let l = login();
        let mut tracker = LoginAttemptTracker::new();

        let failure = l.no_such_user(&mut tracker);

        assert!(matches!(failure, LoginFailure::InvalidCredentials { .. }));
        assert_eq!(tracker.tally(), AttemptTally::Failed);
    }

    /// An unknown account at a locked origin returns the lockout result without changing the tally.
    #[test]
    fn no_such_user_reads_as_locked_once_its_origin_is() {
        let l = login();
        let until = crate::shared::clock::now() + time::Duration::minutes(10);
        let mut tracker = LoginAttemptTracker::standing(Lockout::Until(until));

        let failure = l.no_such_user(&mut tracker);

        assert!(matches!(failure, LoginFailure::AccountLocked { .. }));
        assert_eq!(tracker.tally(), AttemptTally::Untouched);
    }

    /// Mallory's third wrong password from her network reaches the strict
    /// limit. The lockout's record names the network locked out and the
    /// address it came from, and how many failures it took.
    #[test]
    fn a_lockout_record_names_the_origin_locked_out() {
        let reached = RateLimitPolicy::STRICT.after_failures(3, crate::shared::clock::now());
        let AttemptOutcome::LockedOut(locked) = reached else {
            panic!("the third failure reaches the strict limit");
        };

        let event = login().locked_out(locked, LockedAddress::Account(UserId::new()));

        let payload = event.payload();
        let origin = AttemptOrigin::of(Fact::Known(&IpAddress::new("10.0.0.1").unwrap()));
        assert_eq!(
            event.event_type().as_str(),
            "authentication.account_locked_out"
        );
        assert_eq!(payload.get("origin"), Some(origin.to_string().as_str()));
        assert_eq!(payload.get("ip_address"), Some("10.0.0.1"));
        assert_eq!(payload.get("failed_attempts"), Some("3"));
    }

    /// Alice's account was deactivated. Her right password fails as invalid
    /// credentials, not as a distinct "deactivated" answer.
    #[test]
    fn deactivated_account_rejected() {
        let tc = TestConfig::standard();
        let mut cand = candidate(&tc.hasher, "correct");
        cand.status = UserStatus::Deactivated;
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert!(matches!(
            result,
            Err(LoginFailure::InvalidCredentials { .. })
        ));
    }

    /// Bob was invited but never finished joining. His right password and
    /// verified address still fail as an account that is not active.
    #[test]
    fn an_account_that_never_joined_is_refused() {
        let tc = TestConfig::standard();
        let mut cand = candidate(&tc.hasher, "correct");
        cand.status = UserStatus::Invited;
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        assert!(matches!(result, Err(LoginFailure::AccountNotActive { .. })));
    }

    /// A locked origin refuses even the correct password, records one login
    /// failure, and leaves the tally unchanged.
    #[test]
    fn locked_tracker_rejects_and_records_the_attempt() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let until = crate::shared::clock::now() + time::Duration::minutes(10);
        let mut tracker = LoginAttemptTracker::standing(Lockout::Until(until));

        let result = sign_in(
            "correct",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        let Err(LoginFailure::AccountLocked { events, .. }) = result else {
            panic!("expected AccountLocked");
        };
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.login_failed"
        );
        assert_eq!(tracker.tally(), AttemptTally::Untouched);
    }

    /// Alice types the wrong password. Exactly one `login_failed` event is
    /// produced.
    #[test]
    fn failure_emits_login_failed_event() {
        let tc = TestConfig::standard();
        let cand = candidate(&tc.hasher, "correct");
        let mut tracker = LoginAttemptTracker::new();

        let result = sign_in(
            "wrong",
            &cand,
            &mut tracker,
            &tc.as_login_config(),
            &security_ctx(),
        );

        if let Err(LoginFailure::InvalidCredentials { events }) = result {
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0].event_type().as_str(),
                "authentication.login_failed"
            );
        } else {
            panic!("expected InvalidCredentials");
        }
    }
}
