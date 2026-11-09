//! Signing in to a tenant with an email address and a password.
//!
//! The tenant admits the attempt first, for every address alike. While a
//! flood of failures puts the tenant's sign-in under high pressure, a
//! device nobody trusted must then show a passed challenge, still before
//! any password is hashed. The domain's password sign-in then decides
//! everything: the attempt count, the account, the password, the risk, the
//! second factor owed and the session. This use case only fetches what it
//! asks for, keeps what it produces and records every settled attempt,
//! failed or not.

use std::sync::Arc;
use std::time::Instant;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authentication::credentials::password_rules::PasswordDue;
use ianua_domain::domains::authentication::device_trust::PresentedSecret;
use ianua_domain::domains::authentication::events::login::LockedAddress;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::operations::password_login::{
    LoginCandidate, LoginConfig, LoginRules, PasswordLogin, SecurityContext,
};
use ianua_domain::domains::authentication::risk_engine::attack::AccountAttack;
use ianua_domain::domains::authentication::risk_engine::challenge::ChallengeProof;
use ianua_domain::domains::authentication::risk_engine::history::SignInHistory;
use ianua_domain::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, SessionId, UserId};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{CountedAccount, UserLookup};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::flood_gate::FloodGatePorts;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::sign_in_counts::{CountedAt, SignInCounts};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::sign_in::admission::{TenantRules, admitted};
use crate::use_cases::authentication::password::sign_in::confirmation::{
    ConfirmationLinkPolicy, ConfirmationMailPorts,
};
use crate::use_cases::authentication::password::sign_in::due::{
    DuePorts, PasswordChangeOwed, ProvedPassword,
};
use crate::use_cases::authentication::password::sign_in::flood::{TenantFlood, tenant_budget};
use crate::use_cases::authentication::password::sign_in::kept::KeptSignIn;
use crate::use_cases::authentication::password::sign_in::login_security::{
    LoginSecurityPorts, PresentedDevice, SecurityRules,
};
use crate::use_cases::authentication::password::sign_in::owed_change::OwedChange;
use crate::use_cases::authentication::password::sign_in::settlement::Settlement;

/// The ports [`LoginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LoginPorts {
    /// Tenants, which admit the attempt and set its rules.
    pub tenants: Arc<dyn TenantStore>,
    /// Finds the account an address signs in to.
    pub user_lookup: Arc<dyn UserLookup>,
    /// The failed passwords counted per account and network, and the wait
    /// an account being guessed at asks.
    pub attempts: SignInCounts,
    /// Keeps the session a sign-in opens.
    pub sessions: Arc<dyn SessionStore>,
    /// Checks the typed password against the stored hash, under the node's
    /// cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// The tenant's count of failures, and the challenge a device nobody
    /// trusted passes while it is high.
    pub flood: FloodGatePorts,
    /// Makes session tokens.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// What the sign-in asks once the password is proven.
    pub security: LoginSecurityPorts,
    /// Mails the link a sign-in owing an email confirmation waits for.
    pub confirmation: ConfirmationMailPorts,
    /// Whether the password must change first, the change the sign-in then
    /// begins, and keeping the password in the platform's own hash.
    pub password_due: DuePorts,
}

/// How a password sign-in ended, short of a refusal.
pub enum LoginOutcome {
    /// A session opened, owing whatever second factor the sign-in asks.
    SignedIn(LoginSuccess),
    /// The password was right, but an admin set it or it expired. No
    /// session opened; a new password set with the change's token finishes
    /// the sign-in.
    PasswordChangeOwed(PasswordChangeOwed),
}

/// What the deployment decides for every tenant's password sign-in.
#[derive(Debug, Clone)]
pub struct LoginSettings {
    /// Breach checks and remembered browsers.
    pub security: SecurityRules,
    /// The links that confirm a sign-in by email.
    pub confirmation: ConfirmationLinkPolicy,
}

/// One password sign-in attempt.
pub struct LoginRequest {
    /// The address the person signs in with.
    pub email: Email,
    /// The password as typed.
    pub password: Secret,
    /// The secret of a browser the person remembered, if it sent one.
    pub device_secret: Option<PresentedSecret>,
    /// The proof of a passed challenge, if the browser solved one.
    pub challenge: Option<ChallengeProof>,
    /// Where the request came from.
    pub origin: ClientOrigin,
    /// Where a link confirming the sign-in by email lands, when one is owed.
    pub confirm_at: LinkScope,
}

/// A password sign-in that opened a session.
pub struct LoginSuccess {
    /// The new session.
    pub session_id: SessionId,
    /// The account signed in to.
    pub user_id: UserId,
    /// The raw refresh token, sent to the client and never stored.
    pub refresh_token: Secret,
    /// What the sign-in still owes. A confirmation by email was mailed when
    /// it owes one.
    pub second_factor: SecondFactor,
}

/// Signs people in to a tenant with their password.
pub struct LoginUseCase {
    ports: LoginPorts,
    settings: LoginSettings,
}

/// One attempt as the use case's steps read it.
pub(super) struct Attempt<'a> {
    /// The tenant signed in to.
    pub(super) tenant: &'a ScopedTenant,
    /// The tenant as stored, with its sign-in settings.
    pub(super) record: &'a Tenant,
    /// The domain's sign-in for the attempt.
    pub(super) login: &'a PasswordLogin,
    /// What the person presented.
    pub(super) request: &'a LoginRequest,
    /// The tenant's lockout and session rules.
    pub(super) rules: &'a TenantRules,
    /// When the attempt began.
    pub(super) started: Instant,
}

/// A settled attempt and the attack on its account it found, whose mark
/// is kept once the attempt is recorded.
struct Tracked {
    /// What the caller is told and the trail keeps.
    settlement: Settlement,
    /// The attack the attempt found.
    attack: AccountAttack,
}

type PortsRules<'a> = LoginRules<'a, Arc<dyn RefreshTokenGenerator>>;

impl LoginUseCase {
    /// A use case signing in through `ports` under `settings`.
    #[must_use]
    pub fn new(ports: LoginPorts, settings: LoginSettings) -> Self {
        Self { ports, settings }
    }

    /// What the sign-in is held to before its password is hashed.
    fn flood(&self) -> TenantFlood<'_> {
        TenantFlood {
            gate: &self.ports.flood,
            security: &self.ports.security,
            device_trust: self.settings.security.device_trust,
        }
    }

    /// Finishes a sign-in whose password was just changed inside it: the
    /// new password signs `request.email` in as any password does, owing
    /// whatever second factor the sign-in asks, and is recorded alike.
    ///
    /// The flood gate is not asked again: the sign-in that began the
    /// change already passed it, and its puzzle is spent.
    ///
    /// # Errors
    ///
    /// The errors of [`LoginUseCase::execute`], short of the challenge.
    pub(in crate::use_cases::authentication::password) async fn after_change(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: LoginRequest,
    ) -> Result<LoginOutcome, AppError> {
        let started = Instant::now();
        let admitted = admitted(self.ports.tenants.as_ref(), tenant, &request).await?;
        let candidate = self
            .candidate(tenant, &admitted.record, &request.email)
            .await?;
        let attempt = Attempt {
            tenant,
            record: &admitted.record,
            login: &admitted.login,
            request: &request,
            rules: &admitted.rules,
            started,
        };
        let Tracked { settlement, attack } = self.tracked(&attempt, candidate).await?;
        auditor.dispatch(&settlement.events).await.or_internal()?;
        self.attack_recorded(&attempt, attack).await?;
        settlement.result
    }

    /// Runs the domain's sign-in on the lockout of where the attempt came
    /// from, once the account's pace has been waited out, under whatever
    /// attack the account is under, and counts what it did whatever its
    /// answer. The failure that locks its origin out, and the attack this
    /// attempt found begun, are recorded with it.
    async fn tracked(
        &self,
        attempt: &Attempt<'_>,
        candidate: Option<LoginCandidate>,
    ) -> Result<Tracked, AppError> {
        let counted = counted_at(attempt);
        let address = locked_address(candidate.as_ref());
        let flood = self.flood();
        let device = flood.device_of(attempt.tenant, attempt.request, candidate.as_ref());
        let mut tracker = self.ports.attempts.held(counted, device).await?;
        let attack = self.ports.attempts.attack(counted).await?;
        let settled = self.settled(attempt, candidate, &mut tracker, attack).await;
        let lockout = self.ports.attempts.settled(counted, &tracker).await?;
        let mut settlement = settled?;
        let found = attack
            .begun()
            .map(|begun| attempt.login.under_attack(begun, address));
        let locked = lockout.map(|lockout| attempt.login.locked_out(lockout, address));
        settlement.events.extend(found.into_iter().chain(locked));
        Ok(Tracked { settlement, attack })
    }

    /// Marks the account `attempt` signed in to under the attack it found
    /// begun, now that its record is written.
    async fn attack_recorded(
        &self,
        attempt: &Attempt<'_>,
        attack: AccountAttack,
    ) -> Result<(), AppError> {
        self.ports
            .attempts
            .mark_recorded(counted_at(attempt), attack)
            .await
    }

    /// Runs the domain's sign-in for an admitted attempt, counting it on
    /// `tracker`, under `attack`. The password is hashed under a permit,
    /// given back as soon as the hash is done.
    async fn settled(
        &self,
        attempt: &Attempt<'_>,
        candidate: Option<LoginCandidate>,
        tracker: &mut LoginAttemptTracker,
        attack: AccountAttack,
    ) -> Result<Settlement, AppError> {
        let Some(candidate) = candidate else {
            return self.unknown_account(attempt, tracker).await;
        };
        let password = attempt.request.password.expose();
        let verified = {
            let hasher = self.ports.hashing.permitted().await?;
            let config = self.config(attempt, &hasher);
            attempt.login.verify(password, &candidate, tracker, &config)
        };
        let verified = match verified {
            Ok(verified) => verified,
            Err(failure) => return Ok(Settlement::refused(failure)),
        };
        let history = self.history_of(attempt, &candidate.user_id).await?;
        let security = self
            .security_of(attempt, &candidate, &history, attack)
            .await;
        let result = match verified.conclude(tracker, &self.rules(attempt), &security) {
            Ok(result) => result,
            Err(failure) => return Ok(Settlement::refused(failure)),
        };
        self.keep_house_hash(attempt, &candidate).await?;
        match result.password_due {
            PasswordDue::Current => self.kept().succeeded(attempt, result).await,
            PasswordDue::ChangeRequired(reason) => {
                self.owed_change().begun(attempt, result, reason).await
            }
        }
    }

    /// Replaces a proved hash another system made with one of the
    /// platform's own.
    async fn keep_house_hash(
        &self,
        attempt: &Attempt<'_>,
        candidate: &LoginCandidate,
    ) -> Result<(), AppError> {
        let proved = ProvedPassword {
            tenant: attempt.tenant,
            user_id: &candidate.user_id,
            stored: &candidate.password_hash,
            typed: &attempt.request.password,
        };
        self.ports
            .password_due
            .rehash_if_foreign(proved, &self.ports.hashing)
            .await
    }

    /// The tenant's rules with this deployment's ports.
    fn rules<'a>(&'a self, attempt: &Attempt<'a>) -> PortsRules<'a> {
        let auth = attempt.record.auth_config();
        LoginRules {
            timeout_policy: &attempt.rules.timeout,
            token_generator: &self.ports.token_generator,
            mfa_policy: auth.mfa_policy(),
            step_up_policy: auth.step_up_policy(),
            breach_policy: self.settings.security.breach_policy,
            mail: self.ports.confirmation.mail.reach(),
        }
    }

    /// The tenant's rules, with `hasher` to check the password.
    fn config<'a, H: PasswordHasher>(
        &'a self,
        attempt: &Attempt<'a>,
        hasher: &'a H,
    ) -> LoginConfig<'a, H, Arc<dyn RefreshTokenGenerator>> {
        LoginConfig {
            rules: self.rules(attempt),
            hasher,
        }
    }

    /// The account `email` signs in to in `tenant`, with whether its
    /// password must change worked out from the credential store and the
    /// tenant's expiry in `record`.
    async fn candidate(
        &self,
        tenant: &ScopedTenant,
        record: &Tenant,
        email: &Email,
    ) -> Result<Option<LoginCandidate>, AppError> {
        let Some(mut candidate) = self
            .ports
            .user_lookup
            .find_by_email(tenant, email)
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        candidate.password_due = self
            .ports
            .password_due
            .due(tenant, record, &candidate.user_id)
            .await?;
        Ok(Some(candidate))
    }

    /// The refusal for an address with no account, reached only after as
    /// long as a real password check takes, under a permit like one, and
    /// counted under the tenant's lockout like any other failure.
    async fn unknown_account(
        &self,
        attempt: &Attempt<'_>,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<Settlement, AppError> {
        {
            let hasher = self.ports.hashing.permitted().await?;
            let _ = hasher.hash(attempt.request.password.expose());
        }
        let refused = attempt.login.no_such_user(tracker);
        Ok(Settlement::refused(refused))
    }

    async fn history_of(
        &self,
        attempt: &Attempt<'_>,
        user_id: &UserId,
    ) -> Result<SignInHistory, AppError> {
        self.ports
            .security
            .sign_in_history
            .history(attempt.tenant, user_id)
            .await
            .or_internal()
    }

    /// What the outside world says about a sign-in whose password was
    /// proven, to an account under `attack` or not.
    async fn security_of<'h>(
        &self,
        attempt: &Attempt<'_>,
        candidate: &LoginCandidate,
        history: &'h SignInHistory,
        attack: AccountAttack,
    ) -> SecurityContext<'h> {
        let security = &self.ports.security;
        let rules = self.settings.security;
        let device = PresentedDevice {
            tenant: attempt.tenant,
            user_id: &candidate.user_id,
            secret: attempt.request.device_secret.as_ref(),
        };
        SecurityContext {
            breach: security
                .breach_of(&attempt.request.password, rules.breach_policy)
                .await,
            location: security.location_of(attempt.login.ip_address()).await,
            device: security
                .device_familiarity(device, rules.device_trust)
                .await,
            history,
            attack,
        }
    }

    /// Where a successful sign-in is kept.
    fn kept(&self) -> KeptSignIn<'_> {
        KeptSignIn {
            ports: &self.ports,
            settings: &self.settings,
        }
    }

    /// Where the change a proved password owes begins.
    fn owed_change(&self) -> OwedChange<'_> {
        OwedChange {
            ports: &self.ports,
            settings: &self.settings,
        }
    }
}

impl Command for LoginUseCase {
    type Caller = ScopedTenant;
    type Input = LoginRequest;
    type Output = Result<LoginOutcome, AppError>;

    /// Signs `request.email` in to `tenant` with `request.password`.
    ///
    /// Every settled attempt is recorded, failed or not, and the address's
    /// failed-attempt count is kept for the next one. While failures from
    /// many networks put the account under attack, a right password from a
    /// device nobody trusted owes the second factor or a mailed
    /// confirmation, and the attempt that finds the attack records
    /// `authentication.account_under_attack` once. If the record cannot
    /// be written, no token is handed out: a sign-in the audit trail cannot
    /// show must not grant access.
    ///
    /// A right password that an admin set, or that is past the tenant's
    /// age, opens no session: the answer is
    /// [`LoginOutcome::PasswordChangeOwed`], with the token a new password
    /// is set with through
    /// [`ChangeDueUseCase`](crate::use_cases::authentication::password::ChangeDueUseCase),
    /// and `authentication.password_reset_requested` is recorded, started by
    /// the system. For a password an admin set, the token goes back only
    /// when the person's own factor is asked with the new password; when
    /// their mailbox is the proof it is mailed to them instead.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` ("invalid credentials") hides unknown addresses, wrong passwords, locked/deactivated/closing accounts and network lockouts; it also reports a missing tenant.
    /// - `AppError::EmailNotVerified` for a right password with an unconfirmed address; `TenantUnavailable` for a suspended, archived or deleted tenant.
    /// - `AppError::Forbidden` for unfinished joining, excessive risk, disallowed password origin/assurance, or an untrusted device during an attack without factor/mail proof; an administrator-set password without personal factor/mail proof requires an invitation instead.
    /// - `AppError::ChallengeRequired` under high pressure without trusted-device/challenge proof, before hashing, alike for every address and without counting a failure; `Busy` when hashing cannot start in time, without hashing or counting.
    /// - `AppError::Internal` on storage, token, mail or audit failure, or invalid tenant policy limits.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: LoginRequest,
    ) -> Result<LoginOutcome, AppError> {
        let started = Instant::now();
        let admitted = admitted(self.ports.tenants.as_ref(), tenant, &request).await?;
        let candidate = self
            .candidate(tenant, &admitted.record, &request.email)
            .await?;
        let budget = tenant_budget(&admitted.record);
        let flood = self.flood();
        let eased = flood
            .admit(tenant, &request, candidate.as_ref(), budget)
            .await?;
        let attempt = Attempt {
            tenant,
            record: &admitted.record,
            login: &admitted.login,
            request: &request,
            rules: &admitted.rules,
            started,
        };
        let Tracked { settlement, attack } = self.tracked(&attempt, candidate).await?;
        let rose = flood.counted(&settlement, budget).await;
        let recorded: Vec<_> = [eased, settlement.events, rose]
            .into_iter()
            .flatten()
            .collect();
        auditor.dispatch(&recorded).await.or_internal()?;
        self.attack_recorded(&attempt, attack).await?;
        settlement.result
    }
}

/// Where `attempt`'s password is counted: the address it names in its
/// tenant, from the network it came from, under the tenant's lockout.
fn counted_at<'a>(attempt: &Attempt<'a>) -> CountedAt<'a> {
    CountedAt {
        account: CountedAccount::Tenant {
            tenant: attempt.tenant,
            email: &attempt.request.email,
        },
        origin: attempt.login.origin(),
        policy: &attempt.rules.rate,
    }
}

/// Whose lockout a failure against `candidate` records: the account, or a
/// record of attempts against an address without an account.
fn locked_address(candidate: Option<&LoginCandidate>) -> LockedAddress {
    candidate.map_or(LockedAddress::NoAccount, |candidate| {
        LockedAddress::Account(candidate.user_id)
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::{BreachPolicy, BreachStatus};
    use ianua_domain::domains::authentication::credentials::password_rules::ChangeReason;
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::{
        DeviceSecret, TrustWindow, TrustedDevice, TrustedDeviceRow,
    };
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::authentication::mfa::owed::Enrolment;
    use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
    use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
    use ianua_domain::domains::authentication::risk_engine::challenge::{
        ChallengeKind, RequiredChallenge,
    };
    use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
    use ianua_domain::domains::authentication::risk_engine::pace::MOST_PACE;
    use ianua_domain::domains::authentication::risk_engine::pressure::FailureThreshold;
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::password_policy::{ExpiryDays, PasswordExpiry, PasswordHygiene};
    use ianua_domain::types::{
        CidrRange, CountryCode, Fact, HttpsUrl, IpAddress, Label, Lifetime, PasswordPolicy,
        PrincipalId, TenantSlug, TrustedDeviceId, UserAgent,
    };
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::authentication::{
        ChallengeVerifier, CredentialBreachChecker, FailureScope, Geolocator, PasswordHashFormat,
        PasswordHashPermits, SignInAttemptCounts, TrustedDeviceStore,
    };
    use crate::ports::identity::UserStore;
    use crate::ports::shared::MailSetup;
    use crate::test_support::authentication::{
        BusyHashPermits, CountingHasher, FakeBreachChecker, FakeChallengeVerifier, FakeGeolocator,
        FakeHashPermits, FakeMfaEnrollmentStore, FakeSessionStore, FakeSignInAttemptCounts,
        FakeSignInFailureBudget, FakeSignInHistory, FakeTrustedDeviceStore, FakeUserLookup,
        ForeignHashFormat, HouseHashFormat, RecordingPause, UnreachableBreachChecker,
        UnreachableGeolocator, UnreachableSignInAttemptCounts,
    };
    use crate::test_support::identity::{FakeUserStore, RecordingCredentialStore};
    use crate::test_support::oauth::hash_of;
    use crate::test_support::tenant::{tenant_store_in_status, tenant_store_signing_in_with};
    use crate::test_support::{
        FailingEventDispatcher, Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on,
        test_auditor, test_ctx,
    };
    use crate::use_cases::authentication::password::sign_in::due::ChangeToken;

    const ANN: &str = "ann@acme.test";
    const PASSWORD: &str = "correct horse battery staple";
    const OFFICE: &str = "203.0.113.7";
    const MALLORY: &str = "198.51.100.66";
    const SOLVED: &str = "solved-puzzle-0042";

    fn device_secret() -> PresentedSecret {
        PresentedSecret::on_dashboard(DeviceSecret::new("ab".repeat(32)).unwrap())
    }

    /// Ann's account as sign-in finds it, and the stores a sign-in touches.
    struct Fixture {
        ann: UserId,
        status: UserStatus,
        standing: AddressStanding,
        enrolment: Enrolment,
        vouching: Vouching,
        settings: TenantAuthSettings,
        breach_policy: BreachPolicy,
        breach_checker: Arc<dyn CredentialBreachChecker>,
        geolocator: Arc<dyn Geolocator>,
        devices: Arc<FakeTrustedDeviceStore>,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        counts: Arc<dyn SignInAttemptCounts>,
        pause: Arc<RecordingPause>,
        history: Arc<FakeSignInHistory>,
        mailer: Arc<FakeMailer>,
        mail: Arc<dyn MailSetup>,
        factors: Arc<FakeMfaEnrollmentStore>,
        audit: Arc<FakeEventDispatcher>,
        credentials: Arc<RecordingCredentialStore>,
        hash_format: Arc<dyn PasswordHashFormat>,
        hasher: Arc<CountingHasher>,
        permits: Arc<dyn PasswordHashPermits>,
        failures: Arc<FakeSignInFailureBudget>,
        challenges: Option<Arc<dyn ChallengeVerifier>>,
    }

    impl Fixture {
        fn new() -> Self {
            let ann = UserId::new();
            let credentials =
                RecordingCredentialStore::holding(ann, &FakeHasher.hash(PASSWORD).unwrap());
            Self {
                credentials: Arc::new(credentials),
                hash_format: Arc::new(HouseHashFormat),
                hasher: Arc::new(CountingHasher::default()),
                permits: Arc::new(FakeHashPermits::default()),
                failures: Arc::new(FakeSignInFailureBudget::default()),
                challenges: Some(Arc::new(FakeChallengeVerifier::accepting(SOLVED))),
                ann,
                status: UserStatus::Active,
                standing: AddressStanding::Verified,
                enrolment: Enrolment::NotEnrolled,
                vouching: Vouching::Absent,
                settings: TenantAuthSettings::default(),
                breach_policy: BreachPolicy::Off,
                breach_checker: Arc::new(FakeBreachChecker::default()),
                geolocator: Arc::new(FakeGeolocator::default()),
                devices: Arc::new(FakeTrustedDeviceStore::empty()),
                users: Arc::new(FakeUserStore::with_user(ann, ANN)),
                sessions: Arc::new(FakeSessionStore::empty()),
                counts: Arc::new(FakeSignInAttemptCounts::default()),
                pause: Arc::new(RecordingPause::default()),
                history: Arc::new(FakeSignInHistory::default()),
                mailer: Arc::new(FakeMailer::new()),
                mail: Fake::fake(),
                factors: Arc::new(FakeMfaEnrollmentStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn enrolled(self) -> Self {
            Self {
                enrolment: Enrolment::Enrolled,
                ..self
            }
        }

        fn under(self, mfa_policy: MfaPolicy, step_up_policy: StepUpPolicy) -> Self {
            Self {
                settings: TenantAuthSettings {
                    mfa_policy,
                    step_up_policy,
                    ..self.settings
                },
                ..self
            }
        }

        /// Acme's threshold set at ten failures, with none counted yet.
        fn watching(self) -> Self {
            Self {
                settings: TenantAuthSettings {
                    challenge_threshold: FailureThreshold::new(10).unwrap(),
                    ..self.settings
                },
                ..self
            }
        }

        /// Acme locking a network out of an account after three failures
        /// from it.
        fn locking_after_three(self) -> Self {
            Self {
                settings: TenantAuthSettings {
                    max_login_attempts: 3,
                    ..self.settings
                },
                ..self
            }
        }

        /// A thousand failures counted against Ann's account, spread over
        /// as many networks as a botnet has.
        fn guessed_at_from_many_networks(self) -> Self {
            let tenant = test_ctx().tenant();
            let ann = email();
            let account = CountedAccount::Tenant {
                tenant: &tenant,
                email: &ann,
            };
            Self {
                counts: Arc::new(FakeSignInAttemptCounts::guessed_at(account, 1_000)),
                ..self
            }
        }

        /// Failures against Ann's account from twenty networks, twice Acme's
        /// limit of ten a network, as a botnet leaves them: her account is
        /// under attack.
        fn under_attack(self) -> Self {
            let tenant = test_ctx().tenant();
            let ann = email();
            let account = CountedAccount::Tenant {
                tenant: &tenant,
                email: &ann,
            };
            Self {
                counts: Arc::new(FakeSignInAttemptCounts::guessed_from_networks(account, 20)),
                ..self
            }
        }

        /// Acme's sign-in under high pressure: ten failures counted against
        /// a threshold of ten.
        fn flooded(self) -> Self {
            Self {
                failures: Arc::new(FakeSignInFailureBudget::over(acme(), 10)),
                ..self.watching()
            }
        }

        fn candidate(&self) -> LoginCandidate {
            LoginCandidate {
                user_id: self.ann,
                password_hash: FakeHasher.hash(PASSWORD).unwrap(),
                status: self.status,
                email_standing: self.standing,
                enrolment: self.enrolment,
                vouching: self.vouching,
                password_due: PasswordDue::Current,
            }
        }

        fn use_case(&self) -> LoginUseCase {
            self.use_case_in(tenant_store_signing_in_with(self.settings.clone()))
        }

        fn use_case_in(&self, tenants: Arc<dyn TenantStore>) -> LoginUseCase {
            let ports = LoginPorts {
                tenants,
                user_lookup: Arc::new(FakeUserLookup::holding([(email(), self.candidate())])),
                attempts: SignInCounts::new(self.counts.clone(), self.pause.clone()),
                sessions: self.sessions.clone(),
                security: self.security_ports(),
                confirmation: ConfirmationMailPorts {
                    mailer: self.mailer.clone(),
                    mail: self.mail.clone(),
                    ..ConfirmationMailPorts::fakes()
                },
                password_due: DuePorts {
                    credentials: self.credentials.clone(),
                    hash_format: self.hash_format.clone(),
                    mailer: self.mailer.clone(),
                    mail: self.mail.clone(),
                    enrollments: self.factors.clone(),
                    ..DuePorts::fakes()
                },
                hashing: PasswordHashing::new(self.hasher.clone(), self.permits.clone()),
                flood: FloodGatePorts {
                    failures: self.failures.clone(),
                    challenges: self.challenges.clone(),
                },
                ..LoginPorts::fakes()
            };
            LoginUseCase::new(ports, self.settings_of())
        }

        /// The login checks breaches, location and remembered devices against this fixture.
        fn security_ports(&self) -> LoginSecurityPorts {
            LoginSecurityPorts {
                breach_checker: self.breach_checker.clone(),
                geolocator: self.geolocator.clone(),
                devices: self.devices.clone(),
                sign_in_history: self.history.clone(),
                users: self.users.clone(),
                ..LoginSecurityPorts::fakes()
            }
        }

        fn settings_of(&self) -> LoginSettings {
            LoginSettings {
                security: SecurityRules {
                    breach_policy: self.breach_policy,
                    device_trust: TrustWindow::standard(),
                },
                confirmation: ConfirmationLinkPolicy {
                    lifetime: Lifetime::seconds(900).unwrap(),
                    base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
                },
            }
        }

        fn sign_in(&self, request: LoginRequest) -> Result<LoginSuccess, AppError> {
            self.sign_in_with(&self.use_case(), request)
        }

        fn sign_in_with(
            &self,
            use_case: &LoginUseCase,
            request: LoginRequest,
        ) -> Result<LoginSuccess, AppError> {
            let auditor = test_auditor(self.audit.clone());
            let outcome = block_on(use_case.execute(&test_ctx().tenant(), &auditor, request))?;
            match outcome {
                LoginOutcome::SignedIn(success) => Ok(success),
                LoginOutcome::PasswordChangeOwed(_) => panic!("the sign-in owes a password change"),
            }
        }

        /// What the sign-in ended in, short of a refusal.
        fn outcome(&self, request: LoginRequest) -> Result<LoginOutcome, AppError> {
            let auditor = test_auditor(self.audit.clone());
            block_on(
                self.use_case()
                    .execute(&test_ctx().tenant(), &auditor, request),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn last_login(&self) -> Option<OffsetDateTime> {
            block_on(self.users.find_by_id(&test_ctx().tenant(), &self.ann))
                .unwrap()
                .unwrap()
                .last_login_at()
        }

        fn laptop(&self) -> TrustedDevice<ResolvedTenant> {
            block_on(self.devices.list_by_user(&test_ctx().tenant(), &self.ann))
                .unwrap()
                .remove(0)
        }

        fn trusting(self, status: DeviceStatus) -> Self {
            let device = remembered_device(self.ann, status);
            Self {
                devices: Arc::new(FakeTrustedDeviceStore::holding([device])),
                ..self
            }
        }
    }

    fn email() -> Email {
        Email::new(ANN).unwrap()
    }

    fn typed(password: &str) -> LoginRequest {
        LoginRequest {
            email: email(),
            password: Secret::new(password),
            device_secret: None,
            challenge: None,
            origin: ClientOrigin::default(),
            confirm_at: confirm_at(),
        }
    }

    fn acme() -> FailureScope {
        FailureScope::Tenant(test_ctx().tenant_id())
    }

    fn proving(proof: &str, request: LoginRequest) -> LoginRequest {
        LoginRequest {
            challenge: Some(ChallengeProof::new(proof).unwrap()),
            ..request
        }
    }

    fn nobody() -> LoginRequest {
        LoginRequest {
            email: Email::new("nobody@acme.test").unwrap(),
            ..typed("guess")
        }
    }

    fn confirm_at() -> LinkScope {
        let limits = DomainLimits::default();
        LinkScope::tenant(
            TenantSlug::new("acme", &limits.slug).unwrap(),
            TenantSlug::new("prod", &limits.slug).unwrap(),
        )
    }

    fn right_password() -> LoginRequest {
        typed(PASSWORD)
    }

    fn from_the_office(request: LoginRequest) -> LoginRequest {
        LoginRequest {
            origin: ClientOrigin {
                ip_address: Fact::Known(IpAddress::new(OFFICE).unwrap()),
                user_agent: None,
            },
            ..request
        }
    }

    fn from_mallory(request: LoginRequest) -> LoginRequest {
        LoginRequest {
            origin: ClientOrigin {
                ip_address: Fact::Known(IpAddress::new(MALLORY).unwrap()),
                user_agent: None,
            },
            ..request
        }
    }

    fn mallorys_network() -> AttemptOrigin {
        AttemptOrigin::of(Fact::Known(&IpAddress::new(MALLORY).unwrap()))
    }

    fn on_her_laptop(request: LoginRequest) -> LoginRequest {
        LoginRequest {
            device_secret: Some(device_secret()),
            ..request
        }
    }

    fn remembered_device(owner: UserId, status: DeviceStatus) -> TrustedDevice<ResolvedTenant> {
        let now = clock::now();
        TrustedDevice::reconstitute(TrustedDeviceRow {
            id: TrustedDeviceId::new(),
            subject_id: PrincipalId::from(owner),
            secret_hash: hash_of(&"ab".repeat(32)),
            device_name: Label::new("device_name", "Laptop").unwrap(),
            last_user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            last_ip: IpAddress::new(OFFICE).unwrap(),
            status,
            last_seen_at: now,
            created_at: now,
        })
        .unwrap()
    }

    fn berlin() -> IpGeolocation {
        IpGeolocation::new(52.5, 13.4, CountryCode::new("DE").unwrap(), None).unwrap()
    }

    /// Ann types her password. A session opens for her, nothing more is
    /// owed, and the sign-in is recorded.
    #[test]
    fn a_right_password_opens_a_session_and_is_recorded() {
        let fixture = Fixture::new();

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.user_id, fixture.ann);
        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert!(!success.refresh_token.expose().is_empty());
        assert!(fixture.sessions.get_session(&success.session_id).is_some());
        assert_eq!(fixture.recorded(), ["authentication.login_succeeded"]);
    }

    /// Ann signs in with her password. Her account now shows when she last
    /// signed in.
    #[test]
    fn a_sign_in_stamps_the_account_signed_in() {
        let fixture = Fixture::new();

        fixture.sign_in(right_password()).unwrap();

        assert!(fixture.last_login().is_some());
    }

    /// A wrong-password attempt leaves Ann's last-sign-in timestamp unset.
    #[test]
    fn a_refused_sign_in_leaves_the_account_unstamped() {
        let fixture = Fixture::new();

        let _ = fixture.sign_in(typed("wrong"));

        assert!(fixture.last_login().is_none());
    }

    /// Ann's password is in a known breach and the deployment records
    /// breaches. She signs in, and the breach is on record.
    #[test]
    fn a_breached_password_is_recorded() {
        let fixture = Fixture {
            breach_policy: BreachPolicy::Record,
            breach_checker: Arc::new(FakeBreachChecker {
                status: BreachStatus::Breached(42),
            }),
            ..Fixture::new()
        };

        fixture.sign_in(right_password()).unwrap();

        assert!(
            fixture
                .recorded()
                .contains(&"authentication.password_breach_detected".to_owned())
        );
    }

    /// A wrong password returns invalid credentials, opens no session, and
    /// records the failed sign-in.
    #[test]
    fn a_wrong_password_opens_nothing_and_is_recorded() {
        let fixture = Fixture::new();

        let result = fixture.sign_in(typed("guess"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
        assert_eq!(fixture.recorded(), ["authentication.login_failed"]);
    }

    /// Two wrong passwords are both refused and counted against Mallory's
    /// network and Ann's account.
    #[test]
    fn two_wrong_passwords_both_count() {
        let counts = Arc::new(FakeSignInAttemptCounts::default());
        let fixture = Fixture {
            counts: counts.clone(),
            ..Fixture::new()
        };
        let use_case = fixture.use_case();

        let first = fixture.sign_in_with(&use_case, from_mallory(typed("guess")));
        let second = fixture.sign_in_with(&use_case, from_mallory(typed("another guess")));

        assert!(matches!(first, Err(AppError::NotFound(_))));
        assert!(matches!(second, Err(AppError::NotFound(_))));
        let tenant = test_ctx().tenant();
        let ann = email();
        let account = CountedAccount::Tenant {
            tenant: &tenant,
            email: &ann,
        };
        assert_eq!(counts.from_origin(account, &mallorys_network()), 2);
        assert_eq!(counts.on_account(account), 2);
    }

    /// An unknown address returns invalid credentials and records a failed
    /// sign-in.
    #[test]
    fn an_unknown_address_opens_nothing_and_is_recorded() {
        let fixture = Fixture::new();
        let request = LoginRequest {
            email: Email::new("nobody@acme.test").unwrap(),
            ..right_password()
        };

        let result = fixture.sign_in(request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.recorded(), ["authentication.login_failed"]);
    }

    /// A wrong password and an unknown address return the same invalid-credentials
    /// message, keeping the response from identifying an existing account.
    #[test]
    fn a_wrong_password_and_an_unknown_address_answer_alike() {
        let fixture = Fixture::new();
        let unknown = LoginRequest {
            email: Email::new("nobody@acme.test").unwrap(),
            ..right_password()
        };

        let wrong = fixture.sign_in(typed("guess"));
        let missing = fixture.sign_in(unknown);

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b))) = (wrong, missing) else {
            panic!("both are refused as invalid credentials");
        };
        assert_eq!(a, b);
    }

    /// A deactivated account returns invalid credentials even with the right
    /// password and opens no session.
    #[test]
    fn a_deactivated_account_reads_as_invalid_credentials() {
        let fixture = Fixture {
            status: UserStatus::Deactivated,
            ..Fixture::new()
        };

        let result = fixture.sign_in(right_password());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// An unverified address returns an email-verification error despite the
    /// right password and opens no session.
    #[test]
    fn an_unverified_address_is_told_so() {
        let fixture = Fixture {
            standing: AddressStanding::Unverified,
            ..Fixture::new()
        };

        let result = fixture.sign_in(right_password());

        assert!(matches!(result, Err(AppError::EmailNotVerified)));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// Three wrong passwords lock Mallory's network out of Ann's account.
    /// A correct password is then refused, no session opens, and the lockout
    /// is recorded once.
    #[test]
    fn the_tenants_lockout_holds_even_against_the_right_password() {
        let fixture = Fixture::new().locking_after_three();
        let use_case = fixture.use_case();
        for _ in 0..3 {
            let _ = fixture.sign_in_with(&use_case, from_mallory(typed("guess")));
        }

        let result = fixture.sign_in_with(&use_case, from_mallory(right_password()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
        let lockouts = fixture
            .recorded()
            .iter()
            .filter(|name| *name == "authentication.account_locked_out")
            .count();
        assert_eq!(lockouts, 1);
    }

    /// Mallory guesses Ann's password twenty times from her own network.
    /// Ann, at the office, still signs in with her password.
    #[test]
    fn the_guessers_lockout_never_locks_the_owner_out() {
        let fixture = Fixture::new().locking_after_three();
        let use_case = fixture.use_case();
        for _ in 0..20 {
            let _ = fixture.sign_in_with(&use_case, from_mallory(typed("guess")));
        }

        let ann = fixture.sign_in_with(&use_case, from_the_office(right_password()));

        assert_eq!(ann.unwrap().user_id, fixture.ann);
    }

    /// A wrong password, an unknown address, and a correct password from a
    /// locked-out network return the same invalid-credentials message.
    #[test]
    fn a_locked_out_network_answers_as_a_wrong_password_does() {
        let fixture = Fixture::new().locking_after_three();
        let use_case = fixture.use_case();
        let wrong = fixture.sign_in_with(&use_case, from_the_office(typed("guess")));
        let missing = fixture.sign_in_with(&use_case, from_the_office(nobody()));
        for _ in 0..3 {
            let _ = fixture.sign_in_with(&use_case, from_mallory(typed("guess")));
        }

        let locked = fixture.sign_in_with(&use_case, from_mallory(right_password()));

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b)), Err(AppError::NotFound(c))) =
            (wrong, missing, locked)
        else {
            panic!("all three are refused as invalid credentials");
        };
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    /// Three failed attempts at an unknown address record a lockout, and a
    /// further attempt is refused with invalid credentials.
    #[test]
    fn an_unknown_address_locks_like_a_real_one() {
        let fixture = Fixture::new().locking_after_three();
        let use_case = fixture.use_case();
        for _ in 0..3 {
            let _ = fixture.sign_in_with(&use_case, from_mallory(nobody()));
        }

        let result = fixture.sign_in_with(&use_case, from_mallory(nobody()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.account_locked_out".to_owned())
        );
    }

    /// A botnet's failures against Ann's account pile up from many
    /// networks. Ann's sign-in from a new device waits a few seconds at
    /// most, then goes through with her password.
    #[test]
    fn guessing_from_many_networks_slows_the_owner_but_lets_her_in() {
        let fixture = Fixture::new().guessed_at_from_many_networks();

        let ann = fixture.sign_in(from_the_office(right_password()));

        assert_eq!(ann.unwrap().user_id, fixture.ann);
        assert_eq!(fixture.pause.waited(), [MOST_PACE]);
    }

    /// Ann signs in on the laptop she told her tenant to remember while a
    /// botnet guesses at her account. She does not wait.
    #[test]
    fn a_trusted_device_is_not_slowed_by_guessing_elsewhere() {
        let fixture = Fixture::new()
            .guessed_at_from_many_networks()
            .trusting(DeviceStatus::Trusted);

        let ann = fixture.sign_in(on_her_laptop(from_the_office(right_password())));

        assert_eq!(ann.unwrap().user_id, fixture.ann);
        assert!(fixture.pause.waited().is_empty());
    }

    /// An enrolled account under attack from twenty networks still requires
    /// its factor after a correct password from Mallory's laptop.
    #[test]
    fn under_attack_a_botnets_right_guess_owes_the_factor() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
            .under_attack();

        let botnet = fixture.sign_in(from_mallory(right_password())).unwrap();

        assert_eq!(botnet.second_factor, SecondFactor::Verify);
    }

    /// The same wrong guess answers alike whether or not Ann's account is
    /// under attack.
    #[test]
    fn under_attack_a_wrong_password_answers_as_ever() {
        let quiet = Fixture::new();
        let attacked = Fixture::new().under_attack();

        let before = quiet.sign_in(from_mallory(typed("guess")));
        let during = attacked.sign_in(from_mallory(typed("guess")));

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b))) = (before, during) else {
            panic!("both are refused as invalid credentials");
        };
        assert_eq!(a, b);
    }

    /// Ann signs in on the laptop she told her tenant to remember while her
    /// account is under attack. She neither waits nor is asked for more.
    #[test]
    fn under_attack_a_trusted_device_goes_straight_in() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
            .trusting(DeviceStatus::Trusted)
            .under_attack();

        let ann = fixture
            .sign_in(on_her_laptop(from_the_office(right_password())))
            .unwrap();

        assert_eq!(ann.second_factor, SecondFactor::NotOwed);
        assert!(fixture.pause.waited().is_empty());
    }

    /// Ann, with no factor, signs in from her new phone while her account
    /// is under attack. The sign-in waits for the link mailed to her, the
    /// confirmation any new device would owe.
    #[test]
    fn under_attack_a_new_device_without_a_factor_confirms_by_mail() {
        let fixture = Fixture::new()
            .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
            .under_attack();

        let ann = fixture.sign_in(from_the_office(right_password())).unwrap();

        assert_eq!(ann.second_factor, SecondFactor::ConfirmByEmail);
        assert_eq!(fixture.mailer.recipients(), [ANN]);
        assert!(fixture.mailer.action_url().contains("confirm-sign-in"));
    }

    /// An account under attack with neither a factor nor mail is refused
    /// despite the right password. The response asks for a new invitation,
    /// and no session opens.
    #[test]
    fn under_attack_without_a_factor_or_mail_is_refused() {
        let fixture = Fixture {
            mail: FakeMailSetup::not_set_up(),
            ..Fixture::new()
                .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
                .under_attack()
        };

        let refused = fixture.sign_in(from_mallory(right_password()));

        assert!(matches!(
            refused,
            Err(AppError::Forbidden(message)) if message.as_str().contains("new invitation")
        ));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// The botnet keeps guessing at Ann's account. The first attempt after
    /// the attack shows records it; the ones after it record it no more.
    #[test]
    fn the_attack_is_recorded_once() {
        let fixture = Fixture::new().under_attack();
        let use_case = fixture.use_case();

        for _ in 0..3 {
            let _ = fixture.sign_in_with(&use_case, from_mallory(typed("guess")));
        }

        let found = fixture
            .recorded()
            .iter()
            .filter(|name| *name == "authentication.account_under_attack")
            .count();
        assert_eq!(found, 1);
    }

    /// An audit failure while detecting an attack fails the sign-in and
    /// leaves the account unmarked as under attack.
    #[test]
    fn an_attack_whose_record_is_lost_is_not_marked() {
        let tenant = test_ctx().tenant();
        let ann = email();
        let account = CountedAccount::Tenant {
            tenant: &tenant,
            email: &ann,
        };
        let counts = Arc::new(FakeSignInAttemptCounts::guessed_from_networks(account, 20));
        let fixture = Fixture {
            counts: counts.clone(),
            ..Fixture::new()
        };
        let auditor = test_auditor(Arc::new(FailingEventDispatcher));

        let result = block_on(fixture.use_case().execute(
            &tenant,
            &auditor,
            from_mallory(typed("guess")),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(!counts.marked_under_attack(account));
    }

    /// Thirty wrong passwords from one network produce no account-under-attack
    /// event. Ann can still sign in from the office without another factor.
    #[test]
    fn guessing_from_one_network_never_puts_the_account_under_attack() {
        let fixture = Fixture::new();
        let use_case = fixture.use_case();
        for _ in 0..30 {
            let _ = fixture.sign_in_with(&use_case, from_mallory(typed("guess")));
        }

        let ann = fixture.sign_in_with(&use_case, from_the_office(right_password()));

        assert_eq!(ann.unwrap().second_factor, SecondFactor::NotOwed);
        assert!(
            !fixture
                .recorded()
                .contains(&"authentication.account_under_attack".to_owned())
        );
    }

    /// Unreachable attempt counts fail the sign-in with an internal error
    /// and leave no session open.
    #[test]
    fn unreachable_counts_let_nobody_in() {
        let fixture = Fixture {
            counts: Arc::new(UnreachableSignInAttemptCounts),
            ..Fixture::new()
        };

        let result = fixture.sign_in(right_password());

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// An address outside the tenant's allowed network is forbidden with
    /// either a right or wrong password, and neither attempt opens a session.
    #[test]
    fn an_unlisted_address_is_refused_whatever_the_password() {
        let fixture = Fixture {
            settings: TenantAuthSettings {
                ip_allowlist: vec![CidrRange::new("198.51.100.0/24").unwrap()],
                ..TenantAuthSettings::default()
            },
            ..Fixture::new()
        };

        let right = fixture.sign_in(from_the_office(right_password()));
        let wrong = fixture.sign_in(from_the_office(typed("guess")));

        assert!(matches!(right, Err(AppError::Forbidden(_))));
        assert!(matches!(wrong, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// A suspended tenant returns a workspace-unavailable error even when
    /// Ann supplies the right password.
    #[test]
    fn a_suspended_tenant_admits_nobody() {
        let fixture = Fixture::new();
        let use_case = fixture.use_case_in(tenant_store_in_status(TenantStatus::Suspended));

        let result = fixture.sign_in_with(&use_case, right_password());

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
    }

    /// Ann's password is in a breach, and her tenant steps up on breaches.
    /// She has a second factor, so the sign-in asks for it.
    #[test]
    fn a_breached_password_asks_for_the_second_factor() {
        let fixture = Fixture {
            breach_policy: BreachPolicy::StepUp,
            breach_checker: Arc::new(FakeBreachChecker {
                status: BreachStatus::Breached(42),
            }),
            ..Fixture::new()
                .enrolled()
                .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
        };

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Ann's password is clean and she signs in on the laptop she
    /// remembered. Under the same tenant, she is asked for nothing more.
    #[test]
    fn a_clean_password_asks_for_nothing_more() {
        let fixture = Fixture {
            breach_policy: BreachPolicy::StepUp,
            ..Fixture::new()
                .enrolled()
                .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
                .trusting(DeviceStatus::Trusted)
        };

        let success = fixture.sign_in(on_her_laptop(right_password())).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
    }

    /// Ann's password is in a breach and she has no second factor. Setting
    /// one up now would not show she is Ann, so the sign-in waits for her to
    /// confirm from her mailbox, and the link goes to her address.
    #[test]
    fn a_breached_password_without_a_factor_is_confirmed_by_email() {
        let fixture = Fixture {
            breach_policy: BreachPolicy::StepUp,
            breach_checker: Arc::new(FakeBreachChecker {
                status: BreachStatus::Breached(42),
            }),
            ..Fixture::new().under(MfaPolicy::Optional, StepUpPolicy::relaxed())
        };

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::ConfirmByEmail);
        assert_eq!(fixture.mailer.recipients(), [ANN]);
        assert!(fixture.mailer.action_url().contains("confirm-sign-in"));
    }

    /// Ann's tenant requires a second factor and she has one. She is asked
    /// for it.
    #[test]
    fn a_tenant_requiring_a_factor_asks_for_it() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Required, StepUpPolicy::relaxed());

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Ann's tenant requires a second factor and she has none. She must set
    /// one up before she is in.
    #[test]
    fn a_tenant_requiring_a_factor_has_one_set_up() {
        let fixture = Fixture::new().under(MfaPolicy::Required, StepUpPolicy::relaxed());

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Enrol);
        assert_eq!(fixture.mailer.count(), 0);
    }

    /// Ann signs in on the laptop she told her tenant to remember. Her
    /// tenant asks for a factor on new devices only, so she is not asked.
    #[test]
    fn a_remembered_device_is_not_challenged() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
            .trusting(DeviceStatus::Trusted);

        let success = fixture.sign_in(on_her_laptop(right_password())).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
    }

    /// Ann signs in on her remembered laptop from a new browser version at
    /// the office. The laptop is stamped as just used, with that browser and
    /// address, so it keeps counting while she uses it.
    #[test]
    fn a_sign_in_on_a_remembered_device_stamps_the_device() {
        let fixture = Fixture::new().trusting(DeviceStatus::Trusted);
        let request = LoginRequest {
            origin: ClientOrigin {
                ip_address: Fact::Known(IpAddress::new("198.51.100.4").unwrap()),
                user_agent: Some(UserAgent::new("Mozilla/6.0").unwrap()),
            },
            ..on_her_laptop(right_password())
        };

        fixture.sign_in(request).unwrap();

        let laptop = fixture.laptop();
        assert_eq!(laptop.last_ip().as_str(), "198.51.100.4");
        assert_eq!(laptop.last_user_agent().as_str(), "Mozilla/6.0");
    }

    /// Ann signs in from her remembered laptop. The session she gets names
    /// it, so the tokens it hands out carry it to a device posture check.
    #[test]
    fn a_sign_in_on_a_remembered_device_names_it_on_the_session() {
        let fixture = Fixture::new().trusting(DeviceStatus::Trusted);

        let success = fixture.sign_in(on_her_laptop(right_password())).unwrap();

        let session = fixture.sessions.get_session(&success.session_id).unwrap();
        assert_eq!(
            session.signed_in_from(),
            Fact::Known(*fixture.laptop().id())
        );
    }

    /// A missing device secret and a revoked device secret both leave the
    /// resulting session's device unknown.
    #[test]
    fn a_sign_in_without_a_remembered_device_names_none() {
        let plain = Fixture::new().enrolled().trusting(DeviceStatus::Trusted);
        let revoked = Fixture::new().enrolled().trusting(DeviceStatus::Revoked);

        let without = plain.sign_in(right_password()).unwrap();
        let forgotten = revoked.sign_in(on_her_laptop(right_password())).unwrap();

        let named = |fixture: &Fixture, id: &SessionId| {
            fixture.sessions.get_session(id).unwrap().signed_in_from()
        };
        assert_eq!(named(&plain, &without.session_id), Fact::Unknown);
        assert_eq!(named(&revoked, &forgotten.session_id), Fact::Unknown);
    }

    /// A sign-in without the trusted device's secret still requires Ann's
    /// enrolled factor.
    #[test]
    fn a_sign_in_without_a_device_secret_is_challenged() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
            .trusting(DeviceStatus::Trusted);

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// A device secret matching none of Ann's devices still requires her
    /// enrolled factor.
    #[test]
    fn a_device_secret_that_matches_nothing_is_challenged() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
            .trusting(DeviceStatus::Trusted);
        let request = LoginRequest {
            device_secret: Some(PresentedSecret::on_dashboard(
                DeviceSecret::new("cd".repeat(32)).unwrap(),
            )),
            ..right_password()
        };

        let success = fixture.sign_in(request).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// A revoked device's secret still requires Ann's enrolled factor.
    #[test]
    fn a_revoked_device_is_challenged_again() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
            .trusting(DeviceStatus::Revoked);

        let success = fixture.sign_in(on_her_laptop(right_password())).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Ann has no factor and signs in from a new device to a tenant that
    /// asks about new devices. The deployment can send mail, so the sign-in
    /// waits for her to confirm from her mailbox, and the link goes out.
    #[test]
    fn a_new_device_without_a_factor_is_confirmed_by_email() {
        let fixture = Fixture::new().under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices());

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::ConfirmByEmail);
        assert_eq!(fixture.mailer.recipients(), [ANN]);
    }

    /// A returning account with no factor or mail cannot sign in from a new
    /// device under the untrusted-device policy. It is told to request a new
    /// invitation, opens no session, and sends no mail.
    #[test]
    fn a_new_device_without_a_factor_or_mail_is_refused() {
        let fixture = Fixture {
            mail: FakeMailSetup::not_set_up(),
            ..Fixture::new().under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
        };

        let refused = fixture.sign_in(right_password());

        assert!(matches!(
            refused,
            Err(AppError::Forbidden(message)) if message.as_str().contains("new invitation")
        ));
        assert_eq!(fixture.sessions.session_count(), 0);
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Ann accepted the invitation an admin handed her, on a deployment with
    /// no mail server. Her first sign-in, from a new device, goes on owing a
    /// factor she sets up there and then: the invitation already proved her.
    #[test]
    fn the_first_sign_in_an_invitation_vouches_for_sets_up_a_factor() {
        let fixture = Fixture {
            mail: FakeMailSetup::not_set_up(),
            vouching: Vouching::Fresh,
            ..Fixture::new().under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
        };

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Enrol);
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Ann accepted an invitation mailed to her, and her first sign-in comes
    /// from a new device where mail reaches her. The invitation answers the
    /// risk, so under an optional policy she goes straight in.
    #[test]
    fn with_mail_the_first_sign_in_an_invitation_vouches_for_is_let_in() {
        let fixture = Fixture {
            vouching: Vouching::Fresh,
            ..Fixture::new().under(MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
        };

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Ann's address was typed in by an admin on a deployment with no mail
    /// server. She signs in, and her address stays unverified.
    #[test]
    fn an_unverified_address_signs_in_where_nothing_is_mailed() {
        let fixture = Fixture {
            standing: AddressStanding::Unverified,
            mail: FakeMailSetup::not_set_up(),
            ..Fixture::new()
        };

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// An enrolled account signing in from a new device still requires its
    /// factor even when the tenant's step-up policy is relaxed.
    #[test]
    fn a_relaxed_tenant_asks_an_enrolled_person_for_their_factor_on_a_new_device() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::relaxed());

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Ann signs in on the laptop she told her tenant to remember, in a
    /// tenant whose rules do not count new devices as a risk. She owes
    /// nothing more.
    #[test]
    fn a_relaxed_tenant_asks_nothing_on_a_remembered_device() {
        let fixture = Fixture::new()
            .enrolled()
            .under(MfaPolicy::Optional, StepUpPolicy::relaxed())
            .trusting(DeviceStatus::Trusted);

        let success = fixture.sign_in(on_her_laptop(right_password())).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
    }

    /// Bob has no factor and signs in on a new device in a tenant whose
    /// rules do not count new devices as a risk. He is asked for nothing
    /// more, as before: nothing he could give would prove more.
    #[test]
    fn a_relaxed_tenant_asks_nothing_more_of_someone_without_a_factor() {
        let fixture = Fixture::new().under(MfaPolicy::Optional, StepUpPolicy::relaxed());

        let success = fixture.sign_in(right_password()).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
    }

    /// The deployment does not check passwords against breaches. The
    /// checker is never asked, and no missing check is recorded.
    #[test]
    fn a_deployment_that_does_not_check_never_asks_the_checker() {
        let checker = Arc::new(UnreachableBreachChecker::default());
        let fixture = Fixture {
            breach_checker: checker.clone(),
            ..Fixture::new()
        };

        fixture.sign_in(right_password()).unwrap();

        assert_eq!(checker.asked(), 0);
        assert_eq!(fixture.recorded(), ["authentication.login_succeeded"]);
    }

    /// The breach service is down. Ann still signs in, and the missing
    /// check is on record.
    #[test]
    fn a_breach_outage_is_recorded_and_still_signs_in() {
        let fixture = Fixture {
            breach_policy: BreachPolicy::Record,
            breach_checker: Arc::new(UnreachableBreachChecker::default()),
            ..Fixture::new()
        };

        let result = fixture.sign_in(right_password());

        assert!(result.is_ok());
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.sign_in_check_unavailable".to_owned())
        );
    }

    /// The geolocation database cannot be read. Ann still signs in from the
    /// office, and the missing check is on record.
    #[test]
    fn a_location_outage_is_recorded_and_still_signs_in() {
        let fixture = Fixture {
            geolocator: Arc::new(UnreachableGeolocator),
            ..Fixture::new()
        };

        let result = fixture.sign_in(from_the_office(right_password()));

        assert!(result.is_ok());
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.sign_in_check_unavailable".to_owned())
        );
    }

    /// Ann signs in from Berlin. Berlin joins the places she has signed in
    /// from.
    #[test]
    fn where_ann_signed_in_from_is_remembered() {
        let fixture = Fixture {
            geolocator: Arc::new(FakeGeolocator {
                location: Some(berlin()),
            }),
            ..Fixture::new()
        };

        fixture.sign_in(from_the_office(right_password())).unwrap();

        assert_eq!(fixture.history.recorded(), 1);
    }

    /// Failure to write the sign-in audit record returns an internal error
    /// instead of a successful sign-in result.
    #[test]
    fn a_sign_in_whose_record_cannot_be_written_hands_out_no_token() {
        let fixture = Fixture::new();
        let auditor = test_auditor(Arc::new(FailingEventDispatcher));

        let result = block_on(fixture.use_case().execute(
            &test_ctx().tenant(),
            &auditor,
            right_password(),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Ann, whose password Sam set and told her on the phone.
    fn set_by_sam(fixture: Fixture) -> Fixture {
        let set_by_sam = Arc::new(
            RecordingCredentialStore::holding(fixture.ann, &FakeHasher.hash(PASSWORD).unwrap())
                .set_by_admin(fixture.ann),
        );
        Fixture {
            credentials: set_by_sam,
            ..fixture
        }
    }

    /// An admin-set password for an account without a factor requires a
    /// change through a mailed link. No session opens, the token is mailed
    /// to Ann, and the reset request is recorded.
    #[test]
    fn a_password_an_admin_set_is_changed_through_the_mailbox() {
        let fixture = set_by_sam(Fixture::new());

        let outcome = fixture.outcome(right_password()).unwrap();

        let LoginOutcome::PasswordChangeOwed(owed) = outcome else {
            panic!("the sign-in owes a password change");
        };
        assert_eq!(owed.reason, ChangeReason::SetByAdmin);
        assert_eq!(owed.proof, ChangeProof::MailedLink);
        assert!(matches!(owed.token, ChangeToken::Mailed));
        assert_eq!(fixture.sessions.session_count(), 0);
        assert_eq!(fixture.mailer.recipients(), [ANN]);
        assert!(fixture.mailer.action_url().contains("change-password"));
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.password_reset_requested".to_owned())
        );
    }

    /// Ann holds an authenticator app. Her sign-in with the password Sam
    /// set hands the change's token back, asking for a code from her app
    /// with the new password; nothing is mailed.
    #[test]
    fn a_password_an_admin_set_asks_for_the_persons_own_factor() {
        let fixture = set_by_sam(Fixture::new());
        let fixture = Fixture {
            factors: Arc::new(FakeMfaEnrollmentStore::active_for(fixture.ann)),
            ..fixture
        };

        let outcome = fixture.outcome(right_password()).unwrap();

        let LoginOutcome::PasswordChangeOwed(owed) = outcome else {
            panic!("the sign-in owes a password change");
        };
        assert_eq!(owed.proof, ChangeProof::OwnFactor);
        assert!(matches!(owed.token, ChangeToken::HandedBack(_)));
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// An admin-set password is refused when neither mail nor a factor can
    /// prove its owner's change. The response requests an invitation, opens
    /// no session, and sends no mail.
    #[test]
    fn a_password_an_admin_set_is_refused_with_no_mail_and_no_factor() {
        let fixture = Fixture {
            mail: FakeMailSetup::not_set_up(),
            ..set_by_sam(Fixture::new())
        };

        let result = fixture.outcome(right_password());

        assert!(
            matches!(result, Err(AppError::Forbidden(ref why)) if why.as_str().contains("invitation"))
        );
        assert_eq!(fixture.sessions.session_count(), 0);
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Acme's passwords last thirty days, and Ann last changed hers
    /// thirty-one days ago. Her sign-in opens no session and owes a new
    /// password.
    #[test]
    fn a_password_past_the_tenants_age_must_change() {
        let fixture = Fixture::new();
        let thirty_days = PasswordHygiene {
            expiry: PasswordExpiry::After(ExpiryDays::new(30).unwrap()),
            ..PasswordHygiene::default()
        };
        let old =
            RecordingCredentialStore::holding(fixture.ann, &FakeHasher.hash(PASSWORD).unwrap())
                .changed_seconds_ago(31 * 86_400);
        let fixture = Fixture {
            credentials: Arc::new(old),
            settings: TenantAuthSettings {
                password_policy: PasswordPolicy::default().with_hygiene(thirty_days),
                ..fixture.settings.clone()
            },
            ..fixture
        };

        let outcome = fixture.outcome(right_password()).unwrap();

        assert!(matches!(
            outcome,
            LoginOutcome::PasswordChangeOwed(PasswordChangeOwed {
                reason: ChangeReason::Expired,
                proof: ChangeProof::PasswordAlone,
                token: ChangeToken::HandedBack(_),
                ..
            })
        ));
        assert_eq!(fixture.sessions.session_count(), 0);
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// Ann's account came over from another system with its bcrypt hash. Her
    /// first sign-in proves the password and replaces the hash with one of
    /// the platform's own.
    #[test]
    fn a_foreign_hash_is_replaced_once_its_password_is_proved() {
        let fixture = Fixture {
            hash_format: Arc::new(ForeignHashFormat),
            ..Fixture::new()
        };

        fixture.sign_in(right_password()).unwrap();

        assert_eq!(fixture.credentials.rehashed(), [fixture.ann]);
    }

    /// A wrong password for an imported account is refused and leaves its
    /// foreign hash unchanged.
    #[test]
    fn a_wrong_password_rehashes_nothing() {
        let fixture = Fixture {
            hash_format: Arc::new(ForeignHashFormat),
            ..Fixture::new()
        };

        let result = fixture.sign_in(typed("wrong"));

        assert!(result.is_err());
        assert!(fixture.credentials.rehashed().is_empty());
    }

    /// Exhausted hash permits return busy for known and unknown addresses.
    /// No hash runs, and neither Ann's account nor the tenant gains a failure.
    #[test]
    fn a_busy_node_refuses_before_any_hash_runs() {
        let counts = Arc::new(FakeSignInAttemptCounts::default());
        let fixture = Fixture {
            permits: Arc::new(BusyHashPermits),
            counts: counts.clone(),
            ..Fixture::new().watching()
        };

        let known = fixture.sign_in(right_password());
        let unknown = fixture.sign_in(nobody());

        assert!(matches!(known, Err(AppError::Busy)));
        assert!(matches!(unknown, Err(AppError::Busy)));
        assert_eq!(fixture.hasher.hashed(), 0);
        assert_eq!(fixture.failures.counted(&acme()), 0);
        let tenant = test_ctx().tenant();
        let ann = email();
        let account = CountedAccount::Tenant {
            tenant: &tenant,
            email: &ann,
        };
        assert_eq!(counts.on_account(account), 0);
    }

    /// Ann signs in, then Mallory types a wrong password and tries an
    /// address with no account. Each hash took a permit, and every permit
    /// is back once its answer is given.
    #[test]
    fn every_permit_is_handed_back_after_success_and_failure() {
        let permits = Arc::new(FakeHashPermits::default());
        let fixture = Fixture {
            permits: permits.clone(),
            ..Fixture::new()
        };

        fixture.sign_in(right_password()).unwrap();
        let _ = fixture.sign_in(typed("guess"));
        let _ = fixture.sign_in(nobody());

        assert_eq!(permits.taken(), 3);
        assert_eq!(permits.held(), 0);
    }

    /// Mallory's bots try ten wrong passwords and unknown addresses at Acme,
    /// whose threshold is ten. Each is counted, and the tenth records that
    /// Acme's sign-in came under pressure.
    #[test]
    fn real_failures_raise_the_pressure_past_the_threshold() {
        let fixture = Fixture::new().watching();
        let use_case = fixture.use_case();

        for round in 0..10 {
            let guess = if round % 2 == 0 {
                typed("guess")
            } else {
                nobody()
            };
            let _ = fixture.sign_in_with(&use_case, guess);
        }

        assert_eq!(fixture.failures.counted(&acme()), 10);
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.sign_in_pressure_rose".to_owned())
        );
    }

    /// Under sign-in pressure, an untrusted device without proof must solve
    /// a work challenge before its password is hashed. No session opens,
    /// and the tenant's failure count stays unchanged.
    #[test]
    fn an_untrusted_device_is_challenged_before_any_hash() {
        let fixture = Fixture::new().flooded();

        let result = fixture.sign_in(right_password());

        assert!(matches!(
            result,
            Err(AppError::ChallengeRequired(RequiredChallenge::Solve(
                ChallengeKind::ProofOfWork
            )))
        ));
        assert_eq!(fixture.hasher.hashed(), 0);
        assert_eq!(fixture.failures.counted(&acme()), 10);
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// Ann signs in on the laptop she trusted while Acme is under pressure.
    /// She goes through without a challenge.
    #[test]
    fn a_trusted_device_goes_through_under_pressure() {
        let fixture = Fixture::new().flooded().trusting(DeviceStatus::Trusted);

        let result = fixture.sign_in(on_her_laptop(right_password()));

        assert!(result.is_ok());
    }

    /// Ann, on a new phone while Acme is under pressure, solves the
    /// challenge and sends its proof with her password. She goes through.
    #[test]
    fn a_passed_challenge_goes_through_under_pressure() {
        let fixture = Fixture::new().flooded();

        let result = fixture.sign_in(proving(SOLVED, right_password()));

        assert!(result.is_ok());
    }

    /// After a solved challenge permits one sign-in, forged and replayed
    /// proofs are challenged again without running another hash.
    #[test]
    fn a_forged_or_replayed_proof_is_refused() {
        let fixture = Fixture::new().flooded();
        let use_case = fixture.use_case();
        fixture
            .sign_in_with(&use_case, proving(SOLVED, right_password()))
            .unwrap();
        let hashed = fixture.hasher.hashed();

        let forged = fixture.sign_in_with(&use_case, proving("made-up", typed("guess")));
        let replayed = fixture.sign_in_with(&use_case, proving(SOLVED, typed("guess")));

        for refused in [forged, replayed] {
            assert!(matches!(refused, Err(AppError::ChallengeRequired(_))));
        }
        assert_eq!(fixture.hasher.hashed(), hashed);
    }

    /// Under pressure without a challenge provider, untrusted devices are
    /// refused with or without proof because no challenge is available.
    /// Ann's trusted laptop can still sign in.
    #[test]
    fn with_no_provider_an_untrusted_device_is_refused() {
        let fixture = Fixture {
            challenges: None,
            ..Fixture::new().flooded().trusting(DeviceStatus::Trusted)
        };

        let bare = fixture.sign_in(right_password());
        let proved = fixture.sign_in(proving(SOLVED, right_password()));
        let trusted = fixture.sign_in(on_her_laptop(right_password()));

        for refused in [bare, proved] {
            assert!(matches!(
                refused,
                Err(AppError::ChallengeRequired(RequiredChallenge::Unavailable))
            ));
        }
        assert!(trusted.is_ok());
    }

    /// Under sign-in pressure, known and unknown addresses receive the same
    /// challenge, keeping the response from identifying an existing account.
    #[test]
    fn the_challenge_reads_the_same_for_known_and_unknown_addresses() {
        let fixture = Fixture::new().flooded();

        let known = fixture.sign_in(typed("guess"));
        let unknown = fixture.sign_in(nobody());

        let (Err(AppError::ChallengeRequired(a)), Err(AppError::ChallengeRequired(b))) =
            (known, unknown)
        else {
            panic!("both are challenged");
        };
        assert_eq!(a, b);
    }
}
