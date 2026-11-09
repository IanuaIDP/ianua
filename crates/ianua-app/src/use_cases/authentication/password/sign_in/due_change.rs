//! Setting a new password inside a sign-in that owes one, and finishing
//! that sign-in.
//!
//! A sign-in whose right password an admin set, or which expired, opened
//! no session and began a single-use change for a few minutes. Only that
//! change's token answers here: a mailed reset link is no token for this.
//! A password past its age needs nothing more. A password an admin set
//! needs the person's own proof, as [`ChangeProof`] decides: a right code
//! from their factor, given here, or their mailbox, which is where the
//! token went. The new password meets the tenant's rules and repeats none
//! of the account's recent ones; every refused try counts against the
//! lockout of where it came from, as a wrong password does. Once set, every earlier
//! session ends and the sign-in finishes with the new password, owing
//! whatever second factor it asks.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password_rules::{
    ChangeReason, PasswordDue,
};
use ianua_domain::domains::authentication::device_trust::PresentedSecret;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
use ianua_domain::domains::authentication::recovery::reset::{
    PasswordResetRequest, ResetInitiator,
};
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::input::validate_password;
use crate::ports::authentication::{
    CountedAccount, ResetRequestStore, SecretEncryptor, SentCodeGenerator, SentCodeStore,
};
use crate::services::authentication::account_factor::{
    AccountFactor, FactorAnswer, FactorChecks, FactorCode, SentCodes,
};
use crate::services::authentication::new_password::NewPassword;
use crate::services::authentication::sign_in_counts::{CountedAt, SignInCounts};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::services::authentication::sign_in_steps::{CodeCheck, SentCodeCheck};
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::new::{ChosenPassword, ReplacementPorts};
use crate::use_cases::authentication::password::reset::lookup::{FollowedReset, ResetLinks};
use crate::use_cases::authentication::password::sign_in::admission::tenant_rules;
use crate::use_cases::authentication::password::sign_in::due::{DuePorts, ensure_possible};
use crate::use_cases::authentication::password::sign_in::login::{
    LoginOutcome, LoginRequest, LoginUseCase,
};

/// The ports [`ChangeDueUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeDuePorts {
    /// Finds and completes the change the sign-in began.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// Loads the account and its tenant's rules, checks the new password
    /// and puts it in force.
    pub replacement: ReplacementPorts,
    /// Hashes the token the way the sign-in stored it.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The failed passwords counted per account and network, which every
    /// refused try here adds to.
    pub attempts: SignInCounts,
    /// Why the password must change, and what the change asks besides it.
    pub due: DuePorts,
    /// Opens an authenticator app's stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against an authenticator app's secret.
    pub verifier: Arc<dyn MfaVerifier>,
    /// The codes sent for mailed and texted factors.
    pub sent_codes: Arc<dyn SentCodeStore>,
    /// Hashes a typed code the way a sent one was hashed.
    pub sent_code_generator: Arc<dyn SentCodeGenerator>,
}

/// The token a sign-in handed back, the new password, and what the
/// sign-in it finishes presents. It holds both secrets, so it has no
/// `Debug`.
pub struct DueChangeRequest {
    /// The single-use token the sign-in handed back.
    pub change_token: Secret,
    /// The chosen replacement secret to install after the required proof.
    pub new_password: Secret,
    /// A code from the person's own second factor, when the change asks for
    /// one: a password an admin set, for someone who holds a factor.
    pub factor_code: Option<String>,
    /// The secret of a browser the person remembered, if it sent one.
    pub device_secret: Option<PresentedSecret>,
    /// Where the request came from.
    pub origin: ClientOrigin,
    /// Where a link confirming the finished sign-in by email lands, when
    /// one is owed.
    pub confirm_at: LinkScope,
}

/// Sets the new password a sign-in owes, and finishes that sign-in.
pub struct ChangeDueUseCase {
    lockout: LockoutPolicy,
    ports: ChangeDuePorts,
    login: Arc<LoginUseCase>,
}

/// A try, where it is counted, and what it did there.
struct Counted<'a> {
    at: CountedAt<'a>,
    tracker: LoginAttemptTracker,
}

/// The account a new password is chosen for, and where the choice came
/// from.
#[derive(Clone, Copy)]
struct Choosing<'a> {
    tenant: &'a ScopedTenant,
    workspace: &'a Tenant,
    holder: &'a User<ResolvedTenant>,
    origin: AttemptOrigin,
}

impl ChangeDueUseCase {
    /// A use case working through `ports`, locking a second factor under
    /// `lockout`, finishing the sign-in through `login`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: ChangeDuePorts, login: Arc<LoginUseCase>) -> Self {
        Self {
            lockout,
            ports,
            login,
        }
    }

    /// Why `holder`'s password must change now, under `workspace`'s rules.
    /// A password that no longer must change is no change to answer.
    async fn reason_owed(
        &self,
        tenant: &ScopedTenant,
        workspace: &Tenant,
        holder: &User<ResolvedTenant>,
    ) -> Result<ChangeReason, AppError> {
        match self.ports.due.due(tenant, workspace, holder.id()).await? {
            PasswordDue::ChangeRequired(reason) => Ok(reason),
            PasswordDue::Current => Err(unusable_change()),
        }
    }

    /// Refuses the change unless the person gave what `proof` asks besides
    /// the password: a right code from their own factor, or, for a change
    /// whose token was mailed, the token itself, already presented.
    async fn ensure_proved(
        &self,
        tenant: &ScopedTenant,
        holder: &User<ResolvedTenant>,
        proof: ChangeProof,
        code: Option<&str>,
    ) -> Result<(), AppError> {
        ensure_possible(proof)?;
        if proof != ChangeProof::OwnFactor {
            return Ok(());
        }
        let given = FactorCode {
            tenant,
            user_id: holder.id(),
            code,
        };
        match self.factor().answer(given).await? {
            FactorAnswer::Answered(_) => Ok(()),
            FactorAnswer::NoneOnFile => Err(AppError::Forbidden(message!(
                "authentication-the-second-factor-this-change-asks",
                "the second factor this change asks for is no longer set up"
            ))),
        }
    }

    /// The person's second factor and how its codes are checked.
    fn factor(&self) -> AccountFactor<'_> {
        AccountFactor {
            enrollments: self.ports.due.enrollments.as_ref(),
            checks: FactorChecks {
                app: CodeCheck {
                    encryptor: self.ports.encryptor.as_ref(),
                    verifier: self.ports.verifier.as_ref(),
                    lockout: self.lockout,
                },
                sent: SentCodes {
                    store: self.ports.sent_codes.as_ref(),
                    check: SentCodeCheck {
                        generator: self.ports.sent_code_generator.as_ref(),
                        lockout: self.lockout,
                    },
                },
            },
        }
    }

    /// The change `raw_token` names and its account, while it can still be
    /// answered at `now`. A mailed reset link is no change at all here.
    async fn open_change(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
        now: OffsetDateTime,
    ) -> Result<FollowedReset, AppError> {
        let links = ResetLinks {
            resets: self.ports.reset_store.as_ref(),
            users: self.ports.replacement.user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        links
            .usable(tenant, raw_token, now)
            .await?
            .filter(|followed| followed.reset.initiator() == ResetInitiator::System)
            .ok_or_else(unusable_change)
    }

    /// The new password `new` chooses, checked; a refused one counts
    /// against the address's lockout before the refusal is answered.
    async fn chosen(
        &self,
        new: NewPassword<'_>,
        counted: Counted<'_>,
    ) -> Result<ChosenPassword, AppError> {
        let refusal = match self.ports.replacement.replacement().chosen(new).await {
            Ok(chosen) => return Ok(chosen),
            Err(refusal @ AppError::Domain(_)) => refusal,
            Err(other) => return Err(other),
        };
        self.count_refused(counted).await?;
        Err(refusal)
    }

    /// Counts a refused try against where it came from on the account.
    async fn count_refused(&self, mut counted: Counted<'_>) -> Result<(), AppError> {
        counted.tracker.record_failure();
        self.ports
            .attempts
            .settled(counted.at, &counted.tracker)
            .await?;
        Ok(())
    }

    /// Refuses the change unless `holder` gave the proof it asks besides
    /// the password, for the reason their password must change now under
    /// `workspace`'s rules.
    async fn ensure_person_proved(
        &self,
        tenant: &ScopedTenant,
        workspace: &Tenant,
        holder: &User<ResolvedTenant>,
        code: Option<&str>,
    ) -> Result<(), AppError> {
        let reason = self.reason_owed(tenant, workspace, holder).await?;
        let proof = self.ports.due.proof_for(tenant, holder, reason).await?;
        self.ensure_proved(tenant, holder, proof, code).await
    }

    /// The new password `request` chooses for `holder`, once the person
    /// proved themselves as the tenant asks and the choice was counted
    /// against where it came from.
    async fn proved_choice(
        &self,
        tenant: &ScopedTenant,
        holder: &User<ResolvedTenant>,
        request: &DueChangeRequest,
    ) -> Result<ChosenPassword, AppError> {
        let tenants = self.ports.replacement.tenant_store.as_ref();
        let workspace = existing_tenant(tenants, tenant).await?;
        let code = request.factor_code.as_deref();
        self.ensure_person_proved(tenant, &workspace, holder, code)
            .await?;
        let choosing = Choosing {
            tenant,
            workspace: &workspace,
            holder,
            origin: AttemptOrigin::of(request.origin.ip_address.as_ref()),
        };
        self.counted_choice(choosing, &request.new_password).await
    }

    /// The new password `chosen` for `choosing`'s holder, checked while
    /// where the choice came from is not locked out of their account; a
    /// refused one counts against it.
    async fn counted_choice(
        &self,
        choosing: Choosing<'_>,
        chosen: &Secret,
    ) -> Result<ChosenPassword, AppError> {
        let rules = tenant_rules(choosing.workspace)?;
        let at = CountedAt {
            account: CountedAccount::Tenant {
                tenant: choosing.tenant,
                email: choosing.holder.email(),
            },
            origin: choosing.origin,
            policy: &rules.rate,
        };
        let tracker = self.unlocked_tracker(at).await?;
        let new = NewPassword {
            tenant: choosing.tenant,
            account: choosing.holder,
            chosen,
        };
        self.chosen(new, Counted { at, tracker }).await
    }

    /// The tracker for a try at `at`, while its origin is not locked out
    /// of the account.
    async fn unlocked_tracker(&self, at: CountedAt<'_>) -> Result<LoginAttemptTracker, AppError> {
        let tracker = self
            .ports
            .attempts
            .held(at, async { Familiarity::New })
            .await?;
        if tracker.is_locked(clock::now()) {
            return Err(AppError::AccountLocked(
                "too many failed attempts".to_owned(),
            ));
        }
        Ok(tracker)
    }

    /// Marks `reset` completed for `holder` at `now` and stores it so,
    /// refusing a change already used.
    async fn complete(
        &self,
        tenant: &ScopedTenant,
        reset: &mut PasswordResetRequest,
        holder: &User<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        reset
            .complete_in_sign_in(holder, now)
            .map_err(|_| unusable_change())?;
        self.ensure_completed_here(tenant, reset).await
    }

    /// Stores `reset` as completed, refusing it when another try completed
    /// it first: a change sets one password.
    async fn ensure_completed_here(
        &self,
        tenant: &ScopedTenant,
        reset: &PasswordResetRequest,
    ) -> Result<(), AppError> {
        let completed = self
            .ports
            .reset_store
            .complete(tenant, reset)
            .await
            .or_internal()?;
        if !completed {
            return Err(unusable_change());
        }
        Ok(())
    }
}

impl Command for ChangeDueUseCase {
    type Caller = ScopedTenant;
    type Input = DueChangeRequest;
    type Output = Result<LoginOutcome, AppError>;

    /// Sets `request.new_password` on the account whose sign-in handed back
    /// `request.change_token`, ends every session it held, records
    /// `authentication.password_reset_completed`, and finishes the sign-in
    /// with the new password: a session opens, owing whatever second factor
    /// the sign-in asks, recorded as any password sign-in is.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for malformed tokens/passwords or violated tenant password rules; each refusal counts towards address lockout.
    /// - `AppError::NotFound` for an unknown, expired, spent or reset token, an account unable to sign in, or a password not due to change.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` for network lockout or repeated wrong codes.
    /// - `AppError::Forbidden` for a wrong/spent code, disabled passwords, or no personal proof for an admin-set password.
    /// - `AppError::Busy` when hashing cannot start; `Internal` on storage, hashing or audit failure; finishing may return [`LoginUseCase`](crate::use_cases::authentication::password::LoginUseCase)'s errors.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: DueChangeRequest,
    ) -> Result<LoginOutcome, AppError> {
        validate_password(request.new_password.expose())?;
        let now = clock::now();
        let FollowedReset {
            mut reset,
            mut holder,
        } = self
            .open_change(tenant, request.change_token.expose(), now)
            .await?;
        let chosen = self.proved_choice(tenant, &holder, &request).await?;
        self.complete(tenant, &mut reset, &holder, now).await?;
        let replacement = self.ports.replacement.replacement();
        replacement.install(tenant, &mut holder, &chosen).await?;
        auditor
            .dispatch_by(&ActorRef::User(*holder.id()), reset.take_events(tenant))
            .await
            .or_internal()?;
        let sign_in = finished_sign_in(&holder, request);
        self.login.after_change(tenant, auditor, sign_in).await
    }
}

/// The sign-in a change finishes: `holder`'s address with the new password
/// `request` set, from where it came.
fn finished_sign_in(holder: &User<ResolvedTenant>, request: DueChangeRequest) -> LoginRequest {
    LoginRequest {
        email: holder.email().clone(),
        password: request.new_password,
        device_secret: request.device_secret,
        challenge: None,
        origin: request.origin,
        confirm_at: request.confirm_at,
    }
}

/// The answer to a token that cannot set a password: unknown, expired,
/// used, a mailed reset link, or its account shut, all alike.
fn unusable_change() -> AppError {
    AppError::NotFound(message!(
        "authentication-invalid-or-expired-password-change",
        "invalid or expired password change"
    ))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authentication::credentials::breach::BreachPolicy;
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
    use ianua_domain::domains::authentication::credentials::password_rules::PasswordDue;
    use ianua_domain::domains::authentication::device_trust::TrustWindow;
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::authentication::mfa::owed::{Enrolment, SecondFactor};
    use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
    use ianua_domain::domains::authentication::recovery::reset::CreateResetParams;
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::test_support::fakes::{
        FakeHasher, FakeMfaVerifier, FakeRefreshTokenGenerator,
    };
    use ianua_domain::types::password_policy::{ExpiryDays, PasswordExpiry, PasswordHygiene};
    use ianua_domain::types::{Email, HttpsUrl, Lifetime, PasswordPolicy, UserId};

    use super::*;
    use crate::ports::TenantScoped;
    use crate::ports::authentication::UserLookup;
    use crate::ports::identity::UserStore;
    use crate::ports::shared::MailSetup;
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, FakeResetRequestStore, FakeSignInAttemptCounts,
        hashing_with, lockout,
    };
    use crate::test_support::identity::{FakeUserStore, RecordingCredentialStore};
    use crate::test_support::tenant::{FakeTenantStore, tenant_store_signing_in_with};
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor, test_ctx,
        test_link_scope,
    };
    use crate::use_cases::authentication::password::sign_in::confirmation::{
        ConfirmationLinkPolicy, ConfirmationMailPorts,
    };
    use crate::use_cases::authentication::password::sign_in::due::{
        ChangeToken, DuePorts, PasswordChangeOwed,
    };
    use crate::use_cases::authentication::password::sign_in::login::{LoginPorts, LoginSettings};
    use crate::use_cases::authentication::password::sign_in::login_security::{
        LoginSecurityPorts, SecurityRules,
    };

    const ANN: &str = "ann@acme.test";
    const CURRENT: &str = "told on the phone 41";
    const CHOSEN: &str = "Quiet harbour at 6 bells";
    const RIGHT_CODE: &str = "123456";

    /// Ann's account as sign-in finds it, with the password the credential
    /// store holds now, so a changed password signs her in.
    struct CurrentPassword {
        ann: UserId,
        credentials: Arc<RecordingCredentialStore>,
    }

    impl TenantScoped for CurrentPassword {}

    #[async_trait]
    impl UserLookup for CurrentPassword {
        async fn find_by_email(
            &self,
            _: &ScopedTenant,
            email: &Email,
        ) -> Result<Option<LoginCandidate>, DomainError> {
            if email.as_str() != ANN {
                return Ok(None);
            }
            Ok(self
                .credentials
                .hash_of(&self.ann)
                .map(|password_hash| LoginCandidate {
                    user_id: self.ann,
                    password_hash,
                    status: UserStatus::Active,
                    email_standing: AddressStanding::Verified,
                    enrolment: Enrolment::NotEnrolled,
                    vouching: Vouching::Absent,
                    password_due: PasswordDue::Current,
                }))
        }
    }

    /// How Ann's current password came to need changing.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Owed {
        /// She chose it, and it is past Acme's thirty days.
        Expired,
        /// Sam set it; she holds no factor.
        SetBySam,
        /// Sam set it; she holds an authenticator app.
        SetBySamWithApp,
    }

    /// Ann, whose password must change as `owed` says, in a tenant under
    /// `settings`, on a deployment whose mail is set up as `mail` says.
    struct Acme {
        ann: UserId,
        resets: Arc<FakeResetRequestStore>,
        credentials: Arc<RecordingCredentialStore>,
        attempts: Arc<FakeSignInAttemptCounts>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        login: Arc<LoginUseCase>,
        change: ChangeDueUseCase,
    }

    /// The stores both halves of the sign-in share.
    struct Shared {
        credentials: Arc<RecordingCredentialStore>,
        resets: Arc<FakeResetRequestStore>,
        factors: Arc<FakeMfaEnrollmentStore>,
        mailer: Arc<FakeMailer>,
        mail: Arc<dyn MailSetup>,
    }

    impl Shared {
        fn due(&self) -> DuePorts {
            DuePorts {
                credentials: self.credentials.clone(),
                reset_store: self.resets.clone(),
                enrollments: self.factors.clone(),
                mail: self.mail.clone(),
                mailer: self.mailer.clone(),
                ..DuePorts::fakes()
            }
        }
    }

    /// Acme's rules: `settings`, with passwords lasting thirty days.
    fn with_expiry(settings: TenantAuthSettings) -> TenantAuthSettings {
        let thirty_days = PasswordHygiene {
            expiry: PasswordExpiry::After(ExpiryDays::new(30).unwrap()),
            ..PasswordHygiene::default()
        };
        TenantAuthSettings {
            password_policy: PasswordPolicy::default().with_hygiene(thirty_days),
            ..settings
        }
    }

    /// Ann's current password as `owed` says it came about.
    fn current_password(ann: UserId, owed: Owed) -> RecordingCredentialStore {
        let held = RecordingCredentialStore::holding(ann, &FakeHasher.hash(CURRENT).unwrap());
        match owed {
            Owed::Expired => held.changed_seconds_ago(31 * 86_400),
            Owed::SetBySam | Owed::SetBySamWithApp => held.set_by_admin(ann),
        }
    }

    /// Ann's factors as `owed` says.
    fn factors_of(ann: UserId, owed: Owed) -> FakeMfaEnrollmentStore {
        match owed {
            Owed::SetBySamWithApp => FakeMfaEnrollmentStore::active_for(ann),
            Owed::Expired | Owed::SetBySam => FakeMfaEnrollmentStore::empty(),
        }
    }

    /// Account lookup and rate limits shared by password login and replacement.
    struct PasswordSetup {
        users: Arc<FakeUserStore>,
        tenants: Arc<FakeTenantStore>,
        tokens: Arc<dyn RefreshTokenGenerator>,
        counts: SignInCounts,
    }

    impl PasswordSetup {
        /// Login reads the current password and issues challenges through the shared stores.
        fn login(&self, ann: UserId, shared: &Shared) -> Arc<LoginUseCase> {
            Arc::new(LoginUseCase::new(
                LoginPorts {
                    tenants: self.tenants.clone(),
                    user_lookup: Arc::new(CurrentPassword {
                        ann,
                        credentials: shared.credentials.clone(),
                    }),
                    attempts: self.counts.clone(),
                    token_generator: self.tokens.clone(),
                    hashing: hashing_with(Arc::new(FakeHasher)),
                    security: LoginSecurityPorts {
                        users: self.users.clone(),
                        ..LoginSecurityPorts::fakes()
                    },
                    confirmation: ConfirmationMailPorts {
                        mail: shared.mail.clone(),
                        ..ConfirmationMailPorts::fakes()
                    },
                    password_due: shared.due(),
                    ..LoginPorts::fakes()
                },
                settings_of(),
            ))
        }

        /// Password replacement updates the credentials used by the follow-up login.
        fn change(&self, shared: &Shared, login: &Arc<LoginUseCase>) -> ChangeDueUseCase {
            ChangeDueUseCase::new(
                lockout(),
                ChangeDuePorts {
                    reset_store: shared.resets.clone(),
                    replacement: ReplacementPorts {
                        user_store: self.users.clone(),
                        credential_store: shared.credentials.clone(),
                        tenant_store: self.tenants.clone(),
                        hashing: hashing_with(Arc::new(FakeHasher)),
                        ..ReplacementPorts::fakes()
                    },
                    token_generator: self.tokens.clone(),
                    attempts: self.counts.clone(),
                    due: shared.due(),
                    encryptor: Arc::new(FakeEncryptor),
                    verifier: Arc::new(FakeMfaVerifier {
                        valid_code: RIGHT_CODE.to_owned(),
                    }),
                    ..ChangeDuePorts::fakes()
                },
                Arc::clone(login),
            )
        }
    }

    impl Acme {
        fn under(owed: Owed, settings: TenantAuthSettings, mail: Arc<dyn MailSetup>) -> Self {
            let ann = UserId::new();
            let credentials = Arc::new(current_password(ann, owed));
            let shared = Shared {
                credentials: credentials.clone(),
                resets: Arc::new(FakeResetRequestStore::empty()),
                factors: Arc::new(factors_of(ann, owed)),
                mailer: Arc::new(FakeMailer::new()),
                mail,
            };
            let attempts = Arc::new(FakeSignInAttemptCounts::default());
            let setup = PasswordSetup {
                users: Arc::new(FakeUserStore::with_user(ann, ANN)),
                tenants: tenant_store_signing_in_with(with_expiry(settings)),
                tokens: Arc::new(FakeRefreshTokenGenerator::new()),
                counts: SignInCounts::new(attempts.clone(), Fake::fake()),
            };
            let login = setup.login(ann, &shared);
            let change = setup.change(&shared, &login);
            Self {
                ann,
                resets: shared.resets.clone(),
                credentials,
                attempts,
                mailer: shared.mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                login,
                change,
            }
        }

        /// Ann, whose own password expired, on a deployment that mails.
        fn new() -> Self {
            Self::with(Owed::Expired)
        }

        /// Ann, whose password must change as `owed` says, on a deployment
        /// that mails.
        fn with(owed: Owed) -> Self {
            Self::under(owed, TenantAuthSettings::default(), Fake::fake())
        }

        /// Ann signs in with her current password, and is told of the
        /// change her sign-in owes.
        fn owed(&self) -> PasswordChangeOwed {
            let request = LoginRequest {
                email: Email::new(ANN).unwrap(),
                password: Secret::new(CURRENT),
                device_secret: None,
                challenge: None,
                origin: ClientOrigin::default(),
                confirm_at: test_link_scope(),
            };
            let outcome = block_on(self.login.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                request,
            ))
            .unwrap();
            let LoginOutcome::PasswordChangeOwed(owed) = outcome else {
                panic!("the sign-in owes a password change");
            };
            owed
        }

        /// The token of the change `owed`: handed back, or read from the
        /// mail it went out in.
        fn token_of(&self, owed: &PasswordChangeOwed) -> Secret {
            match &owed.token {
                ChangeToken::HandedBack(token) => Secret::new(token.expose()),
                ChangeToken::Mailed => {
                    let link = self.mailer.action_url();
                    let token = link.split("token=").nth(1).expect("the link carries it");
                    Secret::new(token.split('&').next().unwrap_or(token))
                }
            }
        }

        fn change(&self, token: &Secret, password: &str) -> Result<LoginOutcome, AppError> {
            self.change_with(token, password, None)
        }

        fn change_with(
            &self,
            token: &Secret,
            password: &str,
            code: Option<&str>,
        ) -> Result<LoginOutcome, AppError> {
            let request = DueChangeRequest {
                change_token: Secret::new(token.expose()),
                new_password: Secret::new(password),
                factor_code: code.map(str::to_owned),
                device_secret: None,
                origin: ClientOrigin::default(),
                confirm_at: test_link_scope(),
            };
            block_on(self.change.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn failed_attempts(&self) -> u64 {
            let tenant = test_ctx().tenant();
            let ann = Email::new(ANN).unwrap();
            self.attempts.on_account(CountedAccount::Tenant {
                tenant: &tenant,
                email: &ann,
            })
        }
    }

    fn settings_of() -> LoginSettings {
        LoginSettings {
            security: SecurityRules {
                breach_policy: BreachPolicy::Off,
                device_trust: TrustWindow::standard(),
            },
            confirmation: ConfirmationLinkPolicy {
                lifetime: Lifetime::seconds(900).unwrap(),
                base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
            },
        }
    }

    /// Ann's own password expired. She sets a new one with the token her
    /// sign-in handed back. The password is stored as hers, and the sign-in
    /// finishes with a session.
    #[test]
    fn a_new_password_finishes_the_sign_in() {
        let acme = Acme::new();
        let owed = acme.owed();

        let outcome = acme.change(&acme.token_of(&owed), CHOSEN).unwrap();

        let LoginOutcome::SignedIn(success) = outcome else {
            panic!("the sign-in finished");
        };
        assert_eq!(success.user_id, acme.ann);
        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert_eq!(
            acme.credentials.hash_of(&acme.ann),
            Some(FakeHasher.hash(CHOSEN).unwrap())
        );
    }

    /// The same on a deployment with no mail server: nothing waits for a
    /// mail, and the sign-in finishes the same way.
    #[test]
    fn a_new_password_finishes_the_sign_in_where_nothing_is_mailed() {
        let acme = Acme::under(
            Owed::Expired,
            TenantAuthSettings::default(),
            FakeMailSetup::not_set_up(),
        );
        let owed = acme.owed();

        let outcome = acme.change(&acme.token_of(&owed), CHOSEN).unwrap();

        assert!(matches!(outcome, LoginOutcome::SignedIn(_)));
    }

    /// Sam set Ann's password, and she holds no factor. The change's token
    /// went to her mailbox, not back to the browser; following it, she sets
    /// her new password and the sign-in finishes.
    #[test]
    fn a_password_sam_set_is_changed_with_the_mailed_token() {
        let acme = Acme::with(Owed::SetBySam);
        let owed = acme.owed();

        let outcome = acme.change(&acme.token_of(&owed), CHOSEN).unwrap();

        assert!(matches!(owed.token, ChangeToken::Mailed));
        assert!(matches!(outcome, LoginOutcome::SignedIn(_)));
    }

    /// Replacing an administrator-set password without Ann's factor code
    /// requires step-up and preserves the current password.
    #[test]
    fn a_password_sam_set_is_not_changed_without_the_persons_factor() {
        let acme = Acme::with(Owed::SetBySamWithApp);
        let owed = acme.owed();

        let result = acme.change(&acme.token_of(&owed), CHOSEN);

        assert!(matches!(result, Err(AppError::StepUpRequired)));
        assert_eq!(
            acme.credentials.hash_of(&acme.ann),
            Some(FakeHasher.hash(CURRENT).unwrap())
        );
    }

    /// A wrong factor code refuses replacement of the administrator-set
    /// password and preserves its hash.
    #[test]
    fn a_wrong_factor_code_sets_nothing() {
        let acme = Acme::with(Owed::SetBySamWithApp);
        let owed = acme.owed();

        let result = acme.change_with(&acme.token_of(&owed), CHOSEN, Some("000000"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            acme.credentials.hash_of(&acme.ann),
            Some(FakeHasher.hash(CURRENT).unwrap())
        );
    }

    /// Ann gives a right code from her authenticator with the new password,
    /// on a deployment with no mail server too. The change is made and the
    /// sign-in finishes.
    #[test]
    fn a_password_sam_set_is_changed_with_the_persons_factor() {
        let setups: [Arc<dyn MailSetup>; 2] = [Fake::fake(), FakeMailSetup::not_set_up()];
        for mail in setups {
            let acme = Acme::under(Owed::SetBySamWithApp, TenantAuthSettings::default(), mail);
            let owed = acme.owed();

            let outcome = acme
                .change_with(&acme.token_of(&owed), CHOSEN, Some(RIGHT_CODE))
                .unwrap();

            assert!(matches!(outcome, LoginOutcome::SignedIn(_)));
            assert!(acme.mailer.recipients().is_empty());
        }
    }

    /// Acme requires a second factor and Ann has none. Setting the new
    /// password finishes the sign-in still owing the factor to set up.
    #[test]
    fn a_new_password_leaves_the_second_factor_owed() {
        let required = TenantAuthSettings {
            mfa_policy: MfaPolicy::Required,
            ..TenantAuthSettings::default()
        };
        let acme = Acme::under(Owed::Expired, required, Fake::fake());
        let owed = acme.owed();

        let outcome = acme.change(&acme.token_of(&owed), CHOSEN).unwrap();

        let LoginOutcome::SignedIn(success) = outcome else {
            panic!("the sign-in finished");
        };
        assert_eq!(success.second_factor, SecondFactor::Enrol);
    }

    /// Reusing a consumed change token returns not found and preserves
    /// the password chosen by its first use.
    #[test]
    fn a_change_sets_one_password() {
        let acme = Acme::new();
        let token = acme.token_of(&acme.owed());
        acme.change(&token, CHOSEN).unwrap();

        let again = acme.change(&token, "Another quiet river 7");

        assert!(matches!(again, Err(AppError::NotFound(_))));
        assert_eq!(
            acme.credentials.hash_of(&acme.ann),
            Some(FakeHasher.hash(CHOSEN).unwrap())
        );
    }

    /// A short password increments Ann's failed attempts without consuming
    /// the change token, which still accepts a valid replacement.
    #[test]
    fn a_refused_password_counts_and_the_change_stays_open() {
        let acme = Acme::new();
        let token = acme.token_of(&acme.owed());

        let refused = acme.change(&token, "nine char");

        assert!(matches!(refused, Err(AppError::Domain(_))));
        assert_eq!(acme.failed_attempts(), 1);
        assert!(acme.change(&token, CHOSEN).is_ok());
    }

    /// A user-requested reset token cannot answer an in-sign-in password
    /// change and leaves the current password intact.
    #[test]
    fn a_mailed_reset_link_does_not_answer_a_sign_in_change() {
        let acme = Acme::new();
        let holder = FakeUserStore::with_user(acme.ann, ANN);
        let ann = block_on(holder.find_by_id(&test_ctx().tenant(), &acme.ann))
            .unwrap()
            .unwrap();
        let tokens = FakeRefreshTokenGenerator::new();
        let link = tokens.generate().unwrap();
        let (raw, token_hash) = link.into_parts();
        let mailed = PasswordResetRequest::create(
            &ann,
            CreateResetParams {
                initiator: ResetInitiator::User,
                token_hash,
                lifetime: Lifetime::seconds(900).unwrap(),
            },
        )
        .unwrap();
        block_on(acme.resets.save(&test_ctx().tenant(), &mailed)).unwrap();

        let result = acme.change(&raw, CHOSEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            acme.credentials.hash_of(&acme.ann),
            Some(FakeHasher.hash(CURRENT).unwrap())
        );
    }

    /// An unknown change token is refused as not found.
    #[test]
    fn an_unknown_token_sets_nothing() {
        let acme = Acme::new();

        let result = acme.change(&Secret::new("fake_refresh_99"), CHOSEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
