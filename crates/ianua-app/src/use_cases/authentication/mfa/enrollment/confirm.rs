//! Confirming a newly scanned authenticator with a code from it: the
//! factor comes into force, a fresh set of recovery codes is shown once,
//! and a sign-in that waited for the factor is let in.
//!
//! A new factor is a change of how the account signs in, so it ends every
//! session opened before it. The session the person set it up from is kept
//! through it, proved by the code that confirmed the factor.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    AnsweredCode, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, TokenHash};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{RecoveryCodeGenerator, RecoveryCodeStore};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::failed_factor::FactorCodePorts;
use crate::use_cases::authentication::mfa::enrollment::setup_proof::{
    FactorSetter, enrollment_refused,
};
use crate::use_cases::authentication::mfa::lookup::existing_pending_enrollment;
use crate::use_cases::authentication::mfa::sessions::raise::{Raise, SessionRaise, answer};
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::{
    PendingSignIn, SignInParties, SignInSources,
};

/// How many recovery codes a confirmed factor comes with.
const RECOVERY_CODES: u8 = 10;

/// The ports [`ConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmPorts {
    /// The person's second factor, and what checks its codes.
    pub codes: FactorCodePorts,
    /// Makes the recovery codes.
    pub recovery_generator: Arc<dyn RecoveryCodeGenerator>,
    /// Keeps the recovery codes.
    pub recovery_store: Arc<dyn RecoveryCodeStore>,
    /// The account, whose way of signing in changes.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant, for its step-up policy.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The session the factor is set up from, or the sign-in that waits
    /// for it.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A code from a newly scanned authenticator.
pub struct ConfirmRequest {
    /// The code it shows.
    pub code: String,
}

/// The recovery codes a confirmed factor comes with, shown once and never
/// kept. They are secrets, so this has no `Debug`.
pub struct EnrollmentConfirmed {
    /// Raw fallback secrets returned only at enrollment confirmation.
    pub recovery_codes: Vec<Secret>,
}

/// The session a confirmation comes from.
enum SetUpFrom {
    /// A finished session of the person, kept through the change.
    OwnSession(Box<Session<ResolvedTenant>>),
    /// A sign-in waiting for this factor, let in by it under the tenant's
    /// step-up policy.
    WaitingSignIn {
        /// The waiting sign-in's session.
        session: Box<Session<ResolvedTenant>>,
        /// What the tenant asks a sign-in to reach.
        policy: StepUpPolicy,
    },
}

impl SetUpFrom {
    /// The session, finished or waiting.
    fn session(&self) -> &Session<ResolvedTenant> {
        match self {
            Self::OwnSession(session) | Self::WaitingSignIn { session, .. } => session,
        }
    }

    /// Carries this session through the change `account` just made, on the
    /// `code` that confirmed the new factor: a finished session is
    /// kept through it, a waiting sign-in is let in by it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the code was proved for another
    ///   account, the session is not a finished one of the account, or the
    ///   waiting sign-in does not take the factor.
    /// - `AppError::Conflict` when the waiting sign-in already proved a
    ///   factor at least as strong.
    fn carry_through(
        &mut self,
        account: &User<ResolvedTenant>,
        code: &AnsweredCode,
    ) -> Result<(), AppError> {
        let proof = ProvedFactor::by_code(code);
        match self {
            Self::OwnSession(session) => session
                .keep_through_own_factor_addition(account, proof)
                .map_err(AppError::from_domain),
            Self::WaitingSignIn { session, policy } => answer(
                session,
                Raise {
                    account,
                    proof,
                    policy,
                },
            ),
        }
    }
}

/// Who confirms a factor: the tenant, their account as it is now, and the
/// session they confirm it from.
struct Setter {
    tenant: ScopedTenant,
    account: User<ResolvedTenant>,
    from: SetUpFrom,
}

/// Confirms a newly scanned authenticator.
pub struct ConfirmUseCase {
    lockout: LockoutPolicy,
    ports: ConfirmPorts,
}

impl ConfirmUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: ConfirmPorts) -> Self {
        Self { lockout, ports }
    }

    /// The account's pending enrollment, with its answer to the code.
    async fn answered_pending(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        code: &str,
        auditor: &RequestAuditor,
    ) -> Result<(MfaEnrollment<ResolvedTenant>, AnsweredCode), AppError> {
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment = existing_pending_enrollment(store, tenant, account.id()).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, auditor)
            .answered(tenant, &mut enrollment, code)
            .await?;
        Ok((enrollment, answered))
    }

    /// Puts `enrollment` in force on `answered`, with a fresh set of
    /// recovery codes, and hands back the codes to show once.
    async fn confirmed(
        &self,
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        answered: &AnsweredCode,
    ) -> Result<(RecoveryCodeSet<ResolvedTenant>, Vec<Secret>), AppError> {
        let pairs = self
            .ports
            .recovery_generator
            .generate_batch(RECOVERY_CODES)
            .await
            .or_internal()?;
        let (raw, hashes): (Vec<Secret>, Vec<TokenHash>) =
            pairs.into_iter().map(|pair| (pair.raw, pair.hash)).unzip();
        let joined = joined_hash(&hashes);
        let codes = RecoveryCodeSet::generate(enrollment.subject_id(), hashes, answered)
            .map_err(AppError::from_domain)?;
        enrollment
            .verify(answered, joined)
            .map_err(|error| enrollment_refused(&error))?;
        Ok((codes, raw))
    }

    /// Who `setter` is: a person signed in, with the session they act
    /// through, or a sign-in waiting for this factor.
    async fn setter(&self, setter: &FactorSetter) -> Result<Setter, AppError> {
        match setter {
            FactorSetter::SignedIn(caller) => {
                let person = self.ports.tenant_authorities.signed_in(caller).await?;
                Ok(Setter {
                    tenant: caller.tenant(),
                    account: person.account,
                    from: SetUpFrom::OwnSession(Box::new(person.session)),
                })
            }
            FactorSetter::SigningIn(pending) => self.waiting(pending).await,
        }
    }

    /// The sign-in `pending` names, waiting for this factor, with its
    /// account and the tenant's step-up policy.
    async fn waiting(&self, pending: &PendingSignIn) -> Result<Setter, AppError> {
        let sources = SignInSources {
            sessions: self.ports.session_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            tenants: self.ports.tenant_store.as_ref(),
        };
        let SignInParties {
            session,
            account,
            policy,
        } = sources
            .parties(&pending.tenant, &pending.session_id, &pending.user_id)
            .await?;
        Ok(Setter {
            tenant: pending.tenant,
            account,
            from: SetUpFrom::WaitingSignIn {
                session: Box::new(session),
                policy,
            },
        })
    }

    /// Keeps the factor, its recovery codes, the account's change of how
    /// it signs in, so sessions from before the change stop counting, and
    /// the session the factor was set up from, carried through it.
    async fn save(
        &self,
        tenant: &ScopedTenant,
        confirmed: Confirmed<'_>,
        from: &SetUpFrom,
    ) -> Result<(), AppError> {
        self.ports
            .codes
            .enrollment_store
            .save(tenant, confirmed.enrollment)
            .await
            .or_internal()?;
        self.ports
            .recovery_store
            .save(tenant, confirmed.codes)
            .await
            .or_internal()?;
        self.ports
            .user_store
            .save(tenant, confirmed.account)
            .await
            .or_internal()?;
        SessionRaise {
            session_store: self.ports.session_store.as_ref(),
        }
        .keep(tenant, from.session())
        .await
    }
}

impl Command for ConfirmUseCase {
    type Caller = FactorSetter;
    type Input = ConfirmRequest;
    type Output = Result<EnrollmentConfirmed, AppError>;

    /// Confirms `setter`'s pending authenticator with `request.code`, and
    /// records `authentication.mfa_enrolled` and
    /// `authentication.recovery_codes_generated`. A sign-in waiting for this
    /// factor is let in by the same code.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `Unauthenticated` for an invalid setter session.
    /// - `AppError::Forbidden` when the originating session cannot survive setup or cannot accept the code, or the code is wrong/spent.
    /// - `AppError::NotFound` for no pending enrollment or a waiting sign-in belonging to another account.
    /// - `AppError::AccountLocked` after too many wrong codes; `Internal` on decryption or storage failure.
    async fn execute(
        &self,
        setter: &FactorSetter,
        auditor: &RequestAuditor,
        request: ConfirmRequest,
    ) -> Result<EnrollmentConfirmed, AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let Setter {
            tenant,
            mut account,
            mut from,
        } = self.setter(setter).await?;
        let (mut enrollment, answered) = self
            .answered_pending(&tenant, &account, &request.code, auditor)
            .await?;
        let (mut codes, recovery_codes) = self.confirmed(&mut enrollment, &answered).await?;
        account.record_credential_change();
        from.carry_through(&account, &answered)?;
        let confirmed = Confirmed {
            enrollment: &enrollment,
            codes: &codes,
            account: &account,
        };
        self.save(&tenant, confirmed, &from).await?;
        let raised = taken_in_order(&tenant, &mut enrollment, &mut codes);
        auditor
            .dispatch_by(&ActorRef::User(*account.id()), raised)
            .await
            .or_internal()?;
        Ok(EnrollmentConfirmed { recovery_codes })
    }
}

/// What a confirmation saves.
#[derive(Clone, Copy)]
struct Confirmed<'a> {
    enrollment: &'a MfaEnrollment<ResolvedTenant>,
    codes: &'a RecoveryCodeSet<ResolvedTenant>,
    account: &'a User<ResolvedTenant>,
}

/// One hash standing for the whole set of recovery codes shown, kept on the
/// confirmed factor.
fn joined_hash(hashes: &[TokenHash]) -> TokenHash {
    let joined: Vec<&str> = hashes.iter().map(TokenHash::as_str).collect();
    TokenHash::from_stored(joined.join(","))
}

/// What the confirmation raised, the factor coming into force first and
/// then the recovery codes it came with, for `tenant`.
fn taken_in_order(
    tenant: &ScopedTenant,
    enrollment: &mut MfaEnrollment<ResolvedTenant>,
    codes: &mut RecoveryCodeSet<ResolvedTenant>,
) -> Vec<DomainEvent> {
    let mut raised = enrollment.take_events(tenant);
    raised.extend(codes.take_events(tenant));
    raised
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
    use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::session::{SessionOrigin, SessionRow};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{CredentialChange, Fact, SessionId, UserId};

    use super::*;
    use crate::ports::authentication::MfaEnrollmentStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeRecoveryCodeStore, FakeSessionStore, lockout,
        session_signed_in, test_caller_id,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };
    use crate::use_cases::authentication::mfa::sessions::sign_in_parties::PendingSignIn;

    const RIGHT_CODE: &str = "123456";

    struct Fixture {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        codes: Arc<FakeRecoveryCodeStore>,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        authorities: FakeTenantAuthorities,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn pending_for(user_id: UserId) -> Self {
            Self {
                enrollments: Arc::new(FakeMfaEnrollmentStore::pending_for(user_id)),
                codes: Arc::new(FakeRecoveryCodeStore::empty()),
                users: Arc::new(FakeUserStore::with_user(user_id, "ann@acme.test")),
                sessions: Arc::new(FakeSessionStore::empty()),
                authorities: FakeTenantAuthorities::holding(&[]),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn confirm_as(
            self,
            setter: &FactorSetter,
            code: &str,
        ) -> (Result<EnrollmentConfirmed, AppError>, Self) {
            let use_case = ConfirmUseCase::new(
                lockout(),
                ConfirmPorts {
                    codes: FactorCodePorts {
                        enrollment_store: self.enrollments.clone(),
                        ..FactorCodePorts::fakes()
                    },
                    recovery_store: self.codes.clone(),
                    user_store: self.users.clone(),
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    session_store: self.sessions.clone(),
                    tenant_authorities: Arc::new(self.authorities),
                    ..ConfirmPorts::fakes()
                },
            );
            let request = ConfirmRequest {
                code: code.to_owned(),
            };
            let audit = self.audit.clone();
            let result = block_on(use_case.execute(setter, &test_auditor(audit), request));
            let fixture = Self {
                authorities: FakeTenantAuthorities::holding(&[]),
                ..self
            };
            (result, fixture)
        }

        fn confirm(self, code: &str) -> (Result<EnrollmentConfirmed, AppError>, Self) {
            self.confirm_as(&FactorSetter::SignedIn(Box::new(test_ctx())), code)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn signing_in(user_id: UserId, session_id: SessionId) -> FactorSetter {
        FactorSetter::SigningIn(PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id,
            user_id,
        })
    }

    /// Whether `session` still counts for the caller's account as the
    /// confirmation left it.
    fn passes_check(fixture: &Fixture, session: &Session<ResolvedTenant>) -> bool {
        let account = block_on(
            fixture
                .users
                .find_by_id(&test_ctx().tenant(), &test_caller_id()),
        )
        .unwrap()
        .unwrap();
        SessionCheck {
            account: &account,
            timeout: &SessionTimeoutPolicy::STANDARD,
            now: clock::now(),
        }
        .admits(session)
    }

    /// A finished session of `user_id` signed in half an hour ago, on
    /// another device.
    fn signed_in_earlier(user_id: UserId) -> Session<ResolvedTenant> {
        let now = clock::now();
        let earlier = now - time::Duration::minutes(30);
        Session::reconstitute(SessionRow {
            id: SessionId::new(),
            user_id,
            refresh_token_hash: TokenHash::from_stored("phone".to_owned()),
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
            signed_in_at: earlier,
            created_at: earlier,
            last_active_at: now,
            expires_at: now + time::Duration::hours(4),
            kept_through: CredentialChange::Never,
            last_use: Fact::Unknown,
        })
        .unwrap()
    }

    fn owing_setup() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Enrol,
        }
    }

    /// Ann types the code her newly scanned authenticator shows. Her factor
    /// is in force, she gets ten recovery codes to keep, they are stored,
    /// and both are recorded.
    #[test]
    fn a_right_code_puts_the_factor_in_force_with_recovery_codes() {
        let (result, fixture) = Fixture::pending_for(test_caller_id()).confirm(RIGHT_CODE);

        let confirmed = result.unwrap();

        assert_eq!(confirmed.recovery_codes.len(), 10);
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .is_active()
        );
        assert_eq!(fixture.codes.remaining(), Some(10));
        assert_eq!(
            fixture.recorded(),
            [
                "authentication.mfa_enrolled",
                "authentication.recovery_codes_generated"
            ]
        );
    }

    /// Confirming Ann's authenticator records the enrollment event used to
    /// invalidate cached callers.
    #[test]
    fn confirming_records_what_drops_cached_sign_ins() {
        let (result, fixture) = Fixture::pending_for(test_caller_id()).confirm(RIGHT_CODE);

        result.unwrap();

        assert!(
            fixture
                .recorded()
                .contains(&"authentication.mfa_enrolled".to_owned())
        );
    }

    /// Ann's new factor changes how she signs in, so devices she remembered
    /// before no longer skip it.
    #[test]
    fn confirming_records_a_change_of_how_the_account_signs_in() {
        let (result, fixture) = Fixture::pending_for(test_caller_id()).confirm(RIGHT_CODE);

        result.unwrap();

        let account = block_on(
            fixture
                .users
                .find_by_id(&test_ctx().tenant(), &test_caller_id()),
        )
        .unwrap()
        .unwrap();
        assert_ne!(account.credentials_changed_at(), CredentialChange::Never);
    }

    /// Pat, signed in on her laptop, sets up an authenticator app and
    /// confirms it with its code. Her laptop session keeps working; the
    /// session on her phone, opened before the change, no longer counts.
    #[test]
    fn the_session_the_factor_was_set_up_from_is_kept_and_earlier_ones_end() {
        let (result, fixture) = Fixture::pending_for(test_caller_id()).confirm(RIGHT_CODE);

        result.unwrap();

        let laptop = fixture.sessions.get_session(&test_session_id()).unwrap();
        assert!(passes_check(&fixture, &laptop));
        assert!(!passes_check(
            &fixture,
            &signed_in_earlier(test_caller_id())
        ));
    }

    /// A wrong setup code is refused without saving the originating session.
    #[test]
    fn a_guessed_code_keeps_no_session() {
        let (result, fixture) = Fixture::pending_for(test_caller_id()).confirm("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.sessions.get_session(&test_session_id()).is_none());
    }

    /// A wrong code leaves enrollment pending and increments its failed attempts.
    #[test]
    fn a_wrong_code_is_refused_and_counted() {
        let (result, fixture) = Fixture::pending_for(test_caller_id()).confirm("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .is_pending()
        );
        assert_eq!(fixture.enrollments.failed_attempts(), 1);
    }

    /// Five failed attempts lock enrollment against confirmation with a valid code.
    #[test]
    fn a_locked_setup_refuses_even_the_right_code() {
        let fixture = Fixture::pending_for(test_caller_id());
        let mut enrollment = fixture.enrollments.enrollment_of(test_caller_id()).unwrap();
        for _ in 0..5 {
            enrollment.record_failed_attempt(lockout());
        }
        block_on(fixture.enrollments.save(&test_ctx().tenant(), &enrollment)).unwrap();

        let (result, _) = fixture.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
    }

    /// Ann has no setup waiting, only a factor in force. Confirming finds
    /// nothing to confirm.
    #[test]
    fn nothing_pending_is_not_found() {
        let fixture = Fixture {
            enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(test_caller_id())),
            ..Fixture::pending_for(test_caller_id())
        };

        let (result, _) = fixture.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot confirm a pending authenticator.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture {
            authorities: FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ..Fixture::pending_for(test_caller_id())
        };

        let (result, _) = fixture.confirm(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann signs in to a workspace that requires a factor and sets one up.
    /// The code that confirms it lets her waiting sign-in in.
    #[test]
    fn confirming_lets_in_the_sign_in_that_waited_for_it() {
        let ann = UserId::new();
        let session = session_signed_in(ann, owing_setup());
        let session_id = *session.id();
        let fixture = Fixture {
            sessions: Arc::new(FakeSessionStore::with_session(session)),
            ..Fixture::pending_for(ann)
        };

        let (result, fixture) = fixture.confirm_as(&signing_in(ann, session_id), RIGHT_CODE);

        result.unwrap();
        let session = fixture.sessions.get_session(&session_id).unwrap();
        assert_eq!(session.owed(), SecondFactor::NotOwed);
    }

    /// Mallory cannot confirm her factor against Ann's session; the lookup
    /// returns not found and Ann's session still owes enrollment.
    #[test]
    fn a_factor_cannot_let_in_another_users_sign_in() {
        let ann = UserId::new();
        let mallory = UserId::new();
        let session = session_signed_in(ann, owing_setup());
        let session_id = *session.id();
        let fixture = Fixture {
            sessions: Arc::new(FakeSessionStore::with_session(session)),
            ..Fixture::pending_for(mallory)
        };

        let (result, fixture) = fixture.confirm_as(&signing_in(mallory, session_id), RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let session = fixture.sessions.get_session(&session_id).unwrap();
        assert_eq!(session.owed(), SecondFactor::Enrol);
    }
}
