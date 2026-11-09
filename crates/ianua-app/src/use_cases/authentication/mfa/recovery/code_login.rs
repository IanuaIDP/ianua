//! Answering a session's second factor with a recovery code, for a person
//! who lost their authenticator.
//!
//! A recovery code stands in for the factor, so it shares the factor's lock:
//! switching between the two buys no extra guesses. Under a workspace that
//! asks for more than a password, a recovery code alone leaves the person
//! owing a new factor to set up.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    CodeRefused, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::recovery::codes::{RecoveryAttempt, RecoveryCodeSet};
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId, TokenHash, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, RecoveryCodeGenerator, RecoveryCodeStore};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_steps::recovery_refused;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::failed_factor::FailedFactorLog;
use crate::use_cases::authentication::mfa::lookup::{
    existing_active_enrollment, existing_recovery_codes,
};
use crate::use_cases::authentication::mfa::sessions::raise::{SessionRaise, answer_parties};
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::SignInSources;

/// The ports [`RecoveryCodeLoginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RecoveryCodeLoginPorts {
    /// The session the code is given for.
    pub session_store: Arc<dyn SessionStore>,
    /// The session's account.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant, for its step-up policy.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The person's recovery codes.
    pub recovery_store: Arc<dyn RecoveryCodeStore>,
    /// Hashes a typed code the way the codes are stored.
    pub recovery_generator: Arc<dyn RecoveryCodeGenerator>,
    /// The second factor whose lock recovery codes share.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
}

/// A recovery code offered in place of a second factor. The code is a
/// secret, so this has no `Debug`.
pub struct RecoveryCodeLoginRequest {
    /// The session waiting on the second factor.
    pub session_id: SessionId,
    /// Whose session it is.
    pub user_id: UserId,
    /// The recovery code as typed.
    pub raw_code: Secret,
}

/// Answers a session's second factor with a recovery code.
pub struct RecoveryCodeLoginUseCase {
    lockout: LockoutPolicy,
    ports: RecoveryCodeLoginPorts,
}

impl RecoveryCodeLoginUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: RecoveryCodeLoginPorts) -> Self {
        Self { lockout, ports }
    }

    /// The person's codes with the typed one spent, not yet stored: the
    /// code stays unspent unless the session takes it. A refused code is
    /// saved with the factor, so a wrong one counts, and recorded before
    /// the refusal.
    async fn redeemed(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        user_id: &UserId,
        raw_code: &Secret,
    ) -> Result<Redeemed, AppError> {
        let store = self.ports.enrollment_store.as_ref();
        let mut factor = existing_active_enrollment(store, tenant, user_id).await?;
        let mut codes =
            existing_recovery_codes(self.ports.recovery_store.as_ref(), tenant, user_id).await?;
        let hash = self.ports.recovery_generator.hash_raw(raw_code);
        let redeemed = codes.redeem(RecoveryAttempt {
            hash: &hash,
            factor: &mut factor,
            lockout: self.lockout,
        });
        let refused = match redeemed {
            Ok(proof) => {
                return Ok(Redeemed {
                    codes,
                    hash,
                    factor,
                    proof,
                });
            }
            Err(refused) => refused,
        };
        self.save_factor(tenant, &factor).await?;
        if let CodeRefused::Wrong = refused {
            self.record_wrong(tenant, auditor, &mut factor).await?;
        }
        Err(recovery_refused(refused))
    }

    /// Stores the code `hash` of `codes` as used, unless another sign-in
    /// spent it first, which refuses this one as if the code were wrong.
    async fn spend(
        &self,
        tenant: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
        hash: &TokenHash,
    ) -> Result<(), AppError> {
        let spent = self
            .ports
            .recovery_store
            .spend(tenant, codes, hash)
            .await
            .or_internal()?;
        if !spent {
            return Err(recovery_refused(CodeRefused::Wrong));
        }
        Ok(())
    }

    async fn save_factor(
        &self,
        tenant: &ScopedTenant,
        factor: &MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .enrollment_store
            .save(tenant, factor)
            .await
            .or_internal()
    }

    fn session_raise(&self) -> SessionRaise<'_> {
        SessionRaise {
            session_store: self.ports.session_store.as_ref(),
        }
    }

    async fn record_wrong(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        factor: &mut MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), AppError> {
        FailedFactorLog { auditor }.record(tenant, factor).await
    }
}

impl Command for RecoveryCodeLoginUseCase {
    type Caller = ScopedTenant;
    type Input = RecoveryCodeLoginRequest;
    type Output = Result<SecondFactor, AppError>;

    /// Spends `request.raw_code`, records it on the session as the domain
    /// allows, and records `authentication.recovery_code_used`. Answers what
    /// the session still owes: [`SecondFactor::Enrol`] when the person must
    /// set up a new factor before they are let in. Of two sign-ins offering
    /// one code at once, only one gets through.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `NotFound` for an unknown/foreign session, no factor or no recovery codes.
    /// - `AppError::Forbidden` for a foreign/spent code, a concurrent spend, or a session that cannot accept it.
    /// - `AppError::Conflict` when a factor is already proved; `AccountLocked` after too many failures.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RecoveryCodeLoginRequest,
    ) -> Result<SecondFactor, AppError> {
        crate::input::validate_token("recovery_code", request.raw_code.expose())?;
        let sources = SignInSources {
            sessions: self.ports.session_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            tenants: self.ports.tenant_store.as_ref(),
        };
        let mut parties = sources
            .parties(tenant, &request.session_id, &request.user_id)
            .await?;
        let Redeemed {
            mut codes,
            hash,
            factor,
            proof,
        } = self
            .redeemed(tenant, auditor, &request.user_id, &request.raw_code)
            .await?;
        answer_parties(&mut parties, proof)?;
        self.spend(tenant, &codes, &hash).await?;
        self.session_raise().keep(tenant, &parties.session).await?;
        self.save_factor(tenant, &factor).await?;
        auditor
            .dispatch_by(&ActorRef::User(request.user_id), codes.take_events(tenant))
            .await
            .or_internal()?;
        Ok(parties.session.owed())
    }
}

/// A recovery code spent on the person's codes, with its hash, the factor
/// it stood in for and the proof it gives, before any is stored.
struct Redeemed {
    codes: RecoveryCodeSet<ResolvedTenant>,
    hash: TokenHash,
    factor: MfaEnrollment<ResolvedTenant>,
    proof: ProvedFactor,
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;

    use super::*;
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeRecoveryCodeStore, FakeSessionStore, lockout, session_signed_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_signing_in_with, test_tenant_for_ctx,
    };
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    fn owing_a_factor() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Verify,
        }
    }

    struct Fixture {
        ann: UserId,
        session_id: SessionId,
        sessions: Arc<FakeSessionStore>,
        codes: Arc<FakeRecoveryCodeStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn signed_in_as(progress: SignInProgressRow) -> Self {
            let ann = UserId::new();
            let session = session_signed_in(ann, progress);
            Self {
                ann,
                session_id: *session.id(),
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                codes: Arc::new(FakeRecoveryCodeStore::with_codes(
                    ann,
                    &["hash_a", "hash_b"],
                )),
                enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn waiting() -> Self {
            Self::signed_in_as(owing_a_factor())
        }

        fn redeem_as(&self, user_id: UserId, code: &str) -> Result<SecondFactor, AppError> {
            let request = RecoveryCodeLoginRequest {
                session_id: self.session_id,
                user_id,
                raw_code: Secret::new(code),
            };
            self.redeem_through(self.codes.clone(), request)
        }

        fn redeem_through(
            &self,
            recovery_store: Arc<dyn RecoveryCodeStore>,
            request: RecoveryCodeLoginRequest,
        ) -> Result<SecondFactor, AppError> {
            let use_case = RecoveryCodeLoginUseCase::new(
                lockout(),
                RecoveryCodeLoginPorts {
                    session_store: self.sessions.clone(),
                    user_store: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                    tenant_store: self.tenants.clone(),
                    recovery_store,
                    enrollment_store: self.enrollments.clone(),
                    ..RecoveryCodeLoginPorts::fakes()
                },
            );
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn redeem(&self, code: &str) -> Result<SecondFactor, AppError> {
            self.redeem_as(self.ann, code)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann lost her phone and types one of her recovery codes. Her sign-in
    /// is finished, one code is spent, and the use is recorded.
    #[test]
    fn a_right_code_finishes_the_sign_in_and_is_recorded() {
        let fixture = Fixture::waiting();

        let owed = fixture.redeem("code_a").unwrap();

        assert_eq!(owed, SecondFactor::NotOwed);
        assert_eq!(fixture.codes.remaining(), Some(1));
        assert_eq!(fixture.recorded(), ["authentication.recovery_code_used"]);
    }

    /// Ann's workspace asks every sign-in for a second factor. Her recovery
    /// code lets her past the lost one, and she is asked to set up a new
    /// factor before she is let in.
    #[test]
    fn under_a_required_factor_a_recovery_code_leaves_a_factor_to_set_up() {
        let fixture = Fixture {
            tenants: tenant_store_signing_in_with(TenantAuthSettings {
                mfa_policy: MfaPolicy::Required,
                step_up_policy: StepUpPolicy::strict(),
                ..TenantAuthSettings::default()
            }),
            ..Fixture::waiting()
        };

        let owed = fixture.redeem("code_a").unwrap();

        assert_eq!(owed, SecondFactor::Enrol);
    }

    /// A wrong recovery code is refused, increments the factor's failed
    /// attempts and records a failed verification.
    #[test]
    fn a_wrong_code_is_refused_counted_and_recorded() {
        let fixture = Fixture::waiting();

        let result = fixture.redeem("code_z");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.enrollments.failed_attempts(), 1);
        assert_eq!(fixture.recorded(), ["authentication.mfa_failed"]);
    }

    /// A factor locked after five failed attempts refuses a valid recovery
    /// code without spending either available code.
    #[test]
    fn a_locked_factor_refuses_even_a_right_code() {
        let fixture = Fixture::waiting();
        let mut factor = fixture.enrollments.enrollment_of(fixture.ann).unwrap();
        for _ in 0..5 {
            factor.record_failed_attempt(lockout());
        }
        block_on(fixture.enrollments.save(&test_ctx().tenant(), &factor)).unwrap();

        let result = fixture.redeem("code_a");

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
        assert_eq!(fixture.codes.remaining(), Some(2));
    }

    /// Naming Ann's waiting session with another user's ID returns not found.
    #[test]
    fn another_users_session_is_not_found() {
        let fixture = Fixture::waiting();

        let result = fixture.redeem_as(UserId::new(), "code_a");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann never kept recovery codes. There is nothing to spend, so it is
    /// not found.
    #[test]
    fn an_account_without_codes_is_not_found() {
        let fixture = Fixture {
            codes: Arc::new(FakeRecoveryCodeStore::empty()),
            ..Fixture::waiting()
        };

        let result = fixture.redeem("code_a");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's session already proved her authenticator code. A recovery code
    /// on top answers nothing it owes, so it is refused and stays unspent.
    #[test]
    fn a_finished_session_refuses_a_recovery_code_and_keeps_it() {
        let fixture = Fixture::signed_in_as(SignInProgressRow {
            factor: FactorProved::Proved(MfaFactor::Totp),
            owed: SecondFactor::NotOwed,
            ..owing_a_factor()
        });

        let result = fixture.redeem("code_a");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.codes.remaining(), Some(2));
    }

    /// A recovery code spent on one session is refused on a new waiting session.
    #[test]
    fn a_used_code_cannot_be_used_again() {
        let fixture = Fixture::waiting();
        fixture.redeem("code_a").unwrap();
        let again = session_signed_in(fixture.ann, owing_a_factor());
        let fixture = Fixture {
            session_id: *again.id(),
            sessions: Arc::new(FakeSessionStore::with_session(again)),
            ..fixture
        };

        let result = fixture.redeem("code_a");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Two sign-ins read the same unused recovery code, but only the first
    /// spends it; the second is refused and still owes its factor.
    #[test]
    fn a_code_spent_twice_at_once_finishes_one_sign_in() {
        let fixture = Fixture::waiting();
        let mallorys = session_signed_in(fixture.ann, owing_a_factor());
        let mallorys_id = *mallorys.id();
        block_on(fixture.sessions.save(&test_ctx().tenant(), &mallorys)).unwrap();
        let racing: Arc<dyn RecoveryCodeStore> = Arc::new(ReadBeforeWrite::new(
            FakeRecoveryCodeStore::with_codes(fixture.ann, &["hash_a", "hash_b"]),
            fixture.codes.clone(),
        ));
        fixture
            .redeem_through(racing.clone(), code_a_for(fixture.session_id, fixture.ann))
            .unwrap();

        let result = fixture.redeem_through(racing, code_a_for(mallorys_id, fixture.ann));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        let still_waiting = fixture.sessions.get_session(&mallorys_id).unwrap();
        assert_eq!(still_waiting.owed(), SecondFactor::Verify);
    }

    /// The code `code_a` offered for `user_id`'s session `session_id`.
    fn code_a_for(session_id: SessionId, user_id: UserId) -> RecoveryCodeLoginRequest {
        RecoveryCodeLoginRequest {
            session_id,
            user_id,
            raw_code: Secret::new("code_a"),
        }
    }
}
