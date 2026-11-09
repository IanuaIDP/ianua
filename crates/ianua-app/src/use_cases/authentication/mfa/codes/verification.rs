//! Answering a session's second factor with a code from the person's
//! authenticator.
//!
//! Called after a sign-in reports that it owes a factor, or later on a
//! session that signed in without one and now needs one for a sensitive
//! action. The domain decides whether the code answers what the session
//! owes, and how far it raises it.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, SessionId, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::failed_factor::FactorCodePorts;
use crate::use_cases::authentication::mfa::lookup::existing_active_enrollment;
use crate::use_cases::authentication::mfa::sessions::raise::SessionRaise;
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::SignInSources;

/// The ports [`VerificationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct VerificationPorts {
    /// The session the code is given for.
    pub session_store: Arc<dyn SessionStore>,
    /// The session's account.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant, for its step-up policy.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The person's second factor, and what checks its codes.
    pub codes: FactorCodePorts,
}

/// A second-factor code offered for one session.
pub struct VerificationRequest {
    /// The session the code is for.
    pub session_id: SessionId,
    /// Whose session it is.
    pub user_id: UserId,
    /// The code as typed.
    pub code: String,
}

/// Answers a session's second factor with an authenticator code.
pub struct VerificationUseCase {
    lockout: LockoutPolicy,
    ports: VerificationPorts,
}

impl VerificationUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: VerificationPorts) -> Self {
        Self { lockout, ports }
    }

    fn sources(&self) -> SignInSources<'_> {
        SignInSources {
            sessions: self.ports.session_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            tenants: self.ports.tenant_store.as_ref(),
        }
    }
}

impl Command for VerificationUseCase {
    type Caller = ScopedTenant;
    type Input = VerificationRequest;
    type Output = Result<(), AppError>;

    /// Checks `request.code` against the person's authenticator, records
    /// the factor on the session as the domain allows, and records
    /// `authentication.mfa_verified`. A wrong code records
    /// `authentication.mfa_failed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `NotFound` for an unknown/foreign session or no active factor.
    /// - `AppError::Forbidden` for a wrong/spent code or a session that cannot accept it.
    /// - `AppError::Conflict` when an equally strong or stronger factor is already proved.
    /// - `AppError::AccountLocked` after too many wrong codes; `Internal` on storage or decryption failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: VerificationRequest,
    ) -> Result<(), AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let mut parties = self
            .sources()
            .parties(tenant, &request.session_id, &request.user_id)
            .await?;
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment = existing_active_enrollment(store, tenant, &request.user_id).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, auditor)
            .answered(tenant, &mut enrollment, &request.code)
            .await?;
        SessionRaise {
            session_store: self.ports.session_store.as_ref(),
        }
        .raise_parties(tenant, &mut parties, ProvedFactor::by_code(&answered))
        .await?;
        parties.session.record_factor_verified();
        auditor
            .dispatch_by(
                &ActorRef::User(request.user_id),
                parties.session.take_events(tenant),
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::ports::authentication::MfaEnrollmentStore;
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSessionStore, lockout, session_signed_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    const RIGHT_CODE: &str = "123456";

    fn owing_a_factor() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Verify,
        }
    }

    fn password_alone() -> SignInProgressRow {
        SignInProgressRow {
            owed: SecondFactor::NotOwed,
            ..owing_a_factor()
        }
    }

    fn proved_by_code() -> SignInProgressRow {
        SignInProgressRow {
            factor: FactorProved::Proved(MfaFactor::Totp),
            ..password_alone()
        }
    }

    struct Fixture {
        ann: UserId,
        sessions: Arc<FakeSessionStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn signed_in_as(progress: SignInProgressRow) -> (Self, SessionId) {
            let ann = UserId::new();
            let session = session_signed_in(ann, progress);
            let id = *session.id();
            let fixture = Self {
                ann,
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
                audit: Arc::new(FakeEventDispatcher::new()),
            };
            (fixture, id)
        }

        fn verify(
            &self,
            session_id: SessionId,
            user_id: UserId,
            code: &str,
        ) -> Result<(), AppError> {
            self.verify_through(self.enrollments.clone(), guess(session_id, user_id, code))
        }

        fn verify_through(
            &self,
            enrollment_store: Arc<dyn MfaEnrollmentStore>,
            request: VerificationRequest,
        ) -> Result<(), AppError> {
            let use_case = VerificationUseCase::new(
                lockout(),
                VerificationPorts {
                    session_store: self.sessions.clone(),
                    user_store: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    codes: FactorCodePorts {
                        enrollment_store,
                        ..FactorCodePorts::fakes()
                    },
                    ..VerificationPorts::fakes()
                },
            );
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn session(&self, id: &SessionId) -> Session<ResolvedTenant> {
            self.sessions.get_session(id).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann typed her password and owes her code. She types the one her
    /// authenticator shows; her sign-in is finished and the step recorded.
    #[test]
    fn a_right_code_finishes_the_sign_in_and_is_recorded() {
        let (fixture, session) = Fixture::signed_in_as(owing_a_factor());

        fixture.verify(session, fixture.ann, RIGHT_CODE).unwrap();

        assert_eq!(fixture.session(&session).owed(), SecondFactor::NotOwed);
        assert_eq!(fixture.recorded(), ["authentication.mfa_verified"]);
    }

    /// Ann signed in with her password alone and now steps up for a
    /// sensitive action. Her code raises the session to the second level.
    #[test]
    fn a_session_signed_in_with_a_password_alone_can_step_up() {
        let (fixture, session) = Fixture::signed_in_as(password_alone());

        fixture.verify(session, fixture.ann, RIGHT_CODE).unwrap();

        assert_eq!(
            fixture.session(&session).assurance_level(),
            AssuranceLevel::Aal2
        );
    }

    /// A code spent on Ann's first session cannot finish another session
    /// in the same time window; that session still owes its factor.
    #[test]
    fn a_code_already_used_does_not_answer_a_second_session() {
        let _clock = clock::freeze(clock::now());
        let (fixture, ann_session) = Fixture::signed_in_as(owing_a_factor());
        let mallory = session_signed_in(fixture.ann, owing_a_factor());
        let mallory_session = *mallory.id();
        block_on(fixture.sessions.save(&test_ctx().tenant(), &mallory)).unwrap();
        fixture
            .verify(ann_session, fixture.ann, RIGHT_CODE)
            .unwrap();

        let replayed = fixture.verify(mallory_session, fixture.ann, RIGHT_CODE);

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
        assert_eq!(
            fixture.session(&mallory_session).owed(),
            SecondFactor::Verify
        );
    }

    /// A wrong authenticator code is refused, counts towards the factor's
    /// lock and records a failed verification.
    #[test]
    fn a_wrong_code_is_refused_counted_and_recorded() {
        let (fixture, session) = Fixture::signed_in_as(owing_a_factor());

        let result = fixture.verify(session, fixture.ann, "000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.enrollments.failed_attempts(), 1);
        assert_eq!(fixture.recorded(), ["authentication.mfa_failed"]);
    }

    /// Two wrong codes read through stale enrollment snapshots are both
    /// refused and both count towards the factor's lock.
    #[test]
    fn two_wrong_codes_at_once_both_count() {
        let (fixture, session) = Fixture::signed_in_as(owing_a_factor());
        let racing: Arc<dyn MfaEnrollmentStore> = Arc::new(ReadBeforeWrite::new(
            FakeMfaEnrollmentStore::active_for(fixture.ann),
            fixture.enrollments.clone(),
        ));

        let first = fixture.verify_through(racing.clone(), guess(session, fixture.ann, "000000"));
        let second = fixture.verify_through(racing, guess(session, fixture.ann, "111111"));

        assert!(matches!(first, Err(AppError::Forbidden(_))));
        assert!(matches!(second, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.enrollments.failed_attempts(), 2);
    }

    /// Five failed attempts lock the factor, so even the right code is refused.
    #[test]
    fn a_locked_factor_refuses_even_the_right_code() {
        let (fixture, session) = Fixture::signed_in_as(owing_a_factor());
        let mut enrollment = fixture.enrollments.enrollment_of(fixture.ann).unwrap();
        for _ in 0..5 {
            enrollment.record_failed_attempt(lockout());
        }
        block_on(fixture.enrollments.save(&test_ctx().tenant(), &enrollment)).unwrap();

        let result = fixture.verify(session, fixture.ann, RIGHT_CODE);

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
    }

    /// Naming Ann's waiting session with another user's ID returns not found.
    #[test]
    fn another_users_session_is_not_found() {
        let (fixture, session) = Fixture::signed_in_as(owing_a_factor());

        let result = fixture.verify(session, UserId::new(), RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's session already proved her code. Sending another is a
    /// conflict, not a second proof.
    #[test]
    fn a_session_that_proved_its_code_is_a_conflict() {
        let (fixture, session) = Fixture::signed_in_as(proved_by_code());

        let result = fixture.verify(session, fixture.ann, RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A code offered without an active authenticator returns not found.
    #[test]
    fn an_account_without_a_factor_is_not_found() {
        let (fixture, session) = Fixture::signed_in_as(owing_a_factor());
        let fixture = Fixture {
            enrollments: Arc::new(FakeMfaEnrollmentStore::empty()),
            ..fixture
        };

        let result = fixture.verify(session, fixture.ann, RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A code offered for an unknown session returns not found.
    #[test]
    fn an_unknown_session_is_not_found() {
        let (fixture, _) = Fixture::signed_in_as(owing_a_factor());

        let result = fixture.verify(SessionId::new(), fixture.ann, RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The code `code` sent for `user_id`'s session `session_id`.
    fn guess(session_id: SessionId, user_id: UserId, code: &str) -> VerificationRequest {
        VerificationRequest {
            session_id,
            user_id,
            code: code.to_owned(),
        }
    }
}
