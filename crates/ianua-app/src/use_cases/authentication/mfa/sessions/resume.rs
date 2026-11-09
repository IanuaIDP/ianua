//! Lifting a session's suspension with a code from the person's
//! authenticator, proved live.
//!
//! The platform froze the session because a request on it did not look like
//! the person who signed in. Whoever holds it proves a second factor now;
//! the domain decides whether that factor lifts it, and at what level the
//! session goes on.

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
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::{
    SignInParties, SignInSources,
};

/// The ports [`ResumeSessionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumeSessionPorts {
    /// The suspended session.
    pub session_store: Arc<dyn SessionStore>,
    /// The session's account.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant, for its step-up policy.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The person's second factor, and what checks its codes.
    pub codes: FactorCodePorts,
}

/// A code offered to lift one session's suspension.
pub struct ResumeSessionRequest {
    /// The suspended session.
    pub session_id: SessionId,
    /// Whose session it is.
    pub user_id: UserId,
    /// The code as typed.
    pub code: String,
}

/// Resumes a suspended session with an authenticator code.
pub struct ResumeSessionUseCase {
    lockout: LockoutPolicy,
    ports: ResumeSessionPorts,
}

impl ResumeSessionUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: ResumeSessionPorts) -> Self {
        Self { lockout, ports }
    }

    /// The factor `request.code` proves for its user, checked against their
    /// authenticator and claimed so it works once.
    async fn proved(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: &ResumeSessionRequest,
    ) -> Result<ProvedFactor, AppError> {
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment = existing_active_enrollment(store, tenant, &request.user_id).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, auditor)
            .answered(tenant, &mut enrollment, &request.code)
            .await?;
        Ok(ProvedFactor::by_code(&answered))
    }

    /// Lifts the suspension of the session in `parties` with `proof`, and
    /// saves it so the next request goes through.
    async fn resume(
        &self,
        tenant: &ScopedTenant,
        parties: &mut SignInParties,
        proof: ProvedFactor,
    ) -> Result<(), AppError> {
        parties
            .session
            .resume(proof, &parties.policy)
            .map_err(AppError::from_domain)?;
        self.ports
            .session_store
            .save(tenant, &parties.session)
            .await
            .or_internal()
    }
}

impl Command for ResumeSessionUseCase {
    type Caller = ScopedTenant;
    type Input = ResumeSessionRequest;
    type Output = Result<(), AppError>;

    /// Checks `request.code` against the person's authenticator, lifts the
    /// session's suspension as the domain allows, and records
    /// `authentication.session_resumed`. A wrong code records
    /// `authentication.mfa_failed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the code is empty or too long, or the session
    ///   is not suspended.
    /// - `AppError::NotFound` if the session is unknown or another user's,
    ///   or the user has no active second factor.
    /// - `AppError::Forbidden` if the code is wrong or already used, or
    ///   falls short of what the tenant asks.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` on persistence or decryption failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ResumeSessionRequest,
    ) -> Result<(), AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let sources = SignInSources {
            sessions: self.ports.session_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            tenants: self.ports.tenant_store.as_ref(),
        };
        let mut parties = sources
            .parties(tenant, &request.session_id, &request.user_id)
            .await?;
        let proof = self.proved(tenant, auditor, &request).await?;
        self.resume(tenant, &mut parties, proof).await?;
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
    use ianua_domain::domains::authentication::events::session::SuspensionReason;
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::types::EventLabel;

    use super::*;
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSessionStore, lockout, session_signed_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const RIGHT_CODE: &str = "123456";

    fn proved_by_code() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::Proved(MfaFactor::Totp),
            owed: SecondFactor::NotOwed,
        }
    }

    struct Fixture {
        ann: UserId,
        session_id: SessionId,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn signed_in() -> Self {
            let ann = UserId::new();
            let session = session_signed_in(ann, proved_by_code());
            Self {
                ann,
                session_id: *session.id(),
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn suspended() -> Self {
            let fixture = Self::signed_in();
            let mut session = fixture.sessions.get_session(&fixture.session_id).unwrap();
            session
                .suspend(SuspensionReason::RiskEscalation, EventLabel::of("Ann"))
                .unwrap();
            block_on(fixture.sessions.save(&test_ctx().tenant(), &session)).unwrap();
            fixture
        }

        fn resume(&self, user_id: UserId, code: &str) -> Result<(), AppError> {
            let use_case = ResumeSessionUseCase::new(
                lockout(),
                ResumeSessionPorts {
                    session_store: self.sessions.clone(),
                    user_store: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    codes: FactorCodePorts {
                        enrollment_store: Arc::new(FakeMfaEnrollmentStore::active_for(self.ann)),
                        ..FactorCodePorts::fakes()
                    },
                },
            );
            let request = ResumeSessionRequest {
                session_id: self.session_id,
                user_id,
                code: code.to_owned(),
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, request))
        }

        fn status(&self) -> Option<SessionStatus> {
            self.sessions.get_status(&self.session_id)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann's session was frozen after a request from a device it is not
    /// bound to. She types the code her authenticator shows; the session
    /// goes on and the resumption is recorded.
    #[test]
    fn a_right_code_resumes_a_suspended_session() {
        let fixture = Fixture::suspended();

        fixture.resume(fixture.ann, RIGHT_CODE).unwrap();

        assert_eq!(fixture.status(), Some(SessionStatus::Active));
        assert_eq!(fixture.recorded(), ["authentication.session_resumed"]);
    }

    /// A wrong code is refused and recorded as a failed verification while
    /// the session remains suspended.
    #[test]
    fn a_wrong_code_leaves_the_session_suspended() {
        let fixture = Fixture::suspended();

        let result = fixture.resume(fixture.ann, "000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.status(), Some(SessionStatus::Suspended));
        assert_eq!(fixture.recorded(), ["authentication.mfa_failed"]);
    }

    /// An active session refuses resumption without recording an event.
    #[test]
    fn an_active_session_is_not_resumed() {
        let fixture = Fixture::signed_in();

        let result = fixture.resume(fixture.ann, RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Resuming Ann's session under another user's ID returns not found
    /// and leaves the session suspended.
    #[test]
    fn another_users_session_is_not_found() {
        let fixture = Fixture::suspended();

        let result = fixture.resume(UserId::new(), RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.status(), Some(SessionStatus::Suspended));
    }
}
