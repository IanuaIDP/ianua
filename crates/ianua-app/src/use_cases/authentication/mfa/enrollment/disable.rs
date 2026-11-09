//! Turning off one's own authenticator, on a code from it.
//!
//! Changing a password takes the old password. Taking the second factor
//! away takes a code from it, so a stolen session, or a mailbox by way of a
//! sign-in link, is not enough to strip it and set up another.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::failed_factor::FactorCodePorts;
use crate::use_cases::authentication::mfa::enrollment::setup_proof::enrollment_refused;
use crate::use_cases::authentication::mfa::lookup::existing_active_enrollment;

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// The person's second factor, and what checks its codes.
    pub codes: FactorCodePorts,
    /// The account, whose way of signing in changes.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's sessions, to keep the one the factor is turned off from.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A code from the authenticator being turned off.
pub struct DisableRequest {
    /// The code it shows.
    pub code: String,
}

/// Turns off the signed-in person's own authenticator.
pub struct DisableUseCase {
    lockout: LockoutPolicy,
    ports: DisablePorts,
}

impl DisableUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: DisablePorts) -> Self {
        Self { lockout, ports }
    }

    /// Keeps the person's change of how they sign in and the session they
    /// made it from, so every other session from before the change stops
    /// counting.
    async fn keep_through_removal(
        &self,
        tenant: &ScopedTenant,
        person: &SignedInAccount,
    ) -> Result<(), AppError> {
        self.ports
            .user_store
            .save(tenant, &person.account)
            .await
            .or_internal()?;
        self.ports
            .session_store
            .save(tenant, &person.session)
            .await
            .or_internal()
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = DisableRequest;
    type Output = Result<(), AppError>;

    /// Turns off the caller's authenticator on `request.code`, and records
    /// `authentication.mfa_unenrolled`. Every other session the person
    /// holds ends; the one they turned it off from stays.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `Unauthenticated` for an invalid session.
    /// - `AppError::NotFound` for no active authenticator; `Forbidden` for a wrong/spent code.
    /// - `AppError::AccountLocked` after too many wrong codes; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: DisableRequest,
    ) -> Result<(), AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let mut person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment =
            existing_active_enrollment(store, &tenant, person.account.id()).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, auditor)
            .answered(&tenant, &mut enrollment, &request.code)
            .await?;
        enrollment
            .turn_off_with_code(&answered)
            .map_err(|error| enrollment_refused(&error))?;
        person.account.record_credential_change();
        person
            .session
            .keep_through_own_removal(&person.account, &person.signed_in)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &enrollment).await.or_internal()?;
        self.keep_through_removal(&tenant, &person).await?;
        let holder = ActorRef::User(*person.account.id());
        auditor
            .dispatch_by(&holder, enrollment.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::types::CredentialChange;

    use super::*;
    use crate::ports::authentication::MfaEnrollmentStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSessionStore, lockout, test_caller_id,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    const RIGHT_CODE: &str = "123456";

    struct Fixture {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn over(enrollments: FakeMfaEnrollmentStore) -> Self {
            Self {
                enrollments: Arc::new(enrollments),
                users: Arc::new(FakeUserStore::empty()),
                sessions: Arc::new(FakeSessionStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn enrolled() -> Self {
            Self::over(FakeMfaEnrollmentStore::active_for(test_caller_id()))
        }

        fn disable_as(
            &self,
            authorities: FakeTenantAuthorities,
            code: &str,
        ) -> Result<(), AppError> {
            let use_case = DisableUseCase::new(
                lockout(),
                DisablePorts {
                    codes: FactorCodePorts {
                        enrollment_store: self.enrollments.clone(),
                        ..FactorCodePorts::fakes()
                    },
                    user_store: self.users.clone(),
                    session_store: self.sessions.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..DisablePorts::fakes()
                },
            );
            let request = DisableRequest {
                code: code.to_owned(),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request))
        }

        fn disable(&self, code: &str) -> Result<(), AppError> {
            self.disable_as(FakeTenantAuthorities::holding(&[]), code)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann turns off her authenticator with a code from it. It no longer
    /// counts, the change of how she signs in is noted, and it is recorded.
    #[test]
    fn a_right_code_turns_the_factor_off() {
        let fixture = Fixture::enrolled();

        fixture.disable(RIGHT_CODE).unwrap();

        assert!(
            !fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .is_active()
        );
        let account = block_on(
            fixture
                .users
                .find_by_id(&test_ctx().tenant(), &test_caller_id()),
        )
        .unwrap()
        .unwrap();
        assert_ne!(account.credentials_changed_at(), CredentialChange::Never);
        assert_eq!(fixture.recorded(), ["authentication.mfa_unenrolled"]);
    }

    /// Ann turns her authenticator off from her laptop's session. The
    /// change ends her sessions from before it, but the laptop's is kept
    /// through it.
    #[test]
    fn the_session_the_factor_was_turned_off_from_is_kept() {
        let fixture = Fixture::enrolled();

        fixture.disable(RIGHT_CODE).unwrap();

        let account = block_on(
            fixture
                .users
                .find_by_id(&test_ctx().tenant(), &test_caller_id()),
        )
        .unwrap()
        .unwrap();
        let laptop = fixture.sessions.get_session(&test_session_id()).unwrap();
        assert_eq!(laptop.kept_through(), account.credentials_changed_at());
        assert_ne!(laptop.kept_through(), CredentialChange::Never);
    }

    /// Turning off Ann's authenticator records the unenrollment event used
    /// to invalidate cached callers.
    #[test]
    fn turning_the_factor_off_records_what_drops_cached_sign_ins() {
        let fixture = Fixture::enrolled();

        fixture.disable(RIGHT_CODE).unwrap();

        assert!(
            fixture
                .recorded()
                .contains(&"authentication.mfa_unenrolled".to_owned())
        );
    }

    /// A wrong code cannot remove the signed-in person's active authenticator.
    #[test]
    fn a_session_alone_cannot_strip_the_factor() {
        let fixture = Fixture::enrolled();

        let result = fixture.disable("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .is_active()
        );
    }

    /// Five failed attempts lock the factor against removal even with its right code.
    #[test]
    fn a_locked_factor_refuses_even_the_right_code() {
        let fixture = Fixture::enrolled();
        let mut enrollment = fixture.enrollments.enrollment_of(test_caller_id()).unwrap();
        for _ in 0..5 {
            enrollment.record_failed_attempt(lockout());
        }
        block_on(fixture.enrollments.save(&test_ctx().tenant(), &enrollment)).unwrap();

        let result = fixture.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
    }

    /// Ann has no authenticator. There is nothing to turn off.
    #[test]
    fn no_factor_is_not_found() {
        let fixture = Fixture::over(FakeMfaEnrollmentStore::empty());

        let result = fixture.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann turned her authenticator off already. Doing it again finds
    /// nothing in force.
    #[test]
    fn turning_off_twice_is_not_found() {
        let _clock = clock::freeze(clock::now());
        let fixture = Fixture::enrolled();
        fixture.disable(RIGHT_CODE).unwrap();

        let again = fixture.disable(RIGHT_CODE);

        assert!(matches!(again, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot remove the authenticator; it remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::enrolled();

        let result = fixture.disable_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            RIGHT_CODE,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .is_active()
        );
    }
}
