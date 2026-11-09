//! A member turning off their own authenticator, on a code from it.
//!
//! Taking the second factor away takes a code from it, so a stolen session
//! is not enough to strip it and set up another. Where the organization
//! requires a second factor it cannot be turned off at all: with it gone,
//! the password alone would sign in.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::MfaPolicy;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgUserStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::mfa::codes::{MemberCodePorts, member_enrollment_in_force};
use crate::use_cases::organization::mfa::setter::refused_member_setup;

/// The ports [`OrgDisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgDisablePorts {
    /// The member's second factor, and what checks its codes.
    pub codes: MemberCodePorts,
    /// The members, whose way of signing in changes.
    pub members: Arc<dyn OrgUserStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// A code from the authenticator being turned off.
pub struct OrgDisableRequest {
    /// The code it shows.
    pub code: String,
}

/// Turns off the signed-in member's own authenticator.
pub struct OrgDisableUseCase {
    lockout: LockoutPolicy,
    ports: OrgDisablePorts,
}

impl OrgDisableUseCase {
    /// A use case working through `ports`, locking the factor under
    /// `lockout`.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: OrgDisablePorts) -> Self {
        Self { lockout, ports }
    }

    /// Turns off `member`'s authenticator on `code`.
    async fn turn_off(&self, member: &OrgUser, code: &str) -> Result<(), AppError> {
        let store = self.ports.codes.enrollment_store.as_ref();
        let mut enrollment = member_enrollment_in_force(store, member.id()).await?;
        let answered = self
            .ports
            .codes
            .checked(self.lockout, *member.organization_id())
            .answered(member.id(), &mut enrollment, code)
            .await?;
        enrollment
            .turn_off_with_code(&answered)
            .map_err(|refused| refused_member_setup(&refused))?;
        store.save(member.id(), &enrollment).await.or_internal()
    }
}

impl Command for OrgDisableUseCase {
    type Caller = OrgCaller;
    type Input = OrgDisableRequest;
    type Output = Result<(), AppError>;

    /// Turns off the caller's authenticator on `request.code`, and records
    /// `organization.org_mfa_unenrolled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` for an empty/oversized code; `Unauthenticated` for an invalid session or key-based caller.
    /// - `AppError::Forbidden` for a required factor, a barred member or a wrong/spent code.
    /// - `AppError::NotFound` for no active authenticator; `AccountLocked` after wrong codes; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: OrgDisableRequest,
    ) -> Result<(), AppError> {
        crate::input::validate_short_code("totp_code", &request.code)?;
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor.signed_in()?;
        ensure_factor_optional(organization.auth_config().mfa_policy())?;
        let members = self.ports.members.as_ref();
        let mut member = existing_member(members, organization.id(), actor.member().id()).await?;
        self.turn_off(&member, &request.code).await?;
        member.record_mfa_turned_off();
        members.save(&member).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), member.take_events())
            .await
            .or_internal()
    }
}

/// Refuses turning the factor off where the organization requires one.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `policy` is `Required`.
fn ensure_factor_optional(policy: MfaPolicy) -> Result<(), AppError> {
    match policy {
        MfaPolicy::Required => Err(AppError::Forbidden(message!(
            "organization-your-organization-requires-a-second-factor",
            "your organization requires a second factor, so it cannot be turned off"
        ))),
        MfaPolicy::Optional | MfaPolicy::Disabled => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, lockout};
    use crate::test_support::organization::{FakeOrgUserStore, stored_caller};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    const RIGHT_CODE: &str = "123456";

    struct Setup {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: OrgDisableUseCase,
    }

    impl Setup {
        fn with(enrollments: FakeMfaEnrollmentStore, actors: FakeOrgActors) -> Self {
            let enrollments = Arc::new(enrollments);
            let members = FakeOrgUserStore::empty();
            block_on(members.save(&stored_caller(OrgRole::Member, "pw"))).unwrap();
            let use_case = OrgDisableUseCase::new(
                lockout(),
                OrgDisablePorts {
                    codes: MemberCodePorts {
                        enrollment_store: enrollments.clone(),
                        ..MemberCodePorts::fakes()
                    },
                    members: Arc::new(members),
                    org_actors: Arc::new(actors),
                },
            );
            Self {
                enrollments,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn enrolled() -> Self {
            Self::with(
                FakeMfaEnrollmentStore::active_for(*test_org_caller().member()),
                FakeOrgActors::in_role(OrgRole::Member),
            )
        }

        fn disable(&self, code: &str) -> Result<(), AppError> {
            block_on(self.use_case.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                OrgDisableRequest {
                    code: code.to_owned(),
                },
            ))
        }

        fn in_force(&self) -> bool {
            self.enrollments
                .enrollment_of(*test_org_caller().member())
                .is_some_and(|enrollment| enrollment.is_active())
        }
    }

    /// Olivia, a member, turns off her authenticator with a code from it.
    /// It stops counting, and the change is recorded.
    #[test]
    fn disable_marks_org_enrollment_disabled() {
        let setup = Setup::enrolled();

        setup.disable(RIGHT_CODE).unwrap();

        assert!(!setup.in_force());
        assert_eq!(
            setup.audit.records.lock().unwrap().clone(),
            vec!["organization.org_mfa_unenrolled"]
        );
    }

    /// A wrong authenticator code cannot disable the member's active factor.
    #[test]
    fn a_wrong_code_does_not_disable_the_factor() {
        let setup = Setup::enrolled();

        let result = setup.disable("000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.in_force());
    }

    /// Reusing an accepted authenticator code is forbidden and leaves the
    /// factor active.
    #[test]
    fn a_replayed_code_does_not_disable_the_factor() {
        let setup = Setup::enrolled();
        let first = setup
            .use_case
            .ports
            .codes
            .checked(lockout(), test_org_caller().organization_id());
        let mut enrollment = setup
            .enrollments
            .enrollment_of(*test_org_caller().member())
            .unwrap();
        block_on(first.answered(test_org_caller().member(), &mut enrollment, RIGHT_CODE)).unwrap();

        let result = setup.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.in_force());
    }

    /// Repeated wrong codes lock the factor against disabling, even with
    /// the correct code, and it stays active.
    #[test]
    fn a_locked_factor_is_not_disabled() {
        let setup = Setup::enrolled();
        for _ in 0..5 {
            let _ = setup.disable("000000");
        }

        let result = setup.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::AccountLocked(_))));
        assert!(setup.in_force());
    }

    /// Olivia has no authenticator in force. There is nothing to turn off.
    #[test]
    fn disable_without_org_enrollment_returns_not_found() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::empty(),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = setup.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot disable the member's active factor.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::active_for(*test_org_caller().member()),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = setup.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.in_force());
    }

    /// Disabling a factor propagates the organization actor's forbidden response.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::active_for(*test_org_caller().member()),
            FakeOrgActors::refusing(Refusal::Forbidden),
        );

        let result = setup.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An API key cannot disable the member's authenticator, which stays active.
    #[test]
    fn a_key_caller_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::active_for(*test_org_caller().member()),
            FakeOrgActors::through_key(OrgRole::Member, Vec::new()),
        );

        let result = setup.disable(RIGHT_CODE);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.in_force());
    }

    /// Where the organization requires a second factor, turning one off is
    /// refused, whatever the code.
    #[test]
    fn the_factor_cannot_be_turned_off_where_the_organization_requires_it() {
        let result = ensure_factor_optional(MfaPolicy::Required);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
