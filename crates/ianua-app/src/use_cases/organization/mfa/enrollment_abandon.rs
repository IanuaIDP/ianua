//! A member giving up an authenticator setup that was never confirmed, so
//! they can start again with a new secret.
//!
//! Giving up is the first step of starting again, so it asks for the same
//! proof. Otherwise Mallory, holding Olivia's session, gives up each setup
//! Olivia starts, and Olivia never gets a second factor.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::SetupProof;
use crate::use_cases::organization::mfa::codes::member_enrollment_waiting;
use crate::use_cases::organization::mfa::setter::{
    MemberFactorSetter, MemberSetterPorts, give_up_member_enrollment,
};

/// The ports [`OrgAbandonUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgAbandonPorts {
    /// Where members' enrollments are kept.
    pub enrollment_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// Who gives up the setup, and what lets them.
    pub setters: MemberSetterPorts,
}

/// Gives up a member's pending authenticator setup.
pub struct OrgAbandonUseCase {
    ports: OrgAbandonPorts,
}

impl OrgAbandonUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgAbandonPorts) -> Self {
        Self { ports }
    }
}

impl Command for OrgAbandonUseCase {
    type Caller = MemberFactorSetter;
    type Input = SetupProof;
    type Output = Result<(), AppError>;

    /// Gives up `setter`'s pending authenticator setup on `proof`. Nothing
    /// is recorded: the setup never protected anything.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a signed-in member's session no
    ///   longer counts, or they act through a key.
    /// - `AppError::Forbidden` when the proof does not let the member set
    ///   up a factor now.
    /// - `AppError::StepUpRequired` when the member must give a code from a
    ///   factor they hold.
    /// - `AppError::NotFound` when no setup is pending, or the member, their
    ///   organization or a waiting sign-in's session is gone.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        setter: &MemberFactorSetter,
        _: &RequestAuditor,
        proof: SetupProof,
    ) -> Result<(), AppError> {
        let found = self.ports.setters.setter(setter).await?;
        let leave = self.ports.setters.leave(&found, proof).await?;
        let store = self.ports.enrollment_store.as_ref();
        let member = found.member.id();
        let mut enrollment = member_enrollment_waiting(store, member).await?;
        give_up_member_enrollment(&mut enrollment, &leave)?;
        store.save(member, &enrollment).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::ports::organization::OrgUserStore;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, right_password, wrong_password,
    };
    use crate::test_support::organization::{FakeOrgUserStore, stored_caller};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        use_case: OrgAbandonUseCase,
    }

    impl Setup {
        fn with(enrollments: FakeMfaEnrollmentStore, actors: FakeOrgActors) -> Self {
            let enrollments = Arc::new(enrollments);
            let members = FakeOrgUserStore::empty();
            block_on(members.save(&stored_caller(OrgRole::Member, "pw"))).unwrap();
            let use_case = OrgAbandonUseCase::new(OrgAbandonPorts {
                enrollment_store: enrollments.clone(),
                setters: MemberSetterPorts {
                    org_actors: Arc::new(actors),
                    members: Arc::new(members),
                    ..MemberSetterPorts::fakes()
                },
            });
            Self {
                enrollments,
                use_case,
            }
        }

        fn pending() -> Self {
            Self::with(
                FakeMfaEnrollmentStore::pending_for(*test_org_caller().member()),
                FakeOrgActors::in_role(OrgRole::Member),
            )
        }

        fn abandon(&self, proof: SetupProof) -> Result<(), AppError> {
            block_on(self.use_case.execute(
                &MemberFactorSetter::SignedIn(test_org_caller()),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                proof,
            ))
        }

        fn still_pending(&self) -> bool {
            self.enrollments
                .enrollment_of(*test_org_caller().member())
                .is_some_and(|enrollment| enrollment.is_pending())
        }
    }

    /// Olivia, a member, types her password again and gives up the setup
    /// she never confirmed. It no longer waits, so she can start again.
    #[test]
    fn a_pending_setup_is_given_up() {
        let setup = Setup::pending();

        setup
            .abandon(SetupProof::Reentered(right_password()))
            .unwrap();

        assert!(!setup.still_pending());
    }

    /// A wrong password cannot authorize abandoning enrollment, which
    /// remains pending.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::pending();

        let result = setup.abandon(SetupProof::Reentered(wrong_password()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.still_pending());
    }

    /// Olivia has no setup waiting. There is nothing to give up.
    #[test]
    fn nothing_pending_is_not_found() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::active_for(*test_org_caller().member()),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = setup.abandon(SetupProof::Reentered(right_password()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot abandon the member's pending enrollment.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::pending_for(*test_org_caller().member()),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = setup.abandon(SetupProof::Reentered(right_password()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.still_pending());
    }

    /// An API key cannot authorize abandoning factor setup.
    #[test]
    fn a_key_caller_is_refused() {
        let setup = Setup::with(
            FakeMfaEnrollmentStore::pending_for(*test_org_caller().member()),
            FakeOrgActors::through_key(OrgRole::Member, Vec::new()),
        );

        let result = setup.abandon(SetupProof::Reentered(right_password()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
