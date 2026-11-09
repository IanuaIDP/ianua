//! A member replacing their recovery codes with a new set, after using
//! most of them or fearing they were seen.
//!
//! A recovery code lets its holder past the second factor, so whoever
//! steals a session must not mint codes with it: the member proves who
//! they are again first. Every earlier code stops working.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, TokenHash};

use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::RecoveryCodeGenerator;
use crate::ports::organization::{OrgMfaEnrollmentStore, OrgRecoveryCodeStore};
use crate::services::authentication::fresh_proof::ReenteredProof;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::SetupProof;
use crate::use_cases::organization::lookup::existing_member_recovery_codes;
use crate::use_cases::organization::mfa::codes::member_enrollment_in_force;
use crate::use_cases::organization::mfa::enrollment_confirm::MEMBER_RECOVERY_CODES;
use crate::use_cases::organization::mfa::setter::{
    MemberFactorSetter, MemberLeave, MemberSetterPorts,
};

/// The ports [`RegenerateOrgRecoveryCodesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegenerateOrgRecoveryCodesPorts {
    /// The member's second factor, which the codes stand in for.
    pub enrollment_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// The member's recovery codes.
    pub recovery_store: Arc<dyn OrgRecoveryCodeStore>,
    /// Makes the new codes.
    pub recovery_generator: Arc<dyn RecoveryCodeGenerator>,
    /// Who the member is, and what proves them again.
    pub setters: MemberSetterPorts,
}

/// Replaces a member's recovery codes.
pub struct RegenerateOrgRecoveryCodesUseCase {
    ports: RegenerateOrgRecoveryCodesPorts,
}

impl RegenerateOrgRecoveryCodesUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegenerateOrgRecoveryCodesPorts) -> Self {
        Self { ports }
    }

    /// A fresh batch of codes: the raw ones to show once, and their hashes
    /// to keep.
    async fn fresh_batch(&self) -> Result<(Vec<Secret>, Vec<TokenHash>), AppError> {
        let pairs = self
            .ports
            .recovery_generator
            .generate_batch(MEMBER_RECOVERY_CODES)
            .await
            .or_internal()?;
        Ok(pairs.into_iter().map(|pair| (pair.raw, pair.hash)).unzip())
    }
}

impl Command for RegenerateOrgRecoveryCodesUseCase {
    type Caller = OrgCaller;
    type Input = ReenteredProof;
    type Output = Result<Vec<Secret>, AppError>;

    /// Replaces the caller's recovery codes with a new set, proved by what
    /// they typed again, and records
    /// `organization.org_recovery_codes_generated`. The new codes come back
    /// once; only their hashes are kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts, or they act through a key.
    /// - `AppError::Forbidden` when what they typed does not prove them.
    /// - `AppError::StepUpRequired` when they must give a code from their
    ///   factor too.
    /// - `AppError::NotFound` when they have no second factor in force or
    ///   no recovery codes.
    /// - `AppError::Internal` on generation, storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        proof: ReenteredProof,
    ) -> Result<Vec<Secret>, AppError> {
        let setters = &self.ports.setters;
        let mut found = setters
            .setter(&MemberFactorSetter::SignedIn(caller.clone()))
            .await?;
        let leave = setters.leave(&found, SetupProof::Reentered(proof)).await?;
        let member = *found.member.id();
        let factor =
            member_enrollment_in_force(self.ports.enrollment_store.as_ref(), &member).await?;
        let mut codes =
            existing_member_recovery_codes(self.ports.recovery_store.as_ref(), &member).await?;
        let (shown, hashes) = self.fresh_batch().await?;
        regenerate(&mut codes, hashes, &factor, &leave)?;
        self.ports
            .recovery_store
            .save(&member, &codes)
            .await
            .or_internal()?;
        found.member.record_recovery_codes_generated(&codes);
        auditor
            .dispatch_by(&ActorRef::OrgUser(member), found.member.take_events())
            .await
            .or_internal()?;
        Ok(shown)
    }
}

/// `codes` replaced by `hashes`, standing in for `factor`, on `leave`.
///
/// # Errors
///
/// - `AppError::Forbidden` when `leave` does not prove the member, or the
///   factor is not theirs or not in force.
/// - `AppError::Domain` when no hash is given, or one is given twice.
fn regenerate(
    codes: &mut RecoveryCodeSet<ResolvedOrganization>,
    hashes: Vec<TokenHash>,
    factor: &MfaEnrollment<ResolvedOrganization>,
    leave: &MemberLeave,
) -> Result<(), AppError> {
    let replaced = match leave {
        MemberLeave::Fresh(proof) => codes.regenerate(hashes, factor, proof),
        MemberLeave::Enrolment(proof) => codes.regenerate(hashes, factor, proof),
    };
    replaced.map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, right_password, wrong_password,
    };
    use crate::test_support::organization::{
        FakeOrgRecoveryCodeStore, org_user_store_with, stored_caller,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    /// The caller, Olivia, holding an authenticator in force and two
    /// recovery codes, acting as `actors` say.
    struct Setup {
        codes: Arc<FakeOrgRecoveryCodeStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: RegenerateOrgRecoveryCodesUseCase,
    }

    impl Setup {
        fn with(actors: FakeOrgActors) -> Self {
            let olivia = *test_org_caller().member();
            let codes = Arc::new(FakeOrgRecoveryCodeStore::with_codes(
                olivia,
                &["old_1", "old_2"],
            ));
            let use_case =
                RegenerateOrgRecoveryCodesUseCase::new(RegenerateOrgRecoveryCodesPorts {
                    enrollment_store: Arc::new(FakeMfaEnrollmentStore::active_for(olivia)),
                    recovery_store: codes.clone(),
                    setters: MemberSetterPorts {
                        org_actors: Arc::new(actors),
                        members: Arc::new(org_user_store_with([stored_caller(
                            OrgRole::Member,
                            "irrelevant",
                        )])),
                        ..MemberSetterPorts::fakes()
                    },
                    ..RegenerateOrgRecoveryCodesPorts::fakes()
                });
            Self {
                codes,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        /// Asks for new codes, proved by `proof`.
        fn regenerate(&self, proof: ReenteredProof) -> Result<Vec<Secret>, AppError> {
            block_on(self.use_case.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                proof,
            ))
        }

        /// How many of Olivia's codes are unused.
        fn remaining(&self) -> usize {
            self.codes.remaining(test_org_caller().member())
        }

        /// What the audit trail recorded.
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia used most of her codes and types her password again. She is
    /// shown ten new codes, which replace the old ones, and the new set is
    /// recorded.
    #[test]
    fn a_new_set_replaces_the_old_codes() {
        let setup = Setup::with(FakeOrgActors::in_role(OrgRole::Member));

        let shown = setup.regenerate(right_password()).unwrap();

        assert_eq!(shown.len(), usize::from(MEMBER_RECOVERY_CODES));
        assert_eq!(setup.remaining(), usize::from(MEMBER_RECOVERY_CODES));
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_recovery_codes_generated"]
        );
    }

    /// A wrong password prevents recovery-code regeneration; the two
    /// existing codes remain unused and no event is recorded.
    #[test]
    fn a_wrong_password_mints_nothing() {
        let setup = Setup::with(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.regenerate(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.remaining(), 2);
        assert!(setup.recorded().is_empty());
    }

    /// An API key cannot regenerate recovery codes, leaving both existing
    /// codes unused.
    #[test]
    fn a_key_caller_is_refused() {
        let setup = Setup::with(FakeOrgActors::through_key(OrgRole::Member, Vec::new()));

        let result = setup.regenerate(right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.remaining(), 2);
    }

    /// A signed-out session cannot authorize recovery-code regeneration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.regenerate(right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
