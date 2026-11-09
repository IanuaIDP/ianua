//! The code a member gives from the second factor they have on file,
//! checked against it, for every step on the organization plane that asks
//! the member again rather than trusting the session: proving who they are
//! before a change, and confirming a reset.
//!
//! A member's factor is always an authenticator app: an organization lists
//! no kind whose codes are sent, so no member has one to answer.

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::services::authentication::account_factor::FactorAnswer;
use crate::services::authentication::sign_in_steps::{
    CodeCheck, SeedHolder, ensure_step_unused, step_to_claim,
};

/// A member's second factor, where it is kept and how its codes are
/// checked.
pub(crate) struct MemberFactor<'a> {
    /// Where members' enrollments are kept.
    pub(crate) enrollments: &'a dyn OrgMfaEnrollmentStore,
    /// Checks a code against the enrollment's secret.
    pub(crate) check: CodeCheck<'a>,
}

impl MemberFactor<'_> {
    /// What the factor of `member`, of `organization`, says to `code`.
    ///
    /// A member with no factor in use answers [`FactorAnswer::NoneOnFile`]
    /// whatever was given. One with a factor must answer it. A wrong code
    /// counts towards the factor's lock, and is saved before the refusal.
    ///
    /// # Errors
    ///
    /// - `AppError::StepUpRequired` when the member has a factor and no
    ///   code was given.
    /// - `AppError::Forbidden` when the code is wrong or was used before.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` when the enrollment cannot be read or saved,
    ///   or the code cannot be checked.
    pub(crate) async fn answer(
        &self,
        organization: &OrganizationId,
        member: &OrgUserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let Some(mut enrollment) = self.active_enrollment(member).await? else {
            return Ok(FactorAnswer::NoneOnFile);
        };
        let Some(code) = code else {
            return Err(AppError::StepUpRequired);
        };
        let holder = SeedHolder::Member(*organization);
        let answered = self.check.answer(holder, &mut enrollment, code).await;
        self.enrollments
            .save(member, &enrollment)
            .await
            .or_internal()?;
        let answered = answered?;
        let Some(step) = step_to_claim(&answered) else {
            return Ok(FactorAnswer::Answered(answered));
        };
        let claimed = self
            .enrollments
            .claim_step(member, step)
            .await
            .or_internal()?;
        ensure_step_unused(claimed.into())?;
        Ok(FactorAnswer::Answered(answered))
    }

    async fn active_enrollment(
        &self,
        member: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, AppError> {
        Ok(self
            .enrollments
            .find_by_user(member)
            .await
            .or_internal()?
            .filter(MfaEnrollment::is_active))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::test_support::fakes::FakeMfaVerifier;

    use super::*;
    use crate::test_support::authentication::{FakeEncryptor, FakeMfaEnrollmentStore, lockout};
    use crate::test_support::{block_on, test_ctx};

    const RIGHT_CODE: &str = "123456";

    fn answer(
        store: &FakeMfaEnrollmentStore,
        member: OrgUserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        answer_in(test_ctx().organization_id(), store, member, code)
    }

    /// `member`'s factor's answer to `code`, its seed opened as a member
    /// of `organization`.
    fn answer_in(
        organization: OrganizationId,
        store: &FakeMfaEnrollmentStore,
        member: OrgUserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let verifier = FakeMfaVerifier {
            valid_code: RIGHT_CODE.to_owned(),
        };
        let factor = MemberFactor {
            enrollments: store,
            check: CodeCheck {
                encryptor: &FakeEncryptor,
                verifier: &verifier,
                lockout: lockout(),
            },
        };
        block_on(factor.answer(&organization, &member, code))
    }

    /// Opening Ann's factor under another organization fails with an
    /// internal error, even when the supplied code is correct.
    #[test]
    fn a_factor_opened_for_another_organization_does_not_pass() {
        let ann = OrgUserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answer = answer_in(OrganizationId::new(), &store, ann, Some(RIGHT_CODE));

        assert!(matches!(answer, Err(AppError::Internal(_))));
    }

    /// Ann, a member, has no second factor. Whatever she gives, there is
    /// nothing to answer.
    #[test]
    fn a_member_without_a_factor_has_none_on_file() {
        let store = FakeMfaEnrollmentStore::empty();

        let answer = answer(&store, OrgUserId::new(), Some("000000"));

        assert!(matches!(answer, Ok(FactorAnswer::NoneOnFile)));
    }

    /// Ann has a second factor and gives its right code. The factor
    /// answers it.
    #[test]
    fn the_right_code_is_answered() {
        let ann = OrgUserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answer = answer(&store, ann, Some(RIGHT_CODE));

        assert!(matches!(answer, Ok(FactorAnswer::Answered(_))));
    }

    /// Ann has a second factor and gives no code. She is asked for one.
    #[test]
    fn a_member_with_a_factor_must_give_a_code() {
        let ann = OrgUserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answer = answer(&store, ann, None);

        assert!(matches!(answer, Err(AppError::StepUpRequired)));
    }

    /// A wrong code cannot answer Ann's organization factor and returns
    /// forbidden.
    #[test]
    fn a_wrong_code_is_refused() {
        let ann = OrgUserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answer = answer(&store, ann, Some("999999"));

        assert!(matches!(answer, Err(AppError::Forbidden(_))));
    }

    /// Reusing Ann's accepted organization code is forbidden because its
    /// time step has already been claimed.
    #[test]
    fn a_replayed_code_is_refused() {
        let ann = OrgUserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);
        answer(&store, ann, Some(RIGHT_CODE)).unwrap();

        let replayed = answer(&store, ann, Some(RIGHT_CODE));

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }
}
