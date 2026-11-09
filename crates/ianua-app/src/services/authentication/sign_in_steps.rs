//! Steps of proving who someone is that every plane takes the same way:
//! answering a second-factor code, from an app or sent, refusing a code
//! already used, and refusing a risky sign-in nothing could confirm.

use ianua_domain::domains::authentication::mfa::enrollment::{
    AnsweredCode, CodeAttempt, CodeRefused, CodeReplay, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::mfa::one_time_code::{OneTimeCode, SentCodeAttempt};
use ianua_domain::domains::authentication::mfa::time_step::TimeStep;
use ianua_domain::domains::authentication::mfa::verifier::{MfaVerifier, TotpSeed};
use ianua_domain::isolation::SecurityScope;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{OrganizationId, PrincipalId, TenantId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    SealOwner, SealedField, SealedFor, SecretEncryptor, SentCodeGenerator,
};

/// The refusal of a risky sign-in by someone with no second factor, where
/// no mail could confirm it and no invitation vouches for them. It tells
/// them what gets them in: a new invitation, whose acceptance proves them
/// again and lets their next sign-in set up a factor.
pub(crate) fn no_factor_to_prove_with() -> AppError {
    AppError::Forbidden(message!(
        "authentication-this-sign-in-needs-a-second",
        "this sign-in needs a second factor and the account has none; \
         ask an administrator to send you a new invitation"
    ))
}

/// Whose authenticator seed is sealed or opened: a tenant user's, or an
/// organization member's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedHolder {
    /// A user's seed sealed within the named tenant's scope.
    TenantUser(TenantId),
    /// A member of this organization.
    Member(OrganizationId),
}

impl SeedHolder {
    /// Where the seed of `subject`'s enrollment is kept.
    pub(crate) fn place(self, subject: PrincipalId) -> SealedFor {
        let (owner, field) = match self {
            Self::TenantUser(tenant) => (SealOwner::Tenant(tenant), SealedField::TotpSeed),
            Self::Member(organization) => (
                SealOwner::Organization(organization),
                SealedField::MemberTotpSeed,
            ),
        };
        SealedFor::new(owner, field, subject.as_uuid())
    }
}

/// Checks a code against an MFA enrollment's secret, counting failures on the
/// enrollment. The caller saves the enrollment afterwards, whatever the answer.
pub(crate) struct CodeCheck<'a> {
    /// Opens the stored secret.
    pub(crate) encryptor: &'a dyn SecretEncryptor,
    /// Checks a code against the secret.
    pub(crate) verifier: &'a dyn MfaVerifier,
    /// Wrong codes tolerated before the enrollment locks, and for how long.
    pub(crate) lockout: LockoutPolicy,
}

impl CodeCheck<'_> {
    /// Answers `code` against the authenticator app of `enrollment`, whose
    /// seed `holder` keeps.
    ///
    /// A right code is not yet an unused one. The caller claims the step
    /// [`step_to_claim`] names on its enrollment store, and passes the claim
    /// to [`ensure_step_unused`], before treating the factor as proved.
    ///
    /// # Errors
    ///
    /// - [`AppError::AccountLocked`] after too many wrong codes.
    /// - [`AppError::Forbidden`] when the code is wrong, the factor is not in
    ///   use, its codes are sent rather than made by an app, or the
    ///   enrollment is another account's.
    /// - [`AppError::Internal`] when the secret cannot be opened or the code
    ///   cannot be checked.
    pub(crate) async fn answer<S: SecurityScope>(
        &self,
        holder: SeedHolder,
        enrollment: &mut MfaEnrollment<S>,
        code: &str,
    ) -> Result<AnsweredCode, AppError> {
        let Some(sealed) = enrollment.factor().sealed_secret() else {
            return Err(refusal_error(CodeRefused::OtherKind));
        };
        let place = holder.place(enrollment.subject_id());
        let seed = TotpSeed::new(self.encryptor.decrypt(sealed, &place).await.or_internal()?);
        enrollment
            .answer(
                self.verifier,
                CodeAttempt { seed: &seed, code },
                self.lockout,
            )
            .map_err(refusal_error)
    }
}

/// Checks a typed code against the code sent for a factor whose codes are
/// mailed or texted, counting wrong tries on the code and on the factor.
/// The caller saves both afterwards, whatever the answer.
pub(crate) struct SentCodeCheck<'a> {
    /// Hashes the typed code the way the sent one was hashed.
    pub(crate) generator: &'a dyn SentCodeGenerator,
    /// Wrong codes tolerated before the factor locks, and for how long.
    pub(crate) lockout: LockoutPolicy,
}

impl SentCodeCheck<'_> {
    /// Answers `typed` against `sent`, the latest code sent for
    /// `enrollment`, spending it when it matches.
    ///
    /// # Errors
    ///
    /// - [`AppError::AccountLocked`] after too many wrong codes.
    /// - [`AppError::Forbidden`] when the code is wrong, spent, lapsed or
    ///   another factor's, or the factor is not in use.
    pub(crate) fn answer<S: SecurityScope>(
        &self,
        sent: &mut OneTimeCode<S>,
        enrollment: &mut MfaEnrollment<S>,
        typed: &str,
    ) -> Result<AnsweredCode, AppError> {
        let hash = self.generator.hash(&Secret::new(typed));
        sent.redeem(SentCodeAttempt {
            hash: &hash,
            factor: enrollment,
            lockout: self.lockout,
        })
        .map_err(refusal_error)
    }
}

/// The time step a right code from an app must claim before it counts, or
/// none for a sent code, which was spent when it was checked.
pub(crate) fn step_to_claim(answered: &AnsweredCode) -> Option<TimeStep> {
    match answered.replay() {
        CodeReplay::ClaimStep(step) => Some(step),
        CodeReplay::Spent => None,
    }
}

/// What the store answered when a code's time step was claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepClaim {
    /// The step is later than every one accepted before. The code is fresh.
    Claimed,
    /// This step, or a later one, was accepted before. The code was used.
    AlreadyUsed,
}

impl From<bool> for StepClaim {
    /// The claim the store's `claim_step` answered: `true` when it took the
    /// step.
    fn from(claimed: bool) -> Self {
        match claimed {
            true => Self::Claimed,
            false => Self::AlreadyUsed,
        }
    }
}

/// Refuses a code whose step was already claimed.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] when the code was already used.
pub(crate) fn ensure_step_unused(claim: StepClaim) -> Result<(), AppError> {
    match claim {
        StepClaim::Claimed => Ok(()),
        StepClaim::AlreadyUsed => Err(AppError::Forbidden(message!(
            "authentication-this-code-was-already-used-wait",
            "this code was already used; wait for the next one"
        ))),
    }
}

/// The error a refused recovery code answers with, on every plane alike.
pub(crate) fn recovery_refused(refused: CodeRefused) -> AppError {
    match refused {
        CodeRefused::Locked => AppError::AccountLocked("too many failed MFA attempts".to_owned()),
        CodeRefused::Wrong => AppError::Forbidden(message!(
            "authentication-invalid-recovery-code",
            "invalid recovery code"
        )),
        CodeRefused::Retired
        | CodeRefused::ForAnotherAccount
        | CodeRefused::OtherKind
        | CodeRefused::Lapsed => AppError::Forbidden(refused.to_string().into()),
        CodeRefused::Unchecked(source) => AppError::internal(source),
    }
}

/// The error a refused code answers with.
fn refusal_error(refused: CodeRefused) -> AppError {
    match refused {
        CodeRefused::Locked => AppError::AccountLocked("too many failed MFA attempts".to_owned()),
        CodeRefused::Wrong => {
            AppError::Forbidden(message!("authentication-invalid-code-2", "invalid code"))
        }
        CodeRefused::Lapsed => AppError::Forbidden(message!(
            "authentication-this-code-is-spent-or-lapsed",
            "this code is spent or lapsed; ask for a new one"
        )),
        CodeRefused::Retired | CodeRefused::ForAnotherAccount | CodeRefused::OtherKind => {
            AppError::Forbidden(refused.to_string().into())
        }
        CodeRefused::Unchecked(source) => AppError::internal(source),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::enrollment::EnrolledFactor;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::test_support::fakes::FakeMfaVerifier;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, FakeSentCodeGenerator, FakeSentCodeStore, SENT_CODE,
        lockout,
    };
    use crate::test_support::{block_on, test_ctx};

    const RIGHT_CODE: &str = "123456";

    fn verifier() -> FakeMfaVerifier {
        FakeMfaVerifier {
            valid_code: RIGHT_CODE.to_owned(),
        }
    }

    fn enrolled() -> MfaEnrollment<ResolvedTenant> {
        let ann = UserId::new();
        FakeMfaEnrollmentStore::pending_for(ann)
            .enrollment_of(ann)
            .unwrap()
    }

    fn answer(
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        code: &str,
    ) -> Result<AnsweredCode, AppError> {
        let verifier = verifier();
        let check = CodeCheck {
            encryptor: &FakeEncryptor,
            verifier: &verifier,
            lockout: lockout(),
        };
        block_on(check.answer(
            SeedHolder::TenantUser(test_ctx().tenant_id()),
            enrollment,
            code,
        ))
    }

    /// Ann types the code her authenticator shows. It is accepted, and her
    /// earlier wrong tries are forgotten.
    #[test]
    fn the_right_code_is_answered() {
        let mut enrollment = enrolled();
        enrollment.record_failed_attempt(lockout());

        let answered = answer(&mut enrollment, RIGHT_CODE);

        assert!(answered.is_ok());
        assert_eq!(enrollment.failed_attempts(), 0);
    }

    /// A wrong authenticator code is forbidden and increments the factor's
    /// failed-attempt count.
    #[test]
    fn a_wrong_code_is_refused_and_counted() {
        let mut enrollment = enrolled();

        let answered = answer(&mut enrollment, "000000");

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
        assert_eq!(enrollment.failed_attempts(), 1);
    }

    /// Five failed attempts lock the factor, so even the right code
    /// returns account locked.
    #[test]
    fn a_locked_factor_refuses_even_the_right_code() {
        let mut enrollment = enrolled();
        for _ in 0..5 {
            enrollment.record_failed_attempt(lockout());
        }

        let answered = answer(&mut enrollment, RIGHT_CODE);

        assert!(matches!(answered, Err(AppError::AccountLocked(_))));
    }

    /// Ann's code was accepted once already. The store will not take its
    /// step again, so sending it a second time is refused.
    #[test]
    fn a_code_already_used_is_refused() {
        assert!(matches!(
            ensure_step_unused(StepClaim::from(false)),
            Err(AppError::Forbidden(_))
        ));
    }

    /// Ann's code is fresh. The store takes its step and the code passes.
    #[test]
    fn a_fresh_code_passes() {
        assert!(ensure_step_unused(StepClaim::from(true)).is_ok());
    }

    /// Ann's factor whose codes are mailed, in force, and the code just sent
    /// for it.
    fn mailed() -> (MfaEnrollment<ResolvedTenant>, OneTimeCode<ResolvedTenant>) {
        let ann = UserId::new();
        let enrollment = FakeMfaEnrollmentStore::active_with_factor(ann, EnrolledFactor::EmailCode)
            .enrollment_of(ann)
            .unwrap();
        let sent = FakeSentCodeStore::sent_for(&enrollment)
            .latest_of(ann)
            .unwrap();
        (enrollment, sent)
    }

    fn redeem(
        sent: &mut OneTimeCode<ResolvedTenant>,
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        typed: &str,
    ) -> Result<AnsweredCode, AppError> {
        SentCodeCheck {
            generator: &FakeSentCodeGenerator,
            lockout: lockout(),
        }
        .answer(sent, enrollment, typed)
    }

    /// Ann types the code mailed to her. It is accepted, spent, and needs no
    /// time step claimed.
    #[test]
    fn the_right_sent_code_is_answered_and_spent() {
        let (mut enrollment, mut sent) = mailed();

        let answered = redeem(&mut sent, &mut enrollment, SENT_CODE).unwrap();

        assert!(sent.spent_at().is_some());
        assert_eq!(step_to_claim(&answered), None);
    }

    /// Redeeming the mailed code once succeeds; redeeming that same code
    /// again is forbidden.
    #[test]
    fn a_sent_code_works_once() {
        let (mut enrollment, mut sent) = mailed();
        redeem(&mut sent, &mut enrollment, SENT_CODE).unwrap();

        let replayed = redeem(&mut sent, &mut enrollment, SENT_CODE);

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }

    /// A wrong mailed code is forbidden and adds one failed attempt to
    /// both the sent code and its factor.
    #[test]
    fn a_wrong_sent_code_is_refused_and_counted() {
        let (mut enrollment, mut sent) = mailed();

        let answered = redeem(&mut sent, &mut enrollment, "000000");

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
        assert_eq!(sent.wrong_tries(), 1);
        assert_eq!(enrollment.failed_attempts(), 1);
    }

    /// An authenticator code cannot answer a mailed-code factor. The
    /// forbidden result leaves the factor's failed-attempt count at zero.
    #[test]
    fn an_app_code_does_not_answer_a_sent_factor() {
        let (mut enrollment, _) = mailed();

        let answered = answer(&mut enrollment, RIGHT_CODE);

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
        assert_eq!(enrollment.failed_attempts(), 0);
    }
}
