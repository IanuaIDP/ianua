//! The code a person gives from the second factor their account has on
//! file, checked against it, for every step that asks the person again
//! rather than trusting the session: proving who they are before a change,
//! and confirming a reset.

use ianua_domain::domains::authentication::mfa::enrollment::{
    AnsweredCode, CodeDelivery, MfaEnrollment,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, SentCodeStore};
use crate::services::authentication::sign_in_steps::{
    CodeCheck, SeedHolder, SentCodeCheck, ensure_step_unused, step_to_claim,
};
use crate::tenancy::ScopedTenant;

/// What the account's second factor said to the code given.
#[derive(Debug)]
pub(crate) enum FactorAnswer {
    /// The account has no second factor in use, so there was nothing to
    /// answer.
    NoneOnFile,
    /// The account's factor accepted the code, and its time step was not
    /// used before.
    Answered(AnsweredCode),
}

/// The account's second factor, where it is kept and how its codes are
/// checked.
pub(crate) struct AccountFactor<'a> {
    /// Where the account's enrollment is kept.
    pub(crate) enrollments: &'a dyn MfaEnrollmentStore,
    /// Checks a code against the enrollment, whatever its kind.
    pub(crate) checks: FactorChecks<'a>,
}

/// How a code is checked against a tenant user's factor of any kind.
pub(crate) struct FactorChecks<'a> {
    /// Checks a code against an authenticator app's secret.
    pub(crate) app: CodeCheck<'a>,
    /// Checks a code against the one sent for a mailed or texted factor.
    pub(crate) sent: SentCodes<'a>,
}

impl FactorChecks<'_> {
    /// `enrollment`'s answer to `code`: from its app, or against the code
    /// sent for it, as its kind decides.
    ///
    /// # Errors
    ///
    /// As [`CodeCheck::answer`] and [`SentCodes::answer`] list.
    pub(crate) async fn answer(
        &self,
        tenant: &ScopedTenant,
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        code: &str,
    ) -> Result<AnsweredCode, AppError> {
        match enrollment.method().delivery() {
            CodeDelivery::Generated => {
                self.app
                    .answer(SeedHolder::TenantUser(**tenant), enrollment, code)
                    .await
            }
            CodeDelivery::Sent => self.sent.answer(tenant, enrollment, code).await,
        }
    }
}

/// The codes sent for tenant users' mailed and texted factors, and how a
/// typed one is checked against them.
pub(crate) struct SentCodes<'a> {
    /// Where the latest code sent for each person is kept.
    pub(crate) store: &'a dyn SentCodeStore,
    /// Checks a typed code against the sent one.
    pub(crate) check: SentCodeCheck<'a>,
}

impl SentCodes<'_> {
    /// `enrollment`'s answer to `typed`, checked against the latest code
    /// sent for it, which is saved whatever the answer: a wrong try counts,
    /// a right one is spent.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when no code was sent, or the code is wrong,
    ///   spent or lapsed.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` when the sent code cannot be read or saved.
    pub(crate) async fn answer(
        &self,
        tenant: &ScopedTenant,
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        typed: &str,
    ) -> Result<AnsweredCode, AppError> {
        let owner = UserId::from_uuid(*enrollment.subject_id().as_uuid());
        let Some(mut sent) = self.store.hold_latest(tenant, &owner).await.or_internal()? else {
            return Err(AppError::Forbidden(message!(
                "authentication-no-code-was-sent-for-this",
                "no code was sent for this factor; ask for one"
            )));
        };
        let answered = self.check.answer(&mut sent, enrollment, typed);
        self.store.save(tenant, &sent).await.or_internal()?;
        answered
    }
}

/// Refuses an app's code whose time step was claimed before. A sent code
/// was spent when it was checked, so it claims nothing.
///
/// # Errors
///
/// - `AppError::Forbidden` when the code was already used.
/// - `AppError::Internal` when the claim cannot be recorded.
pub(crate) async fn ensure_unused(
    enrollments: &dyn MfaEnrollmentStore,
    tenant: &ScopedTenant,
    owner: &UserId,
    answered: &AnsweredCode,
) -> Result<(), AppError> {
    let Some(step) = step_to_claim(answered) else {
        return Ok(());
    };
    let claimed = enrollments
        .claim_step(tenant, owner, step)
        .await
        .or_internal()?;
    ensure_step_unused(claimed.into())
}

/// Whose factor answers, and with what code.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FactorCode<'a> {
    /// The tenant the account is in.
    pub(crate) tenant: &'a ScopedTenant,
    /// The account.
    pub(crate) user_id: &'a UserId,
    /// The code the person gave, or that they gave none.
    pub(crate) code: Option<&'a str>,
}

impl AccountFactor<'_> {
    /// What the account's factor says to `given.code`.
    ///
    /// An account with no factor in use answers [`FactorAnswer::NoneOnFile`]
    /// whatever was given. One with a factor must answer it. A wrong code
    /// counts towards the factor's lock, and is saved before the refusal.
    ///
    /// # Errors
    ///
    /// - `AppError::StepUpRequired` when the account has a factor and no
    ///   code was given.
    /// - `AppError::Forbidden` when the code is wrong or was used before.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` when the enrollment cannot be read or saved,
    ///   or the code cannot be checked.
    pub(crate) async fn answer(&self, given: FactorCode<'_>) -> Result<FactorAnswer, AppError> {
        let Some(mut enrollment) = self.active_enrollment(given).await? else {
            return Ok(FactorAnswer::NoneOnFile);
        };
        let Some(code) = given.code else {
            return Err(AppError::StepUpRequired);
        };
        let answered = self
            .checks
            .answer(given.tenant, &mut enrollment, code)
            .await;
        self.enrollments
            .save(given.tenant, &enrollment)
            .await
            .or_internal()?;
        let answered = answered?;
        ensure_unused(self.enrollments, given.tenant, given.user_id, &answered).await?;
        Ok(FactorAnswer::Answered(answered))
    }

    /// The account's factor in force, held until the unit of work ends, so
    /// a second code answered at once waits for this one's count.
    async fn active_enrollment(
        &self,
        given: FactorCode<'_>,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, AppError> {
        Ok(self
            .enrollments
            .hold_by_user(given.tenant, given.user_id)
            .await
            .or_internal()?
            .filter(MfaEnrollment::is_active))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::enrollment::EnrolledFactor;
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::test_support::fakes::FakeMfaVerifier;

    use super::*;
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, FakeSentCodeGenerator, FakeSentCodeStore, SENT_CODE,
        lockout,
    };
    use crate::test_support::{block_on, test_ctx};

    const RIGHT_CODE: &str = "123456";

    fn answer(
        store: &FakeMfaEnrollmentStore,
        user_id: UserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        answer_with_sent(store, &FakeSentCodeStore::empty(), user_id, code)
    }

    fn answer_with_sent(
        store: &FakeMfaEnrollmentStore,
        sent: &FakeSentCodeStore,
        user_id: UserId,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let verifier = FakeMfaVerifier {
            valid_code: RIGHT_CODE.to_owned(),
        };
        let factor = AccountFactor {
            enrollments: store,
            checks: FactorChecks {
                app: CodeCheck {
                    encryptor: &FakeEncryptor,
                    verifier: &verifier,
                    lockout: lockout(),
                },
                sent: SentCodes {
                    store: sent,
                    check: SentCodeCheck {
                        generator: &FakeSentCodeGenerator,
                        lockout: lockout(),
                    },
                },
            },
        };
        let tenant = test_ctx().tenant();
        block_on(factor.answer(FactorCode {
            tenant: &tenant,
            user_id: &user_id,
            code,
        }))
    }

    /// Ann's factor texts her codes. She types the one just sent and her
    /// factor answers it; the code is spent.
    #[test]
    fn a_texted_code_is_answered() {
        let ann = UserId::new();
        let number = PhoneNumber::new("+4930123456").unwrap();
        let store =
            FakeMfaEnrollmentStore::active_with_factor(ann, EnrolledFactor::SmsCode(number));
        let sent = FakeSentCodeStore::sent_for(&store.enrollment_of(ann).unwrap());

        let answered = answer_with_sent(&store, &sent, ann, Some(SENT_CODE)).unwrap();

        assert!(matches!(answered, FactorAnswer::Answered(_)));
        assert!(sent.latest_of(ann).unwrap().spent_at().is_some());
    }

    /// Ann's email factor has no sent code to check against. Presenting
    /// a code is forbidden even though the factor is active.
    #[test]
    fn a_mailed_factor_without_a_sent_code_is_refused() {
        let ann = UserId::new();
        let store = FakeMfaEnrollmentStore::active_with_factor(ann, EnrolledFactor::EmailCode);

        let answered = answer(&store, ann, Some(SENT_CODE));

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
    }

    /// Ann has no second factor. Whatever she types, there is nothing to
    /// answer, and she passes on her other proof alone.
    #[test]
    fn an_account_without_a_factor_has_nothing_to_answer() {
        let ann = UserId::new();

        let answered = answer(&FakeMfaEnrollmentStore::empty(), ann, None).unwrap();

        assert!(matches!(answered, FactorAnswer::NoneOnFile));
    }

    /// Ann types the code her authenticator shows. Her factor answers it.
    #[test]
    fn the_right_code_is_answered() {
        let ann = UserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answered = answer(&store, ann, Some(RIGHT_CODE)).unwrap();

        assert!(matches!(answered, FactorAnswer::Answered(_)));
    }

    /// An active authenticator factor requires a code; omitting it
    /// returns step-up required.
    #[test]
    fn an_account_with_a_factor_must_give_a_code() {
        let ann = UserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answered = answer(&store, ann, None);

        assert!(matches!(answered, Err(AppError::StepUpRequired)));
    }

    /// A wrong authenticator code is forbidden, with one failed attempt
    /// saved on Ann's factor.
    #[test]
    fn a_wrong_code_is_refused_and_counted() {
        let ann = UserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);

        let answered = answer(&store, ann, Some("000000"));

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
        assert_eq!(store.failed_attempts(), 1);
    }

    /// Ann's authenticator code succeeds once. Reusing it is forbidden
    /// after its time step has been claimed.
    #[test]
    fn a_replayed_code_is_refused() {
        let ann = UserId::new();
        let store = FakeMfaEnrollmentStore::active_for(ann);
        answer(&store, ann, Some(RIGHT_CODE)).unwrap();

        let replayed = answer(&store, ann, Some(RIGHT_CODE));

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }
}
