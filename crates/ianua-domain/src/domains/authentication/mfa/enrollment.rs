use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::events::mfa::{
    FactorLock, FailedFactor, MfaEnrolled, MfaEnrollmentStarted, MfaFailed, MfaUnenrolled,
};
use crate::domains::authentication::keeper::{ChangedBy, FactorWithdrawal};
pub use crate::domains::authentication::mfa::answered_code::{
    AnsweredCode, CodeAttempt, CodeRefused, CodeReplay,
};
pub use crate::domains::authentication::mfa::enrolled_factor::{
    CodeDelivery, EnrolledFactor, MfaMethod,
};
pub use crate::domains::authentication::mfa::enrollment_state::{
    Confirmation, EnrollmentState, LockoutPolicy, RecentFailures,
};
use crate::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
use crate::domains::authentication::mfa::offer::FactorOffer;
use crate::domains::authentication::mfa::verifier::MfaVerifier;
use crate::domains::authentication::sessions::fresh_sign_in::FactorSetupProof;
use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::isolation::SecurityScope;
use crate::isolation::scope::{ResolvedTenant, TenantScope};
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{PrincipalId, TokenHash, UserId};

/// A subject's second factor, with its lockout after wrong answers.
///
/// The `S: SecurityScope` parameter keeps tenant users' enrollments,
/// `MfaEnrollment<ResolvedTenant>`, apart from organization users',
/// `MfaEnrollment<ResolvedOrganization>`. Storage keeps them in separate
/// tables.
///
/// What answering the factor needs is in its [`EnrolledFactor`]: an
/// authenticator app's seed, held only in sealed form, or the number texted
/// codes go to. Codes that are sent are checked through
/// [`OneTimeCode`](crate::domains::authentication::mfa::one_time_code::OneTimeCode).
///
/// A tenant user's enrollment raises its setup, its confirmation, its
/// turning off and every wrong answer, taken with [`Raises::take_events`]
/// once it is saved. An organization user's enrollment raises them too, but
/// its plane records events of its own, so they are dropped with it.
#[derive(Debug)]
pub struct MfaEnrollment<S: SecurityScope> {
    subject_id: PrincipalId,
    factor: EnrolledFactor,
    state: EnrollmentState,
    failures: RecentFailures,
    enrolled_at: OffsetDateTime,
    raised: Raised<ResolvedTenant>,
    _scope: PhantomData<S>,
}

/// Persisted state for repository hydration.
pub struct MfaEnrollmentRow {
    /// The tenant user or organization user this enrollment belongs to.
    pub subject_id: PrincipalId,
    /// The factor enrolled, with what answering it needs.
    pub factor: EnrolledFactor,
    /// Where the enrollment stands. See [`EnrollmentState::from_stored`].
    pub state: EnrollmentState,
    /// Wrong answers that still count. See [`RecentFailures::from_stored`].
    pub failures: RecentFailures,
    /// When enrollment began.
    pub enrolled_at: OffsetDateTime,
}

impl<S: SecurityScope> MfaEnrollment<S> {
    /// Starts a new enrollment of `factor` in the pending state, for a
    /// subject who proved who they are just now, where `offer` says the
    /// boundary offers that kind of factor.
    ///
    /// It becomes active only after the subject confirms it with a right
    /// code: from their app, or sent to the address or number it uses.
    /// Mallory steals Ann's session and sets up her own authenticator on
    /// Ann's account. Without the fresh proof, Ann's next sign-in asks for a
    /// code only Mallory has. Someone setting up the factor a sign-in owes
    /// uses that sign-in's
    /// [`EnrolmentProof`](crate::domains::authentication::sessions::fresh_sign_in::EnrolmentProof).
    ///
    /// Raises `authentication.mfa_enrollment_started`.
    ///
    /// # Errors
    ///
    /// - [`MfaEnrollmentError::NotOffered`] when `offer` is for another kind
    ///   of factor than `factor`.
    /// - [`MfaEnrollmentError::NotProvedNow`] when `proof` does not let
    ///   `subject_id` set up a factor now.
    pub fn begin(
        subject_id: PrincipalId,
        factor: EnrolledFactor,
        offer: &FactorOffer,
        proof: &impl FactorSetupProof,
    ) -> Result<Self, MfaEnrollmentError> {
        if offer.method() != factor.method() {
            return Err(MfaEnrollmentError::NotOffered);
        }
        if !proof.lets_set_up(&subject_id) {
            return Err(MfaEnrollmentError::NotProvedNow);
        }
        let mut enrollment = Self {
            subject_id,
            factor,
            state: EnrollmentState::Pending,
            failures: RecentFailures::Clear,
            enrolled_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        enrollment.raised.raise(MfaEnrollmentStarted {
            user_id: enrollment.owner(),
            occurred_at: enrollment.enrolled_at,
        });
        Ok(enrollment)
    }

    /// Rebuilds an enrollment from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it was confirmed
    ///   before it began.
    /// - [`DomainError::Infrastructure`] when the row says it was turned off
    ///   before it began.
    /// - [`DomainError::Infrastructure`] when the row says it was turned off
    ///   before it was confirmed.
    pub fn reconstitute(row: MfaEnrollmentRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            subject_id: row.subject_id,
            factor: row.factor,
            state: row.state,
            failures: row.failures,
            enrolled_at: row.enrolled_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &MfaEnrollmentRow) -> Result<(), DomainError> {
        RowCheck::of("MFA enrollment")
            .in_order_if(
                row.enrolled_at,
                row.state.verified_at(),
                "confirmed before it began",
            )
            .in_order_if(
                row.enrolled_at,
                row.state.disabled_at(),
                "turned off before it began",
            )
            .holds(
                row.state.confirmed_before_disabled(),
                "turned off before it was confirmed",
            )
            .finish()
    }

    /// The tenant user or organization user this enrollment belongs to.
    #[must_use]
    pub fn subject_id(&self) -> PrincipalId {
        self.subject_id
    }

    /// The kind of second factor enrolled.
    #[must_use]
    pub fn method(&self) -> MfaMethod {
        self.factor.method()
    }

    /// The factor enrolled, with what answering it needs: the sealed seed
    /// of an authenticator app, which infrastructure opens, or the number
    /// texted codes go to.
    #[must_use]
    pub fn factor(&self) -> &EnrolledFactor {
        &self.factor
    }

    /// Where the enrollment stands.
    #[must_use]
    pub fn state(&self) -> &EnrollmentState {
        &self.state
    }

    /// Where the enrollment is in its lifecycle.
    #[must_use]
    pub fn status(&self) -> MfaEnrollmentStatus {
        self.state.status()
    }

    /// Hash of the recovery codes, once the enrollment was confirmed.
    #[must_use]
    pub fn recovery_codes_hash(&self) -> Option<&TokenHash> {
        self.state.recovery_codes_hash()
    }

    /// When enrollment began.
    #[must_use]
    pub fn enrolled_at(&self) -> OffsetDateTime {
        self.enrolled_at
    }

    /// When the subject confirmed the enrollment with a valid code.
    #[must_use]
    pub fn verified_at(&self) -> Option<OffsetDateTime> {
        self.state.verified_at()
    }

    /// When the enrollment was abandoned or disabled.
    #[must_use]
    pub fn disabled_at(&self) -> Option<OffsetDateTime> {
        self.state.disabled_at()
    }

    /// Whether this enrollment is verified and so in force.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.state, EnrollmentState::Verified(_))
    }

    /// Whether the enrollment is waiting for the subject to confirm it with
    /// a valid code.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self.state, EnrollmentState::Pending)
    }

    /// Wrong answers that still count, as stored.
    #[must_use]
    pub fn failures(&self) -> RecentFailures {
        self.failures
    }

    /// How many wrong answers are stored in the current run.
    #[must_use]
    pub fn failed_attempts(&self) -> u32 {
        self.failures.count()
    }

    /// When the last failed attempt happened.
    #[must_use]
    pub fn last_failed_at(&self) -> Option<OffsetDateTime> {
        self.failures.last_at()
    }

    /// Whether too many attempts have failed lately to allow another.
    ///
    /// A lock lasts the policy's window from the last failure, then lifts on
    /// its own. A factor locked for good would shut its owner out of the
    /// account, recovery codes included.
    #[must_use]
    pub fn is_locked_out(&self, policy: LockoutPolicy) -> bool {
        let recent = self.failures.at(crate::shared::clock::now(), policy);
        recent.count() >= policy.max_attempts()
    }

    /// Records a wrong code for this factor: from the authenticator, or a
    /// sent code typed wrong.
    ///
    /// Failures older than the policy's window are forgotten first. Raises
    /// `authentication.mfa_failed`, naming the kind of factor and saying
    /// whether this one locked it.
    pub fn record_failed_attempt(&mut self, policy: LockoutPolicy) {
        self.fail(policy, FailedFactor::from(self.method()));
    }

    /// Records a wrong recovery code, which counts towards the same lock as
    /// a wrong code from the factor. Raises `authentication.mfa_failed` for
    /// a recovery code.
    pub(crate) fn record_failed_recovery_code(&mut self, policy: LockoutPolicy) {
        self.fail(policy, FailedFactor::RecoveryCode);
    }

    /// Counts a wrong answer made with `factor`, and raises it with whether
    /// it locked the factor.
    fn fail(&mut self, policy: LockoutPolicy, factor: FailedFactor) {
        let now = crate::shared::clock::now();
        self.failures = self.failures.at(now, policy).and_one_more(now);
        self.raised.raise(MfaFailed {
            factor,
            locked: FactorLock::from(self.is_locked_out(policy)),
            occurred_at: now,
        });
    }

    /// The account this enrollment belongs to, as a tenant user's id.
    fn owner(&self) -> UserId {
        UserId::from_uuid(*self.subject_id.as_uuid())
    }

    /// Forgets every counted wrong answer, after a right one.
    ///
    /// Only a right answer from the factor, or a recovery code standing in
    /// for it, calls this. A caller who cleared the count on their own word
    /// could guess codes past the lock.
    pub(crate) fn reset_failed_attempts(&mut self) {
        self.failures = RecentFailures::Clear;
    }

    /// Checks a code from an authenticator app against this factor,
    /// counting a wrong one towards the lock and forgetting past wrong ones
    /// after a right one. A code sent for the factor is checked through
    /// [`OneTimeCode::redeem`](crate::domains::authentication::mfa::one_time_code::OneTimeCode::redeem).
    ///
    /// A pending factor answers too, so its setup can be confirmed. The
    /// caller saves the enrollment whatever the outcome, so a wrong code
    /// still counts.
    ///
    /// # Errors
    ///
    /// - [`CodeRefused::OtherKind`] when this factor's codes are sent, not
    ///   worked out by an app.
    /// - [`CodeRefused::Retired`] when the factor was given up or turned off.
    /// - [`CodeRefused::Locked`] when too many wrong codes came lately. The
    ///   code is not checked.
    /// - [`CodeRefused::Wrong`] when the code matches no step in the window.
    /// - [`CodeRefused::Unchecked`] when `verifier` cannot check the code.
    pub fn answer(
        &mut self,
        verifier: &(impl MfaVerifier + ?Sized),
        attempt: CodeAttempt<'_>,
        lockout: LockoutPolicy,
    ) -> Result<AnsweredCode, CodeRefused> {
        if self.method().delivery() != CodeDelivery::Generated {
            return Err(CodeRefused::OtherKind);
        }
        self.ensure_answers(lockout)?;
        let matched = verifier
            .matched_step(attempt.seed, attempt.code, crate::shared::clock::now())
            .map_err(CodeRefused::Unchecked)?;
        let Some(step) = matched else {
            self.record_failed_attempt(lockout);
            return Err(CodeRefused::Wrong);
        };
        self.reset_failed_attempts();
        Ok(self.answered(CodeReplay::ClaimStep(step)))
    }

    /// A right code from this factor, kept from a second use by `replay`.
    pub(super) fn answered(&self, replay: CodeReplay) -> AnsweredCode {
        AnsweredCode::new(self.subject_id, self.enrolled_at, self.method(), replay)
    }

    /// Refuses a code for a factor that is retired, or locked by recent
    /// wrong answers.
    pub(super) fn ensure_answers(&self, lockout: LockoutPolicy) -> Result<(), CodeRefused> {
        self.ensure_in_use()?;
        if self.is_locked_out(lockout) {
            return Err(CodeRefused::Locked);
        }
        Ok(())
    }

    /// Confirms the enrollment with a right code from it.
    ///
    /// The code shows the subject's app holds the secret, or that a code
    /// sent to the address or number reached them, so a setup nobody
    /// finished never comes into force. It keeps the hash of the recovery
    /// codes shown to the subject. The caller follows
    /// [`AnsweredCode::replay`] before saving.
    ///
    /// Raises `authentication.mfa_enrolled`.
    ///
    /// # Errors
    ///
    /// - [`MfaEnrollmentError::NotItsCode`] when `answer` was checked against
    ///   another enrollment.
    /// - [`MfaEnrollmentError::NotPending`] when the enrollment is not
    ///   waiting to be confirmed.
    pub fn verify(
        &mut self,
        answer: &AnsweredCode,
        recovery_codes_hash: TokenHash,
    ) -> Result<(), MfaEnrollmentError> {
        if !answer.is_for(self.subject_id, self.enrolled_at) {
            return Err(MfaEnrollmentError::NotItsCode);
        }
        self.ensure_moves_to(
            MfaEnrollmentStatus::Verified,
            MfaEnrollmentError::NotPending,
        )?;
        let now = crate::shared::clock::now();
        self.state = EnrollmentState::Verified(Confirmation::new(now, recovery_codes_hash));
        self.raised.raise(MfaEnrolled { occurred_at: now });
        Ok(())
    }

    /// Turns off the owner's active factor after a valid code proves possession.
    /// The caller follows [`AnsweredCode::replay`] before saving.
    /// Raises `authentication.mfa_unenrolled`.
    ///
    /// # Errors
    /// [`MfaEnrollmentError::NotItsCode`] if the code names another enrollment.
    /// [`MfaEnrollmentError::NotActive`] if the factor is not in force.
    pub fn turn_off_with_code(&mut self, answer: &AnsweredCode) -> Result<(), MfaEnrollmentError> {
        if !answer.is_for(self.subject_id, self.enrolled_at) {
            return Err(MfaEnrollmentError::NotItsCode);
        }
        self.turn_off_raised(ChangedBy::Holder)
    }

    /// Resets someone else's factor for an administrator holding all their permissions.
    /// The owner enrolls again at next sign-in; self-service uses [`Self::turn_off_with_code`].
    /// Raises `authentication.mfa_unenrolled`.
    ///
    /// # Errors
    /// [`MfaEnrollmentError::AccountHoldsMore`] for another account's control, missing
    /// user-update rights, or permissions held by the account but not the administrator.
    /// [`MfaEnrollmentError::NotActive`] if the factor is not in force.
    pub fn reset_by_admin(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<(), MfaEnrollmentError> {
        let account = self.owner();
        control
            .ensure_allowed(&account, AccountAction::ChangeSignIn)
            .map_err(|_| MfaEnrollmentError::AccountHoldsMore)?;
        self.turn_off_raised(ChangedBy::SomeoneElse(account))
    }

    /// Abandons an unconfirmed enrollment so the freshly proven subject can restart it.
    /// A session alone cannot cancel another person's ongoing setup.
    ///
    /// # Errors
    /// [`MfaEnrollmentError::NotProvedNow`] if proof does not permit setup now.
    /// [`MfaEnrollmentError::NotPending`] unless enrollment awaits confirmation.
    pub fn abandon(&mut self, proof: &impl FactorSetupProof) -> Result<(), MfaEnrollmentError> {
        if !proof.lets_set_up(&self.subject_id) {
            return Err(MfaEnrollmentError::NotProvedNow);
        }
        self.give_up()
    }

    /// Takes this factor away from an account that passes to a new holder,
    /// whether it is in force or still being set up. A factor already
    /// retired stays as it is. Its recovery codes stand in for nothing once
    /// it is off.
    ///
    /// Bob's account is reopened for a new invitation to his address.
    /// Without this, whoever accepts is asked for Bob's authenticator, and
    /// Bob's codes still get past the factor.
    ///
    /// # Errors
    ///
    /// - [`MfaEnrollmentError::NotThisAccount`] when `by` takes away the
    ///   ways in of another account.
    pub fn withdraw(&mut self, by: &impl FactorWithdrawal<S>) -> Result<(), MfaEnrollmentError> {
        if !by.withdraws_from(&self.subject_id) {
            return Err(MfaEnrollmentError::NotThisAccount);
        }
        match self.state {
            EnrollmentState::Verified(_) => self.turn_off(),
            EnrollmentState::Pending => self.give_up(),
            EnrollmentState::Abandoned { .. } | EnrollmentState::Disabled { .. } => Ok(()),
        }
    }

    /// Gives up a setup still waiting to be confirmed.
    fn give_up(&mut self) -> Result<(), MfaEnrollmentError> {
        if !self.is_pending() {
            return Err(MfaEnrollmentError::NotPending);
        }
        self.ensure_moves_to(
            MfaEnrollmentStatus::Disabled,
            MfaEnrollmentError::NotPending,
        )?;
        self.state = EnrollmentState::Abandoned {
            at: crate::shared::clock::now(),
        };
        Ok(())
    }

    /// Turns off a factor in force and raises that `by` turned it off.
    fn turn_off_raised(&mut self, by: ChangedBy<UserId>) -> Result<(), MfaEnrollmentError> {
        self.turn_off()?;
        self.raised.raise(MfaUnenrolled {
            by,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Turns off a factor in force. The sealed secret stays on the record,
    /// but the enrollment stops counting, and the subject can enroll again.
    fn turn_off(&mut self) -> Result<(), MfaEnrollmentError> {
        let EnrollmentState::Verified(confirmation) = &self.state else {
            return Err(MfaEnrollmentError::NotActive);
        };
        self.ensure_moves_to(MfaEnrollmentStatus::Disabled, MfaEnrollmentError::NotActive)?;
        self.state = EnrollmentState::Disabled {
            confirmation: confirmation.clone(),
            at: crate::shared::clock::now(),
        };
        Ok(())
    }

    /// Refuses a code for a factor that was given up or turned off.
    pub(super) fn ensure_in_use(&self) -> Result<(), CodeRefused> {
        match self.state {
            EnrollmentState::Pending | EnrollmentState::Verified(_) => Ok(()),
            EnrollmentState::Abandoned { .. } | EnrollmentState::Disabled { .. } => {
                Err(CodeRefused::Retired)
            }
        }
    }

    fn ensure_moves_to(
        &self,
        to: MfaEnrollmentStatus,
        refusal: MfaEnrollmentError,
    ) -> Result<(), MfaEnrollmentError> {
        self.status().try_transition(to).map_err(|_| refusal)?;
        Ok(())
    }
}

impl<T: TenantScope> Raises for MfaEnrollment<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Why an enrollment refused to change state.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MfaEnrollmentError {
    /// A confirm or abandon on an enrollment that is not pending.
    #[error("MFA enrollment is not in pending state")]
    NotPending,

    /// A turn-off or reset of an enrollment that is not verified.
    #[error("MFA enrollment is not active")]
    NotActive,

    /// A turn-off with a code checked against another enrollment.
    #[error("the code was not checked against this second factor")]
    NotItsCode,

    /// A reset by an admin who holds less than the account does.
    #[error("the account holds more than the person resetting its second factor")]
    AccountHoldsMore,

    /// A setup started, or given up, without a fresh proof of the person.
    #[error("setting up a second factor needs the person to prove who they are again")]
    NotProvedNow,

    /// A withdrawal made for another account.
    #[error("the second factor belongs to another account than the one withdrawn")]
    NotThisAccount,

    /// A setup of a kind of factor the boundary does not offer.
    #[error("this kind of second factor is not offered here")]
    NotOffered,
}

/// A right code from a factor of `subject_id`, for tests elsewhere in the
/// crate.
#[cfg(test)]
pub(crate) fn answer_for(subject_id: PrincipalId) -> AnsweredCode {
    AnsweredCode::new(
        subject_id,
        crate::shared::clock::now(),
        MfaMethod::Totp,
        CodeReplay::ClaimStep(
            crate::domains::authentication::mfa::time_step::TimeStep::from_number(1),
        ),
    )
}

/// A pending authenticator app of `subject_id`, set up with a fresh proof,
/// for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn app_setup_of<S: SecurityScope>(subject_id: PrincipalId) -> MfaEnrollment<S> {
    MfaEnrollment::begin(
        subject_id,
        EnrolledFactor::Totp(crate::types::SealedSecret::new("sealed").unwrap()),
        &crate::domains::authentication::mfa::offer::offered(MfaMethod::Totp),
        &crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of(subject_id),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::offer::offered;
    use crate::domains::authentication::mfa::time_step::TimeStep;
    use crate::domains::authentication::mfa::verifier::TotpSeed;
    use crate::domains::authentication::sessions::fresh_sign_in::{FreshSignIn, fresh_proof_of};
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::identity::account::profile_values::PhoneNumber;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::shared::security::secret::Secret;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::SealedSecret;

    const RIGHT_CODE: &str = "424242";

    /// A verifier that knows one right code.
    struct KnowsOneCode;

    impl MfaVerifier for KnowsOneCode {
        fn generate_secret(&self) -> Result<TotpSeed, DomainError> {
            Ok(TotpSeed::new(vec![1, 2, 3]))
        }

        fn build_otpauth_uri(&self, _seed: &TotpSeed, _issuer: &str, _account: &str) -> Secret {
            Secret::new("otpauth://totp/test")
        }

        fn matched_step(
            &self,
            _seed: &TotpSeed,
            code: &str,
            at: OffsetDateTime,
        ) -> Result<Option<TimeStep>, DomainError> {
            Ok(TimeStep::containing(at).filter(|_| code == RIGHT_CODE))
        }
    }

    fn app(sealed: &str) -> EnrolledFactor {
        EnrolledFactor::Totp(SealedSecret::new(sealed).unwrap())
    }

    fn pending_enrollment() -> MfaEnrollment<ResolvedTenant> {
        let subject = PrincipalId::from(UserId::new());
        MfaEnrollment::begin(
            subject,
            app("encrypted_secret_abc"),
            &offered(MfaMethod::Totp),
            &fresh_proof_of(subject),
        )
        .unwrap()
    }

    /// An authenticator-app offer cannot authorize setup of a texted-code factor.
    #[test]
    fn a_factor_is_not_set_up_under_an_offer_for_another_kind() {
        let ann = PrincipalId::from(UserId::new());
        let mallorys_number = PhoneNumber::new("+15550100").unwrap();

        let refused = MfaEnrollment::<ResolvedTenant>::begin(
            ann,
            EnrolledFactor::SmsCode(mallorys_number),
            &offered(MfaMethod::Totp),
            &fresh_proof_of(ann),
        );

        assert!(matches!(refused, Err(MfaEnrollmentError::NotOffered)));
    }

    /// Ann sets up texted codes where they are offered. The enrollment is
    /// pending, keeps her number and holds no seed.
    #[test]
    fn a_texted_factor_keeps_its_number() {
        let ann = PrincipalId::from(UserId::new());
        let number = PhoneNumber::new("+4930123456").unwrap();

        let enrollment = MfaEnrollment::<ResolvedTenant>::begin(
            ann,
            EnrolledFactor::SmsCode(number.clone()),
            &offered(MfaMethod::SmsCode),
            &fresh_proof_of(ann),
        )
        .unwrap();

        assert_eq!(enrollment.method(), MfaMethod::SmsCode);
        assert_eq!(enrollment.factor().phone_number(), Some(&number));
        assert!(enrollment.factor().sealed_secret().is_none());
    }

    /// An app code cannot answer a mailed-code enrollment. The refusal leaves
    /// the enrollment's failed-attempt count at zero.
    #[test]
    fn an_app_code_does_not_answer_a_sent_factor() {
        let ann = PrincipalId::from(UserId::new());
        let mut mailed = MfaEnrollment::<ResolvedTenant>::begin(
            ann,
            EnrolledFactor::EmailCode,
            &offered(MfaMethod::EmailCode),
            &fresh_proof_of(ann),
        )
        .unwrap();

        let refused = answered(&mut mailed, RIGHT_CODE);

        assert!(matches!(refused, Err(CodeRefused::OtherKind)));
        assert_eq!(mailed.failed_attempts(), 0);
    }

    fn active_enrollment() -> MfaEnrollment<ResolvedTenant> {
        let mut enrollment = pending_enrollment();
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();
        enrollment
            .verify(&answer, TokenHash::from_stored("hash".to_owned()))
            .unwrap();
        enrollment
    }

    /// Fresh proof of another account cannot authorize Ann's factor setup.
    #[test]
    fn a_factor_is_not_set_up_without_a_fresh_proof_of_its_owner() {
        let ann = PrincipalId::from(UserId::new());
        let mallory = PrincipalId::from(UserId::new());

        let refused = MfaEnrollment::<ResolvedTenant>::begin(
            ann,
            app("mallorys_secret"),
            &offered(MfaMethod::Totp),
            &fresh_proof_of(mallory),
        );

        assert!(matches!(refused, Err(MfaEnrollmentError::NotProvedNow)));
    }

    /// A valid code from another setup cannot confirm Ann's enrollment,
    /// which remains pending.
    #[test]
    fn a_setup_is_not_confirmed_with_another_setups_code() {
        let mut anns = pending_enrollment();
        let mut mallorys = pending_enrollment();
        let mallorys_answer = answered(&mut mallorys, RIGHT_CODE).unwrap();

        let err = anns
            .verify(&mallorys_answer, TokenHash::from_stored("codes".to_owned()))
            .unwrap_err();

        assert_eq!(err, MfaEnrollmentError::NotItsCode);
        assert!(anns.is_pending());
    }

    fn answered(
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        code: &str,
    ) -> Result<AnsweredCode, CodeRefused> {
        let seed = TotpSeed::new(vec![1, 2, 3]);
        enrollment.answer(&KnowsOneCode, CodeAttempt { seed: &seed, code }, lockout(5))
    }

    static EDITOR: [SystemPermission; 1] = [SystemPermission::Users(UserAction::Update)];
    static EDITOR_AND_ROLES: [SystemPermission; 2] = [
        SystemPermission::Users(UserAction::Update),
        SystemPermission::Roles(RoleAction::Manage),
    ];

    fn editor_acting_on(
        enrollment: &MfaEnrollment<ResolvedTenant>,
        target: &'static [SystemPermission],
    ) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(&EDITOR),
            UserId::from_uuid(*enrollment.subject_id().as_uuid()),
            crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
            Handout {
                system: target,
                custom: &[],
            },
        )
    }

    /// Ann starts setting up TOTP. The enrollment is pending, not in force,
    /// and has no confirmation, disable time or recovery codes yet.
    #[test]
    fn begin_creates_pending_enrollment() {
        let enrollment = pending_enrollment();

        assert_eq!(enrollment.status(), MfaEnrollmentStatus::Pending);
        assert_eq!(enrollment.method(), MfaMethod::Totp);
        assert!(enrollment.is_pending());
        assert!(!enrollment.is_active());
        assert!(enrollment.verified_at().is_none());
        assert!(enrollment.disabled_at().is_none());
        assert!(enrollment.recovery_codes_hash().is_none());
    }

    /// A new enrollment keeps the sealed secret it was started with, unchanged.
    #[test]
    fn begin_stores_encrypted_secret() {
        let enrollment = pending_enrollment();
        assert_eq!(
            enrollment
                .factor()
                .sealed_secret()
                .map(SealedSecret::as_str),
            Some("encrypted_secret_abc")
        );
    }

    /// A new enrollment records the moment it began, between the clock
    /// readings taken just before and just after.
    #[test]
    fn begin_sets_enrolled_timestamp() {
        let before = crate::shared::clock::now();
        let enrollment = pending_enrollment();
        let after = crate::shared::clock::now();

        assert!(enrollment.enrolled_at() >= before);
        assert!(enrollment.enrolled_at() <= after);
    }

    /// Ann confirms her setup with a valid code. The enrollment is verified
    /// and in force, with a confirmation time and her recovery-code hash.
    #[test]
    fn verify_activates_enrollment() {
        let mut enrollment = pending_enrollment();
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();

        enrollment
            .verify(
                &answer,
                TokenHash::from_stored("recovery_hash_123".to_owned()),
            )
            .unwrap();

        assert_eq!(enrollment.status(), MfaEnrollmentStatus::Verified);
        assert!(enrollment.is_active());
        assert!(!enrollment.is_pending());
        assert!(enrollment.verified_at().is_some());
        assert_eq!(
            enrollment.recovery_codes_hash().map(TokenHash::as_str),
            Some("recovery_hash_123")
        );
    }

    /// An active enrollment rejects a second verification even with a valid
    /// code and a new recovery-code hash.
    #[test]
    fn cannot_verify_already_verified() {
        let mut enrollment = active_enrollment();
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();

        let err = enrollment
            .verify(&answer, TokenHash::from_stored("hash2".to_owned()))
            .unwrap_err();

        assert_eq!(err, MfaEnrollmentError::NotPending);
    }

    /// Ann gives up a setup and later types a code from it. The abandoned
    /// enrollment cannot be confirmed. She starts again with a new secret.
    #[test]
    fn cannot_verify_an_abandoned_enrollment() {
        let mut enrollment = pending_enrollment();
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();
        enrollment.abandon(&proved_now(&enrollment)).unwrap();

        let err = enrollment
            .verify(&answer, TokenHash::from_stored("hash".to_owned()))
            .unwrap_err();

        assert_eq!(err, MfaEnrollmentError::NotPending);
    }

    /// Ann loses the QR code before confirming. She gives up the setup, which
    /// is now off with a disable time, so she can start over.
    #[test]
    fn a_pending_enrollment_can_be_abandoned() {
        let mut enrollment = pending_enrollment();

        enrollment.abandon(&proved_now(&enrollment)).unwrap();

        assert_eq!(enrollment.status(), MfaEnrollmentStatus::Disabled);
        assert!(!enrollment.is_active());
        assert!(!enrollment.is_pending());
        assert!(enrollment.disabled_at().is_some());
    }

    fn proved_now(enrollment: &MfaEnrollment<ResolvedTenant>) -> FreshSignIn {
        fresh_proof_of(enrollment.subject_id())
    }

    /// Abandoning Ann's setup requires fresh proof of Ann's account.
    /// Another account's proof leaves the setup pending.
    #[test]
    fn a_setup_is_not_given_up_without_a_fresh_proof_of_its_owner() {
        let mut anns = pending_enrollment();
        let mallorys = fresh_proof_of(PrincipalId::from(UserId::new()));

        let refused = anns.abandon(&mallorys);

        assert_eq!(refused, Err(MfaEnrollmentError::NotProvedNow));
        assert!(anns.is_pending());
    }

    /// An admin resets Bob's unfinished setup. It is refused and stays
    /// pending. An unfinished setup is abandoned instead.
    #[test]
    fn resetting_a_pending_enrollment_is_refused() {
        let mut enrollment = pending_enrollment();

        let err = enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap_err();

        assert_eq!(err, MfaEnrollmentError::NotActive);
        assert!(enrollment.is_pending());
    }

    /// Ann types a right code from her TOTP and turns it off. The enrollment
    /// is disabled and records when.
    #[test]
    fn its_owner_turns_off_a_factor_with_a_right_code() {
        let mut enrollment = active_enrollment();
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();

        enrollment.turn_off_with_code(&answer).unwrap();

        assert_eq!(enrollment.status(), MfaEnrollmentStatus::Disabled);
        assert!(enrollment.disabled_at().is_some());
    }

    /// An answer from another factor cannot turn Ann's factor off;
    /// her enrollment remains active.
    #[test]
    fn an_answer_from_another_factor_turns_nothing_off() {
        let mut mallorys = active_enrollment();
        let mut anns = active_enrollment();
        let mallorys_answer = answered(&mut mallorys, RIGHT_CODE).unwrap();

        let result = anns.turn_off_with_code(&mallorys_answer);

        assert!(matches!(result, Err(MfaEnrollmentError::NotItsCode)));
        assert!(anns.is_active());
    }

    /// A wrong code is rejected and increments the enrollment's failed-attempt
    /// count once.
    #[test]
    fn a_wrong_code_gives_no_answer_and_counts() {
        let mut enrollment = active_enrollment();

        let refused = answered(&mut enrollment, "000000");

        assert!(matches!(refused, Err(CodeRefused::Wrong)));
        assert_eq!(enrollment.failed_attempts(), 1);
    }

    /// After five failed attempts lock the factor, even its correct code
    /// is rejected as locked.
    #[test]
    fn a_locked_factor_checks_no_code() {
        let mut enrollment = active_enrollment();
        for _ in 0..5 {
            enrollment.record_failed_attempt(lockout(5));
        }

        let refused = answered(&mut enrollment, RIGHT_CODE);

        assert!(matches!(refused, Err(CodeRefused::Locked)));
    }

    /// Ann's right code clears her two earlier wrong ones.
    #[test]
    fn a_right_code_clears_the_wrong_ones() {
        let mut enrollment = active_enrollment();
        enrollment.record_failed_attempt(lockout(5));
        enrollment.record_failed_attempt(lockout(5));

        answered(&mut enrollment, RIGHT_CODE).unwrap();

        assert_eq!(enrollment.failed_attempts(), 0);
    }

    /// An administrator-reset factor rejects its correct code as retired.
    #[test]
    fn a_factor_that_is_off_gives_no_answer() {
        let mut enrollment = active_enrollment();
        enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap();

        let refused = answered(&mut enrollment, RIGHT_CODE);

        assert!(matches!(refused, Err(CodeRefused::Retired)));
    }

    /// An admin who holds all that Bob holds resets Bob's TOTP. The
    /// enrollment is disabled and records when.
    #[test]
    fn an_admin_holding_what_the_account_holds_resets_its_factor() {
        let mut enrollment = active_enrollment();

        enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap();

        assert_eq!(enrollment.status(), MfaEnrollmentStatus::Disabled);
        assert!(enrollment.disabled_at().is_some());
    }

    /// A user editor cannot reset a factor belonging to someone who also
    /// manages roles. The target enrollment remains active.
    #[test]
    fn an_admin_cannot_reset_the_factor_of_someone_who_holds_more() {
        let mut enrollment = active_enrollment();

        let err = enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR_AND_ROLES))
            .unwrap_err();

        assert_eq!(err, MfaEnrollmentError::AccountHoldsMore);
        assert!(enrollment.is_active());
    }

    /// Resetting a factor that is already off is refused, so the first
    /// disable time stays on record.
    #[test]
    fn cannot_reset_an_already_disabled_factor() {
        let mut enrollment = active_enrollment();
        enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap();

        let err = enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap_err();

        assert_eq!(err, MfaEnrollmentError::NotActive);
    }

    /// Abandoning Ann's verified TOTP is refused and it stays in force. A
    /// factor in force is turned off with a code or reset by an admin.
    #[test]
    fn an_active_enrollment_cannot_be_abandoned() {
        let mut enrollment = active_enrollment();

        let err = enrollment.abandon(&proved_now(&enrollment)).unwrap_err();

        assert_eq!(err, MfaEnrollmentError::NotPending);
        assert!(enrollment.is_active());
    }

    fn lockout(max_attempts: u32) -> LockoutPolicy {
        LockoutPolicy::new(max_attempts, time::Duration::minutes(15)).unwrap()
    }

    /// Ann types two wrong codes in a row. The count goes from 0 to 1 to 2.
    #[test]
    fn record_failed_attempt_increments_counter() {
        let mut enrollment = pending_enrollment();
        assert_eq!(enrollment.failed_attempts(), 0);

        enrollment.record_failed_attempt(lockout(5));
        assert_eq!(enrollment.failed_attempts(), 1);

        enrollment.record_failed_attempt(lockout(5));
        assert_eq!(enrollment.failed_attempts(), 2);
    }

    /// Ann types two wrong codes and then a right one. The count goes back
    /// to 0.
    #[test]
    fn reset_failed_attempts_clears_counter() {
        let mut enrollment = pending_enrollment();
        enrollment.record_failed_attempt(lockout(5));
        enrollment.record_failed_attempt(lockout(5));

        enrollment.reset_failed_attempts();

        assert_eq!(enrollment.failed_attempts(), 0);
    }

    /// Ann's factor locks after 5 wrong codes. Fifteen minutes later it
    /// unlocks, and her next wrong code starts a new count at 1.
    #[test]
    fn a_lock_lifts_once_the_lockout_has_passed() {
        let start = crate::shared::clock::now();
        let mut enrollment = pending_enrollment();
        {
            let _at = crate::shared::clock::freeze(start);
            for _ in 0..5 {
                enrollment.record_failed_attempt(lockout(5));
            }
            assert!(enrollment.is_locked_out(lockout(5)));
        }

        let _later = crate::shared::clock::freeze(start + lockout(5).window());

        assert!(!enrollment.is_locked_out(lockout(5)));
        enrollment.record_failed_attempt(lockout(5));
        assert_eq!(
            enrollment.failed_attempts(),
            1,
            "old failures are forgotten"
        );
    }

    /// After 5 wrong codes, a policy of 5 locks the factor. A policy of 6
    /// still lets one more try through.
    #[test]
    fn is_locked_out_at_max() {
        let mut enrollment = pending_enrollment();
        for _ in 0..5 {
            enrollment.record_failed_attempt(lockout(5));
        }

        assert!(enrollment.is_locked_out(lockout(5)));
        assert!(!enrollment.is_locked_out(lockout(6)));
    }

    /// After 4 wrong codes, a policy of 5 does not lock the factor yet.
    #[test]
    fn is_locked_out_below_max() {
        let mut enrollment = pending_enrollment();
        for _ in 0..4 {
            enrollment.record_failed_attempt(lockout(5));
        }

        assert!(!enrollment.is_locked_out(lockout(5)));
    }

    /// The enrollment hands back the sealed value it was given, not a
    /// decoded seed.
    #[test]
    fn secret_is_encrypted_blob() {
        let enrollment = pending_enrollment();
        assert!(
            enrollment
                .factor()
                .sealed_secret()
                .is_some_and(|secret| secret.as_str().starts_with("encrypted_"))
        );
    }

    /// A stored verified enrollment loads back with the same subject, method,
    /// sealed secret, recovery-code hash and times.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let subject_id = UserId::new().into();
        let now = crate::shared::clock::now();

        let enrollment = MfaEnrollment::<ResolvedTenant>::reconstitute(MfaEnrollmentRow {
            subject_id,
            factor: app("encrypted_xyz"),
            state: EnrollmentState::from_stored(
                MfaEnrollmentStatus::Verified,
                Some(now),
                Some(TokenHash::from_stored("recovery_hash".to_owned())),
                None,
            )
            .unwrap(),
            failures: RecentFailures::from_stored(0, None).unwrap(),
            enrolled_at: now,
        })
        .unwrap();

        assert_eq!(enrollment.subject_id(), subject_id);
        assert_eq!(enrollment.method(), MfaMethod::Totp);
        assert_eq!(enrollment.status(), MfaEnrollmentStatus::Verified);
        assert_eq!(enrollment.factor(), &app("encrypted_xyz"));
        assert_eq!(
            enrollment.recovery_codes_hash().map(TokenHash::as_str),
            Some("recovery_hash")
        );
        assert_eq!(enrollment.enrolled_at(), now);
        assert_eq!(enrollment.verified_at(), Some(now));
        assert!(enrollment.disabled_at().is_none());
    }

    /// Ann's TOTP is confirmed and later reset. It keeps its confirmation
    /// time, so its history still says when it was in force.
    #[test]
    fn a_disabled_factor_keeps_when_it_was_confirmed() {
        let mut enrollment = active_enrollment();
        let confirmed = enrollment.verified_at();

        enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap();

        assert_eq!(enrollment.verified_at(), confirmed);
        assert!(confirmed.is_some());
        assert!(matches!(
            enrollment.state(),
            EnrollmentState::Disabled { .. }
        ));
    }

    fn stored_with(state: EnrollmentState, enrolled_at: OffsetDateTime) -> MfaEnrollmentRow {
        MfaEnrollmentRow {
            subject_id: UserId::new().into(),
            factor: app("encrypted_xyz"),
            state,
            failures: RecentFailures::from_stored(0, None).unwrap(),
            enrolled_at,
        }
    }

    fn confirmed(at: OffsetDateTime) -> Confirmation {
        Confirmation::new(at, TokenHash::from_stored("codes".to_owned()))
    }

    /// A stored row says the enrollment was confirmed one second before it
    /// began. Loading it is refused as corrupt.
    #[test]
    fn a_stored_enrollment_confirmed_before_it_began_is_refused() {
        let now = crate::shared::clock::now();
        let row = stored_with(
            EnrollmentState::Verified(confirmed(now - time::Duration::SECOND)),
            now,
        );

        assert!(refused_as_corrupt(
            &MfaEnrollment::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored row says the factor was turned off a minute before it was
    /// confirmed. Loading it is refused as corrupt.
    #[test]
    fn a_stored_enrollment_turned_off_before_it_was_confirmed_is_refused() {
        let now = crate::shared::clock::now();
        let row = stored_with(
            EnrollmentState::Disabled {
                confirmation: confirmed(now + time::Duration::minutes(2)),
                at: now + time::Duration::minutes(1),
            },
            now,
        );

        assert!(refused_as_corrupt(
            &MfaEnrollment::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann starts setting up her authenticator. The setup raises
    /// `authentication.mfa_enrollment_started`.
    #[test]
    fn beginning_a_setup_raises_its_start() {
        let mut enrollment = pending_enrollment();

        assert_eq!(
            raised_names(&mut enrollment),
            ["authentication.mfa_enrollment_started"]
        );
    }

    /// Ann confirms her setup with a right code. It raises
    /// `authentication.mfa_enrolled`.
    #[test]
    fn confirming_a_setup_raises_the_enrollment() {
        let mut enrollment = pending_enrollment();
        raised_names(&mut enrollment);
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();

        enrollment
            .verify(&answer, TokenHash::from_stored("hash".to_owned()))
            .unwrap();

        assert_eq!(
            raised_names(&mut enrollment),
            ["authentication.mfa_enrolled"]
        );
    }

    /// Ann types a wrong code. It raises `authentication.mfa_failed` for a
    /// code from her authenticator, which has not locked it yet.
    #[test]
    fn a_wrong_code_raises_a_failure_that_has_not_locked_the_factor() {
        let mut enrollment = active_enrollment();
        raised_names(&mut enrollment);

        let _ = answered(&mut enrollment, "000000");

        let events = raised(&mut enrollment);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().as_str(), "authentication.mfa_failed");
        assert_eq!(events[0].payload().get("factor"), Some("totp"));
        assert_eq!(events[0].payload().get("locked"), Some("false"));
    }

    /// Ann's factor locks after two wrong answers. The second failure is
    /// raised as the one that locked it.
    #[test]
    fn the_failure_that_locks_the_factor_says_so() {
        let mut enrollment = active_enrollment();
        enrollment.record_failed_attempt(lockout(2));
        raised_names(&mut enrollment);

        enrollment.record_failed_attempt(lockout(2));

        let events = raised(&mut enrollment);
        assert_eq!(events[0].payload().get("locked"), Some("true"));
    }

    /// A wrong recovery code counts against Ann's factor. It raises
    /// `authentication.mfa_failed` for a recovery code.
    #[test]
    fn a_wrong_recovery_code_raises_a_failure_for_a_recovery_code() {
        let mut enrollment = active_enrollment();
        raised_names(&mut enrollment);

        enrollment.record_failed_recovery_code(lockout(5));

        let events = raised(&mut enrollment);
        assert_eq!(events[0].payload().get("factor"), Some("recovery_code"));
    }

    /// Ann turns her authenticator off with a code from it. It raises
    /// `authentication.mfa_unenrolled`.
    #[test]
    fn turning_off_with_a_code_raises_the_unenrollment() {
        let mut enrollment = active_enrollment();
        let answer = answered(&mut enrollment, RIGHT_CODE).unwrap();
        raised_names(&mut enrollment);

        enrollment.turn_off_with_code(&answer).unwrap();

        assert_eq!(
            raised_names(&mut enrollment),
            ["authentication.mfa_unenrolled"]
        );
    }

    /// An admin who holds all Bob holds resets his factor. It raises
    /// `authentication.mfa_unenrolled`.
    #[test]
    fn an_admin_reset_raises_the_unenrollment() {
        let mut enrollment = active_enrollment();
        raised_names(&mut enrollment);

        enrollment
            .reset_by_admin(&editor_acting_on(&enrollment, &EDITOR))
            .unwrap();

        assert_eq!(
            raised_names(&mut enrollment),
            ["authentication.mfa_unenrolled"]
        );
    }

    /// Verification with another setup's code is rejected without raising
    /// an event on Ann's enrollment.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut anns = pending_enrollment();
        let mut mallorys = pending_enrollment();
        let mallorys_answer = answered(&mut mallorys, RIGHT_CODE).unwrap();
        raised_names(&mut anns);

        let refused = anns.verify(&mallorys_answer, TokenHash::from_stored("codes".to_owned()));

        assert!(refused.is_err());
        assert!(raised(&mut anns).is_empty());
    }

    /// An enrollment read back from storage has raised nothing.
    #[test]
    fn an_enrollment_read_back_has_raised_nothing() {
        let mut enrollment = MfaEnrollment::<ResolvedTenant>::reconstitute(stored_with(
            EnrollmentState::Pending,
            crate::shared::clock::now(),
        ))
        .unwrap();

        assert!(raised(&mut enrollment).is_empty());
    }
}
