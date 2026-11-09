//! Recovery codes: one-time backup codes for a subject who has lost their
//! MFA device.
//!
//! They are generated during MFA enrollment. Each code works once. When all
//! codes are used, the subject must generate a new set.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::events::recovery::{RecoveryCodeUsed, RecoveryCodesGenerated};
use crate::domains::authentication::mfa::enrollment::{
    AnsweredCode, CodeRefused, LockoutPolicy, MfaEnrollment,
};
use crate::domains::authentication::sessions::fresh_sign_in::FactorSetupProof;
use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::isolation::SecurityScope;
use crate::isolation::scope::{ResolvedTenant, TenantScope};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{PrincipalId, TokenHash, Usage};

/// A recovery code someone typed, and the second factor it stands in for.
///
/// A wrong recovery code counts towards the same lock as a wrong code from
/// the factor. Otherwise a locked factor could still be guessed past, one
/// recovery code at a time.
pub struct RecoveryAttempt<'a, S: SecurityScope> {
    /// The hash of the code as typed.
    pub hash: &'a TokenHash,
    /// The second factor the code stands in for.
    pub factor: &'a mut MfaEnrollment<S>,
    /// When wrong answers lock the factor.
    pub lockout: LockoutPolicy,
}

/// Reconstitution data for a persisted `RecoveryCode`.
pub struct RecoveryCodeRow {
    /// The one-way hash.
    pub hash: TokenHash,
    /// Whether this code has been used, and when.
    pub usage: Usage,
}

/// Reconstitution data for a persisted `RecoveryCodeSet`.
pub struct RecoveryCodeSetRow {
    /// The subject these codes belong to.
    pub subject_id: PrincipalId,
    /// The recovery codes.
    pub codes: Vec<RecoveryCode>,
    /// When this set was generated.
    pub generated_at: OffsetDateTime,
}

/// A single recovery code.
///
/// Only its hash is stored. The plain code is shown to the subject once,
/// when it is generated.
#[derive(Debug, Clone)]
pub struct RecoveryCode {
    /// The one-way hash of the recovery code.
    hash: TokenHash,
    /// Whether this code has been used, and when.
    usage: Usage,
}

impl RecoveryCode {
    /// Creates a new unused recovery code from its hash.
    ///
    /// Only its set makes one, from a right code of the subject's factor. A
    /// code made on its own would get past the factor with nobody's say.
    fn new(hash: TokenHash) -> Self {
        Self {
            hash,
            usage: Usage::Unused,
        }
    }

    /// Rebuilds a recovery code from storage.
    ///
    /// # Errors
    ///
    /// - Never fails. No part of the row can contradict another, and each
    ///   part was read through its own checked type.
    pub fn reconstitute(row: RecoveryCodeRow) -> Result<Self, DomainError> {
        Ok(Self {
            hash: row.hash,
            usage: row.usage,
        })
    }

    /// The one-way hash.
    #[must_use]
    pub fn hash(&self) -> &TokenHash {
        &self.hash
    }

    /// Whether this code has been consumed.
    #[must_use]
    pub fn is_used(&self) -> bool {
        self.usage.is_used()
    }

    /// When this code was used.
    #[must_use]
    pub fn used_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// Marks this code as used now.
    ///
    /// A used code stays used at its first time. Only its set calls this,
    /// after finding the code by the hash the subject presented.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the code is already used.
    fn consume(&mut self) -> Result<(), DomainError> {
        if self.is_used() {
            return Err(DomainError::invalid_transition(message!(
                "authentication-this-recovery-code-is-already-used",
                "this recovery code is already used"
            )));
        }
        self.usage = Usage::Used {
            at: crate::shared::clock::now(),
        };
        Ok(())
    }
}

/// A subject's set of recovery codes.
///
/// The `S: SecurityScope` parameter keeps tenant users' sets and
/// organization users' sets apart at compile time.
///
/// A tenant user's set raises its generation and each code used, taken with
/// [`Raises::take_events`] once it is saved. An organization user's set
/// raises them too, but its plane records events of its own, so they are
/// dropped with it.
#[derive(Debug)]
pub struct RecoveryCodeSet<S: SecurityScope> {
    subject_id: PrincipalId,
    codes: Vec<RecoveryCode>,
    generated_at: OffsetDateTime,
    raised: Raised<ResolvedTenant>,
    _scope: PhantomData<S>,
}

impl<S: SecurityScope> RecoveryCodeSet<S> {
    /// Creates a new set of unused recovery codes from their hashes, for a
    /// subject who just gave a right code from their second factor.
    ///
    /// A recovery code lets its holder past the second factor. Mallory
    /// steals Ann's session and asks for a new set. Without the code she
    /// holds codes that get her past Ann's factor long after the session
    /// ends. At setup, the code that confirms the factor is the one asked
    /// for.
    ///
    /// The set holds at least one code, and each hash once. Ann's set with
    /// one hash listed twice would let her one code work twice.
    ///
    /// Raises `authentication.recovery_codes_generated` with how many codes
    /// the set holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `answer` came from another
    ///   account's factor.
    /// - [`DomainError::Validation`] when no hash is given.
    /// - [`DomainError::Validation`] when a hash is given twice.
    pub fn generate(
        subject_id: PrincipalId,
        hashes: Vec<TokenHash>,
        answer: &AnsweredCode,
    ) -> Result<Self, DomainError> {
        if answer.subject() != subject_id {
            return Err(DomainError::forbidden(message!(
                "authentication-new-recovery-codes-need-a-code",
                "new recovery codes need a code from the account's own second factor"
            )));
        }
        validate_count("recovery codes", hashes.len(), 1..=usize::MAX)?;
        ensure_each_hash_once(&hashes)?;
        let mut set = Self {
            subject_id,
            codes: hashes.into_iter().map(RecoveryCode::new).collect(),
            generated_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        set.raised.raise(RecoveryCodesGenerated {
            count: u8::try_from(set.total()).unwrap_or(u8::MAX),
            occurred_at: set.generated_at,
        });
        Ok(set)
    }

    /// Replaces every code in the set with a fresh one from `hashes`, for a
    /// subject who proved who they are just now, while `factor`, the second
    /// factor the codes stand in for, is theirs and in force.
    ///
    /// Every earlier code stops working, used or not. Ann printed her codes
    /// and lost the paper. Without regeneration, whoever finds it keeps a
    /// way past her factor for as long as the factor lasts. Mallory steals
    /// Ann's session and asks for new codes. Without the fresh proof, she
    /// holds codes that outlast the session, as at setup.
    ///
    /// Raises `authentication.recovery_codes_generated` with how many codes
    /// the set now holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` does not let the subject
    ///   set up a factor now.
    /// - [`DomainError::Forbidden`] when `factor` is another subject's, or
    ///   not in force, so the codes would stand in for nothing.
    /// - [`DomainError::Validation`] when no hash is given, or one is given
    ///   twice.
    pub fn regenerate(
        &mut self,
        hashes: Vec<TokenHash>,
        factor: &MfaEnrollment<S>,
        proof: &impl FactorSetupProof,
    ) -> Result<(), DomainError> {
        if !proof.lets_set_up(&self.subject_id) {
            return Err(DomainError::forbidden(message!(
                "authentication-new-recovery-codes-need-the-person",
                "new recovery codes need the person to prove who they are again"
            )));
        }
        if factor.subject_id() != self.subject_id || !factor.is_active() {
            return Err(DomainError::forbidden(message!(
                "authentication-recovery-codes-stand-in-only-for",
                "recovery codes stand in only for the account's own factor in force"
            )));
        }
        validate_count("recovery codes", hashes.len(), 1..=usize::MAX)?;
        ensure_each_hash_once(&hashes)?;
        self.codes = hashes.into_iter().map(RecoveryCode::new).collect();
        self.generated_at = crate::shared::clock::now();
        self.raised.raise(RecoveryCodesGenerated {
            count: u8::try_from(self.total()).unwrap_or(u8::MAX),
            occurred_at: self.generated_at,
        });
        Ok(())
    }

    /// Rebuilds a set of recovery codes from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row holds no code.
    /// - [`DomainError::Infrastructure`] when the row holds one hash twice.
    /// - [`DomainError::Infrastructure`] when the row says a code was used
    ///   before the set was generated.
    pub fn reconstitute(row: RecoveryCodeSetRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            subject_id: row.subject_id,
            codes: row.codes,
            generated_at: row.generated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &RecoveryCodeSetRow) -> Result<(), DomainError> {
        RowCheck::of("recovery code set")
            .holds(!row.codes.is_empty(), "a set with no codes")
            .holds(
                first_repeat(row.codes.iter().map(RecoveryCode::hash)).is_none(),
                "one code held twice",
            )
            .holds(
                row.codes
                    .iter()
                    .all(|code| code.used_at().is_none_or(|at| row.generated_at <= at)),
                "a code used before the set was generated",
            )
            .finish()
    }

    /// The subject these codes belong to.
    #[must_use]
    pub fn subject_id(&self) -> PrincipalId {
        self.subject_id
    }

    /// All recovery codes in this set.
    #[must_use]
    pub fn codes(&self) -> &[RecoveryCode] {
        &self.codes
    }

    /// When this set was generated.
    #[must_use]
    pub fn generated_at(&self) -> OffsetDateTime {
        self.generated_at
    }

    /// Number of unused codes remaining.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.codes.iter().filter(|c| !c.is_used()).count()
    }

    /// Total codes in the set.
    #[must_use]
    pub fn total(&self) -> usize {
        self.codes.len()
    }

    /// Whether all codes have been consumed.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }

    /// Uses up the unused code `attempt` names, as a stand-in for the
    /// subject's second factor.
    ///
    /// The factor must be this subject's and in force, and not locked by
    /// recent wrong answers. A wrong code counts towards that lock, and a
    /// right one clears it, as a right code from the factor does. The caller
    /// saves the set and the factor whatever the outcome.
    ///
    /// A code used raises `authentication.recovery_code_used` with how many
    /// unused codes remain. A wrong one makes the factor raise
    /// `authentication.mfa_failed` for a recovery code.
    ///
    /// # Errors
    ///
    /// - [`CodeRefused::ForAnotherAccount`] when the factor is another
    ///   subject's.
    /// - [`CodeRefused::Retired`] when the factor is not in force, so no
    ///   code stands in for it.
    /// - [`CodeRefused::Locked`] when too many wrong answers came lately.
    ///   The code is not checked.
    /// - [`CodeRefused::Wrong`] when no unused code has this hash.
    pub fn redeem(&mut self, attempt: RecoveryAttempt<'_, S>) -> Result<ProvedFactor, CodeRefused> {
        let RecoveryAttempt {
            hash,
            factor,
            lockout,
        } = attempt;
        self.ensure_stands_in_for(factor, lockout)?;
        if !self.spend(hash) {
            factor.record_failed_recovery_code(lockout);
            return Err(CodeRefused::Wrong);
        }
        factor.reset_failed_attempts();
        self.raised.raise(RecoveryCodeUsed {
            remaining: self.remaining(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(ProvedFactor::recovery_code(self.subject_id))
    }

    /// Refuses a factor these codes do not stand in for now.
    fn ensure_stands_in_for(
        &self,
        factor: &MfaEnrollment<S>,
        lockout: LockoutPolicy,
    ) -> Result<(), CodeRefused> {
        if factor.subject_id() != self.subject_id {
            return Err(CodeRefused::ForAnotherAccount);
        }
        if !factor.is_active() {
            return Err(CodeRefused::Retired);
        }
        if factor.is_locked_out(lockout) {
            return Err(CodeRefused::Locked);
        }
        Ok(())
    }

    /// Uses up the unused code with this hash, and says whether there was
    /// one.
    ///
    /// The hash comparison runs in constant time, as every `TokenHash`
    /// comparison does. So timing cannot reveal a code byte by byte.
    fn spend(&mut self, hash: &TokenHash) -> bool {
        let Some(code) = self.codes.iter_mut().find(|code| code.hash() == hash) else {
            return false;
        };
        code.consume().is_ok()
    }
}

impl<T: TenantScope> Raises for RecoveryCodeSet<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a list of new code hashes that names one hash twice.
fn ensure_each_hash_once(hashes: &[TokenHash]) -> Result<(), DomainError> {
    if first_repeat(hashes).is_none() {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "authentication-a-recovery-code-is-listed-twice",
        "a recovery code is listed twice in the same set"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::enrollment::{
        EnrolledFactor, EnrollmentState, MfaEnrollmentRow, RecentFailures, answer_for,
    };
    use crate::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{SealedSecret, UserId};

    fn hash(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    fn generated(
        subject: PrincipalId,
        hashes: Vec<TokenHash>,
    ) -> Result<RecoveryCodeSet<ResolvedTenant>, DomainError> {
        RecoveryCodeSet::generate(subject, hashes, &answer_for(subject))
    }

    fn test_set() -> RecoveryCodeSet<ResolvedTenant> {
        generated(
            UserId::new().into(),
            vec![hash("hash_1"), hash("hash_2"), hash("hash_3")],
        )
        .unwrap()
    }

    fn lockout() -> LockoutPolicy {
        LockoutPolicy::new(3, time::Duration::minutes(15)).unwrap()
    }

    /// A confirmed factor of the subject `set` belongs to.
    fn factor_of(set: &RecoveryCodeSet<ResolvedTenant>) -> MfaEnrollment<ResolvedTenant> {
        let now = crate::shared::clock::now();
        MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: set.subject_id(),
            factor: EnrolledFactor::Totp(SealedSecret::new("sealed").unwrap()),
            state: EnrollmentState::from_stored(
                MfaEnrollmentStatus::Verified,
                Some(now),
                Some(hash("codes")),
                None,
            )
            .unwrap(),
            failures: RecentFailures::Clear,
            enrolled_at: now,
        })
        .unwrap()
    }

    fn redeem(
        set: &mut RecoveryCodeSet<ResolvedTenant>,
        factor: &mut MfaEnrollment<ResolvedTenant>,
        code: &str,
    ) -> Result<ProvedFactor, CodeRefused> {
        set.redeem(RecoveryAttempt {
            hash: &hash(code),
            factor,
            lockout: lockout(),
        })
    }

    /// A new recovery-code set cannot contain the same hash twice.
    #[test]
    fn a_set_with_one_hash_twice_is_refused() {
        let set = generated(UserId::new().into(), vec![hash("hash_1"), hash("hash_1")]);

        assert!(matches!(set, Err(DomainError::Validation(_))));
    }

    /// Ann's enrollment asks for a set with no codes. It is refused, so she
    /// never holds a set that can recover nothing.
    #[test]
    fn an_empty_set_is_refused() {
        let set = generated(UserId::new().into(), Vec::new());

        assert!(matches!(set, Err(DomainError::Validation(_))));
    }

    /// A factor belonging to Mallory cannot authorize recovery codes for Ann.
    #[test]
    fn new_codes_need_a_code_from_the_accounts_own_factor() {
        let ann = PrincipalId::from(UserId::new());
        let mallory = PrincipalId::from(UserId::new());

        let set = RecoveryCodeSet::<ResolvedTenant>::generate(
            ann,
            vec![hash("hash_1")],
            &answer_for(mallory),
        );

        assert!(matches!(set, Err(DomainError::Forbidden(_))));
    }

    /// Ann lost the paper with her codes and proves who she is again. Her
    /// set holds only the new codes: an old one no longer gets past her
    /// factor, and a new one does.
    #[test]
    fn regenerated_codes_replace_every_earlier_one() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        let proof = fresh_proof_of(set.subject_id());

        set.regenerate(vec![hash("new_1"), hash("new_2")], &factor, &proof)
            .unwrap();

        assert_eq!(set.total(), 2);
        assert!(matches!(
            redeem(&mut set, &mut factor, "hash_1"),
            Err(CodeRefused::Wrong)
        ));
        assert!(redeem(&mut set, &mut factor, "new_1").is_ok());
    }

    /// Regenerating raises `authentication.recovery_codes_generated` with the
    /// new count.
    #[test]
    fn regenerating_raises_the_new_set() {
        let mut set = test_set();
        let factor = factor_of(&set);
        let proof = fresh_proof_of(set.subject_id());
        raised_names(&mut set);

        set.regenerate(vec![hash("new_1")], &factor, &proof)
            .unwrap();

        let events = raised(&mut set);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.recovery_codes_generated"
        );
        assert_eq!(events[0].payload().get("count"), Some("1"));
    }

    /// Mallory's fresh proof cannot regenerate Ann's codes; all three existing codes remain.
    #[test]
    fn regenerating_needs_a_fresh_proof_of_the_owner() {
        let mut set = test_set();
        let factor = factor_of(&set);
        let mallorys = fresh_proof_of(PrincipalId::from(UserId::new()));

        let refused = set.regenerate(vec![hash("mallorys")], &factor, &mallorys);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(set.total(), 3);
    }

    /// A pending factor cannot authorize regenerating recovery codes.
    #[test]
    fn no_codes_are_regenerated_for_a_factor_that_is_off() {
        let mut set = test_set();
        let factor = MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: set.subject_id(),
            factor: EnrolledFactor::Totp(SealedSecret::new("sealed").unwrap()),
            state: EnrollmentState::Pending,
            failures: RecentFailures::Clear,
            enrolled_at: crate::shared::clock::now(),
        })
        .unwrap();
        let proof = fresh_proof_of(set.subject_id());

        let refused = set.regenerate(vec![hash("new")], &factor, &proof);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A regenerated set with one hash twice is refused, as a new set is.
    #[test]
    fn a_regenerated_set_with_one_hash_twice_is_refused() {
        let mut set = test_set();
        let factor = factor_of(&set);
        let proof = fresh_proof_of(set.subject_id());

        let refused = set.regenerate(vec![hash("x"), hash("x")], &factor, &proof);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Duplicate hashes make a stored recovery-code set corrupt.
    #[test]
    fn a_stored_set_with_one_hash_twice_is_refused() {
        let set = RecoveryCodeSet::<ResolvedTenant>::reconstitute(RecoveryCodeSetRow {
            subject_id: UserId::new().into(),
            codes: vec![RecoveryCode::new(hash("a")), RecoveryCode::new(hash("a"))],
            generated_at: crate::shared::clock::now(),
        });

        assert!(refused_as_corrupt(&set));
    }

    /// A stored set with no codes at all is refused as corrupt.
    #[test]
    fn a_stored_set_with_no_codes_is_refused() {
        let set = RecoveryCodeSet::<ResolvedTenant>::reconstitute(RecoveryCodeSetRow {
            subject_id: UserId::new().into(),
            codes: Vec::new(),
            generated_at: crate::shared::clock::now(),
        });

        assert!(refused_as_corrupt(&set));
    }

    /// Replaying a consumed code is refused and preserves its first-use time.
    #[test]
    fn a_used_code_keeps_its_first_use_time() {
        let first = crate::shared::clock::now() - time::Duration::HOUR;
        let mut code = RecoveryCode::reconstitute(RecoveryCodeRow {
            hash: hash("a"),
            usage: Usage::Used { at: first },
        })
        .unwrap();

        let replay = code.consume();

        assert!(matches!(replay, Err(DomainError::InvalidTransition(_))));
        assert_eq!(code.used_at(), Some(first));
    }

    /// Ann gets a fresh set of 3 codes. All 3 are unused and the set is not
    /// used up.
    #[test]
    fn generate_creates_unused_codes() {
        let set = test_set();
        assert_eq!(set.total(), 3);
        assert_eq!(set.remaining(), 3);
        assert!(!set.is_exhausted());
    }

    /// Ann uses one of her 3 codes. It proves a recovery code for her
    /// account, and 2 remain.
    #[test]
    fn a_right_code_proves_a_recovery_code_for_its_account() {
        let mut set = test_set();
        let mut factor = factor_of(&set);

        let proof = redeem(&mut set, &mut factor, "hash_1").unwrap();

        assert_eq!(proof.factor(), MfaFactor::RecoveryCode);
        assert_eq!(proof.account(), set.subject_id());
        assert_eq!(set.remaining(), 2);
    }

    /// Someone types a code that is not in Ann's set. It is refused, counts
    /// towards her factor's lock, and all 3 codes stay unused.
    #[test]
    fn a_wrong_code_is_refused_and_counts() {
        let mut set = test_set();
        let mut factor = factor_of(&set);

        let refused = redeem(&mut set, &mut factor, "wrong_hash");

        assert!(matches!(refused, Err(CodeRefused::Wrong)));
        assert_eq!(factor.failed_attempts(), 1);
        assert_eq!(set.remaining(), 3);
    }

    /// A locked factor refuses even a matching recovery code, leaving all three codes unused.
    #[test]
    fn a_locked_factor_takes_no_recovery_code() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        for _ in 0..3 {
            factor.record_failed_attempt(lockout());
        }

        let refused = redeem(&mut set, &mut factor, "hash_1");

        assert!(matches!(refused, Err(CodeRefused::Locked)));
        assert_eq!(set.remaining(), 3);
    }

    /// Another account's recovery codes cannot answer Ann's factor and remain unused.
    #[test]
    fn codes_do_not_stand_in_for_another_accounts_factor() {
        let mut mallorys = test_set();
        let mut anns_factor = factor_of(&test_set());

        let refused = redeem(&mut mallorys, &mut anns_factor, "hash_1");

        assert!(matches!(refused, Err(CodeRefused::ForAnotherAccount)));
        assert_eq!(mallorys.remaining(), 3);
    }

    /// Reusing a consumed code is refused and leaves two recovery codes available.
    #[test]
    fn code_cannot_be_reused() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        redeem(&mut set, &mut factor, "hash_1").unwrap();

        let replay = redeem(&mut set, &mut factor, "hash_1");

        assert!(matches!(replay, Err(CodeRefused::Wrong)));
        assert_eq!(set.remaining(), 2);
    }

    /// Ann uses all 3 of her codes. The set reports 0 left and is used up,
    /// so she must generate a new set.
    #[test]
    fn exhausted_when_all_used() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        for code in ["hash_1", "hash_2", "hash_3"] {
            redeem(&mut set, &mut factor, code).unwrap();
        }
        assert!(set.is_exhausted());
        assert_eq!(set.remaining(), 0);
    }

    /// After Ann uses a code, that code is marked used and records when.
    #[test]
    fn consumed_code_has_timestamp() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        redeem(&mut set, &mut factor, "hash_1").unwrap();
        let code = set
            .codes()
            .iter()
            .find(|c| c.hash().as_str() == "hash_1")
            .unwrap();
        assert!(code.is_used());
        assert!(code.used_at().is_some());
    }

    /// Ann's set holds a code hashed as "ab". Presenting "ba" is refused and
    /// the code stays unused. The two differ in both bytes by the same
    /// amount, so a badly combined comparison could let them cancel out.
    #[test]
    fn a_rearranged_hash_does_not_cancel_itself_out_and_pass() {
        let mut set = generated(UserId::new().into(), vec![hash("ab")]).unwrap();
        let mut factor = factor_of(&set);

        assert!(redeem(&mut set, &mut factor, "ba").is_err());
        assert_eq!(set.remaining(), 1);
        assert!(redeem(&mut set, &mut factor, "ab").is_ok());
    }

    /// A stored set holds a code used one second before the set was
    /// generated. Loading it is refused as corrupt.
    #[test]
    fn a_stored_set_with_a_code_used_before_it_was_generated_is_refused() {
        let generated_at = crate::shared::clock::now();
        let used = RecoveryCode::reconstitute(RecoveryCodeRow {
            hash: hash("a"),
            usage: Usage::Used {
                at: generated_at - time::Duration::SECOND,
            },
        })
        .unwrap();

        let set = RecoveryCodeSet::<ResolvedTenant>::reconstitute(RecoveryCodeSetRow {
            subject_id: UserId::new().into(),
            codes: vec![used],
            generated_at,
        });

        assert!(refused_as_corrupt(&set));
    }

    /// Ann's factor comes with three new recovery codes. The set raises
    /// `authentication.recovery_codes_generated`, counting three.
    #[test]
    fn a_new_set_raises_how_many_codes_it_holds() {
        let mut set = test_set();

        let events = raised(&mut set);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.recovery_codes_generated"
        );
        assert_eq!(events[0].payload().get("count"), Some("3"));
    }

    /// Ann uses one of her three codes. The set raises
    /// `authentication.recovery_code_used`, with two left.
    #[test]
    fn a_code_used_raises_how_many_remain() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        raised_names(&mut set);

        redeem(&mut set, &mut factor, "hash_1").unwrap();

        let events = raised(&mut set);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.recovery_code_used"
        );
        assert_eq!(events[0].payload().get("remaining"), Some("2"));
    }

    /// A wrong recovery code raises no set event; the factor records the failed
    /// attempt with recovery code as its method.
    #[test]
    fn a_wrong_code_raises_nothing_on_the_set_and_a_failure_on_the_factor() {
        let mut set = test_set();
        let mut factor = factor_of(&set);
        raised_names(&mut set);

        let refused = redeem(&mut set, &mut factor, "guess");

        assert!(matches!(refused, Err(CodeRefused::Wrong)));
        assert!(raised(&mut set).is_empty());
        let failed = raised(&mut factor);
        assert_eq!(failed[0].event_type().as_str(), "authentication.mfa_failed");
        assert_eq!(failed[0].payload().get("factor"), Some("recovery_code"));
    }

    /// A set read back from storage has raised nothing.
    #[test]
    fn a_set_read_back_has_raised_nothing() {
        let mut set = RecoveryCodeSet::<ResolvedTenant>::reconstitute(RecoveryCodeSetRow {
            subject_id: UserId::new().into(),
            codes: vec![RecoveryCode::new(hash("a"))],
            generated_at: crate::shared::clock::now(),
        })
        .unwrap();

        assert!(raised(&mut set).is_empty());
    }
}
