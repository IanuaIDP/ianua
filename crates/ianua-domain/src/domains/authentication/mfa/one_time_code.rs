//! A one-time code sent for a second factor: mailed to the account's
//! address, or texted to the number the factor was set up with.
//!
//! A sent code is short, so it is guarded by everything around it: it
//! lives a few minutes, takes a few wrong tries, works once, and every
//! wrong try also counts towards the factor's own lock.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::events::mfa::MfaCodeSent;
use crate::domains::authentication::mfa::answered_code::{AnsweredCode, CodeRefused, CodeReplay};
use crate::domains::authentication::mfa::enrolled_factor::{CodeDelivery, MfaMethod};
use crate::domains::authentication::mfa::enrollment::{LockoutPolicy, MfaEnrollment};
use crate::isolation::SecurityScope;
use crate::isolation::scope::{ResolvedTenant, TenantScope};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::random::RandomSource;
use crate::shared::security::secret::Secret;
use crate::types::{Lifetime, PrincipalId, TokenHash, Usage};

/// How many digits a sent code has. Short enough to type from a phone,
/// and with the tries below a guess succeeds once in two hundred thousand.
pub(crate) const SENT_CODE_DIGITS: usize = 6;

/// The longest a sent code may live: enough for a slow mail, short enough
/// that a code read later from a mailbox or a lock screen does nothing.
pub(crate) const SENT_CODE_LONGEST: Duration = Duration::minutes(10);

/// How many wrong tries one sent code takes before it stops working.
pub(crate) const SENT_CODE_TRIES: u8 = 5;

/// A code sent for one enrollment's factor, kept as its hash.
///
/// The `S: SecurityScope` parameter keeps tenant users' codes apart from
/// organization users', as their enrollments are.
///
/// A tenant user's code raises its sending, taken with
/// [`Raises::take_events`] once it is saved. An organization user's code
/// raises it too, but its plane records events of its own, so it is
/// dropped with it.
#[derive(Debug)]
pub struct OneTimeCode<S: SecurityScope> {
    subject_id: PrincipalId,
    enrolled_at: OffsetDateTime,
    method: MfaMethod,
    code_hash: TokenHash,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    wrong_tries: u8,
    usage: Usage,
    raised: Raised<ResolvedTenant>,
    _scope: PhantomData<S>,
}

/// Persisted state for repository hydration.
pub struct OneTimeCodeRow {
    /// The account whose factor the code was sent for.
    pub subject_id: PrincipalId,
    /// When that factor's enrollment began, naming the enrollment.
    pub enrolled_at: OffsetDateTime,
    /// The kind of factor: a mailed or a texted code.
    pub method: MfaMethod,
    /// One-way hash of the code sent.
    pub code_hash: TokenHash,
    /// When it was sent.
    pub issued_at: OffsetDateTime,
    /// When it lapses.
    pub expires_at: OffsetDateTime,
    /// Wrong tries made against it so far.
    pub wrong_tries: u8,
    /// Whether it was spent, and when.
    pub usage: Usage,
}

/// A code someone typed for a factor whose codes are sent.
pub struct SentCodeAttempt<'a, S: SecurityScope> {
    /// The hash of the code as typed.
    pub hash: &'a TokenHash,
    /// The factor the code was sent for.
    pub factor: &'a mut MfaEnrollment<S>,
    /// When wrong answers lock the factor.
    pub lockout: LockoutPolicy,
}

impl<S: SecurityScope> OneTimeCode<S> {
    /// Records a code just sent for `factor`, kept as `code_hash`, good for
    /// `lifetime`. A pending factor gets one too, so its setup can be
    /// confirmed: the code reaching the address or number is what shows it
    /// is the person's.
    ///
    /// The caller makes the code with [`new_code`], hashes it and sends it.
    /// A mailed code goes to the address the account holds at that moment.
    /// A texted code goes to [`EnrolledFactor::phone_number`].
    ///
    /// Raises `authentication.mfa_code_sent`.
    ///
    /// [`EnrolledFactor::phone_number`]: crate::domains::authentication::mfa::enrolled_factor::EnrolledFactor::phone_number
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the factor's codes come from an
    ///   app, so nothing is sent.
    /// - [`DomainError::Forbidden`] when the factor was given up or turned
    ///   off.
    /// - [`DomainError::Validation`] when `lifetime` is longer than
    ///   `SENT_CODE_LONGEST`.
    pub fn issue(
        factor: &MfaEnrollment<S>,
        code_hash: TokenHash,
        lifetime: Lifetime,
    ) -> Result<Self, DomainError> {
        ensure_sendable(factor)?;
        lifetime.ensure_at_most(SENT_CODE_LONGEST, "a sent code")?;
        let now = crate::shared::clock::now();
        let mut code = Self {
            subject_id: factor.subject_id(),
            enrolled_at: factor.enrolled_at(),
            method: factor.method(),
            code_hash,
            issued_at: now,
            expires_at: lifetime.ends_after(now),
            wrong_tries: 0,
            usage: Usage::Unused,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        code.raised.raise(MfaCodeSent {
            method: code.method,
            expires_at: code.expires_at,
            occurred_at: now,
        });
        Ok(code)
    }

    /// Rebuilds a sent code from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row is for an app's
    ///   factor, whose codes are never sent.
    /// - [`DomainError::Infrastructure`] when the row was sent before its
    ///   enrollment began, lapses no later than it was sent, or lives longer
    ///   than `SENT_CODE_LONGEST`.
    /// - [`DomainError::Infrastructure`] when the row was spent before it
    ///   was sent or once it had lapsed.
    /// - [`DomainError::Infrastructure`] when the row holds more wrong tries
    ///   than `SENT_CODE_TRIES`.
    pub fn reconstitute(row: OneTimeCodeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            subject_id: row.subject_id,
            enrolled_at: row.enrolled_at,
            method: row.method,
            code_hash: row.code_hash,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            wrong_tries: row.wrong_tries,
            usage: row.usage,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OneTimeCodeRow) -> Result<(), DomainError> {
        RowCheck::of("sent second-factor code")
            .holds(
                row.method.delivery() == CodeDelivery::Sent,
                "a code sent for an authenticator app",
            )
            .holds(
                row.enrolled_at <= row.issued_at,
                "sent before its factor was set up",
            )
            .holds(row.issued_at < row.expires_at, "lapses before it was sent")
            .holds(
                row.expires_at <= row.issued_at.saturating_add(SENT_CODE_LONGEST),
                "lives longer than a sent code may",
            )
            .in_order_if(
                row.issued_at,
                row.usage.used_at(),
                "spent before it was sent",
            )
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "spent after it lapsed",
            )
            .holds(
                row.wrong_tries <= SENT_CODE_TRIES,
                "more wrong tries than a code takes",
            )
            .finish()
    }

    /// The account whose factor the code was sent for.
    #[must_use]
    pub fn subject_id(&self) -> PrincipalId {
        self.subject_id
    }

    /// When the factor's enrollment began, naming the enrollment.
    #[must_use]
    pub fn enrolled_at(&self) -> OffsetDateTime {
        self.enrolled_at
    }

    /// The kind of factor: a mailed or a texted code.
    #[must_use]
    pub fn method(&self) -> MfaMethod {
        self.method
    }

    /// One-way hash of the code sent.
    #[must_use]
    pub fn code_hash(&self) -> &TokenHash {
        &self.code_hash
    }

    /// When the code was sent.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// When the code lapses.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Wrong tries made against the code so far.
    #[must_use]
    pub fn wrong_tries(&self) -> u8 {
        self.wrong_tries
    }

    /// When the code was spent, if it was.
    #[must_use]
    pub fn spent_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// Whether the code still takes a try at `now`: unspent, in date, and
    /// short of `SENT_CODE_TRIES` wrong ones.
    #[must_use]
    pub fn takes_tries_at(&self, now: OffsetDateTime) -> bool {
        !self.usage.is_used() && now < self.expires_at && self.wrong_tries < SENT_CODE_TRIES
    }

    /// Checks the code `attempt` names against this one, spending it on a
    /// match.
    ///
    /// A wrong code counts against this code and against the factor's
    /// lock, as a wrong code from an app does. A right one clears the
    /// factor's count. The caller saves the code and the factor whatever the
    /// outcome. A right answer needs nothing more claimed: this code is
    /// spent, see [`CodeReplay::Spent`].
    ///
    /// # Errors
    ///
    /// - [`CodeRefused::ForAnotherAccount`] when the code was sent for
    ///   another enrollment than `attempt.factor`.
    /// - [`CodeRefused::Retired`] when the factor was given up or turned off.
    /// - [`CodeRefused::Locked`] when too many wrong answers came lately.
    ///   The code is not checked.
    /// - [`CodeRefused::Lapsed`] when the code is spent, out of date, or
    ///   took its last wrong try. A new one is sent.
    /// - [`CodeRefused::Wrong`] when the typed code is not this one.
    pub fn redeem(&mut self, attempt: SentCodeAttempt<'_, S>) -> Result<AnsweredCode, CodeRefused> {
        let SentCodeAttempt {
            hash,
            factor,
            lockout,
        } = attempt;
        if factor.subject_id() != self.subject_id || factor.enrolled_at() != self.enrolled_at {
            return Err(CodeRefused::ForAnotherAccount);
        }
        factor.ensure_answers(lockout)?;
        let now = crate::shared::clock::now();
        if !self.takes_tries_at(now) {
            return Err(CodeRefused::Lapsed);
        }
        if *hash != self.code_hash {
            self.wrong_tries = self.wrong_tries.saturating_add(1);
            factor.record_failed_attempt(lockout);
            return Err(CodeRefused::Wrong);
        }
        self.usage = Usage::Used { at: now };
        factor.reset_failed_attempts();
        Ok(factor.answered(CodeReplay::Spent))
    }
}

impl<T: TenantScope> Raises for OneTimeCode<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// A fresh code of `SENT_CODE_DIGITS` digits, drawn from `random`.
///
/// It comes back as a [`Secret`], so it is never printed by accident. Only
/// its hash is kept, through [`OneTimeCode::issue`].
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] if `random` answers with a digit at or
///   past ten. A weaker code is never made instead.
pub fn new_code(random: &mut impl RandomSource) -> Result<Secret, DomainError> {
    let mut code = String::with_capacity(SENT_CODE_DIGITS);
    for _ in 0..SENT_CODE_DIGITS {
        let digit = u32::try_from(random.index_below(10))
            .ok()
            .and_then(|digit| char::from_digit(digit, 10))
            .ok_or_else(|| DomainError::infra_msg("the random source gave a digit past nine"))?;
        code.push(digit);
    }
    Ok(Secret::new(code))
}

/// Refuses sending a code for a factor whose codes come from an app, or
/// for one given up or turned off.
fn ensure_sendable<S: SecurityScope>(factor: &MfaEnrollment<S>) -> Result<(), DomainError> {
    if factor.method().delivery() != CodeDelivery::Sent {
        return Err(DomainError::invalid(message!(
            "authentication-an-authenticator-app-makes-its-own",
            "an authenticator app makes its own codes; nothing is sent"
        )));
    }
    factor.ensure_in_use().map_err(|_| {
        DomainError::forbidden(message!(
            "authentication-no-code-is-sent-for-a",
            "no code is sent for a retired factor"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::enrolled_factor::EnrolledFactor;
    use crate::domains::authentication::mfa::enrollment::MfaEnrollmentError;
    use crate::domains::authentication::mfa::offer::offered;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::identity::account::profile_values::PhoneNumber;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::test_support::fakes::SequenceRandom;
    use crate::types::{SealedSecret, UserId};

    fn mailed_factor() -> MfaEnrollment<ResolvedTenant> {
        let ann = PrincipalId::from(UserId::new());
        MfaEnrollment::begin(
            ann,
            EnrolledFactor::EmailCode,
            &offered(MfaMethod::EmailCode),
            &fresh_proof_of(ann),
        )
        .unwrap()
    }

    fn texted_factor() -> MfaEnrollment<ResolvedTenant> {
        let ann = PrincipalId::from(UserId::new());
        MfaEnrollment::begin(
            ann,
            EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap()),
            &offered(MfaMethod::SmsCode),
            &fresh_proof_of(ann),
        )
        .unwrap()
    }

    fn hash(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    fn lockout() -> LockoutPolicy {
        LockoutPolicy::new(10, Duration::minutes(15)).unwrap()
    }

    fn five_minutes() -> Lifetime {
        Lifetime::new(Duration::minutes(5)).unwrap()
    }

    fn sent_for(factor: &MfaEnrollment<ResolvedTenant>) -> OneTimeCode<ResolvedTenant> {
        OneTimeCode::issue(factor, hash("right"), five_minutes()).unwrap()
    }

    fn typed(
        code: &mut OneTimeCode<ResolvedTenant>,
        factor: &mut MfaEnrollment<ResolvedTenant>,
        value: &str,
    ) -> Result<AnsweredCode, CodeRefused> {
        code.redeem(SentCodeAttempt {
            hash: &hash(value),
            factor,
            lockout: lockout(),
        })
    }

    /// Ann types the code mailed to her. It answers her factor, is spent,
    /// and needs no time step claimed.
    #[test]
    fn the_right_code_answers_its_factor_once() {
        let mut factor = mailed_factor();
        let mut code = sent_for(&factor);

        let answer = typed(&mut code, &mut factor, "right").unwrap();

        assert_eq!(answer.method(), MfaMethod::EmailCode);
        assert_eq!(answer.replay(), CodeReplay::Spent);
        assert!(code.spent_at().is_some());
    }

    /// Reusing a successfully answered texted code is rejected as lapsed.
    #[test]
    fn a_spent_code_does_not_answer_again() {
        let mut factor = texted_factor();
        let mut code = sent_for(&factor);
        typed(&mut code, &mut factor, "right").unwrap();

        let replayed = typed(&mut code, &mut factor, "right");

        assert!(matches!(replayed, Err(CodeRefused::Lapsed)));
    }

    /// A mailed code is rejected at its expiry instant and remains unspent.
    #[test]
    fn a_lapsed_code_does_not_answer() {
        let mut factor = mailed_factor();
        let mut code = sent_for(&factor);
        let _later = crate::shared::clock::freeze(code.expires_at());

        let refused = typed(&mut code, &mut factor, "right");

        assert!(matches!(refused, Err(CodeRefused::Lapsed)));
        assert!(code.spent_at().is_none());
    }

    /// Exhausting a sent code's allowed guesses rejects even the correct code.
    /// Every wrong guess also counts against the factor.
    #[test]
    fn a_code_stops_after_its_wrong_tries() {
        let mut factor = texted_factor();
        let mut code = sent_for(&factor);
        for guess in 0..SENT_CODE_TRIES {
            let wrong = typed(&mut code, &mut factor, &format!("guess-{guess}"));
            assert!(matches!(wrong, Err(CodeRefused::Wrong)));
        }

        let refused = typed(&mut code, &mut factor, "right");

        assert!(matches!(refused, Err(CodeRefused::Lapsed)));
        assert_eq!(factor.failed_attempts(), u32::from(SENT_CODE_TRIES));
    }

    /// A code sent for another enrollment is rejected without adding a failed
    /// attempt to Ann's factor.
    #[test]
    fn a_code_sent_for_another_factor_answers_nothing() {
        let mallorys = mailed_factor();
        let mut code = sent_for(&mallorys);
        let mut anns = mailed_factor();

        let refused = typed(&mut code, &mut anns, "right");

        assert!(matches!(refused, Err(CodeRefused::ForAnotherAccount)));
        assert_eq!(anns.failed_attempts(), 0);
    }

    /// A locked factor rejects the correct sent code and leaves it unspent.
    #[test]
    fn a_locked_factor_checks_no_sent_code() {
        let mut factor = mailed_factor();
        for _ in 0..10 {
            factor.record_failed_attempt(lockout());
        }
        let mut code = sent_for(&factor);

        let refused = typed(&mut code, &mut factor, "right");

        assert!(matches!(refused, Err(CodeRefused::Locked)));
        assert!(code.spent_at().is_none());
    }

    /// A wrong texted code raises `authentication.mfa_failed` for a texted
    /// code, which has not locked the factor yet.
    #[test]
    fn a_wrong_sent_code_raises_a_failure_of_its_kind() {
        let mut factor = texted_factor();
        let mut code = sent_for(&factor);
        raised_names(&mut factor);

        let _ = typed(&mut code, &mut factor, "wrong");

        let events = raised(&mut factor);
        assert_eq!(events[0].payload().get("factor"), Some("sms_code"));
        assert_eq!(events[0].payload().get("locked"), Some("false"));
    }

    /// Ann's setup of mailed codes is confirmed with the code mailed to her,
    /// as an app's setup is with a code from the app.
    #[test]
    fn a_sent_code_confirms_its_factors_setup() {
        let mut factor = mailed_factor();
        let mut code = sent_for(&factor);
        let answer = typed(&mut code, &mut factor, "right").unwrap();

        factor.verify(&answer, hash("recovery")).unwrap();

        assert!(factor.is_active());
    }

    /// Sending a code raises `authentication.mfa_code_sent`, naming the kind
    /// of factor.
    #[test]
    fn sending_a_code_raises_its_sending() {
        let factor = texted_factor();
        let mut code = sent_for(&factor);

        let events = raised(&mut code);

        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.mfa_code_sent"
        );
        assert_eq!(events[0].payload().get("factor"), Some("sms_code"));
    }

    /// An authenticator app makes its own codes, so none is sent for it.
    #[test]
    fn no_code_is_sent_for_an_app() {
        let ann = PrincipalId::from(UserId::new());
        let app = MfaEnrollment::<ResolvedTenant>::begin(
            ann,
            EnrolledFactor::Totp(SealedSecret::new("sealed").unwrap()),
            &offered(MfaMethod::Totp),
            &fresh_proof_of(ann),
        )
        .unwrap();

        assert!(matches!(
            OneTimeCode::issue(&app, hash("right"), five_minutes()),
            Err(DomainError::Validation(_))
        ));
    }

    /// A code asked to live an hour is refused. Ten minutes is the most.
    #[test]
    fn a_sent_code_lives_at_most_ten_minutes() {
        let factor = mailed_factor();

        let refused = OneTimeCode::issue(
            &factor,
            hash("right"),
            Lifetime::new(Duration::hours(1)).unwrap(),
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// An abandoned mailed-code enrollment cannot issue another code.
    #[test]
    fn no_code_is_sent_for_a_factor_given_up() {
        let mut factor = mailed_factor();
        let proof = fresh_proof_of(factor.subject_id());
        factor.abandon(&proof).unwrap();

        let refused = OneTimeCode::issue(&factor, hash("right"), five_minutes());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A generated code has six digits and nothing else.
    #[test]
    fn a_new_code_has_six_digits() {
        for seed in 0..50 {
            let code = new_code(&mut SequenceRandom::new(seed)).unwrap();

            assert_eq!(code.expose().len(), SENT_CODE_DIGITS);
            assert!(code.expose().bytes().all(|b| b.is_ascii_digit()));
        }
    }

    /// A random source that always answers past its bound.
    struct Broken;

    impl RandomSource for Broken {
        fn index_below(&mut self, upper: usize) -> usize {
            upper
        }
    }

    /// A broken random source makes no code, so a predictable one is never
    /// sent.
    #[test]
    fn a_broken_random_source_makes_no_code() {
        assert!(matches!(
            new_code(&mut Broken),
            Err(DomainError::Infrastructure(_))
        ));
    }

    fn stored(
        change: impl FnOnce(&mut OneTimeCodeRow),
    ) -> Result<OneTimeCode<ResolvedTenant>, DomainError> {
        let now = crate::shared::clock::now();
        let mut row = OneTimeCodeRow {
            subject_id: PrincipalId::from(UserId::new()),
            enrolled_at: now,
            method: MfaMethod::EmailCode,
            code_hash: hash("right"),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            wrong_tries: 0,
            usage: Usage::Unused,
        };
        change(&mut row);
        OneTimeCode::reconstitute(row)
    }

    /// A stored code as it was sent loads back, having raised nothing.
    #[test]
    fn a_stored_code_loads_back() {
        let mut code = stored(|_| {}).unwrap();

        assert!(raised(&mut code).is_empty());
    }

    /// Stored codes for an app, living an hour, spent after they lapsed or
    /// with more wrong tries than a code takes are refused as corrupt.
    #[test]
    fn a_stored_code_breaking_its_rules_is_refused() {
        assert!(refused_as_corrupt(&stored(
            |row| row.method = MfaMethod::Totp
        )));
        assert!(refused_as_corrupt(&stored(|row| {
            row.expires_at = row.issued_at + Duration::hours(1);
        })));
        assert!(refused_as_corrupt(&stored(|row| {
            row.usage = Usage::Used {
                at: row.expires_at + Duration::SECOND,
            };
        })));
        assert!(refused_as_corrupt(&stored(|row| {
            row.wrong_tries = SENT_CODE_TRIES + 1;
        })));
    }

    /// An abandoned setup refuses a code typed afterwards: the factor is
    /// retired.
    #[test]
    fn a_code_for_a_factor_given_up_answers_nothing() {
        let mut factor = mailed_factor();
        let mut code = sent_for(&factor);
        let proof = fresh_proof_of(factor.subject_id());
        factor.abandon(&proof).unwrap();

        let refused = typed(&mut code, &mut factor, "right");

        assert!(matches!(refused, Err(CodeRefused::Retired)));
        assert!(code.spent_at().is_none());
    }

    /// A valid mailed-code answer cannot verify another enrollment.
    #[test]
    fn an_answer_from_another_sent_code_confirms_nothing() {
        let mut mallorys = mailed_factor();
        let mut code = sent_for(&mallorys);
        let answer = typed(&mut code, &mut mallorys, "right").unwrap();
        let mut anns = mailed_factor();

        let refused = anns.verify(&answer, hash("recovery"));

        assert_eq!(refused, Err(MfaEnrollmentError::NotItsCode));
    }
}
