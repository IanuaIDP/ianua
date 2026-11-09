//! A right code from one second factor, and why a code was refused.

use time::OffsetDateTime;

use crate::domains::authentication::mfa::enrolled_factor::MfaMethod;
use crate::domains::authentication::mfa::time_step::TimeStep;
use crate::domains::authentication::mfa::verifier::TotpSeed;
use crate::shared::errors::DomainError;
use crate::types::PrincipalId;

/// A code someone typed for a factor, with the factor's opened seed to check
/// it against.
///
/// Its `Debug` shows neither, since a fresh code signs in like the factor.
#[derive(Clone, Copy)]
pub struct CodeAttempt<'a> {
    /// The factor's seed, opened from its sealed secret.
    pub seed: &'a TotpSeed,
    /// The code as typed.
    pub code: &'a str,
}

impl std::fmt::Debug for CodeAttempt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodeAttempt(redacted)")
    }
}

/// What keeps a right code from being sent a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeReplay {
    /// An authenticator app's code is good for its whole time step. The
    /// caller claims this step as used on its store before acting on the
    /// answer, so a code seen once cannot be sent again.
    ClaimStep(TimeStep),
    /// A sent code was spent on its own record when it was checked, so
    /// nothing more is claimed.
    Spent,
}

/// A right code for one enrollment, checked against its secret or the code
/// sent for it.
///
/// Only [`MfaEnrollment::answer`] and [`OneTimeCode::redeem`] make one, so
/// holding it shows the person had the factor in hand just now. It names
/// the enrollment it was checked against. An answer from one factor cannot
/// act on another.
///
/// A right code from an authenticator app is not yet an unused one. The
/// caller follows [`replay`](Self::replay) before acting on the answer.
///
/// [`MfaEnrollment::answer`]: crate::domains::authentication::mfa::enrollment::MfaEnrollment::answer
/// [`OneTimeCode::redeem`]: crate::domains::authentication::mfa::one_time_code::OneTimeCode::redeem
#[derive(Debug)]
pub struct AnsweredCode {
    subject_id: PrincipalId,
    enrolled_at: OffsetDateTime,
    method: MfaMethod,
    replay: CodeReplay,
}

impl AnsweredCode {
    /// A right code from the `method` factor `subject_id` began at
    /// `enrolled_at`, kept from a second use by `replay`.
    pub(super) fn new(
        subject_id: PrincipalId,
        enrolled_at: OffsetDateTime,
        method: MfaMethod,
        replay: CodeReplay,
    ) -> Self {
        Self {
            subject_id,
            enrolled_at,
            method,
            replay,
        }
    }

    /// What the caller does so the code cannot be sent again.
    #[must_use]
    pub fn replay(&self) -> CodeReplay {
        self.replay
    }

    /// The kind of factor that gave the code.
    #[must_use]
    pub fn method(&self) -> MfaMethod {
        self.method
    }

    /// The account whose factor gave the code.
    pub(crate) fn subject(&self) -> PrincipalId {
        self.subject_id
    }

    /// Whether this answer was checked against the enrollment `subject_id`
    /// began at `enrolled_at`.
    pub(super) fn is_for(&self, subject_id: PrincipalId, enrolled_at: OffsetDateTime) -> bool {
        self.subject_id == subject_id && self.enrolled_at == enrolled_at
    }
}

/// Why a code did not prove a second factor.
#[derive(Debug, thiserror::Error)]
pub enum CodeRefused {
    /// The factor was given up or turned off, so no code from it counts.
    #[error("this second factor is not in use")]
    Retired,
    /// Too many wrong codes came lately. The code was not checked.
    #[error("too many failed MFA attempts")]
    Locked,
    /// The code was offered for another account's factor.
    #[error("this code is not for this account")]
    ForAnotherAccount,
    /// The code is of a kind this factor does not take, such as an
    /// authenticator app's code for a factor whose codes are sent.
    #[error("this second factor takes no code of this kind")]
    OtherKind,
    /// A sent code was spent, ran out of time or took too many wrong
    /// tries. A new one is sent.
    #[error("this code is spent or lapsed")]
    Lapsed,
    /// The code is not the right one. It counts towards the lock.
    #[error("invalid code")]
    Wrong,
    /// The code could not be checked, such as on a malformed seed.
    #[error("the code could not be checked")]
    Unchecked(#[source] DomainError),
}
