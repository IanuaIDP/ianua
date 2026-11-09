//! Where a second factor's enrollment stands, and the wrong answers that
//! lock it.

use std::num::NonZeroU32;

use time::OffsetDateTime;

use crate::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::TokenHash;

/// How many wrong answers a second factor takes before it locks, and how
/// long they are remembered.
///
/// The same window is how long a lock lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    max_attempts: u32,
    window: time::Duration,
}

impl LockoutPolicy {
    /// A policy that locks after `max_attempts` wrong answers within
    /// `window`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `max_attempts` is zero, which would
    ///   allow no attempt at all.
    /// - [`DomainError::Validation`] when `window` is zero or negative, which
    ///   would make a lock that never holds.
    pub fn new(max_attempts: u32, window: time::Duration) -> Result<Self, DomainError> {
        validate_range("max_attempts", max_attempts, 1..=u32::MAX)?;
        if window <= time::Duration::ZERO {
            return Err(DomainError::invalid(message!(
                "authentication-a-second-factor-lockout-needs-a",
                "a second-factor lockout needs a window"
            )));
        }
        Ok(Self {
            max_attempts,
            window,
        })
    }

    /// Wrong answers tolerated before the factor locks.
    #[must_use]
    pub fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// How long wrong answers are remembered. A lock lasts this long too.
    #[must_use]
    pub fn window(self) -> time::Duration {
        self.window
    }
}

/// Where an enrollment stands, with what each stage keeps.
///
/// It is one value, not a status beside optional times. So an enrollment can
/// never read as verified with no confirmation, or disabled with no time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentState {
    /// Started, waiting for the subject to enter a valid code.
    Pending,
    /// Confirmed with a valid code. The factor is in force.
    Verified(Confirmation),
    /// Given up before it was ever confirmed.
    Abandoned {
        /// When it was given up.
        at: OffsetDateTime,
    },
    /// Turned off after it had been in force.
    Disabled {
        /// The confirmation it had.
        confirmation: Confirmation,
        /// When it was turned off.
        at: OffsetDateTime,
    },
}

/// When an enrollment was confirmed, and the recovery codes shown then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    at: OffsetDateTime,
    recovery_codes_hash: TokenHash,
}

impl Confirmation {
    /// A confirmation at `at`, with the hash of the codes shown then.
    pub(super) fn new(at: OffsetDateTime, recovery_codes_hash: TokenHash) -> Self {
        Self {
            at,
            recovery_codes_hash,
        }
    }

    /// When the subject confirmed with a valid code.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }

    /// Hash of the recovery codes shown at confirmation.
    #[must_use]
    pub fn recovery_codes_hash(&self) -> &TokenHash {
        &self.recovery_codes_hash
    }

    /// The confirmation a stored time and recovery-code hash record. A
    /// confirmed enrollment has both. One never confirmed has neither.
    fn from_stored(
        at: Option<OffsetDateTime>,
        recovery_codes_hash: Option<TokenHash>,
    ) -> Result<Option<Self>, DomainError> {
        match (at, recovery_codes_hash) {
            (Some(at), Some(recovery_codes_hash)) => Ok(Some(Self::new(at, recovery_codes_hash))),
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
                "MFA enrollment",
                "a confirmation time without its recovery codes, or codes without the time",
            )),
        }
    }
}

impl EnrollmentState {
    /// The lifecycle label this state carries.
    #[must_use]
    pub fn status(&self) -> MfaEnrollmentStatus {
        match self {
            Self::Pending => MfaEnrollmentStatus::Pending,
            Self::Verified(_) => MfaEnrollmentStatus::Verified,
            Self::Abandoned { .. } | Self::Disabled { .. } => MfaEnrollmentStatus::Disabled,
        }
    }

    /// Reads a state back from its stored columns.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a confirmation time is stored
    ///   without its recovery-code hash, or the hash without the time.
    /// - [`DomainError::Infrastructure`] when the status contradicts the
    ///   other columns, such as a verified enrollment with no confirmation
    ///   or a pending one with a disable time.
    pub fn from_stored(
        status: MfaEnrollmentStatus,
        verified_at: Option<OffsetDateTime>,
        recovery_codes_hash: Option<TokenHash>,
        disabled_at: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        let confirmation = Confirmation::from_stored(verified_at, recovery_codes_hash)?;
        match (status, confirmation, disabled_at) {
            (MfaEnrollmentStatus::Pending, None, None) => Ok(Self::Pending),
            (MfaEnrollmentStatus::Verified, Some(confirmation), None) => {
                Ok(Self::Verified(confirmation))
            }
            (MfaEnrollmentStatus::Disabled, None, Some(at)) => Ok(Self::Abandoned { at }),
            (MfaEnrollmentStatus::Disabled, Some(confirmation), Some(at)) => {
                Ok(Self::Disabled { confirmation, at })
            }
            (
                MfaEnrollmentStatus::Pending
                | MfaEnrollmentStatus::Verified
                | MfaEnrollmentStatus::Disabled,
                _,
                _,
            ) => Err(DomainError::corrupt_row(
                "MFA enrollment",
                "a status its confirmation and disable times contradict",
            )),
        }
    }

    /// When the enrollment was confirmed, if it ever was.
    #[must_use]
    pub fn verified_at(&self) -> Option<OffsetDateTime> {
        self.confirmation().map(Confirmation::at)
    }

    /// Hash of the recovery codes, once the enrollment was confirmed.
    #[must_use]
    pub fn recovery_codes_hash(&self) -> Option<&TokenHash> {
        self.confirmation().map(Confirmation::recovery_codes_hash)
    }

    /// When the enrollment was abandoned or turned off, if it was.
    #[must_use]
    pub fn disabled_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Abandoned { at } | Self::Disabled { at, .. } => Some(*at),
            Self::Pending | Self::Verified(_) => None,
        }
    }

    /// Whether a turned-off enrollment was confirmed no later than it was
    /// turned off. Every other state passes.
    pub(super) fn confirmed_before_disabled(&self) -> bool {
        match self {
            Self::Disabled { confirmation, at } => confirmation.at() <= *at,
            Self::Pending | Self::Verified(_) | Self::Abandoned { .. } => true,
        }
    }

    fn confirmation(&self) -> Option<&Confirmation> {
        match self {
            Self::Verified(confirmation) | Self::Disabled { confirmation, .. } => {
                Some(confirmation)
            }
            Self::Pending | Self::Abandoned { .. } => None,
        }
    }
}

/// Wrong answers to a second factor that still count. Either none, or a run
/// of them ending at the last one.
///
/// It is one value, not a count beside an optional time. So a count is never
/// kept without the time it should be forgotten by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecentFailures {
    /// No wrong answer counts.
    Clear,
    /// `count` wrong answers, the last at `last_at`.
    Run {
        /// How many in a row.
        count: NonZeroU32,
        /// When the last one came.
        last_at: OffsetDateTime,
    },
}

impl RecentFailures {
    /// Reads failures back from their stored columns.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a count is stored with no time,
    ///   or a time with no count.
    pub fn from_stored(count: u32, last_at: Option<OffsetDateTime>) -> Result<Self, DomainError> {
        match (NonZeroU32::new(count), last_at) {
            (None, None) => Ok(Self::Clear),
            (Some(count), Some(last_at)) => Ok(Self::Run { count, last_at }),
            (None, Some(_)) | (Some(_), None) => Err(DomainError::infra_msg(
                "stored MFA failures have a count and a time that disagree",
            )),
        }
    }

    /// How many wrong answers count.
    #[must_use]
    pub fn count(self) -> u32 {
        match self {
            Self::Clear => 0,
            Self::Run { count, .. } => count.get(),
        }
    }

    /// When the last counted wrong answer came.
    #[must_use]
    pub fn last_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Clear => None,
            Self::Run { last_at, .. } => Some(last_at),
        }
    }

    /// The failures that still count at `now`. A run older than the
    /// policy's window is forgotten.
    pub(super) fn at(self, now: OffsetDateTime, policy: LockoutPolicy) -> Self {
        match self {
            Self::Run { last_at, .. } if now < last_at.saturating_add(policy.window()) => self,
            Self::Run { .. } | Self::Clear => Self::Clear,
        }
    }

    /// The run with one more wrong answer, at `now`.
    pub(super) fn and_one_more(self, now: OffsetDateTime) -> Self {
        let count = match self {
            Self::Clear => NonZeroU32::MIN,
            Self::Run { count, .. } => count.saturating_add(1),
        };
        Self::Run {
            count,
            last_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lockout policy of 0 attempts, or one with a zero window, is refused.
    #[test]
    fn a_lockout_needs_an_attempt_and_a_window() {
        assert!(LockoutPolicy::new(0, time::Duration::minutes(15)).is_err());
        assert!(LockoutPolicy::new(5, time::Duration::ZERO).is_err());
    }

    /// A row stores a confirmation time without recovery codes, or codes
    /// without a time. It is refused as damaged, not read as pending.
    #[test]
    fn half_a_confirmation_is_refused_rather_than_dropped() {
        let at = crate::shared::clock::now();
        let codes = TokenHash::from_stored("codes".to_owned());

        for (verified_at, recovery_codes_hash) in [(Some(at), None), (None, Some(codes))] {
            let read = EnrollmentState::from_stored(
                MfaEnrollmentStatus::Pending,
                verified_at,
                recovery_codes_hash,
                None,
            );

            assert!(matches!(read, Err(DomainError::Infrastructure(_))));
        }
    }

    /// Six rows whose columns contradict each other are each refused as
    /// corrupt. One is a verified factor with no recovery codes, which would
    /// be in force with nothing to recover by.
    #[test]
    fn stored_columns_that_disagree_are_refused() {
        let now = crate::shared::clock::now();
        let codes = || Some(TokenHash::from_stored("hash".to_owned()));

        let contradictions = [
            (MfaEnrollmentStatus::Verified, Some(now), None, None),
            (MfaEnrollmentStatus::Verified, None, codes(), None),
            (MfaEnrollmentStatus::Pending, None, None, Some(now)),
            (MfaEnrollmentStatus::Pending, Some(now), codes(), None),
            (MfaEnrollmentStatus::Disabled, None, None, None),
            (MfaEnrollmentStatus::Verified, Some(now), codes(), Some(now)),
        ];

        for (status, verified_at, codes, disabled_at) in contradictions {
            let read = EnrollmentState::from_stored(status, verified_at, codes, disabled_at);
            assert!(
                matches!(read, Err(DomainError::Infrastructure(_))),
                "{status:?}"
            );
        }
    }

    /// A stored count of 3 with no time, or a time with a count of 0, is
    /// refused. A count of 3 with a time reads back as 3.
    #[test]
    fn stored_failures_need_a_count_and_a_time_together() {
        let now = crate::shared::clock::now();

        assert!(RecentFailures::from_stored(3, None).is_err());
        assert!(RecentFailures::from_stored(0, Some(now)).is_err());
        assert_eq!(
            RecentFailures::from_stored(3, Some(now)).unwrap().count(),
            3
        );
    }
}
