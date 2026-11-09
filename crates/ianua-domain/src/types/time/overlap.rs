//! How long the secret or credential a rotation replaces keeps working
//! beside the new one.

use time::{Duration, OffsetDateTime};

use crate::shared::errors::DomainError;
use crate::types::SealedSecret;
use crate::types::time::lifetime::Lifetime;

/// The longest the signing secret before a rotation keeps signing.
const LONGEST_SIGNING_OVERLAP: Duration = Duration::days(7);

/// How long what a rotation replaces keeps working beside its successor.
///
/// An overlap lets the servers that use a secret move to the new one
/// without an outage. Stopping at once is for a leak: Mallory holds the old
/// secret, and every minute it still works is a minute she can use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOverlap {
    /// Not at all: it stops at once, as after a leak.
    Immediate,
    /// For this long.
    For(Lifetime),
}

impl RotationOverlap {
    /// When what a rotation at `now` replaces stops working, or `None` when
    /// it stops at once.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the overlap is longer than
    ///   `longest`, which each kind of secret sets for itself.
    pub fn ends(
        self,
        now: OffsetDateTime,
        longest: Duration,
        what: &str,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let Self::For(lifetime) = self else {
            return Ok(None);
        };
        lifetime.ensure_at_most(longest, what)?;
        Ok(Some(lifetime.ends_after(now)))
    }
}

/// The secret something signed with before its last rotation: a webhook's
/// deliveries, or a push subscription's messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviousSigningSecret {
    /// None signs: it was never rotated, or the overlap ended or was not
    /// given.
    Retired,
    /// The old secret, still signing beside the new one until a time, so
    /// the receiver can move to the new one without refusing a message.
    SignsUntil {
        /// The old secret, sealed.
        secret: SealedSecret,
        /// When it stops signing.
        until: OffsetDateTime,
    },
}

impl PreviousSigningSecret {
    /// What becomes of `current` when a rotation at `now` replaces it,
    /// keeping it signing for `overlap`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the overlap is longer than seven
    ///   days.
    pub(crate) fn after_rotation(
        overlap: RotationOverlap,
        current: SealedSecret,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let ends = overlap.ends(now, LONGEST_SIGNING_OVERLAP, "an old signing secret")?;
        let Some(until) = ends else {
            return Ok(Self::Retired);
        };
        Ok(Self::SignsUntil {
            secret: current,
            until,
        })
    }

    /// The old secret, when it still signs at `now`.
    #[must_use]
    pub fn signing_at(&self, now: OffsetDateTime) -> Option<&SealedSecret> {
        match self {
            Self::SignsUntil { secret, until } if now < *until => Some(secret),
            Self::SignsUntil { .. } | Self::Retired => None,
        }
    }

    /// When the old secret stops signing: `at`, the rotation, when it
    /// stopped at once.
    #[must_use]
    pub fn ends(&self, at: OffsetDateTime) -> OffsetDateTime {
        match self {
            Self::SignsUntil { until, .. } => *until,
            Self::Retired => at,
        }
    }

    /// Whether it ends no sooner than `start`, as one rotated then must.
    pub(crate) fn ends_after(&self, start: OffsetDateTime) -> bool {
        match self {
            Self::SignsUntil { until, .. } => *until > start,
            Self::Retired => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lifetime of `count` days.
    fn days(count: i64) -> Lifetime {
        Lifetime::new(Duration::days(count)).unwrap()
    }

    /// `value` as a sealed secret.
    fn secret(value: &str) -> SealedSecret {
        SealedSecret::new(value).unwrap()
    }

    /// Ann rotates after a leak. The old secret stops at once.
    #[test]
    fn an_immediate_overlap_ends_nothing_later() {
        let now = crate::shared::clock::now();

        let ends = RotationOverlap::Immediate.ends(now, Duration::days(7), "an old secret");

        assert_eq!(ends.unwrap(), None);
    }

    /// Ann keeps the old secret for two days. It works until then.
    #[test]
    fn a_kept_overlap_ends_after_its_lifetime() {
        let now = crate::shared::clock::now();

        let ends = RotationOverlap::For(days(2)).ends(now, Duration::days(7), "an old secret");

        assert_eq!(ends.unwrap(), Some(now.saturating_add(Duration::days(2))));
    }

    /// A thirty-day overlap is rejected as invalid when a rotated secret may
    /// remain usable for at most seven days.
    #[test]
    fn an_overlap_longer_than_the_longest_is_refused() {
        let now = crate::shared::clock::now();

        let ends = RotationOverlap::For(days(30)).ends(now, Duration::days(7), "an old secret");

        assert!(matches!(ends, Err(DomainError::Validation(_))));
    }

    /// A rotation with a day's overlap keeps the old secret signing until a
    /// day later, and not after.
    #[test]
    fn an_old_secret_signs_until_its_overlap_ends() {
        let now = crate::shared::clock::now();
        let day = RotationOverlap::For(Lifetime::seconds(86_400).unwrap());

        let previous = PreviousSigningSecret::after_rotation(day, secret("v1.b2xk"), now).unwrap();

        assert!(previous.signing_at(now + Duration::hours(23)).is_some());
        assert!(previous.signing_at(now + Duration::hours(24)).is_none());
        assert_eq!(previous.ends(now), now + Duration::days(1));
    }

    /// A rotation after a leak stops the old secret at once.
    #[test]
    fn an_immediate_rotation_retires_the_old_secret() {
        let now = crate::shared::clock::now();

        let previous = PreviousSigningSecret::after_rotation(
            RotationOverlap::Immediate,
            secret("v1.b2xk"),
            now,
        )
        .unwrap();

        assert_eq!(previous, PreviousSigningSecret::Retired);
        assert!(previous.signing_at(now).is_none());
        assert_eq!(previous.ends(now), now);
    }

    /// An eight-day signing overlap is rejected as invalid before the retired
    /// secret can be retained beyond the seven-day limit.
    #[test]
    fn a_signing_overlap_over_seven_days_is_refused() {
        let eight_days = RotationOverlap::For(Lifetime::seconds(691_200).unwrap());

        let result = PreviousSigningSecret::after_rotation(
            eight_days,
            secret("v1.b2xk"),
            crate::shared::clock::now(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
