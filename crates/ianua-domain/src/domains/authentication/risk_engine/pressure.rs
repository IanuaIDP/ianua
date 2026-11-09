//! How hard a tenant's or an organization's password sign-in is being
//! pushed, from its count of recent failures.
//!
//! The per-address lockout counts guesses at one address. A flood spread
//! over tens of thousands of addresses and networks stays under it, while
//! every guess still costs a password hash. So every failed password
//! sign-in is also counted against the whole tenant, or the whole
//! organization, over a sliding window kept outside the domain. Below the
//! threshold the sign-in settings set, pressure is normal. At or past it,
//! pressure is high, and a sign-in from a device the person never trusted
//! must pass a challenge before any password is hashed.

use crate::domains::authentication::events::pressure::{SignInPressureEased, SignInPressureRose};
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::scoped;
use crate::shared::validation::numeric::validate_range;
use crate::types::TenantId;

/// The lowest threshold a tenant or organization may set. Below it, a few
/// people mistyping at the same time would put sign-in under pressure.
pub(crate) const MIN_FAILURE_THRESHOLD: u32 = 10;

/// The highest threshold a tenant or organization may set. Past it, the
/// threshold would never be reached before the hashing cap is.
pub(crate) const MAX_FAILURE_THRESHOLD: u32 = 1_000_000;

/// The threshold a tenant or organization gets until it sets its own.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 200;

/// The count of failed password sign-ins in the window at which sign-in is
/// under high pressure.
///
/// Only [`new`](Self::new) makes one, so a threshold of zero, which would
/// put every sign-in under pressure for good, never reaches a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u32", into = "u32"))]
pub struct FailureThreshold(u32);

impl FailureThreshold {
    /// A threshold of `failures`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `failures` is outside
    ///   `MIN_FAILURE_THRESHOLD` to `MAX_FAILURE_THRESHOLD`.
    pub fn new(failures: u32) -> Result<Self, DomainError> {
        validate_range(
            "challenge_threshold",
            failures,
            MIN_FAILURE_THRESHOLD..=MAX_FAILURE_THRESHOLD,
        )?;
        Ok(Self(failures))
    }

    /// The count of failures.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }

    /// The pressure `failures` in the window put sign-in under.
    #[must_use]
    pub fn pressure_at(self, failures: FailureCount) -> Pressure {
        if failures.get() < u64::from(self.0) {
            return Pressure::Normal;
        }
        Pressure::High
    }
}

impl Default for FailureThreshold {
    /// [`DEFAULT_FAILURE_THRESHOLD`].
    fn default() -> Self {
        Self(DEFAULT_FAILURE_THRESHOLD)
    }
}

impl TryFrom<u32> for FailureThreshold {
    type Error = DomainError;

    fn try_from(failures: u32) -> Result<Self, Self::Error> {
        Self::new(failures)
    }
}

impl From<FailureThreshold> for u32 {
    fn from(threshold: FailureThreshold) -> Self {
        threshold.0
    }
}

/// How many failed password sign-ins were counted in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct FailureCount(u64);

impl FailureCount {
    /// The count.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for FailureCount {
    fn from(failures: u64) -> Self {
        Self(failures)
    }
}

/// How hard password sign-in is being pushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pressure {
    /// Failures are under the threshold. Sign-in goes on as usual.
    Normal,
    /// Failures reached the threshold. A sign-in from a device that is not
    /// trusted must pass a challenge before its password is hashed.
    High,
}

impl Pressure {
    /// How pressure moved from `before` to this.
    #[must_use]
    pub fn shift_from(self, before: Self) -> PressureShift {
        match (before, self) {
            (Self::Normal, Self::High) => PressureShift::Rose,
            (Self::High, Self::Normal) => PressureShift::Eased,
            (Self::Normal, Self::Normal) | (Self::High, Self::High) => PressureShift::Held,
        }
    }
}

/// How pressure moved between two readings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureShift {
    /// From normal to high.
    Rose,
    /// From high to normal.
    Eased,
    /// It stayed where it was.
    Held,
}

impl PressureShift {
    /// The record of this shift in `tenant_id`'s password sign-in, made by
    /// the platform, or none when pressure held.
    ///
    /// A rise names the count that reached `threshold`, so the tenant's
    /// administrators can tell a slow climb from a sudden flood.
    #[must_use]
    pub fn recorded(
        self,
        tenant_id: TenantId,
        threshold: FailureThreshold,
        failures: FailureCount,
    ) -> Option<DomainEvent> {
        let occurred_at = crate::shared::clock::now();
        match self {
            Self::Rose => Some(
                scoped(
                    tenant_id,
                    SignInPressureRose {
                        failures: failures.get(),
                        threshold: threshold.get(),
                        occurred_at,
                    },
                )
                .system(),
            ),
            Self::Eased => Some(
                scoped(
                    tenant_id,
                    SignInPressureEased {
                        threshold: threshold.get(),
                        occurred_at,
                    },
                )
                .system(),
            ),
            Self::Held => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threshold(failures: u32) -> FailureThreshold {
        FailureThreshold::new(failures).unwrap()
    }

    /// Acme sets its threshold at 50. Forty-nine failures leave sign-in
    /// under normal pressure; the fiftieth puts it under high pressure.
    #[test]
    fn pressure_rises_when_failures_reach_the_threshold() {
        let fifty = threshold(50);

        assert_eq!(fifty.pressure_at(FailureCount::from(49)), Pressure::Normal);
        assert_eq!(fifty.pressure_at(FailureCount::from(50)), Pressure::High);
        assert_eq!(fifty.pressure_at(FailureCount::from(5_000)), Pressure::High);
    }

    /// An owner tries a threshold of zero, which would challenge every
    /// sign-in for good, and one past the maximum. Both are refused; the
    /// bounds themselves are taken.
    #[test]
    fn a_threshold_outside_its_range_is_refused() {
        assert!(FailureThreshold::new(0).is_err());
        assert!(FailureThreshold::new(MIN_FAILURE_THRESHOLD - 1).is_err());
        assert!(FailureThreshold::new(MAX_FAILURE_THRESHOLD + 1).is_err());
        assert!(FailureThreshold::new(MIN_FAILURE_THRESHOLD).is_ok());
        assert!(FailureThreshold::new(MAX_FAILURE_THRESHOLD).is_ok());
    }

    /// A tenant that never set a threshold gets the default, which is in
    /// range.
    #[test]
    fn the_default_threshold_is_in_range() {
        let default = FailureThreshold::default();

        assert_eq!(default.get(), DEFAULT_FAILURE_THRESHOLD);
        assert!(FailureThreshold::new(default.get()).is_ok());
    }

    /// Pressure going from normal to high is a rise, from high to normal an
    /// easing, and staying put is neither.
    #[test]
    fn a_shift_is_read_from_the_two_readings() {
        let (high, normal) = (Pressure::High, Pressure::Normal);

        assert_eq!(high.shift_from(normal), PressureShift::Rose);
        assert_eq!(normal.shift_from(high), PressureShift::Eased);
        assert_eq!(high.shift_from(high), PressureShift::Held);
        assert_eq!(normal.shift_from(normal), PressureShift::Held);
    }

    /// Acme's sign-in comes under pressure and later eases. Each move is
    /// recorded for Acme under its own name; pressure that holds records
    /// nothing.
    #[test]
    fn each_shift_is_recorded_for_the_tenant() {
        let acme = TenantId::new();
        let rose = PressureShift::Rose.recorded(acme, threshold(50), FailureCount::from(50));
        let eased = PressureShift::Eased.recorded(acme, threshold(50), FailureCount::from(3));
        let held = PressureShift::Held.recorded(acme, threshold(50), FailureCount::from(3));

        let rose = rose.unwrap();
        assert_eq!(
            rose.event_type().as_str(),
            "authentication.sign_in_pressure_rose"
        );
        assert_eq!(rose.tenant_id(), Some(&acme));
        assert_eq!(rose.payload().get("failures"), Some("50"));
        assert_eq!(
            eased.unwrap().event_type().as_str(),
            "authentication.sign_in_pressure_eased"
        );
        assert!(held.is_none());
    }

    /// A stored threshold is read back through the same check as a new one,
    /// so a hand-edited zero is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_threshold_is_checked_when_read() {
        assert!(serde_json::from_str::<FailureThreshold>("0").is_err());
        assert_eq!(
            serde_json::from_str::<FailureThreshold>("75").unwrap(),
            threshold(75)
        );
    }
}
