//! When real traffic sets a backend aside.
//!
//! The health check asks a backend whether it is well. The circuit breaker
//! watches what happens to real requests. After enough failures in a row the
//! backend is set aside for a cooldown, then given traffic again to find out
//! whether it recovered.
//!
//! It decides availability, never who is let in. A breaker that is off
//! leaves the backend eligible, as an unprobed backend is.

use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;
use crate::types::Seconds;

/// Whether real traffic can set a service's backends aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CircuitBreaker {
    /// Failures never set a backend aside. Only the health check does.
    Off,
    /// Failures in a row set a backend aside, as the settings say.
    On(BreakerSettings),
}

impl Default for CircuitBreaker {
    /// Five failures in a row set a backend aside for thirty seconds.
    fn default() -> Self {
        Self::On(BreakerSettings::DEFAULT)
    }
}

impl CircuitBreaker {
    /// The settings, when the breaker is on.
    #[must_use]
    pub fn settings(&self) -> Option<&BreakerSettings> {
        match self {
            Self::On(settings) => Some(settings),
            Self::Off => None,
        }
    }
}

/// How many failures open the circuit, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "BreakerSettingsRecord", into = "BreakerSettingsRecord")
)]
pub struct BreakerSettings {
    failure_threshold: u32,
    cooldown_secs: Seconds,
}

impl BreakerSettings {
    /// Five failures in a row, thirty seconds aside.
    pub const DEFAULT: Self = Self {
        failure_threshold: 5,
        cooldown_secs: Seconds::new(30),
    };

    /// The most failures in a row a breaker may wait for.
    pub const MAX_FAILURES: u32 = 100;

    /// The longest a backend may be set aside, in seconds.
    pub const MAX_COOLDOWN_SECS: u32 = 600;

    /// Checked breaker settings.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `failure_threshold` is outside `1..=100`.
    /// - [`ValidationError`] when `cooldown_secs` is outside `1..=600`. A
    ///   backend set aside for an hour stays out long after it recovered.
    pub fn new(failure_threshold: u32, cooldown_secs: Seconds) -> Result<Self, ValidationError> {
        validate_range(
            "failure_threshold",
            failure_threshold,
            1..=Self::MAX_FAILURES,
        )?;
        validate_range(
            "cooldown_secs",
            cooldown_secs.get(),
            1..=Self::MAX_COOLDOWN_SECS,
        )?;
        Ok(Self {
            failure_threshold,
            cooldown_secs,
        })
    }

    /// Failures in a row that set a backend aside.
    #[must_use]
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// How long a backend stays aside before it is tried again.
    #[must_use]
    pub fn cooldown_secs(&self) -> Seconds {
        self.cooldown_secs
    }
}

/// [`BreakerSettings`] as stored, read back through [`BreakerSettings::new`].
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct BreakerSettingsRecord {
    failure_threshold: u32,
    cooldown_secs: Seconds,
}

#[cfg(feature = "serde")]
impl TryFrom<BreakerSettingsRecord> for BreakerSettings {
    type Error = ValidationError;

    fn try_from(record: BreakerSettingsRecord) -> Result<Self, Self::Error> {
        Self::new(record.failure_threshold, record.cooldown_secs)
    }
}

#[cfg(feature = "serde")]
impl From<BreakerSettings> for BreakerSettingsRecord {
    fn from(settings: BreakerSettings) -> Self {
        Self {
            failure_threshold: settings.failure_threshold,
            cooldown_secs: settings.cooldown_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service that says nothing about its breaker sets a backend aside
    /// for thirty seconds after five failures in a row.
    #[test]
    fn the_default_breaker_waits_for_five_failures() {
        let settings = *CircuitBreaker::default().settings().unwrap();

        assert_eq!(settings.failure_threshold(), 5);
        assert_eq!(settings.cooldown_secs(), Seconds::new(30));
    }

    /// Ann sets her breaker to ten failures and a two minute cooldown. Both
    /// are kept.
    #[test]
    fn a_breaker_keeps_its_settings() {
        let settings = BreakerSettings::new(10, Seconds::new(120)).unwrap();

        assert_eq!(settings.failure_threshold(), 10);
        assert_eq!(settings.cooldown_secs(), Seconds::new(120));
    }

    /// A threshold of zero opens the circuit before any failure, and one of
    /// a thousand never opens it. Both are refused.
    #[test]
    fn the_failure_threshold_is_bounded() {
        assert!(BreakerSettings::new(0, Seconds::new(30)).is_err());
        assert!(BreakerSettings::new(1_000, Seconds::new(30)).is_err());
    }

    /// A cooldown of zero, or of an hour, is refused.
    #[test]
    fn the_cooldown_is_bounded() {
        assert!(BreakerSettings::new(5, Seconds::new(0)).is_err());
        assert!(BreakerSettings::new(5, Seconds::new(3_600)).is_err());
    }

    /// A breaker that is off has no settings.
    #[test]
    fn a_breaker_that_is_off_has_no_settings() {
        assert!(CircuitBreaker::Off.settings().is_none());
    }

    /// A stored breaker with a threshold of zero is refused when read.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_breaker_is_held_to_the_same_rules() {
        let stored = serde_json::json!({
            "on": { "failure_threshold": 0, "cooldown_secs": 30 }
        });

        assert!(serde_json::from_value::<CircuitBreaker>(stored).is_err());
    }
}
