//! Times of day a policy rule names, read in a timezone.
//!
//! "Allow the billing app on weekdays' office hours in Berlin" needs the
//! request's time where the rule says, not on the server. The domain holds
//! no timezone database, so the gateway works out the local time in each
//! zone the policy names ([`PolicySet::timezones`]) and hands it in as a
//! [`ZonedTime`].
//!
//! [`PolicySet::timezones`]: crate::domains::authorization::policy::set::PolicySet::timezones

use std::fmt;

use crate::message;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;
use crate::types::Timezone;

/// The last minute of a day, 23:59, counted from midnight.
const LAST_MINUTE: u16 = 1439;

/// Minutes in an hour.
const MINUTES_PER_HOUR: u16 = 60;

/// A time of day to the minute, from 00:00 to 23:59.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct TimeOfDay(u16);

impl TimeOfDay {
    /// The time `hour`:`minute`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::OutOfRange`] when the hour is past 23 or the
    ///   minute past 59.
    pub fn at(hour: u8, minute: u8) -> Result<Self, ValidationError> {
        validate_range("hour", hour, 0..=23)?;
        validate_range("minute", minute, 0..=59)?;
        Ok(Self(
            u16::from(hour)
                .saturating_mul(MINUTES_PER_HOUR)
                .saturating_add(u16::from(minute)),
        ))
    }

    /// The minutes since midnight.
    #[must_use]
    pub fn minutes(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for TimeOfDay {
    type Error = ValidationError;

    /// Reads minutes since midnight, as a stored rule keeps them.
    fn try_from(minutes: u16) -> Result<Self, Self::Error> {
        validate_range("time_of_day", minutes, 0..=LAST_MINUTE)?;
        Ok(Self(minutes))
    }
}

impl From<TimeOfDay> for u16 {
    fn from(time: TimeOfDay) -> Self {
        time.0
    }
}

impl fmt::Display for TimeOfDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}",
            self.0.div_euclid(MINUTES_PER_HOUR),
            self.0.rem_euclid(MINUTES_PER_HOUR)
        )
    }
}

/// A stretch of the day in one timezone, such as 08:00 to 18:00 in
/// `Europe/Berlin`. It may run past midnight: 22:00 to 06:00 is the night.
///
/// It starts at its first minute and ends before its last, so 08:00 to
/// 18:00 holds 17:59 and not 18:00. Its ends differ: one window from 08:00
/// to 08:00 could mean the whole day or none of it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "TimeWindowWire"))]
pub struct TimeWindow {
    starts: TimeOfDay,
    ends: TimeOfDay,
    zone: Timezone,
}

/// A window as stored, before its ends are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct TimeWindowWire {
    starts: TimeOfDay,
    ends: TimeOfDay,
    zone: Timezone,
}

#[cfg(feature = "serde")]
impl TryFrom<TimeWindowWire> for TimeWindow {
    type Error = ValidationError;

    fn try_from(wire: TimeWindowWire) -> Result<Self, Self::Error> {
        Self::new(wire.starts, wire.ends, wire.zone)
    }
}

impl TimeWindow {
    /// The window from `starts` up to `ends`, in `zone`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Rule`] when both ends are the same time.
    pub fn new(
        starts: TimeOfDay,
        ends: TimeOfDay,
        zone: Timezone,
    ) -> Result<Self, ValidationError> {
        if starts == ends {
            return Err(ValidationError::Rule {
                message: message!(
                    "authorization-a-time-window-starts-and-ends",
                    "a time window starts and ends at different times"
                ),
            });
        }
        Ok(Self { starts, ends, zone })
    }

    /// When it starts.
    #[must_use]
    pub fn starts(&self) -> TimeOfDay {
        self.starts
    }

    /// When it ends.
    #[must_use]
    pub fn ends(&self) -> TimeOfDay {
        self.ends
    }

    /// The timezone it is read in.
    #[must_use]
    pub fn zone(&self) -> &Timezone {
        &self.zone
    }

    /// Whether `time`, read in this window's zone, falls inside it.
    #[must_use]
    pub fn holds(&self, time: TimeOfDay) -> bool {
        if self.starts < self.ends {
            return self.starts <= time && time < self.ends;
        }
        time >= self.starts || time < self.ends
    }
}

impl fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} to {} in {}", self.starts, self.ends, self.zone)
    }
}

/// The time of day a request arrived, read in one timezone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZonedTime {
    zone: Timezone,
    time: TimeOfDay,
}

impl ZonedTime {
    /// It was `time` in `zone`.
    #[must_use]
    pub fn new(zone: Timezone, time: TimeOfDay) -> Self {
        Self { zone, time }
    }

    /// The IANA region used to interpret this local time.
    #[must_use]
    pub fn zone(&self) -> &Timezone {
        &self.zone
    }

    /// The time there.
    #[must_use]
    pub fn time(&self) -> TimeOfDay {
        self.time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hour: u8, minute: u8) -> TimeOfDay {
        TimeOfDay::at(hour, minute).unwrap()
    }

    fn berlin() -> Timezone {
        Timezone::new("Europe/Berlin").unwrap()
    }

    /// Office hours run from 08:00 up to 18:00. 08:00 and 17:59 are inside,
    /// 18:00 and 07:59 are not.
    #[test]
    fn a_day_window_holds_its_start_and_not_its_end() {
        let office = TimeWindow::new(at(8, 0), at(18, 0), berlin()).unwrap();

        assert!(office.holds(at(8, 0)));
        assert!(office.holds(at(17, 59)));
        assert!(!office.holds(at(18, 0)));
        assert!(!office.holds(at(7, 59)));
    }

    /// The night shift runs from 22:00 to 06:00, past midnight. 23:30 and
    /// 01:00 are inside, noon is not.
    #[test]
    fn a_window_may_run_past_midnight() {
        let night = TimeWindow::new(at(22, 0), at(6, 0), berlin()).unwrap();

        assert!(night.holds(at(23, 30)));
        assert!(night.holds(at(1, 0)));
        assert!(!night.holds(at(12, 0)));
    }

    /// A window from 08:00 to 08:00 could mean all day or never. It is
    /// refused.
    #[test]
    fn a_window_whose_ends_meet_is_refused() {
        assert!(TimeWindow::new(at(8, 0), at(8, 0), berlin()).is_err());
    }

    /// Hour 24 and minute 60 are refused, and so is a stored 1440, one past
    /// the last minute of the day. 23:59 reads back as 1439.
    #[test]
    fn times_stay_inside_one_day() {
        assert!(TimeOfDay::at(24, 0).is_err());
        assert!(TimeOfDay::at(0, 60).is_err());
        assert!(TimeOfDay::try_from(1440).is_err());
        assert_eq!(at(23, 59).minutes(), 1439);
        assert_eq!(at(9, 5).to_string(), "09:05");
    }

    /// Deserializing a time window with both ends at 09:00 is rejected.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_window_whose_ends_meet_is_refused() {
        let stored = r#"{"starts":540,"ends":540,"zone":"Europe/Berlin"}"#;

        assert!(serde_json::from_str::<TimeWindow>(stored).is_err());
    }
}
