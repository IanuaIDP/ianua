//! A whole number of seconds.

use std::fmt;

use time::Duration;

/// A whole number of seconds, for how long something lasts or how often it
/// happens.
///
/// Settings keep durations in this unit, and the type names it. So a value
/// in seconds cannot be passed where milliseconds are meant. It is stored
/// and sent as the plain number. The record that holds it checks the range,
/// since a cache lifetime and a lockout have different limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Seconds(u32);

impl Seconds {
    /// `count` seconds.
    #[must_use]
    pub const fn new(count: u32) -> Self {
        Self(count)
    }

    /// The number of seconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The length as a duration.
    #[must_use]
    pub fn duration(self) -> Duration {
        Duration::seconds(i64::from(self.0))
    }

    /// The length as a standard-library duration, for timers.
    #[must_use]
    pub fn std_duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.0))
    }
}

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ninety seconds reads back as 90, as a 90-second duration and as a
    /// 90-second timer duration.
    #[test]
    fn a_count_of_seconds_reads_back_as_each_kind_of_duration() {
        let ninety = Seconds::new(90);

        assert_eq!(ninety.get(), 90);
        assert_eq!(ninety.duration(), Duration::seconds(90));
        assert_eq!(ninety.std_duration(), std::time::Duration::from_secs(90));
    }

    /// Thirty seconds is written to JSON as `30` and read back from `30`.
    #[cfg(feature = "serde")]
    #[test]
    fn seconds_are_stored_as_the_plain_number() {
        assert_eq!(serde_json::to_string(&Seconds::new(30)).unwrap(), "30");
        assert_eq!(
            serde_json::from_str::<Seconds>("30").unwrap(),
            Seconds::new(30)
        );
    }
}
