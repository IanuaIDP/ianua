//! How long something issued stays good, such as a token, a code, a link or
//! a grace period.

use std::fmt;
use std::num::NonZeroU32;

use time::{Duration, OffsetDateTime};

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;

/// A length of time something stays valid.
///
/// It is always positive. A lifetime of zero or less would issue something
/// already expired. It is also at most [`Lifetime::MAX`], so the moment it
/// ends is always one `time` can hold and write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lifetime(Duration);

impl Lifetime {
    /// The longest lifetime: `u32::MAX` seconds, about 136 years.
    ///
    /// Nothing issued here lasts near that long. The longest are sessions of
    /// days, decision windows and waits of weeks. Without a bound, a lifetime
    /// could end past the year 9999, where `time` stops, and its end would be
    /// cut short to that year without a word. Ended from any start before the
    /// year 9863, this one stays inside. It is also exactly what
    /// [`from_secs`](Self::from_secs) can be given, so that one needs no
    /// check.
    pub const MAX: Self = Self(Duration::seconds(u32::MAX as i64));

    /// Accepts a positive duration of at most [`Lifetime::MAX`].
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `duration` is zero or negative.
    /// - [`ValidationError`] if `duration` is longer than
    ///   [`Lifetime::MAX`].
    pub fn new(duration: Duration) -> Result<Self, ValidationError> {
        if !duration.is_positive() {
            return Err(refused(
                "not_positive",
                format!("a lifetime must be longer than zero, not {duration}"),
            ));
        }
        if duration > Self::MAX.0 {
            return Err(refused(
                "too_long",
                format!("a lifetime may be at most {}, not {duration}", Self::MAX.0),
            ));
        }
        Ok(Self(duration))
    }

    /// Accepts a positive number of seconds, up to [`Lifetime::MAX`].
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `seconds` is zero or negative.
    /// - [`ValidationError`] if `seconds` is longer than
    ///   [`Lifetime::MAX`].
    pub fn seconds(seconds: i64) -> Result<Self, ValidationError> {
        Self::new(Duration::seconds(seconds))
    }

    /// A lifetime of `seconds`, which its type already keeps above zero.
    ///
    /// It is for lengths fixed in code. `NonZeroU32::new(n).unwrap()` in a
    /// `const` is checked when the code compiles.
    #[must_use]
    pub const fn from_secs(seconds: NonZeroU32) -> Self {
        Self(Duration::seconds(seconds.get() as i64))
    }

    /// The length as a duration.
    #[must_use]
    pub fn duration(self) -> Duration {
        self.0
    }

    /// The length in whole seconds.
    #[must_use]
    pub fn whole_seconds(self) -> i64 {
        self.0.whole_seconds()
    }

    /// The moment something issued at `start` stops being valid.
    #[must_use]
    pub fn ends_after(self, start: OffsetDateTime) -> OffsetDateTime {
        start.saturating_add(self.0)
    }

    /// Refuses `what`, meant to live this long, when that is longer than
    /// `longest`.
    ///
    /// One-time codes and links carry a sign-in from one place to another.
    /// One that lived for days would wait in a browser history, a log or a
    /// mailbox for whoever finds it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when this is longer than `longest`.
    pub fn ensure_at_most(self, longest: Duration, what: &str) -> Result<(), DomainError> {
        if self.0 <= longest {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "values-lives-at-most-minutes",
            format!("{what} lives at most {} minutes", longest.whole_minutes())
        )))
    }
}

impl fmt::Display for Lifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A lifetime is written as its whole seconds.
#[cfg(feature = "serde")]
impl serde::Serialize for Lifetime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.whole_seconds())
    }
}

/// A lifetime is read back from its whole seconds through
/// [`Lifetime::seconds`], so zero or a length past the longest is refused.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Lifetime {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let seconds = <i64 as serde::Deserialize>::deserialize(deserializer)?;
        Self::seconds(seconds).map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// A lifetime refused for `code`, with `message` saying why.
fn refused(code: &str, message: String) -> ValidationError {
    ValidationError::Custom {
        field: "lifetime",
        code: code.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A code allowed five minutes may live five minutes, and not six.
    #[test]
    fn a_lifetime_past_its_ceiling_is_refused() {
        let ceiling = Duration::minutes(5);

        assert!(
            Lifetime::seconds(300)
                .unwrap()
                .ensure_at_most(ceiling, "a code")
                .is_ok()
        );
        assert!(matches!(
            Lifetime::seconds(360)
                .unwrap()
                .ensure_at_most(ceiling, "a code"),
            Err(DomainError::Validation(_))
        ));
    }

    /// A one-minute lifetime is accepted and reads back as 60 seconds.
    #[test]
    fn a_positive_length_is_a_lifetime() {
        let lifetime = Lifetime::seconds(60).unwrap();

        assert_eq!(lifetime.whole_seconds(), 60);
    }

    /// Lifetimes of zero seconds, minus one second and a zero duration are
    /// refused. A link issued with one would be expired the moment it
    /// exists.
    #[test]
    fn zero_or_less_is_refused() {
        assert!(Lifetime::seconds(0).is_err());
        assert!(Lifetime::seconds(-1).is_err());
        assert!(Lifetime::new(Duration::ZERO).is_err());
    }

    /// The maximum lifetime is accepted, while one additional second exceeds
    /// the bound and is refused.
    #[test]
    fn a_lifetime_longer_than_the_longest_is_refused() {
        let longest = Lifetime::MAX.duration();

        assert!(Lifetime::new(longest + Duration::SECOND).is_err());
        assert!(Lifetime::new(longest).is_ok());
    }

    /// The longest lifetime, started on the last day of the year 9862, ends
    /// at a moment `time` holds without cutting it short.
    #[test]
    fn the_longest_lifetime_ends_inside_the_years_time_holds() {
        let start = time::Date::from_calendar_date(9862, time::Month::December, 31)
            .unwrap()
            .midnight()
            .assume_utc();

        let end = Lifetime::MAX.ends_after(start);

        assert_eq!(end, start + Lifetime::MAX.duration());
    }

    /// A code issued at the start with a 30-second lifetime stops being
    /// valid 30 seconds later.
    #[test]
    fn it_ends_its_length_after_the_start() {
        let start = OffsetDateTime::UNIX_EPOCH;

        assert_eq!(
            Lifetime::seconds(30).unwrap().ends_after(start),
            start + Duration::seconds(30)
        );
    }

    /// A lifetime is written as its seconds and read back from them, and a
    /// stored zero is refused rather than read as a lifetime.
    #[cfg(feature = "serde")]
    #[test]
    fn a_lifetime_is_stored_as_its_seconds() {
        let lifetime = Lifetime::seconds(90).unwrap();

        assert_eq!(serde_json::to_string(&lifetime).unwrap(), "90");
        assert_eq!(serde_json::from_str::<Lifetime>("90").unwrap(), lifetime);
        assert!(serde_json::from_str::<Lifetime>("0").is_err());
    }
}
