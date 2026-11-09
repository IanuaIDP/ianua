//! How long a resolver may cache an answer.

use time::Duration;

use crate::shared::errors::DomainError;

/// How long a resolver may cache an answer.
///
/// It lies between one minute and one hour. Below a minute many resolvers
/// use their own value instead, so a shorter one would not be kept. Above an
/// hour, an answer we already replaced stays in other caches too long for
/// whoever waits on the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ttl(u32);

impl Ttl {
    /// The shortest a resolver will honour in practice.
    const MIN_SECONDS: u32 = 60;

    /// Long enough that no answer we write is stuck for more than an hour.
    const MAX_SECONDS: u32 = 3600;

    /// Five minutes, what a record gets unless something asks otherwise.
    #[must_use]
    pub fn standard() -> Self {
        Self(300)
    }

    /// The shortest cache a resolver will honour.
    ///
    /// It is for records that must be replaceable at once. An ACME challenge
    /// is written, checked and withdrawn inside a minute.
    #[must_use]
    pub fn shortest() -> Self {
        Self(Self::MIN_SECONDS)
    }

    /// A specific cache lifetime, in seconds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `value` is below 60 or above 3600
    ///   seconds.
    pub fn seconds(value: u32) -> Result<Self, DomainError> {
        crate::shared::validation::numeric::validate_range(
            "ttl_seconds",
            u64::from(value),
            u64::from(Self::MIN_SECONDS)..=u64::from(Self::MAX_SECONDS),
        )?;

        Ok(Self(value))
    }

    /// The lifetime in seconds, as a zone file spells it.
    #[must_use]
    pub fn as_seconds(self) -> u32 {
        self.0
    }

    /// The lifetime as a duration.
    #[must_use]
    pub fn as_duration(self) -> Duration {
        Duration::seconds(i64::from(self.0))
    }
}

impl Default for Ttl {
    fn default() -> Self {
        Self::standard()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 60, 300 and 3600 seconds are each accepted and read back unchanged.
    #[test]
    fn a_ttl_inside_the_honoured_range_is_accepted() {
        assert_eq!(Ttl::seconds(60).unwrap().as_seconds(), 60);
        assert_eq!(Ttl::seconds(3600).unwrap().as_seconds(), 3600);
        assert_eq!(Ttl::seconds(300).unwrap().as_seconds(), 300);
    }

    /// 59 and 0 seconds are refused. A resolver would use its own value, so
    /// the stored number would not be the one honoured.
    #[test]
    fn a_ttl_below_the_floor_is_refused() {
        assert!(Ttl::seconds(59).is_err());
        assert!(Ttl::seconds(0).is_err());
    }

    /// 3601 seconds and a full day are refused, so a replaced answer never
    /// lingers in caches for more than an hour.
    #[test]
    fn a_ttl_above_the_ceiling_is_refused() {
        assert!(Ttl::seconds(3601).is_err());
        assert!(Ttl::seconds(86_400).is_err());
    }

    /// The shortest TTL is the 60-second minimum, and the standard one is
    /// longer.
    #[test]
    fn the_shortest_ttl_is_the_floor_and_the_standard_one_is_above_it() {
        assert_eq!(Ttl::shortest().as_seconds(), Ttl::MIN_SECONDS);
        assert!(Ttl::standard() > Ttl::shortest());
    }

    /// A TTL of 600 seconds converts to a duration of ten minutes.
    #[test]
    fn a_ttl_converts_to_a_duration_of_the_same_length() {
        assert_eq!(
            Ttl::seconds(600).unwrap().as_duration(),
            Duration::minutes(10)
        );
    }
}
