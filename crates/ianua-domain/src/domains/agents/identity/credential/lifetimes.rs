//! How long agent credentials, and the assertions they sign, stay good.

use time::Duration;

use crate::message;
use crate::shared::errors::DomainError;

/// How old an assertion may be and still verify. It is long enough for one
/// already sent to arrive.
///
/// Whoever holds the key writes the signing time, so a captured assertion
/// replays only for this long.
pub(crate) const MAX_IN_FLIGHT: Duration = Duration::seconds(60);

/// How far ahead of the platform's clock a signing time may be.
///
/// It allows for a little drift between the agent's clock and ours. An
/// assertion dated later is refused, so no one signs one today that
/// replays tomorrow.
pub(crate) const MAX_CLOCK_SKEW: Duration = Duration::seconds(30);

/// How long agent credentials live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialLifetimes {
    default_lifetime: Duration,
    max_lifetime: Duration,
    rotation_grace: Duration,
}

impl CredentialLifetimes {
    /// The longest lifetime an operator may set: one year.
    pub const LONGEST_LIFETIME: Duration = Duration::days(365);

    /// The longest rotation grace an operator may set: one hour.
    ///
    /// A key is usually rotated because it is suspect. A grace of years
    /// would keep it working for years.
    pub const LONGEST_GRACE: Duration = Duration::hours(1);

    /// Lifetimes from the operator's settings.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the default lifetime is not positive.
    /// - [`DomainError::Validation`] when the default is longer than the
    ///   longest.
    /// - [`DomainError::Validation`] when the longest is past
    ///   [`LONGEST_LIFETIME`](Self::LONGEST_LIFETIME).
    /// - [`DomainError::Validation`] when the grace is negative, or past
    ///   [`LONGEST_GRACE`](Self::LONGEST_GRACE).
    pub fn new(
        default_lifetime: Duration,
        max_lifetime: Duration,
        rotation_grace: Duration,
    ) -> Result<Self, DomainError> {
        if default_lifetime <= Duration::ZERO || default_lifetime > max_lifetime {
            return Err(DomainError::invalid(message!(
                "agents-an-agent-credential-s-default-lifetime",
                "an agent credential's default lifetime must be positive and no longer than \
                 its longest"
            )));
        }
        if max_lifetime > Self::LONGEST_LIFETIME {
            return Err(DomainError::invalid(message!(
                "agents-an-agent-credential-may-live-a",
                "an agent credential may live a year at most"
            )));
        }
        if rotation_grace < Duration::ZERO || rotation_grace > Self::LONGEST_GRACE {
            return Err(DomainError::invalid(message!(
                "agents-a-rotation-grace-must-be-between",
                "a rotation grace must be between zero and one hour"
            )));
        }
        Ok(Self {
            default_lifetime,
            max_lifetime,
            rotation_grace,
        })
    }

    /// How long a credential lives when no expiry is asked for.
    #[must_use]
    pub fn default_lifetime(self) -> Duration {
        self.default_lifetime
    }

    /// The longest a credential may live.
    #[must_use]
    pub fn max_lifetime(self) -> Duration {
        self.max_lifetime
    }

    /// How long a rotated credential keeps verifying assertions signed before
    /// the rotation.
    ///
    /// It is long enough for requests already sent to arrive. It is short
    /// enough that a rotated key stops working soon.
    #[must_use]
    pub fn rotation_grace(self) -> Duration {
        self.rotation_grace
    }
}

impl Default for CredentialLifetimes {
    /// 30 days by default, 90 at most, 5 minutes of grace after rotation.
    fn default() -> Self {
        Self {
            default_lifetime: Duration::days(30),
            max_lifetime: Duration::days(90),
            rotation_grace: Duration::minutes(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: Duration = Duration::minutes(5);

    /// An operator sets a 91 day default with a 90 day maximum. The settings
    /// are refused.
    #[test]
    fn a_default_lifetime_longer_than_the_longest_is_refused() {
        assert!(CredentialLifetimes::new(Duration::days(91), Duration::days(90), GRACE).is_err());
    }

    /// A ten-year credential lifetime and a year of rotation grace both
    /// exceed their respective limits and are refused as invalid settings.
    #[test]
    fn a_lifetime_or_grace_past_the_limit_is_refused() {
        let ten_years = Duration::days(3650);

        let long_life = CredentialLifetimes::new(Duration::days(30), ten_years, GRACE);
        let long_grace =
            CredentialLifetimes::new(Duration::days(30), Duration::days(90), Duration::days(365));

        assert!(matches!(long_life, Err(DomainError::Validation(_))));
        assert!(matches!(long_grace, Err(DomainError::Validation(_))));
    }

    /// A rotation grace of minus one minute is refused as an invalid
    /// setting, preventing construction of lifetimes with negative grace.
    #[test]
    fn a_negative_grace_is_refused() {
        let negative =
            CredentialLifetimes::new(Duration::days(30), Duration::days(90), -Duration::MINUTE);

        assert!(matches!(negative, Err(DomainError::Validation(_))));
    }

    /// The default settings, and settings right at both limits, are
    /// accepted.
    #[test]
    fn lifetimes_at_the_limits_are_accepted() {
        let at_limits = CredentialLifetimes::new(
            Duration::days(30),
            CredentialLifetimes::LONGEST_LIFETIME,
            CredentialLifetimes::LONGEST_GRACE,
        );

        assert!(at_limits.is_ok());
        let defaults = CredentialLifetimes::default();
        assert!(
            CredentialLifetimes::new(
                defaults.default_lifetime(),
                defaults.max_lifetime(),
                defaults.rotation_grace()
            )
            .is_ok()
        );
    }
}
