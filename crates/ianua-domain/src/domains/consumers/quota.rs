//! How many requests a consumer may send in a period.
//!
//! A rate limit stage guards a route against bursts from anyone. A quota is
//! the consumer's own allowance, such as the 10 000 calls a day a partner's
//! contract pays for. The gateway counts the consumer's requests in the
//! current period and asks [`ConsumerQuota::admits`] before forwarding.

use std::num::NonZeroU64;

use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;

/// The period a quota is counted over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaPeriod {
    /// A calendar minute.
    Minute,
    /// A calendar hour.
    Hour,
    /// A calendar day, in UTC.
    Day,
    /// A calendar month, in UTC.
    Month,
}

impl QuotaPeriod {
    /// The stored form, such as `day`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }

    /// Reads a period from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a value this version does not
    ///   know.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "minute" => Ok(Self::Minute),
            "hour" => Ok(Self::Hour),
            "day" => Ok(Self::Day),
            "month" => Ok(Self::Month),
            _ => Err(DomainError::corrupt_row(
                "consumer",
                "an unknown quota period",
            )),
        }
    }
}

/// A number of requests per period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestAllowance {
    requests: NonZeroU64,
    per: QuotaPeriod,
}

impl RequestAllowance {
    /// The most requests a quota may allow in one period.
    pub const MAX_REQUESTS: u64 = 1_000_000_000;

    /// `requests` per `per`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `requests` is zero or above
    ///   [`Self::MAX_REQUESTS`]. A quota of zero would refuse every request
    ///   while reading as a limit; disable the consumer instead.
    pub fn new(requests: u64, per: QuotaPeriod) -> Result<Self, ValidationError> {
        validate_range("quota_requests", requests, 1..=Self::MAX_REQUESTS)?;
        let requests = NonZeroU64::new(requests).ok_or(ValidationError::OutOfRange {
            field: "quota_requests",
            min: 1,
            max: Self::MAX_REQUESTS,
            actual: 0,
        })?;
        Ok(Self { requests, per })
    }

    /// The requests allowed per period.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.requests.get()
    }

    /// The period they are counted over.
    #[must_use]
    pub fn per(&self) -> QuotaPeriod {
        self.per
    }
}

/// How many requests a consumer may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerQuota {
    /// No allowance of its own. Route rate limits still apply.
    Unlimited,
    /// At most this many requests per period.
    Limited(RequestAllowance),
}

/// Whether one more request fits a consumer's quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaVerdict {
    /// It fits, leaving this many after it. Unlimited quotas leave
    /// `u64::MAX`.
    Within {
        /// Requests left in the period once this one is counted.
        remaining: u64,
    },
    /// The period's allowance is spent. The request is refused until the
    /// next period.
    Exhausted,
}

impl ConsumerQuota {
    /// Whether one more request fits, when `used` requests were already
    /// counted in the current period.
    #[must_use]
    pub fn admits(&self, used: u64) -> QuotaVerdict {
        let Self::Limited(allowance) = self else {
            return QuotaVerdict::Within {
                remaining: u64::MAX,
            };
        };
        let left = allowance.requests().saturating_sub(used);
        let Some(remaining) = left.checked_sub(1) else {
            return QuotaVerdict::Exhausted;
        };
        QuotaVerdict::Within { remaining }
    }

    /// The quota as an audit record writes it, such as `10000 per day` or
    /// `unlimited`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Unlimited => "unlimited".to_owned(),
            Self::Limited(allowance) => {
                format!("{} per {}", allowance.requests(), allowance.per().as_str())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn daily(requests: u64) -> ConsumerQuota {
        ConsumerQuota::Limited(RequestAllowance::new(requests, QuotaPeriod::Day).unwrap())
    }

    /// A quota of zero requests, or more than a billion, is refused. One
    /// request a day is accepted.
    #[test]
    fn an_allowance_is_between_one_and_a_billion() {
        assert!(RequestAllowance::new(0, QuotaPeriod::Day).is_err());
        assert!(
            RequestAllowance::new(RequestAllowance::MAX_REQUESTS + 1, QuotaPeriod::Day).is_err()
        );
        assert!(RequestAllowance::new(1, QuotaPeriod::Day).is_ok());
    }

    /// "billing-sync" may send 3 requests a day and has sent 2. The third is
    /// admitted with none left after it.
    #[test]
    fn the_last_request_of_the_allowance_is_admitted() {
        assert_eq!(daily(3).admits(2), QuotaVerdict::Within { remaining: 0 });
    }

    /// A three-request daily quota is exhausted at three used requests
    /// and remains exhausted even when the supplied count is u64::MAX.
    #[test]
    fn a_request_past_the_allowance_is_refused() {
        assert_eq!(daily(3).admits(3), QuotaVerdict::Exhausted);
        assert_eq!(daily(3).admits(u64::MAX), QuotaVerdict::Exhausted);
    }

    /// An unlimited consumer is admitted whatever it has sent.
    #[test]
    fn an_unlimited_quota_admits_every_request() {
        assert!(matches!(
            ConsumerQuota::Unlimited.admits(u64::MAX),
            QuotaVerdict::Within { .. }
        ));
    }

    /// A daily quota of 10000 is written as `10000 per day`, and none as
    /// `unlimited`.
    #[test]
    fn a_quota_is_described_in_plain_words() {
        assert_eq!(daily(10_000).describe(), "10000 per day");
        assert_eq!(ConsumerQuota::Unlimited.describe(), "unlimited");
    }

    /// Every period reads back from its stored form, and `week` is refused
    /// as a corrupt row.
    #[test]
    fn periods_read_back_from_storage() {
        for period in [
            QuotaPeriod::Minute,
            QuotaPeriod::Hour,
            QuotaPeriod::Day,
            QuotaPeriod::Month,
        ] {
            assert_eq!(QuotaPeriod::from_stored(period.as_str()).unwrap(), period);
        }
        assert!(QuotaPeriod::from_stored("week").is_err());
    }
}
