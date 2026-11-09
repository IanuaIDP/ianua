//! A single point in the authentication success-rate time series.

use time::OffsetDateTime;

use crate::domains::metrics::login_outcomes::{LoginOutcomeCounts, SuccessRate};

/// One bucket of the success-rate line chart.
///
/// It holds the login outcomes that fell within
/// `[bucket_start, bucket_start + granularity)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSeriesPoint {
    bucket_start: OffsetDateTime,
    outcomes: LoginOutcomeCounts,
}

impl TimeSeriesPoint {
    /// Creates a point for the bucket starting at `bucket_start`.
    #[must_use]
    pub fn new(bucket_start: OffsetDateTime, outcomes: LoginOutcomeCounts) -> Self {
        Self {
            bucket_start,
            outcomes,
        }
    }

    /// The inclusive start of the bucket.
    #[must_use]
    pub fn bucket_start(&self) -> OffsetDateTime {
        self.bucket_start
    }

    /// The login outcomes within the bucket.
    #[must_use]
    pub fn outcomes(&self) -> LoginOutcomeCounts {
        self.outcomes
    }

    /// The success rate within the bucket, or `None` when the bucket
    /// had no attempts.
    #[must_use]
    pub fn success_rate(&self) -> Option<SuccessRate> {
        self.outcomes.success_rate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    /// A bucket with nine successful logins and one failure reports its start
    /// time and a 90 percent success rate.
    #[test]
    fn point_exposes_bucket_and_rate() {
        let point = TimeSeriesPoint::new(at(1_000), LoginOutcomeCounts::new(9, 1));
        assert_eq!(point.bucket_start(), at(1_000));
        assert_eq!(point.success_rate().unwrap().percent(), 90.0);
    }
}
