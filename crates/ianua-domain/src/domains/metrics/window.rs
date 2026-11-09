//! The time window a metrics query covers, and the window of equal length
//! before it that trends compare against.

use time::{Duration, OffsetDateTime};

use crate::message;
use crate::shared::errors::DomainError;

/// A half-open `[start, end)` time window for a metrics query.
///
/// Every "since date" figure on the overview covers a window the caller
/// picks. The window of equal length just before it,
/// [`previous`](Self::previous), is the baseline for trends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsWindow {
    start: OffsetDateTime,
    end: OffsetDateTime,
}

/// The bucket size for time-series aggregation within a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    /// One bucket per hour, for windows of up to two days.
    Hourly,
    /// One bucket per day, for longer windows.
    Daily,
}

impl MetricsWindow {
    /// A window that includes `start` and stops just before `end`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `end` is not after `start`.
    pub fn new(start: OffsetDateTime, end: OffsetDateTime) -> Result<Self, DomainError> {
        if end <= start {
            return Err(DomainError::invalid(message!(
                "metrics-metrics-window-end-must-be-after",
                "metrics window end must be after start"
            )));
        }

        Ok(Self { start, end })
    }

    /// The inclusive start of the window.
    #[must_use]
    pub fn start(&self) -> OffsetDateTime {
        self.start
    }

    /// The exclusive end of the window.
    #[must_use]
    pub fn end(&self) -> OffsetDateTime {
        self.end
    }

    /// The length of the window.
    #[must_use]
    pub fn duration(&self) -> Duration {
        crate::shared::clock::between(self.start, self.end)
    }

    /// The window of equal length just before this one,
    /// `[start - duration, start)`. Trends use it as their baseline.
    #[must_use]
    pub fn previous(&self) -> Self {
        Self {
            start: self.start.saturating_sub(self.duration()),
            end: self.start,
        }
    }

    /// The bucket size for the time series. It follows the window length,
    /// so a line chart stays readable.
    #[must_use]
    pub fn granularity(&self) -> Granularity {
        if self.duration() <= Duration::days(2) {
            return Granularity::Hourly;
        }

        Granularity::Daily
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    /// A window that starts and ends at the same moment covers no time. It
    /// is refused.
    #[test]
    fn new_rejects_empty_window() {
        let t = at(1_000);
        assert!(MetricsWindow::new(t, t).is_err());
    }

    /// A caller asks for a window whose end comes before its start. It is
    /// refused.
    #[test]
    fn new_rejects_reversed_window() {
        assert!(MetricsWindow::new(at(2_000), at(1_000)).is_err());
    }

    /// A ten-minute window from 1000 to 1600 has a baseline from 400 to
    /// 1000. It is as long and ends where the window starts.
    #[test]
    fn previous_is_equal_length_and_adjacent() {
        let window = MetricsWindow::new(at(1_000), at(1_600)).unwrap();
        let previous = window.previous();

        assert_eq!(previous.end(), window.start());
        assert_eq!(previous.duration(), window.duration());
        assert_eq!(previous.start(), at(400));
    }

    /// A one-day window is charted in hourly buckets.
    #[test]
    fn granularity_is_hourly_for_short_windows() {
        let window = MetricsWindow::new(at(0), at(Duration::days(1).whole_seconds())).unwrap();
        assert_eq!(window.granularity(), Granularity::Hourly);
    }

    /// A seven-day window is charted in daily buckets, so the line stays
    /// readable.
    #[test]
    fn granularity_is_daily_for_long_windows() {
        let window = MetricsWindow::new(at(0), at(Duration::days(7).whole_seconds())).unwrap();
        assert_eq!(window.granularity(), Granularity::Daily);
    }
}
