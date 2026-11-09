//! A current value compared with the one before it, as a direction and a
//! percentage change.

/// Which way a metric moved relative to its baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendDirection {
    /// The current value exceeds the baseline.
    Up,
    /// The current value is below the baseline.
    Down,
    /// The current value equals the baseline.
    Flat,
}

/// A current measurement paired with the baseline it is compared to.
///
/// The baseline is the same metric over the window of equal length just
/// before, from
/// [`MetricsWindow::previous`](crate::domains::metrics::window::MetricsWindow::previous).
/// The percentage change is `None` when the baseline is zero, since growth
/// from nothing has no ratio.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Trend {
    current: f64,
    previous: f64,
}

impl Trend {
    /// Builds a trend from two counts.
    #[must_use]
    pub fn from_counts(current: u64, previous: u64) -> Self {
        Self {
            current: current as f64,
            previous: previous as f64,
        }
    }

    /// Builds a trend from two computed values, such as rates or latencies.
    #[must_use]
    pub fn from_values(current: f64, previous: f64) -> Self {
        Self { current, previous }
    }

    /// The current value.
    #[must_use]
    pub fn current(&self) -> f64 {
        self.current
    }

    /// The baseline value.
    #[must_use]
    pub fn previous(&self) -> f64 {
        self.previous
    }

    /// The signed percentage change from baseline to current, or `None`
    /// when the baseline is zero.
    #[must_use]
    pub fn change_pct(&self) -> Option<f64> {
        if self.previous == 0.0 {
            return None;
        }

        Some((self.current - self.previous) / self.previous * 100.0)
    }

    /// Which way the metric moved relative to baseline.
    #[must_use]
    pub fn direction(&self) -> TrendDirection {
        if self.current > self.previous {
            return TrendDirection::Up;
        }
        if self.current < self.previous {
            return TrendDirection::Down;
        }

        TrendDirection::Flat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Logins rose from 100 to 150. The trend points up with a 50 percent
    /// change.
    #[test]
    fn growth_is_up_with_positive_pct() {
        let trend = Trend::from_counts(150, 100);
        assert_eq!(trend.direction(), TrendDirection::Up);
        assert_eq!(trend.change_pct(), Some(50.0));
    }

    /// Logins fell from 100 to 75. The trend points down with a -25 percent
    /// change.
    #[test]
    fn decline_is_down_with_negative_pct() {
        let trend = Trend::from_counts(75, 100);
        assert_eq!(trend.direction(), TrendDirection::Down);
        assert_eq!(trend.change_pct(), Some(-25.0));
    }

    /// Logins stayed at 100. The trend is flat with a zero percent change.
    #[test]
    fn equal_values_are_flat_with_zero_pct() {
        let trend = Trend::from_counts(100, 100);
        assert_eq!(trend.direction(), TrendDirection::Flat);
        assert_eq!(trend.change_pct(), Some(0.0));
    }

    /// A new tenant went from 0 logins to 10. The trend points up but has no
    /// percentage, since growth from nothing has no ratio.
    #[test]
    fn zero_baseline_has_no_defined_pct() {
        let trend = Trend::from_counts(10, 0);
        assert_eq!(trend.direction(), TrendDirection::Up);
        assert_eq!(trend.change_pct(), None);
    }

    /// A rate dropped from 50 to 40. The trend points down with a -20
    /// percent change, the same as for counts.
    #[test]
    fn value_trend_tracks_rates() {
        let trend = Trend::from_values(40.0, 50.0);
        assert_eq!(trend.direction(), TrendDirection::Down);
        assert_eq!(trend.change_pct(), Some(-20.0));
    }

    /// A trend built from 40 and 50, or from counts 7 and 3, reads back
    /// those same values. The dashboard shows both beside the arrow.
    #[test]
    fn a_trend_reports_both_of_the_values_it_compares() {
        let trend = Trend::from_values(40.0, 50.0);

        assert!((trend.current() - 40.0).abs() < f64::EPSILON);
        assert!((trend.previous() - 50.0).abs() < f64::EPSILON);

        let from_counts = Trend::from_counts(7, 3);
        assert!((from_counts.current() - 7.0).abs() < f64::EPSILON);
        assert!((from_counts.previous() - 3.0).abs() < f64::EPSILON);
    }
}
