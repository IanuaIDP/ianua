//! Login outcome counts, with the success rate and failure ratio the
//! authentication charts show.

/// A success percentage in `[0, 100]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SuccessRate(f64);

impl SuccessRate {
    /// The rate as a percentage in `[0, 100]`.
    #[must_use]
    pub fn percent(&self) -> f64 {
        self.0
    }
}

/// A part of a whole, such as "12 failed out of 300".
///
/// The failed-login pie chart uses it. `part` is the failures and the
/// remainder, `whole - part`, is the successes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    part: u64,
    whole: u64,
}

impl Ratio {
    /// The part, such as failed attempts.
    #[must_use]
    pub fn part(&self) -> u64 {
        self.part
    }

    /// The whole, such as all attempts.
    #[must_use]
    pub fn whole(&self) -> u64 {
        self.whole
    }

    /// What is left of `whole` after `part`, such as successes. Never below
    /// zero.
    #[must_use]
    pub fn remainder(&self) -> u64 {
        self.whole.saturating_sub(self.part)
    }

    /// `part` as a percentage of `whole`, or `None` when `whole` is zero.
    #[must_use]
    pub fn percent(&self) -> Option<f64> {
        if self.whole == 0 {
            return None;
        }

        Some(self.part as f64 / self.whole as f64 * 100.0)
    }
}

/// Succeeded and failed logins over a window.
///
/// Both the success-rate line chart and the failed-attempts pie chart are
/// worked out from these counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginOutcomeCounts {
    succeeded: u64,
    failed: u64,
}

impl LoginOutcomeCounts {
    /// Counts of succeeded and failed login attempts.
    #[must_use]
    pub fn new(succeeded: u64, failed: u64) -> Self {
        Self { succeeded, failed }
    }

    /// Successful logins.
    #[must_use]
    pub fn succeeded(&self) -> u64 {
        self.succeeded
    }

    /// Failed logins.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed
    }

    /// Total attempts, succeeded plus failed.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.succeeded.saturating_add(self.failed)
    }

    /// The share of attempts that succeeded, as a percentage, or `None`
    /// when there were no attempts.
    #[must_use]
    pub fn success_rate(&self) -> Option<SuccessRate> {
        let total = self.total();
        if total == 0 {
            return None;
        }

        Some(SuccessRate(self.succeeded as f64 / total as f64 * 100.0))
    }

    /// The failed-out-of-total breakdown for the pie chart.
    #[must_use]
    pub fn failure_ratio(&self) -> Ratio {
        Ratio {
            part: self.failed,
            whole: self.total(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant had 288 good logins and 12 failed ones. The total is 300 and
    /// the success rate is 96 percent.
    #[test]
    fn success_rate_is_percentage_of_total() {
        let outcomes = LoginOutcomeCounts::new(288, 12);
        assert_eq!(outcomes.total(), 300);
        assert_eq!(outcomes.success_rate().unwrap().percent(), 96.0);
    }

    /// A window with no login attempts has no success rate, rather than a
    /// made-up 0 or 100 percent.
    #[test]
    fn success_rate_is_none_without_attempts() {
        assert!(LoginOutcomeCounts::new(0, 0).success_rate().is_none());
    }

    /// With 288 good and 12 failed logins, the pie chart gets 12 out of 300,
    /// 288 left over and 4 percent.
    #[test]
    fn failure_ratio_carries_part_and_whole() {
        let ratio = LoginOutcomeCounts::new(288, 12).failure_ratio();
        assert_eq!(ratio.part(), 12);
        assert_eq!(ratio.whole(), 300);
        assert_eq!(ratio.remainder(), 288);
        assert_eq!(ratio.percent(), Some(4.0));
    }

    /// With no attempts at all, the failure ratio has no percentage instead
    /// of dividing by zero.
    #[test]
    fn ratio_percent_is_none_when_empty() {
        assert!(
            LoginOutcomeCounts::new(0, 0)
                .failure_ratio()
                .percent()
                .is_none()
        );
    }

    /// Counts of 90 good and 10 failed logins read back as 90, 10 and a total
    /// of 100. An administrator watching for a spike in failures sees the
    /// real failure count.
    #[test]
    fn each_count_is_reported_on_its_own() {
        let counts = LoginOutcomeCounts::new(90, 10);

        assert_eq!(counts.succeeded(), 90);
        assert_eq!(counts.failed(), 10);
        assert_eq!(counts.total(), 100);
    }
}
