//! The health score from 0 to 100 on the tenant overview.

/// A health score in `[0, 100]`.
///
/// It averages the rates that have data, such as the login success rate
/// and the proxied-request success rate. A rate with no samples is left
/// out, so it does not pull the score down. A tenant with no traffic at
/// all scores 100, because no traffic is not a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthScore(u8);

impl HealthScore {
    /// Averages the rates that have data into a score.
    ///
    /// Each rate is a percentage. A value outside `[0, 100]` is clamped to
    /// that range. A `None` rate is skipped. With no rates at all the score
    /// is 100.
    ///
    /// The cast to `u8` cannot cut or flip anything. The average of values
    /// in `[0, 100]` rounds to a whole number in the same range.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn from_rates(rates: impl IntoIterator<Item = Option<f64>>) -> Self {
        let measured: Vec<f64> = rates
            .into_iter()
            .flatten()
            .map(|rate| rate.clamp(0.0, 100.0))
            .collect();

        if measured.is_empty() {
            return Self(100);
        }

        let average = measured.iter().sum::<f64>() / measured.len() as f64;
        Self(average.round() as u8)
    }

    /// The score in `[0, 100]`.
    #[must_use]
    pub fn value(&self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant has a 90 percent login rate and a 70 percent proxy rate. Its
    /// score is the average, 80.
    #[test]
    fn from_rates_averages_available_components() {
        let score = HealthScore::from_rates([Some(90.0), Some(70.0)]);
        assert_eq!(score.value(), 80);
    }

    /// A tenant has a 60 percent login rate and no proxied requests. The
    /// score is 60, not pulled down by the rate with no data.
    #[test]
    fn from_rates_skips_missing_components() {
        let score = HealthScore::from_rates([Some(60.0), None]);
        assert_eq!(score.value(), 60);
    }

    /// A new tenant with no logins and no requests scores 100, since no
    /// traffic is not a fault.
    #[test]
    fn from_rates_is_perfect_without_data() {
        let score = HealthScore::from_rates([None, None]);
        assert_eq!(score.value(), 100);
    }

    /// Rates of 150 and -50 are clamped to 100 and 0 before averaging, so
    /// the score is 50 and stays in range.
    #[test]
    fn from_rates_clamps_out_of_range_components() {
        let score = HealthScore::from_rates([Some(150.0), Some(-50.0)]);
        assert_eq!(score.value(), 50);
    }

    /// A single rate of 99.5 rounds up to a score of 100.
    #[test]
    fn from_rates_rounds_to_nearest_integer() {
        let score = HealthScore::from_rates([Some(99.5)]);
        assert_eq!(score.value(), 100);
    }
}
