//! Building blocks shared by the organization and tenant metrics
//! overviews.
//!
//! Both overviews present the same figures (trended counts, latency
//! averages, login success rates, and proxied-request aggregates),
//! differing only in scope. The value assembly lives here once; the
//! per-scope use cases fetch raw figures through their reader port and
//! delegate to these types.

use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, Ratio, SuccessRate, TimeSeriesPoint, Trend,
};
use time::OffsetDateTime;

use crate::ports::metrics::RequestMetrics;

/// A current measurement paired with its period-over-period trend.
pub struct Trended<T> {
    /// The value over the requested window.
    pub current: T,
    /// How the value moved versus the preceding window.
    pub trend: Trend,
}

/// Authentication figures: timing, success rate, failed-attempt
/// breakdown, and the success-rate time series.
pub struct AuthenticationMetrics {
    /// Average time to authenticate successfully.
    pub average_auth_time: Trended<Option<LatencyMs>>,
    /// Fraction of login attempts that succeeded.
    pub success_rate: Trended<Option<SuccessRate>>,
    /// Failed-out-of-total breakdown, trended against the preceding
    /// window's failure count.
    pub failed_attempts: Trended<Ratio>,
    /// Per-bucket success rate for the line chart.
    pub success_rate_series: Vec<TimeSeriesPoint>,
    /// When anyone in scope last logged in successfully.
    pub last_login: Option<OffsetDateTime>,
}

/// Raw authentication figures for a window and its baseline, ready to
/// assemble into [`AuthenticationMetrics`].
pub(crate) struct AuthenticationFigures {
    /// Login outcomes over the requested window.
    pub current: LoginOutcomeCounts,
    /// Login outcomes over the preceding window.
    pub baseline: LoginOutcomeCounts,
    /// Bucketed outcomes for the line chart.
    pub series: Vec<TimeSeriesPoint>,
    /// Average authentication time over the requested window.
    pub avg_auth_ms: Option<LatencyMs>,
    /// Average authentication time over the preceding window.
    pub baseline_avg_auth_ms: Option<LatencyMs>,
    /// The most recent successful login, unbounded by the window.
    pub last_login: Option<OffsetDateTime>,
}

impl From<AuthenticationFigures> for AuthenticationMetrics {
    fn from(figures: AuthenticationFigures) -> Self {
        Self {
            average_auth_time: latency_trend(figures.avg_auth_ms, figures.baseline_avg_auth_ms),
            success_rate: Trended {
                current: figures.current.success_rate(),
                trend: Trend::from_values(
                    success_percent(&figures.current),
                    success_percent(&figures.baseline),
                ),
            },
            failed_attempts: Trended {
                current: figures.current.failure_ratio(),
                trend: Trend::from_counts(figures.current.failed(), figures.baseline.failed()),
            },
            success_rate_series: figures.series,
            last_login: figures.last_login,
        }
    }
}

/// Proxied API usage figures.
pub struct ApiUsageMetrics {
    /// Total requests served.
    pub request_count: Trended<u64>,
    /// Blocked requests as a percentage of the total.
    pub error_rate: Trended<Option<f64>>,
    /// 95th-percentile request latency.
    pub p95_latency: Trended<Option<LatencyMs>>,
}

impl ApiUsageMetrics {
    /// Assembles the usage figures from a window and its baseline.
    #[must_use]
    pub fn from_windows(current: RequestMetrics, previous: RequestMetrics) -> Self {
        Self {
            request_count: count_trend(current.request_count, previous.request_count),
            error_rate: Trended {
                current: current.error_rate_percent(),
                trend: Trend::from_values(
                    current.error_rate_percent().unwrap_or(0.0),
                    previous.error_rate_percent().unwrap_or(0.0),
                ),
            },
            p95_latency: latency_trend(current.p95_latency_ms, previous.p95_latency_ms),
        }
    }

    /// Requests that succeeded as a percentage of the total, or `None`
    /// when there were no requests.
    #[must_use]
    pub fn success_rate_percent(&self) -> Option<f64> {
        self.error_rate.current.map(|rate| 100.0 - rate)
    }
}

/// Pairs a count with its trend against a baseline count.
#[must_use]
pub(crate) fn count_trend(current: u64, previous: u64) -> Trended<u64> {
    Trended {
        current,
        trend: Trend::from_counts(current, previous),
    }
}

/// Pairs a latency with its trend against a baseline latency.
#[must_use]
pub(crate) fn latency_trend(
    current: Option<LatencyMs>,
    previous: Option<LatencyMs>,
) -> Trended<Option<LatencyMs>> {
    Trended {
        current,
        trend: Trend::from_values(millis_or_zero(current), millis_or_zero(previous)),
    }
}

fn millis_or_zero(latency: Option<LatencyMs>) -> f64 {
    f64::from(latency.map_or(0, |latency| latency.millis()))
}

fn success_percent(outcomes: &LoginOutcomeCounts) -> f64 {
    outcomes.success_rate().map_or(0.0, |rate| rate.percent())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::metrics::TrendDirection;

    use super::*;

    /// Acme had 288 good sign-ins and 12 failed ones, against 180 and 20 the
    /// week before. The success rate reads 96 percent and rising, the
    /// failures falling, and the average sign-in time 120 ms.
    #[test]
    fn authentication_figures_assemble_rates_and_trends() {
        let metrics = AuthenticationMetrics::from(AuthenticationFigures {
            current: LoginOutcomeCounts::new(288, 12),
            baseline: LoginOutcomeCounts::new(180, 20),
            series: vec![],
            avg_auth_ms: Some(LatencyMs::new(120)),
            baseline_avg_auth_ms: Some(LatencyMs::new(150)),
            last_login: None,
        });

        assert_eq!(metrics.success_rate.current.unwrap().percent(), 96.0);
        assert_eq!(metrics.success_rate.trend.direction(), TrendDirection::Up);
        assert_eq!(metrics.failed_attempts.current.part(), 12);
        assert_eq!(
            metrics.failed_attempts.trend.direction(),
            TrendDirection::Down
        );
        assert_eq!(metrics.average_auth_time.current.unwrap().millis(), 120);
    }

    /// Acme's proxy served 200 requests, 4 of them blocked. Its success rate
    /// is the other 98 percent, and the request count is rising.
    #[test]
    fn api_usage_success_rate_complements_the_error_rate() {
        let usage = ApiUsageMetrics::from_windows(
            RequestMetrics {
                request_count: 200,
                error_count: 4,
                p95_latency_ms: Some(LatencyMs::new(80)),
            },
            RequestMetrics {
                request_count: 100,
                error_count: 1,
                p95_latency_ms: Some(LatencyMs::new(90)),
            },
        );

        assert_eq!(usage.success_rate_percent(), Some(98.0));
        assert_eq!(usage.request_count.trend.direction(), TrendDirection::Up);
    }

    /// With no requests at all there is no success rate, rather than a zero
    /// that reads as an outage.
    #[test]
    fn api_usage_success_rate_is_none_without_requests() {
        let empty = RequestMetrics {
            request_count: 0,
            error_count: 0,
            p95_latency_ms: None,
        };
        let usage = ApiUsageMetrics::from_windows(empty, empty);

        assert_eq!(usage.success_rate_percent(), None);
    }
}
