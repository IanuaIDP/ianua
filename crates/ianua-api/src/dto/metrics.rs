//! Metric bodies shared by the organization and tenant overviews: trended
//! counts, rates, latencies and the sign-in success series.
//!
//! Both overviews serialize the same figure shapes, so the response types
//! and their mappings from the app's overview building blocks live here
//! once.

use ianua_app::use_cases::metrics::overview::{ApiUsageMetrics, AuthenticationMetrics, Trended};
use ianua_domain::domains::metrics::{
    LatencyMs, MetricsWindow, Ratio, TimeSeriesPoint, Trend, TrendDirection,
};
use serde::Serialize;
use time::OffsetDateTime;

/// Direction of a period-over-period trend.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TrendDirectionResponse {
    /// Above the previous window.
    Up,
    /// Below the previous window.
    Down,
    /// Equal to the previous window.
    Flat,
}

impl From<TrendDirection> for TrendDirectionResponse {
    fn from(direction: TrendDirection) -> Self {
        match direction {
            TrendDirection::Up => Self::Up,
            TrendDirection::Down => Self::Down,
            TrendDirection::Flat => Self::Flat,
        }
    }
}

/// Percentage change versus the previous window and its direction.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TrendResponse {
    /// Signed percentage change; null when the baseline was zero.
    pub change_pct: Option<f64>,
    /// Direction of movement.
    pub direction: TrendDirectionResponse,
}

impl From<Trend> for TrendResponse {
    fn from(trend: Trend) -> Self {
        Self {
            change_pct: trend.change_pct(),
            direction: trend.direction().into(),
        }
    }
}

/// A counted value with its trend.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CountMetricResponse {
    /// Current value over the window.
    pub current: u64,
    /// Movement versus the previous window.
    pub trend: TrendResponse,
}

impl From<Trended<u64>> for CountMetricResponse {
    fn from(metric: Trended<u64>) -> Self {
        Self {
            current: metric.current,
            trend: metric.trend.into(),
        }
    }
}

/// A percentage value with its trend.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RateMetricResponse {
    /// Current percentage; null when undefined (no samples).
    pub current: Option<f64>,
    /// Movement versus the previous window.
    pub trend: TrendResponse,
}

impl From<Trended<Option<f64>>> for RateMetricResponse {
    fn from(metric: Trended<Option<f64>>) -> Self {
        Self {
            current: metric.current,
            trend: metric.trend.into(),
        }
    }
}

/// A latency value in milliseconds with its trend.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LatencyMetricResponse {
    /// Current latency in milliseconds; null when undefined (no samples).
    pub current_ms: Option<u32>,
    /// Movement versus the previous window.
    pub trend: TrendResponse,
}

impl From<Trended<Option<LatencyMs>>> for LatencyMetricResponse {
    fn from(metric: Trended<Option<LatencyMs>>) -> Self {
        Self {
            current_ms: metric.current.map(|latency| latency.millis()),
            trend: metric.trend.into(),
        }
    }
}

/// Failed-out-of-total breakdown with its trend.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FailedAttemptsResponse {
    /// Failed attempts.
    pub failed: u64,
    /// Total attempts.
    pub total: u64,
    /// Failures as a percentage of the total; null when there were none.
    pub percent: Option<f64>,
    /// Movement of the failure count versus the previous window.
    pub trend: TrendResponse,
}

impl From<Trended<Ratio>> for FailedAttemptsResponse {
    fn from(metric: Trended<Ratio>) -> Self {
        Self {
            failed: metric.current.part(),
            total: metric.current.whole(),
            percent: metric.current.percent(),
            trend: metric.trend.into(),
        }
    }
}

/// One bucket of the success-rate line chart.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SuccessRatePointResponse {
    /// Inclusive start of the bucket.
    #[serde(with = "time::serde::rfc3339")]
    pub bucket_start: OffsetDateTime,
    /// Successful sign-ins in the bucket.
    pub succeeded: u64,
    /// Failed sign-ins in the bucket.
    pub failed: u64,
    /// Success rate in the bucket; null when the bucket had no attempts.
    pub success_rate: Option<f64>,
}

impl From<TimeSeriesPoint> for SuccessRatePointResponse {
    fn from(point: TimeSeriesPoint) -> Self {
        let outcomes = point.outcomes();
        Self {
            bucket_start: point.bucket_start(),
            succeeded: outcomes.succeeded(),
            failed: outcomes.failed(),
            success_rate: point.success_rate().map(|rate| rate.percent()),
        }
    }
}

/// The window the metrics were computed over.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MetricsWindowResponse {
    /// Inclusive start.
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    /// Exclusive end.
    #[serde(with = "time::serde::rfc3339")]
    pub end: OffsetDateTime,
}

impl From<MetricsWindow> for MetricsWindowResponse {
    fn from(window: MetricsWindow) -> Self {
        Self {
            start: window.start(),
            end: window.end(),
        }
    }
}

/// Authentication metrics and charts.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuthenticationMetricsResponse {
    /// Average time to authenticate successfully.
    pub average_auth_time: LatencyMetricResponse,
    /// Sign-in success rate.
    pub success_rate: RateMetricResponse,
    /// Failed-attempt breakdown with its trend.
    pub failed_attempts: FailedAttemptsResponse,
    /// Success-rate line chart points.
    pub success_rate_series: Vec<SuccessRatePointResponse>,
    /// When anyone in scope last signed in; null if never.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_login: Option<OffsetDateTime>,
}

impl From<AuthenticationMetrics> for AuthenticationMetricsResponse {
    fn from(auth: AuthenticationMetrics) -> Self {
        Self {
            average_auth_time: auth.average_auth_time.into(),
            success_rate: RateMetricResponse {
                current: auth.success_rate.current.map(|rate| rate.percent()),
                trend: auth.success_rate.trend.into(),
            },
            failed_attempts: auth.failed_attempts.into(),
            success_rate_series: auth
                .success_rate_series
                .into_iter()
                .map(SuccessRatePointResponse::from)
                .collect(),
            last_login: auth.last_login,
        }
    }
}

/// Proxied API usage metrics.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApiUsageMetricsResponse {
    /// Total requests served.
    pub request_count: CountMetricResponse,
    /// Blocked requests as a percentage of the total.
    pub error_rate: RateMetricResponse,
    /// 95th-percentile request latency.
    pub p95_latency: LatencyMetricResponse,
}

impl From<ApiUsageMetrics> for ApiUsageMetricsResponse {
    fn from(api: ApiUsageMetrics) -> Self {
        Self {
            request_count: api.request_count.into(),
            error_rate: api.error_rate.into(),
            p95_latency: api.p95_latency.into(),
        }
    }
}
