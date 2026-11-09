//! Value objects for the organization and tenant metrics overviews.
//!
//! Windows, trends, login outcomes, latencies, health scores and
//! time-series points, used by the metrics query use cases. The
//! application and infrastructure layers load the figures from storage.
//! This module turns raw counts into rates, ratios and percentage changes.

pub mod health;
pub mod latency;
pub mod login_outcomes;
pub mod series;
pub mod trend;
pub mod window;

pub use health::HealthScore;
pub use latency::LatencyMs;
pub use login_outcomes::{LoginOutcomeCounts, Ratio, SuccessRate};
pub use series::TimeSeriesPoint;
pub use trend::{Trend, TrendDirection};
pub use window::{Granularity, MetricsWindow};
