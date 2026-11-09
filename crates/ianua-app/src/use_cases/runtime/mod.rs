//! Running the service rather than any one context: whether the process
//! may take traffic, and its own metrics for a scrape.

pub(crate) mod metrics;
pub(crate) mod readiness;

pub use metrics::{ExportMetricsPorts, ExportMetricsUseCase};
pub use readiness::{CheckReadinessPorts, CheckReadinessUseCase, ServiceReadiness};
