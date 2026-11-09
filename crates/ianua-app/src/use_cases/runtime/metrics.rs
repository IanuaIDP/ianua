//! Export metrics: the process's own metrics, written out for the
//! Prometheus scrape on the internal listener.
//!
//! No caller rights: only the internal listener serves it, which no public
//! ingress routes to, and what it says is how the process runs, never what
//! any tenant holds.

use std::sync::Arc;

use crate::error::{AppError, OrInternal};
use crate::ports::runtime::{MetricsExporter, MetricsText};
use crate::use_case::Query;

/// The ports [`ExportMetricsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExportMetricsPorts {
    /// Writes out the process's metrics.
    pub exporter: Arc<dyn MetricsExporter>,
}

/// Writes out the process's metrics for a scrape.
pub struct ExportMetricsUseCase {
    ports: ExportMetricsPorts,
}

impl ExportMetricsUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ExportMetricsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ExportMetricsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<MetricsText, AppError>;

    /// Every metric the process records, in the Prometheus text format.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the metrics cannot be written out.
    async fn execute(&self, (): &(), (): ()) -> Result<MetricsText, AppError> {
        self.ports.exporter.render().or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeMetricsExporter, METRICS_TEXT, block_on};

    /// What the scrape is answered with `exporter` behind it.
    fn export(exporter: FakeMetricsExporter) -> Result<MetricsText, AppError> {
        let use_case = ExportMetricsUseCase::new(ExportMetricsPorts {
            exporter: Arc::new(exporter),
        });
        block_on(use_case.execute(&(), ()))
    }

    /// The scraper asks for the metrics and is handed the registry's text
    /// as it is.
    #[test]
    fn the_metrics_are_written_out_as_the_registry_holds_them() {
        let text = export(FakeMetricsExporter::writing(METRICS_TEXT)).unwrap();

        assert_eq!(text.as_str(), METRICS_TEXT);
    }

    /// The registry cannot be written out. The scrape fails rather than
    /// answering with empty metrics that read as a quiet process.
    #[test]
    fn a_registry_that_cannot_be_written_out_fails_the_scrape() {
        let result = export(FakeMetricsExporter::failing());

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
