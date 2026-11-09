//! The process's own metrics, written out for a Prometheus scrape: request
//! counts, latencies and whatever else the process records about itself.
//!
//! These say how the process runs, not what any tenant did, and are served
//! only on the internal listener, where the scraper calls.

use ianua_domain::shared::errors::DomainError;

/// The process's metrics in the Prometheus text exposition format, ready to
/// be served as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsText(String);

impl MetricsText {
    /// Metrics already written in the Prometheus text format.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The text, as served.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Dyn-safe port writing out the process's metrics.
///
/// Synchronous: it reads the process's own registry, held in memory, and
/// calls nothing outside it.
pub trait MetricsExporter: Send + Sync {
    /// Every metric the process records, in the Prometheus text format.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the registry cannot be
    /// written out.
    fn render(&self) -> Result<MetricsText, DomainError>;
}
