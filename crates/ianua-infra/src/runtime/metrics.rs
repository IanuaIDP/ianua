//! The process's own metrics, written out in the Prometheus text format for
//! the scrape on the internal listener.
//!
//! The registry is the composition root's: whatever records the process's
//! counters registers them there, and this only reads it. Nothing is pushed
//! anywhere and nothing is called out, so a scrape can neither slow a
//! request nor fail one.

use ianua_app::ports::runtime::{MetricsExporter, MetricsText};
use ianua_domain::shared::errors::DomainError;
use prometheus::{Registry, TextEncoder};

/// Writes out every metric of one registry in this process.
pub struct LocalMetricsExporter {
    registry: Registry,
}

impl LocalMetricsExporter {
    /// An exporter reading `registry`, the one the process records into.
    #[must_use]
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

impl MetricsExporter for LocalMetricsExporter {
    fn render(&self) -> Result<MetricsText, DomainError> {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .map(MetricsText::new)
            .map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use prometheus::{IntCounter, Opts};

    use super::*;

    /// A counter the process registered shows in the text with its value.
    #[test]
    fn a_registered_counter_is_written_out() {
        let registry = Registry::new();
        let served = IntCounter::with_opts(Opts::new("requests_total", "Requests served")).unwrap();
        registry.register(Box::new(served.clone())).unwrap();
        served.inc_by(3);

        let text = LocalMetricsExporter::new(registry).render().unwrap();

        assert!(
            text.as_str().contains("requests_total 3"),
            "{}",
            text.as_str()
        );
    }

    /// A registry nothing was recorded into writes out nothing.
    #[test]
    fn an_empty_registry_writes_out_nothing() {
        let text = LocalMetricsExporter::new(Registry::new()).render().unwrap();

        assert_eq!(text.as_str(), "");
    }
}
