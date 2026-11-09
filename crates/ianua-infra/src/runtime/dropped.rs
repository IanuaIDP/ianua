//! Records the process's bounded queues dropped, counted into its own
//! metrics registry as `ianua_records_dropped_total`, by destination.
//!
//! The destination is the queue's fixed name (`request records`, `live
//! dashboard` and the like), a closed set, so the metric's series are
//! bounded by the code and never by traffic.

use ianua_app::ports::runtime::DroppedRecords;
use ianua_domain::shared::errors::DomainError;
use prometheus::{IntCounterVec, Registry};

use crate::runtime::series::{counter, register};

/// Counts the records each bounded queue dropped.
pub struct LocalDroppedRecords {
    dropped: IntCounterVec,
}

impl LocalDroppedRecords {
    /// A counter registered in `registry`, the one the process's
    /// [`LocalMetricsExporter`](crate::runtime::LocalMetricsExporter) reads.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `registry` already holds
    /// the metric, such as when it is registered twice.
    pub fn register(registry: &Registry) -> Result<Self, DomainError> {
        let dropped = counter(
            "ianua_records_dropped_total",
            "Records a bounded queue dropped because its destination was not keeping up.",
            &["destination"],
        )?;
        register(registry, vec![Box::new(dropped.clone())])?;
        Ok(Self { dropped })
    }
}

impl DroppedRecords for LocalDroppedRecords {
    fn add(&self, destination: &'static str, count: u64) {
        if let Ok(counter) = self.dropped.get_metric_with_label_values(&[destination]) {
            counter.inc_by(count);
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::runtime::MetricsExporter;

    use super::*;
    use crate::runtime::LocalMetricsExporter;

    /// Seven records dropped in front of the request records, in two
    /// reports, show as seven under that destination.
    #[test]
    fn dropped_records_are_counted_by_destination() {
        let registry = Registry::new();
        let counted = LocalDroppedRecords::register(&registry).unwrap();

        counted.add("request records", 3);
        counted.add("request records", 4);

        let text = LocalMetricsExporter::new(registry)
            .render()
            .unwrap()
            .into_string();
        assert!(
            text.contains("ianua_records_dropped_total{destination=\"request records\"} 7"),
            "{text}"
        );
    }

    /// Registering the dropped-record counter twice returns an infrastructure error.
    #[test]
    fn a_second_counter_in_one_registry_is_refused() {
        let registry = Registry::new();
        LocalDroppedRecords::register(&registry).unwrap();

        let second = LocalDroppedRecords::register(&registry);

        assert!(matches!(second, Err(DomainError::Infrastructure(_))));
    }
}
