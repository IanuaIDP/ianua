//! The use cases for running the service the API serves: the readiness
//! check and the metrics scrape.

use std::sync::Arc;

use ianua_app::ports::runtime::{MetricsExporter, ReadinessProbe};
use ianua_app::use_cases::runtime::{
    CheckReadinessPorts, CheckReadinessUseCase, ExportMetricsPorts, ExportMetricsUseCase,
};

use crate::deps::Adapters;

/// The use cases for running the service.
#[derive(Clone)]
pub struct RuntimeState {
    pub readiness: Arc<CheckReadinessUseCase>,
    pub metrics: Arc<ExportMetricsUseCase>,
}

/// What the endpoints for running the service read: the probes the
/// readiness check asks and the metrics exporter. Every node has them,
/// whatever its mode, so a node serving no API still answers its probes
/// and its scrape.
#[derive(Clone)]
pub struct RuntimePorts {
    /// Asks the database whether it answers.
    pub database: Arc<dyn ReadinessProbe>,
    /// Asks the message bus whether it answers.
    pub message_bus: Arc<dyn ReadinessProbe>,
    /// Asks the cache whether it answers.
    pub cache: Arc<dyn ReadinessProbe>,
    /// Writes out the process's metrics.
    pub exporter: Arc<dyn MetricsExporter>,
}

/// Builds the use cases for running the service over `a`.
pub fn build(a: &Adapters) -> RuntimeState {
    of(RuntimePorts {
        database: a.database_readiness.clone(),
        message_bus: a.message_bus_readiness.clone(),
        cache: a.cache_readiness.clone(),
        exporter: a.metrics_exporter.clone(),
    })
}

/// Builds the use cases for running the service over `ports`.
pub fn of(ports: RuntimePorts) -> RuntimeState {
    RuntimeState {
        readiness: Arc::new(CheckReadinessUseCase::new(CheckReadinessPorts {
            database: ports.database,
            message_bus: ports.message_bus,
            cache: ports.cache,
        })),
        metrics: Arc::new(ExportMetricsUseCase::new(ExportMetricsPorts {
            exporter: ports.exporter,
        })),
    }
}
