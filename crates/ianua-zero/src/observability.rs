//! Where the gateway reports the requests it served.
//!
//! A request is collected while in flight by a [`RequestAudit`] and
//! reported once when it ends, or as undecided when it is dropped without
//! a decision. The report goes to every destination through the app's
//! [`RequestObservers`]: the structured log, the request metrics, the
//! request records a tenant's admins search, the live dashboard, and,
//! where set up, the tenants' log stores and a trace collector. A stream
//! route's connection carries no request, so it is reported in a record of
//! its own shape through [`StreamLog`].
//!
//! Every destination that pushes somewhere sits behind a bounded queue
//! drained in batches by a task of its own: recording never waits, a full
//! queue drops and counts, every delivery has a timeout, and what is queued
//! at the stop is delivered before the drain ends. No task is spawned per
//! request.
//!
//! What is reported is the subject, the resource, the action, the decision,
//! the check and rule that made it, and the correlation id. Never a token,
//! a cookie, a header, a body or a query string: the observation has no
//! place for one.

mod access_log;
mod audit;
mod backlog;
mod batching;
mod dashboard;
mod logging;
mod shipping;
mod sink;
mod streams;
mod traces;

use std::sync::Arc;

use ianua_app::ports::proxy::ProxyAccessLogSink;
use ianua_app::ports::realtime::NotificationPublisher;
use ianua_app::ports::runtime::{DroppedRecords, RequestObserver, RequestObservers};
use ianua_app::use_cases::proxy::log_shipping::ShipRequestRecordsUseCase;
use ianua_boot::shutdown::Shutdown;
use ianua_infra::runtime::LocalRequestObserver;

use self::access_log::AccessLog;
pub(crate) use self::audit::{Arrival, Refusal, RequestAudit, TunnelCloseRecord};
pub(crate) use self::batching::BatchLimits;
use self::dashboard::DashboardFeed;
use self::logging::StructuredLog;
use self::shipping::ShippedLog;
pub(crate) use self::sink::{LogSink, SinkLog};
pub(crate) use self::streams::{StreamDecision, StreamLog, StreamRecord};
pub(crate) use self::traces::{TraceCollector, TraceExport};

/// What the gateway reports its requests through.
pub(crate) struct Reporting {
    /// Writes the request records, in batches.
    pub records: Arc<dyn ProxyAccessLogSink>,
    /// How many request records wait to be written, how many go at once,
    /// and how long one waits at most.
    pub record_batching: BatchLimits,
    /// Counts each request into the process's metrics registry.
    pub metrics: Arc<LocalRequestObserver>,
    /// Counts what the queues in front of every destination drop, into
    /// the same registry.
    pub dropped: Arc<dyn DroppedRecords>,
    /// Publishes to the live dashboard.
    pub dashboard: Arc<dyn NotificationPublisher>,
    /// Ships to the tenants' log stores, when the deployment does.
    pub shipping: Option<Arc<ShipRequestRecordsUseCase>>,
    /// The trace collector and the service spans are reported as, when
    /// there is one.
    pub traces: Option<TraceCollector>,
    /// The deployment's own log collector, when `LOG_SINK_URL` names one.
    pub sink: Option<LogSink>,
}

impl Reporting {
    /// Every destination, started, behind the one observer a request
    /// reports to. The queues drain until `shutdown` stops.
    #[must_use]
    pub(crate) fn observers(self, shutdown: &Shutdown) -> RequestObservers {
        let dropped = self.dropped;
        let shipping = self.shipping.map(|ship| -> Arc<dyn RequestObserver> {
            Arc::new(ShippedLog::start(ship, Arc::clone(&dropped), shutdown))
        });
        let traces = self.traces.map(|collector| -> Arc<dyn RequestObserver> {
            Arc::new(TraceExport::start(
                collector,
                Arc::clone(&dropped),
                shutdown,
            ))
        });
        let records = AccessLog::start(
            self.records,
            self.record_batching,
            Arc::clone(&dropped),
            shutdown,
        );
        let sink = self.sink.map(|sink| -> Arc<dyn RequestObserver> {
            Arc::new(SinkLog::start(sink, Arc::clone(&dropped), shutdown))
        });
        let dashboard = DashboardFeed::start(self.dashboard, dropped, shutdown);
        RequestObservers::none()
            .and(Arc::new(StructuredLog))
            .and(self.metrics)
            .and(Arc::new(records))
            .and(Arc::new(dashboard))
            .and_maybe(shipping)
            .and_maybe(traces)
            .and_maybe(sink)
    }
}
