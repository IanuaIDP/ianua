//! The request records a tenant's admins search: one per finished request
//! that resolved a tenant, written in batches.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::proxy::{ProxyAccessLogSink, ProxyRequestRecord};
use ianua_app::ports::runtime::{DroppedRecords, RequestObserver};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::proxy::observation::{RequestObservation, TunnelClose};

use crate::observability::backlog::Backlog;
use crate::observability::batching::{BatchLimits, Batched, Deliver, Queueing};

/// The longest one batch may take to be written.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// What this destination is called in the log and the metric.
const DESTINATION: &str = "request records";

/// Queues the record of each finished request and writes them in batches.
///
/// Every request that resolved a tenant gets a record, whatever was
/// decided, an undecided one included: a tenant's admin searching refusals
/// finds it there. A request that resolved no tenant has no tenant's log
/// to belong to; the structured log and the metrics still hear of it.
pub(crate) struct AccessLog {
    queue: Batched<ProxyRequestRecord>,
}

impl AccessLog {
    /// Starts writing through `sink`'s batch write until `shutdown` stops,
    /// queued and batched as `limits` says, counting what the queue drops
    /// into `dropped`.
    #[must_use]
    pub(crate) fn start(
        sink: Arc<dyn ProxyAccessLogSink>,
        limits: BatchLimits,
        dropped: Arc<dyn DroppedRecords>,
        shutdown: &Shutdown,
    ) -> Self {
        Self::queued(sink, Queueing::new(limits, dropped), shutdown)
    }

    /// Starts writing through `sink`, queued as `queueing` says.
    fn queued(sink: Arc<dyn ProxyAccessLogSink>, queueing: Queueing, shutdown: &Shutdown) -> Self {
        Self {
            queue: Batched::start(
                Store {
                    sink,
                    backlog: Backlog::new(DESTINATION, queueing.meter()),
                },
                queueing,
                shutdown,
            ),
        }
    }

    /// How many records were dropped because the queue was full.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dropped(&self) -> u64 {
        self.queue.dropped()
    }
}

impl RequestObserver for AccessLog {
    fn observe(&self, observation: &RequestObservation) {
        let Some(record) = ProxyRequestRecord::of(observation) else {
            return;
        };
        self.queue.record(record);
    }

    /// Queues the request's record again with `closed` on it. The sink
    /// keeps the first copy's facts and adds the close, whichever of the
    /// two reaches it first.
    fn observe_tunnel_close(&self, observation: &RequestObservation, closed: TunnelClose) {
        let Some(mut record) = ProxyRequestRecord::of(observation) else {
            return;
        };
        record.closed = Some(closed);
        self.queue.record(record);
    }
}

/// The store a batch of records is written to.
struct Store {
    sink: Arc<dyn ProxyAccessLogSink>,
    backlog: Backlog<ProxyRequestRecord>,
}

impl Deliver<ProxyRequestRecord> for Store {
    async fn deliver(&self, batch: Vec<ProxyRequestRecord>) {
        let due = self.backlog.with_held(batch);
        let records = due.len();
        match tokio::time::timeout(WRITE_TIMEOUT, self.sink.write_batch(&due)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(records, %error, "request records not written, held");
                self.backlog.hold(due);
            }
            Err(_) => {
                tracing::warn!(records, "request records not written in time, held");
                self.backlog.hold(due);
            }
        }
    }

    fn waiting(&self) -> bool {
        self.backlog.waiting()
    }

    fn name(&self) -> &'static str {
        DESTINATION
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use ianua_domain::domains::proxy::observation::{RequestOutcome, TunnelCloseReason};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{CorrelationId, TenantId};

    use super::*;
    use crate::observability::audit::{Arrival, RequestAudit};
    use crate::observability::batching::tests::unmetered;

    const WAIT: Duration = Duration::from_secs(2);

    /// Keeps every record it was asked to write.
    #[derive(Default)]
    struct Kept(Mutex<Vec<ProxyRequestRecord>>);

    #[async_trait]
    impl ProxyAccessLogSink for Kept {
        async fn write_batch(&self, records: &[ProxyRequestRecord]) -> Result<(), DomainError> {
            self.0.lock().unwrap().extend_from_slice(records);
            Ok(())
        }
    }

    impl Kept {
        /// The records written once one arrived, or none when the wait ran
        /// out.
        async fn written(&self) -> Vec<ProxyRequestRecord> {
            let deadline = tokio::time::Instant::now() + WAIT;
            loop {
                let written = self.0.lock().unwrap().clone();
                if !written.is_empty() || tokio::time::Instant::now() >= deadline {
                    return written;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    fn access_log(kept: &Arc<Kept>, shutdown: &Shutdown) -> Arc<AccessLog> {
        Arc::new(AccessLog::queued(
            Arc::clone(kept) as Arc<dyn ProxyAccessLogSink>,
            unmetered(BatchLimits::new(64, 64, Duration::from_millis(20))),
            shutdown,
        ))
    }

    fn arriving(target: &str) -> Arrival<'_> {
        Arrival {
            correlation_id: CorrelationId::new(),
            client: IpAddr::from([198, 51, 100, 4]),
            method: "POST",
            target,
        }
    }

    /// Dropping an audit after resolving its tenant writes one access
    /// record with an undecided outcome.
    #[tokio::test]
    async fn a_request_nothing_decided_is_still_written() {
        let shutdown = Shutdown::new(WAIT);
        let kept = Arc::new(Kept::default());
        let mut audit = RequestAudit::start(arriving("/orders"), access_log(&kept, &shutdown));
        audit.record_tenant(TenantId::new());

        drop(audit);

        let written = kept.written().await;
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].outcome, RequestOutcome::Undecided);
        shutdown.stop();
    }

    /// An allowed reset request writes one access record whose debug output
    /// excludes the token and session values from the query.
    #[tokio::test]
    async fn no_token_reaches_a_written_record() {
        let shutdown = Shutdown::new(WAIT);
        let kept = Arc::new(Kept::default());
        let mut audit = RequestAudit::start(
            arriving("/reset?token=tok_9f8e7d&session=sess_42"),
            access_log(&kept, &shutdown),
        );
        audit.record_tenant(TenantId::new());

        audit.report_allowed(200);

        let written = kept.written().await;
        assert_eq!(written.len(), 1);
        let printed = format!("{written:?}");
        assert!(!printed.contains("tok_9f8e7d"), "{printed}");
        assert!(!printed.contains("sess_42"), "{printed}");
        shutdown.stop();
    }

    /// Tess suspends Pat and the gateway closes her WebSocket: the record
    /// of the handshake is written again with the close on it.
    #[tokio::test]
    async fn a_closed_tunnel_writes_its_close_on_the_record() {
        let shutdown = Shutdown::new(WAIT);
        let kept = Arc::new(Kept::default());
        let mut audit = RequestAudit::start(arriving("/live/feed"), access_log(&kept, &shutdown));
        audit.record_tenant(TenantId::new());
        let closing = audit.tunnel_close_record();

        closing.report(TunnelCloseReason::AccessEnded);

        let written = kept.written().await;
        assert_eq!(written.len(), 1);
        assert_eq!(
            written[0].closed.map(|close| close.reason),
            Some(TunnelCloseReason::AccessEnded)
        );
        assert_eq!(written[0].status(), 101);
        drop(audit);
        shutdown.stop();
    }

    /// Refuses the first write, as a database in an outage does, then
    /// keeps what it is asked to write.
    #[derive(Default)]
    struct OutThenBack {
        refused_once: AtomicBool,
        kept: Kept,
    }

    #[async_trait]
    impl ProxyAccessLogSink for OutThenBack {
        async fn write_batch(&self, records: &[ProxyRequestRecord]) -> Result<(), DomainError> {
            if !self.refused_once.swap(true, Ordering::SeqCst) {
                return Err(DomainError::infra_msg("the database is out"));
            }
            self.kept.write_batch(records).await
        }
    }

    /// The database is out when Pat's request is refused. Once it is back,
    /// with no further request arriving, her record is written.
    #[tokio::test]
    async fn a_record_that_could_not_be_written_is_written_once_the_store_is_back() {
        let shutdown = Shutdown::new(WAIT);
        let store = Arc::new(OutThenBack::default());
        let log = Arc::new(AccessLog::queued(
            Arc::clone(&store) as Arc<dyn ProxyAccessLogSink>,
            unmetered(BatchLimits::new(64, 64, Duration::from_millis(20))),
            &shutdown,
        ));
        let mut audit = RequestAudit::start(
            arriving("/orders"),
            Arc::clone(&log) as Arc<dyn RequestObserver>,
        );
        audit.record_tenant(TenantId::new());

        audit.report_allowed(200);

        assert_eq!(store.kept.written().await.len(), 1);
        shutdown.stop();
    }

    /// A request that resolved no tenant has no tenant's log to go into.
    #[tokio::test]
    async fn a_request_of_no_tenant_is_not_written() {
        let shutdown = Shutdown::new(WAIT);
        let kept = Arc::new(Kept::default());
        let log = access_log(&kept, &shutdown);

        RequestAudit::start(arriving("/"), Arc::clone(&log) as Arc<dyn RequestObserver>)
            .report_allowed(200);
        shutdown.stop();
        assert!(shutdown.join().await.is_ok());

        assert!(kept.0.lock().unwrap().is_empty());
        assert_eq!(log.dropped(), 0);
    }
}
