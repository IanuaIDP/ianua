//! The records of stream connections: one per connection a stream route's
//! port took, whatever was decided, queued and written in batches like the
//! request records. What a record holds is the app's [`StreamRecord`].

use std::sync::Arc;
use std::time::Duration;

pub(crate) use ianua_app::ports::routing::{StreamDecision, StreamRecord, StreamRecordWriter};
use ianua_app::ports::runtime::DroppedRecords;
use ianua_boot::shutdown::Shutdown;

use crate::observability::backlog::Backlog;
use crate::observability::batching::{BatchLimits, Batched, Deliver, Queueing};

/// What this destination is called in the log and the metric.
const DESTINATION: &str = "stream records";

/// The longest one batch may take to be written.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Queues the record of each finished stream connection and writes them in
/// batches. Recording never waits; a full queue drops and counts.
pub(crate) struct StreamLog {
    queue: Batched<StreamRecord>,
}

impl StreamLog {
    /// Starts writing through `writer` until `shutdown` stops, counting
    /// what the queue drops into `dropped`.
    #[must_use]
    pub(crate) fn start(
        writer: Arc<dyn StreamRecordWriter>,
        dropped: Arc<dyn DroppedRecords>,
        shutdown: &Shutdown,
    ) -> Self {
        Self::queued(
            writer,
            Queueing::new(BatchLimits::DEFAULT, dropped),
            shutdown,
        )
    }

    /// Starts writing through `writer`, queued as `queueing` says.
    fn queued(
        writer: Arc<dyn StreamRecordWriter>,
        queueing: Queueing,
        shutdown: &Shutdown,
    ) -> Self {
        Self {
            queue: Batched::start(
                Store {
                    writer,
                    backlog: Backlog::new(DESTINATION, queueing.meter()),
                },
                queueing,
                shutdown,
            ),
        }
    }

    /// Queues `record`, or drops and counts it when the queue is full.
    pub(crate) fn record(&self, record: StreamRecord) {
        self.queue.record(record);
    }

    /// How many records were dropped because the queue was full.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dropped(&self) -> u64 {
        self.queue.dropped()
    }
}

/// The store a batch of stream records is written to.
struct Store {
    writer: Arc<dyn StreamRecordWriter>,
    backlog: Backlog<StreamRecord>,
}

impl Deliver<StreamRecord> for Store {
    async fn deliver(&self, batch: Vec<StreamRecord>) {
        let due = self.backlog.with_held(batch);
        let records = due.len();
        match tokio::time::timeout(WRITE_TIMEOUT, self.writer.write(&due)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(records, %error, "stream records not written, held");
                self.backlog.hold(due);
            }
            Err(_) => {
                tracing::warn!(records, "stream records not written in time, held");
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

    use async_trait::async_trait;
    use ianua_domain::domains::routing::stream::ListenPort;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{StreamRouteId, TenantId};
    use time::OffsetDateTime;

    use super::*;
    use crate::observability::batching::tests::unmetered;

    const WAIT: Duration = Duration::from_secs(2);

    /// Keeps every record it was asked to write.
    #[derive(Default)]
    struct Kept(Mutex<Vec<StreamRecord>>);

    #[async_trait]
    impl StreamRecordWriter for Kept {
        async fn write(&self, records: &[StreamRecord]) -> Result<(), DomainError> {
            self.0.lock().unwrap().extend_from_slice(records);
            Ok(())
        }
    }

    impl Kept {
        /// The records written once one arrived, or none when the wait ran
        /// out.
        async fn written(&self) -> Vec<StreamRecord> {
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

    fn refused() -> StreamRecord {
        StreamRecord {
            tenant_id: TenantId::new(),
            stream_route_id: StreamRouteId::new(),
            listen_port: ListenPort::new(15432).unwrap(),
            client: IpAddr::from([198, 51, 100, 4]),
            server_name: None,
            caller: None,
            decision: StreamDecision::Denied,
            reason: "not_let_in",
            backend: None,
            bytes_to_backend: 0,
            bytes_to_client: 0,
            duration_ms: 3,
            occurred_at: OffsetDateTime::now_utc(),
        }
    }

    /// Queuing a refused stream record writes one record with the denied
    /// decision preserved.
    #[tokio::test]
    async fn a_refused_connection_is_written() {
        let shutdown = Shutdown::new(WAIT);
        let kept = Arc::new(Kept::default());
        let log = StreamLog::queued(
            Arc::clone(&kept) as Arc<dyn StreamRecordWriter>,
            unmetered(BatchLimits::new(64, 64, Duration::from_millis(20))),
            &shutdown,
        );

        log.record(refused());

        let written = kept.written().await;
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].decision, StreamDecision::Denied);
        shutdown.stop();
    }

    /// A writer that never answers.
    struct Stuck;

    #[async_trait]
    impl StreamRecordWriter for Stuck {
        async fn write(&self, _: &[StreamRecord]) -> Result<(), DomainError> {
            std::future::pending().await
        }
    }

    /// With a writer that never answers and room for one queued record,
    /// recording ten refusals increments the dropped-record count.
    #[tokio::test]
    async fn a_full_queue_drops_and_counts() {
        let shutdown = Shutdown::new(WAIT);
        let log = StreamLog::queued(
            Arc::new(Stuck),
            unmetered(BatchLimits::new(1, 1, Duration::from_secs(60))),
            &shutdown,
        );

        for _ in 0..10 {
            log.record(refused());
        }

        assert!(log.dropped() > 0);
        shutdown.stop();
    }
}
