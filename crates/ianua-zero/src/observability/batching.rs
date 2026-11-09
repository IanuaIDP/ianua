//! Handing work off the request path, bounded and batched.
//!
//! Every destination that pushes somewhere (the request records, the live
//! dashboard, a log store, a trace collector) has the same three problems,
//! none of them its own. It must not slow a request down. It must not grow
//! without limit when the far end stops taking what it is sent. And it must
//! not lose what is queued when the gateway stops.
//!
//! So the queue lives here once. A destination is only what is its own: how
//! a batch is delivered. Recording is a `try_send` and nothing else; a full
//! queue drops the record and counts it, and the drain reports the count
//! once per flush rather than once per drop.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ianua_app::ports::runtime::DroppedRecords;
use ianua_boot::shutdown::Shutdown;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::time::{Interval, MissedTickBehavior, interval};
use tokio_util::sync::WaitForCancellationFutureOwned;

/// How much a queue holds and how it is drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchLimits {
    queued: usize,
    batch: usize,
    flush_every: Duration,
}

impl BatchLimits {
    /// The limits every destination of the gateway uses: deep enough to
    /// ride out a slow delivery at a few thousand requests a second,
    /// bounded so a destination that stopped taking anything costs a gap,
    /// never the process's memory.
    pub(crate) const DEFAULT: Self = Self::new(8_192, 256, Duration::from_secs(2));

    /// At most `queued` records waiting, delivered `batch` at a time or
    /// every `flush_every`, whichever comes first. Neither count is less
    /// than one.
    #[must_use]
    pub(crate) const fn new(queued: usize, batch: usize, flush_every: Duration) -> Self {
        Self {
            queued: at_least_one(queued),
            batch: at_least_one(batch),
            flush_every,
        }
    }
}

/// `count`, or one when it is zero: a queue or a batch of nothing would
/// never deliver.
const fn at_least_one(count: usize) -> usize {
    match count {
        0 => 1,
        _ => count,
    }
}

/// How a queue is held: its limits, and the process metric its drops are
/// counted into.
#[derive(Clone)]
pub(crate) struct Queueing {
    limits: BatchLimits,
    meter: Arc<dyn DroppedRecords>,
}

impl Queueing {
    /// A queue under `limits`, its drops counted into `meter`.
    pub(crate) fn new(limits: BatchLimits, meter: Arc<dyn DroppedRecords>) -> Self {
        Self { limits, meter }
    }

    /// The metric its drops are counted into.
    pub(crate) fn meter(&self) -> Arc<dyn DroppedRecords> {
        Arc::clone(&self.meter)
    }
}

/// Somewhere batches are sent.
///
/// Infallible from the drain's side: a destination bounds its own wait and
/// reports its own failure. It drops a batch it could not send, or holds
/// it in a [`Backlog`](crate::observability::backlog::Backlog) of its own
/// when the records are what a tenant's admin searches. Handing the batch
/// back to the drain is the unbounded queue this module exists to prevent.
pub(crate) trait Deliver<T>: Send + Sync + 'static {
    /// Sends one batch, giving up after the destination's own timeout.
    fn deliver(&self, batch: Vec<T>) -> impl Future<Output = ()> + Send;

    /// Whether it holds records of its own to write, so a flush with no
    /// new ones still calls it.
    fn waiting(&self) -> bool {
        false
    }

    /// What the destination is called, for the line reporting drops.
    fn name(&self) -> &'static str;
}

/// A bounded queue in front of a destination, drained in batches by one
/// task of its own.
pub(crate) struct Batched<T> {
    queue: Sender<T>,
    dropped: Arc<AtomicU64>,
}

impl<T: Send + 'static> Batched<T> {
    /// Starts draining into `destination` under `queueing` until
    /// `shutdown` stops, delivering what is still queued at the stop.
    pub(crate) fn start(
        destination: impl Deliver<T>,
        queueing: Queueing,
        shutdown: &Shutdown,
    ) -> Self {
        let Queueing { limits, meter } = queueing;
        let (queue, records) = channel(limits.queued);
        let dropped = Arc::new(AtomicU64::new(0));
        let drain = Drain {
            limits,
            dropped: Arc::clone(&dropped),
            reported: 0,
            meter,
        };
        shutdown.spawn(
            destination.name(),
            drain.run(destination, records, shutdown.stopping()),
        );
        Self { queue, dropped }
    }

    /// Queues `record`, or drops and counts it when the queue is full or
    /// the drain has stopped. Never waits.
    pub(crate) fn record(&self, record: T) {
        if self.queue.try_send(record).is_ok() {
            return;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// How many records were dropped since the queue started.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// What woke the drain.
enum Wake {
    /// The stop was asked for.
    Stopped,
    /// The flush timer ran out.
    Flush,
    /// Records arrived.
    Received,
    /// Every queue handle is gone and nothing is left.
    Closed,
}

/// The drain's own state: its limits, the drops it already reported, and
/// the metric it reports them into.
struct Drain {
    limits: BatchLimits,
    dropped: Arc<AtomicU64>,
    reported: u64,
    meter: Arc<dyn DroppedRecords>,
}

impl Drain {
    /// Delivers batches until the stop or until the queue closes, then
    /// what is left, then waits for the stop: the task is one the process
    /// runs until it stops.
    async fn run<T: Send + 'static>(
        mut self,
        destination: impl Deliver<T>,
        mut records: Receiver<T>,
        stopping: WaitForCancellationFutureOwned,
    ) {
        let mut stopping = pin!(stopping);
        let mut flush = timer(self.limits.flush_every);
        let mut batch = Vec::with_capacity(self.limits.batch);
        loop {
            let room = self.limits.batch - batch.len();
            let wake = tokio::select! {
                () = &mut stopping => Wake::Stopped,
                _ = flush.tick() => Wake::Flush,
                received = records.recv_many(&mut batch, room) => match received {
                    0 => Wake::Closed,
                    _ => Wake::Received,
                },
            };
            match wake {
                Wake::Stopped | Wake::Closed => break,
                Wake::Flush => {
                    send_batch(&destination, &mut batch).await;
                    self.report_drops(destination.name());
                }
                Wake::Received if batch.len() >= self.limits.batch => {
                    send_batch(&destination, &mut batch).await;
                }
                Wake::Received => {}
            }
        }
        self.finish(&destination, records, batch).await;
        stopping.await;
    }

    /// Delivers everything still queued, in batches, and reports the drops.
    ///
    /// Closing first is what makes this end: `recv_many` waits while any
    /// sender lives, and the observers holding one outlive the drain.
    async fn finish<T: Send + 'static>(
        &mut self,
        destination: &impl Deliver<T>,
        mut records: Receiver<T>,
        mut batch: Vec<T>,
    ) {
        records.close();
        while records.recv_many(&mut batch, self.limits.batch).await > 0 {
            send_batch(destination, &mut batch).await;
        }
        send_batch(destination, &mut batch).await;
        self.report_drops(destination.name());
    }

    /// Logs and counts into the metric how many records were dropped since
    /// the last report, if any.
    fn report_drops(&mut self, destination: &'static str) {
        let total = self.dropped.load(Ordering::Relaxed);
        if total <= self.reported {
            return;
        }
        let dropped = total - self.reported;
        tracing::warn!(
            destination,
            dropped,
            "a destination is not keeping up; records were dropped"
        );
        self.meter.add(destination, dropped);
        self.reported = total;
    }
}

/// The flush timer: it waits a whole period after a slow delivery rather
/// than firing a burst of catch-up ticks. A period of zero, which the timer
/// refuses, is taken as a millisecond.
fn timer(every: Duration) -> Interval {
    let mut timer = interval(every.max(Duration::from_millis(1)));
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
    timer
}

/// Delivers `batch`, when it or the destination holds anything, leaving
/// it empty.
async fn send_batch<T: Send + 'static>(destination: &impl Deliver<T>, batch: &mut Vec<T>) {
    if batch.is_empty() && !destination.waiting() {
        return;
    }
    destination.deliver(std::mem::take(batch)).await;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use tokio::sync::Notify;

    use super::*;

    const WAIT: Duration = Duration::from_secs(2);

    /// Keeps what each destination reported dropped.
    #[derive(Default)]
    pub(crate) struct Meter(Mutex<Vec<(&'static str, u64)>>);

    impl DroppedRecords for Meter {
        fn add(&self, destination: &'static str, count: u64) {
            self.0.lock().unwrap().push((destination, count));
        }
    }

    impl Meter {
        /// How many records `destination` reported dropped in all.
        pub(crate) fn total(&self, destination: &str) -> u64 {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| *name == destination)
                .map(|(_, count)| count)
                .sum()
        }
    }

    /// A queue under `limits` whose drops go to a meter nobody reads.
    pub(crate) fn unmetered(limits: BatchLimits) -> Queueing {
        Queueing::new(limits, Arc::new(Meter::default()))
    }

    /// A destination keeping what it was given, or one stuck until told.
    struct Collecting {
        delivered: Arc<Mutex<Vec<Vec<u32>>>>,
        stuck: Option<Arc<Notify>>,
    }

    impl Deliver<u32> for Collecting {
        async fn deliver(&self, batch: Vec<u32>) {
            if let Some(stuck) = &self.stuck {
                stuck.notified().await;
            }
            self.delivered.lock().unwrap().push(batch);
        }

        fn name(&self) -> &'static str {
            "collecting"
        }
    }

    fn collecting() -> (Arc<Mutex<Vec<Vec<u32>>>>, Collecting) {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let destination = Collecting {
            delivered: Arc::clone(&delivered),
            stuck: None,
        };
        (delivered, destination)
    }

    fn shutdown() -> Shutdown {
        Shutdown::new(WAIT)
    }

    /// Every record delivered so far, once `count` arrived or the wait ran
    /// out.
    async fn delivered_after(delivered: &Arc<Mutex<Vec<Vec<u32>>>>, count: usize) -> Vec<u32> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let seen: Vec<u32> = delivered
                .lock()
                .unwrap()
                .iter()
                .flatten()
                .copied()
                .collect();
            if seen.len() >= count || tokio::time::Instant::now() >= deadline {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Queuing ten records with room for four and a blocked destination
    /// counts the six records that do not fit as dropped.
    #[tokio::test]
    async fn a_full_queue_drops_and_counts_what_does_not_fit() {
        let shutdown = shutdown();
        let destination = Collecting {
            delivered: Arc::new(Mutex::new(Vec::new())),
            stuck: Some(Arc::new(Notify::new())),
        };
        let batched = Batched::start(
            destination,
            unmetered(BatchLimits::new(4, 2, Duration::from_secs(3_600))),
            &shutdown,
        );

        for record in 0..10 {
            batched.record(record);
        }

        assert_eq!(batched.dropped(), 6);
        shutdown.stop();
    }

    /// Eight records dropped from a two-slot queue reach the destination's
    /// metric when shutdown drains and joins successfully.
    #[tokio::test]
    async fn dropped_records_are_counted_into_the_metric() {
        let shutdown = shutdown();
        let (_delivered, destination) = collecting();
        let meter = Arc::new(Meter::default());
        let batched = Batched::start(
            destination,
            Queueing::new(
                BatchLimits::new(2, 1, Duration::from_secs(3_600)),
                Arc::clone(&meter) as Arc<dyn DroppedRecords>,
            ),
            &shutdown,
        );

        for record in 0..10 {
            batched.record(record);
        }
        shutdown.stop();
        assert!(shutdown.join().await.is_ok());

        assert_eq!(meter.total("collecting"), 8);
    }

    /// A quiet gateway's last request does not sit in memory until the next
    /// burst: one record, far below a batch, goes when the timer runs out.
    #[tokio::test]
    async fn a_partial_batch_is_flushed_by_time() {
        let shutdown = shutdown();
        let (delivered, destination) = collecting();
        let batched = Batched::start(
            destination,
            unmetered(BatchLimits::new(64, 100, Duration::from_millis(50))),
            &shutdown,
        );

        batched.record(7);

        assert_eq!(delivered_after(&delivered, 1).await, vec![7]);
        shutdown.stop();
    }

    /// A busy gateway does not hold a full batch for the timer: three
    /// records of a batch of three go at once.
    #[tokio::test]
    async fn a_full_batch_is_flushed_without_the_timer() {
        let shutdown = shutdown();
        let (delivered, destination) = collecting();
        let batched = Batched::start(
            destination,
            unmetered(BatchLimits::new(64, 3, Duration::from_secs(3_600))),
            &shutdown,
        );

        for record in 1..=3 {
            batched.record(record);
        }

        assert_eq!(delivered_after(&delivered, 3).await, vec![1, 2, 3]);
        assert_eq!(delivered.lock().unwrap().len(), 1, "one batch, not three");
        shutdown.stop();
    }

    /// Stopping with one record queued delivers that record and lets the
    /// drain join successfully.
    #[tokio::test]
    async fn what_is_queued_at_the_stop_is_delivered() {
        let shutdown = shutdown();
        let (delivered, destination) = collecting();
        let batched = Batched::start(
            destination,
            unmetered(BatchLimits::new(64, 100, Duration::from_secs(3_600))),
            &shutdown,
        );
        batched.record(9);

        shutdown.stop();
        let joined = shutdown.join().await;

        assert!(joined.is_ok());
        assert_eq!(delivered_after(&delivered, 1).await, vec![9]);
    }

    /// After the stop the drain is gone; a record that comes later is
    /// dropped and counted, never waited on.
    #[tokio::test]
    async fn a_record_after_the_stop_is_dropped_and_counted() {
        let shutdown = shutdown();
        let (_delivered, destination) = collecting();
        let batched = Batched::start(
            destination,
            unmetered(BatchLimits::new(64, 100, Duration::from_secs(3_600))),
            &shutdown,
        );
        shutdown.stop();
        assert!(shutdown.join().await.is_ok());

        batched.record(1);

        assert_eq!(batched.dropped(), 1);
    }
}
