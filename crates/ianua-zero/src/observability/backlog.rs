//! Records a store could not take, held to be written once it can.
//!
//! The gateway keeps refusing and allowing while its database is out, and
//! the record of each decision matters most then: Mallory hammering an app
//! through an outage should still be on the log afterwards. So a batch that
//! could not be written waits here and goes out with the next one.
//!
//! It stays bounded, since a store that never comes back must cost a gap
//! and never the process's memory. Past [`HELD`] the oldest are given up and
//! counted, in the log and in the same metric the queue's drops go to. What
//! is held lives in memory, so a gateway that stops during an outage counts
//! what it could not write as lost.
//!
//! A write may have landed though it was reported failed: it timed out, or
//! it reached some tenants and not others. Each record has its own id and
//! the stores keep the first copy, so writing one again changes nothing.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use ianua_app::ports::runtime::DroppedRecords;

/// The most records held at once: about the depth of four full queues.
const HELD: usize = 32_768;

/// The most held records one write carries, so catching up after an outage
/// stays within what one write may take.
const RETRIED: usize = 2_048;

/// Records a destination could not write, oldest first.
pub(crate) struct Backlog<T> {
    held: Mutex<VecDeque<T>>,
    limit: usize,
    destination: &'static str,
    meter: Arc<dyn DroppedRecords>,
}

impl<T> Backlog<T> {
    /// An empty backlog for `destination`, counting what it gives up into
    /// `meter`.
    pub(crate) fn new(destination: &'static str, meter: Arc<dyn DroppedRecords>) -> Self {
        Self::holding_at_most(HELD, destination, meter)
    }

    /// An empty backlog of at most `limit` records.
    fn holding_at_most(
        limit: usize,
        destination: &'static str,
        meter: Arc<dyn DroppedRecords>,
    ) -> Self {
        Self {
            held: Mutex::new(VecDeque::new()),
            limit,
            destination,
            meter,
        }
    }

    /// Whether anything waits to be written.
    pub(crate) fn waiting(&self) -> bool {
        !self.locked().is_empty()
    }

    /// What the next write should carry: up to [`RETRIED`] of the oldest
    /// held records, taken out, then `batch`.
    pub(crate) fn with_held(&self, batch: Vec<T>) -> Vec<T> {
        let mut held = self.locked();
        let due = held.len().min(RETRIED);
        let mut records: Vec<T> = held.drain(..due).collect();
        records.extend(batch);
        records
    }

    /// Holds `unwritten`, oldest first, ahead of what still waits, giving
    /// up the oldest of all past the limit.
    pub(crate) fn hold(&self, unwritten: Vec<T>) {
        let mut held = self.locked();
        for record in unwritten.into_iter().rev() {
            held.push_front(record);
        }
        let over = held.len().saturating_sub(self.limit);
        held.drain(..over);
        drop(held);
        self.report_lost(over);
    }

    /// The held records, however a panic elsewhere left the lock.
    fn locked(&self) -> std::sync::MutexGuard<'_, VecDeque<T>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Logs and counts `lost` records given up, if any.
    fn report_lost(&self, lost: usize) {
        if lost == 0 {
            return;
        }
        let destination = self.destination;
        tracing::warn!(destination, lost, "records held for a store were given up");
        self.meter.add(destination, lost as u64);
    }
}

impl<T> Drop for Backlog<T> {
    /// Counts what could not be written before the gateway stopped.
    fn drop(&mut self) {
        let lost = self.locked().len();
        self.report_lost(lost);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps the total reported given up.
    #[derive(Default)]
    struct Meter(Mutex<u64>);

    impl DroppedRecords for Meter {
        fn add(&self, _destination: &'static str, count: u64) {
            *self.0.lock().unwrap() += count;
        }
    }

    fn backlog(limit: usize) -> (Backlog<u32>, Arc<Meter>) {
        let meter = Arc::new(Meter::default());
        let held = Backlog::holding_at_most(limit, "records", meter.clone());
        (held, meter)
    }

    /// The database is out when two batches arrive. Once it is back they
    /// go out oldest first, ahead of what arrived since.
    #[test]
    fn what_could_not_be_written_goes_out_first_and_in_order() {
        let (held, _) = backlog(10);

        held.hold(vec![1, 2]);
        let second = held.with_held(vec![3]);
        held.hold(second);
        let next = held.with_held(vec![4]);

        assert_eq!(next, [1, 2, 3, 4]);
        assert!(!held.waiting());
    }

    /// An outage outlasts the room. The oldest are given up and counted,
    /// and the newest wait.
    #[test]
    fn past_the_limit_the_oldest_are_given_up_and_counted() {
        let (held, meter) = backlog(2);

        held.hold(vec![1, 2, 3, 4]);

        assert_eq!(held.with_held(Vec::new()), [3, 4]);
        assert_eq!(*meter.0.lock().unwrap(), 2);
    }

    /// One write after a long outage carries only so many held records;
    /// the rest wait for the next.
    #[test]
    fn catching_up_goes_a_write_at_a_time() {
        let (held, _) = backlog(HELD);
        held.hold((0..3_000).collect());

        let first = held.with_held(vec![9_999]);

        assert_eq!(first.len(), RETRIED + 1);
        assert_eq!(first.last(), Some(&9_999));
        assert!(held.waiting());
    }

    /// The gateway stops with records still held. They are counted as
    /// lost, and nothing is counted for an empty backlog.
    #[test]
    fn stopping_counts_what_was_never_written() {
        let (held, meter) = backlog(10);
        held.hold(vec![1, 2, 3]);
        let (empty, untouched) = backlog(10);

        drop(held);
        drop(empty);

        assert_eq!(*meter.0.lock().unwrap(), 3);
        assert_eq!(*untouched.0.lock().unwrap(), 0);
    }
}
