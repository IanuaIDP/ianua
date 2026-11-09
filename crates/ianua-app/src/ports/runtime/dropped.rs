//! What a process's bounded queues dropped, counted for the metrics scrape.
//!
//! A queue in front of a slow destination (request records, the live
//! dashboard, a log store, a trace collector) drops rather than grows. A
//! drop is a gap an operator must be able to see and alert on, not only a
//! log line, so each queue reports what it dropped here.

/// Dyn-safe port counting records a bounded queue dropped.
///
/// Synchronous and infallible: it adds to the process's own registry, held
/// in memory, and a queue that is already dropping must not wait on it.
pub trait DroppedRecords: Send + Sync {
    /// Adds `count` records dropped by the queue in front of `destination`.
    ///
    /// `destination` is the queue's fixed name, never anything a request
    /// chose, so it may be a metric label.
    fn add(&self, destination: &'static str, count: u64);
}
