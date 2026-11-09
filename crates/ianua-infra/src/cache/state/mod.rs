//! The few things every cache-shaped port asks of shared state, behind one
//! trait, so the ports are written once and the state can live in this
//! process or on a cache server every node shares.
//!
//! Every key carries its use and, for tenant data, its tenant, so two uses
//! or two tenants never share a key. On a cache server every key also sits
//! under the deployment's namespace, so two deployments never share one. Every entry expires: nothing kept here
//! is a record, and nothing lasts past the window it was counted for.
//!
//! The state lives in [`MemoryState`], in this process, or in
//! [`ServerState`], on a cache server every node reaches.

mod memory;
mod server;

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
pub use memory::MemoryState;
pub use server::ServerState;

/// Why shared state could not answer. None of it names a key's contents.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// The cache server could not be reached or refused the command.
    #[error("the cache could not be reached")]
    Unreachable(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The cache did not answer in time.
    #[error("the cache did not answer in time")]
    TimedOut,
    /// The cache answered something no command of this crate writes.
    #[error("the cache answered something unexpected")]
    Unexpected,
    /// The cache holds as many live entries as it was given room for, so
    /// a new one is refused rather than one still counting dropped.
    #[error("the cache is full")]
    Full,
}

impl From<CacheError> for DomainError {
    fn from(error: CacheError) -> Self {
        DomainError::infra(error)
    }
}

/// A key of shared state: the use and the parts that tell its entries
/// apart, joined by `:`. A cache server puts it under the deployment's
/// namespace, as `ianua:<key>` by default.
pub(crate) fn key(parts: &[&str]) -> String {
    parts.join(":")
}

/// `at` in microseconds since the epoch, as a log keeps times.
pub(crate) fn micros(at: time::OffsetDateTime) -> i64 {
    i64::try_from(
        at.unix_timestamp_nanos()
            .checked_div(1_000)
            .unwrap_or_default(),
    )
    .unwrap_or(i64::MAX)
}

/// Shared state, as the cache-shaped ports use it.
#[async_trait]
pub trait SharedState: Send + Sync {
    /// Adds `delta` to the counter `key` and answers the count. The counter
    /// starts at the first addition and lapses `window` later; the count
    /// and the lapse are set in one step.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn count(&self, key: &str, delta: u64, window: Duration) -> Result<u64, CacheError>;

    /// The counter `key`, or `None` when nothing counted it or it lapsed.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn read(&self, key: &str) -> Result<Option<u64>, CacheError>;

    /// Takes `by` off the counter `key` while it counts, never below zero,
    /// and answers what is left. A counter that lapsed is not started
    /// again: `None`, and nothing is kept.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn lower(&self, key: &str, by: u64) -> Result<Option<u64>, CacheError>;

    /// Sets the counter `key` to one and lapses it `ttl` from now, whether
    /// it was counting or not, so each hold restarts the wait.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn hold(&self, key: &str, ttl: Duration) -> Result<(), CacheError>;

    /// Adds `members` to the set `key` and answers how many distinct ones
    /// it holds. The set starts at the first addition and lapses `window`
    /// later.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn add_distinct(
        &self,
        key: &str,
        members: &[String],
        window: Duration,
    ) -> Result<u64, CacheError>;

    /// How many distinct members the set `key` holds, or none when nothing
    /// was added to it or it lapsed. It adds nothing and starts no window.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn distinct(&self, key: &str) -> Result<u64, CacheError>;

    /// Claims `key` for `ttl`: `true` for the one caller that claimed it,
    /// `false` for every other while the claim lasts.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn claim_once(&self, key: &str, ttl: Duration) -> Result<bool, CacheError>;

    /// Keeps `value` at `key` for `ttl` and answers what was kept there
    /// before, in one step.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn swap(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> Result<Option<String>, CacheError>;

    /// Keeps `value` at `key` for `ttl`, replacing what was there, without
    /// reading it back: for values too large to send twice.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn keep(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError>;

    /// The text kept at `key` by [`swap`](Self::swap) or
    /// [`keep`](Self::keep), or `None` when nothing is kept there or it
    /// lapsed.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn text(&self, key: &str) -> Result<Option<String>, CacheError>;

    /// Drops whatever is kept at `key`, so the next count there starts
    /// again. Nothing kept there is no error.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn forget(&self, key: &str) -> Result<(), CacheError>;

    /// Adds `entry` at `at` to the log `key`, drops its entries from before
    /// `forget_before`, and keeps the log `keep` past its newest entry.
    /// Times are microseconds since the epoch.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn log(&self, key: &str, entry: &LogEntry<'_>, keep: Duration) -> Result<(), CacheError>;

    /// The entries of the log `key` at or after `since`, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn log_since(&self, key: &str, since: i64) -> Result<Vec<String>, CacheError>;

    /// Drops the entries of the log `key` from before `forget_before`, then
    /// adds `entry` when the log already holds its text, which moves it to
    /// `at`, or holds fewer than `capacity.entries` entries; keeps the log
    /// for `capacity.keep` past
    /// this call. Answers whether `entry` is in the log, in one step, so two
    /// nodes never both take the last place.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn enroll(
        &self,
        key: &str,
        entry: &LogEntry<'_>,
        capacity: LogCapacity,
    ) -> Result<bool, CacheError>;

    /// Whether the state answers now, for the readiness check.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the state cannot answer.
    async fn ping(&self) -> Result<(), CacheError>;
}

/// One entry added to a log: what it says, when, and from when the log
/// forgets.
#[derive(Debug, Clone, Copy)]
pub struct LogEntry<'a> {
    /// What the entry says. Two entries at one moment must differ.
    pub text: &'a str,
    /// When it happened, in microseconds since the epoch.
    pub at: i64,
    /// The moment before which the log's entries are dropped.
    pub forget_before: i64,
}

/// The entry bound and lifetime of a roster on shared state.
#[derive(Debug, Clone, Copy)]
pub struct LogCapacity {
    /// The most distinct entries the roster may hold at once.
    pub entries: u64,
    /// How long the roster remains after an accepted entry.
    pub keep: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key joins its parts, and the default namespace puts it where the
    /// platform has always kept it.
    #[test]
    fn a_key_joins_its_parts_under_the_namespace() {
        let joined = key(&["rate", "tenant", "t1"]);

        assert_eq!(joined, "rate:tenant:t1");
        assert_eq!(
            crate::namespace::Namespace::default().key(&joined),
            "ianua:rate:tenant:t1"
        );
    }
}
