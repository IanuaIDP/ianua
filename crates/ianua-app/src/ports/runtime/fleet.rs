//! Counters every proxy instance shares.
//!
//! The data plane scales by running more copies of itself, and a count kept in
//! one copy's memory is really a count *per copy*: run four and a limit of a
//! hundred lets four hundred through, while a single-use token spent on one
//! instance is still unspent on the other three.
//!
//! This is the counter that makes those mean one thing across the fleet.
//!
//! Every method answers `None` when the shared store cannot, unreachable,
//! slow, or not configured. The gateway then refuses the request with a
//! `503`: a limit it cannot count is not a limit, and counting on one
//! instance alone would let a fleet of four admit four times the limit.
//! [`FleetCounters::claim_once`] answers `None` for the same reason: "I
//! could not check" and "nobody has claimed this" are not the same thing for
//! a replay check.

use async_trait::async_trait;
use ianua_domain::types::Seconds;

/// A counter and a single-use ledger, shared by every proxy instance.
///
/// Deliberately small and untyped in its keys. What a key *means*, a
/// delegation, a client address, a proof id, belongs to the stage that owns
/// the rule, and a port that knew about all of them would grow a method per
/// stage.
#[async_trait]
pub trait FleetCounters: Send + Sync {
    /// Records one event against `key` and returns the running count for the
    /// current window.
    ///
    /// The window starts at the first event and lasts `window`, matching the
    /// fixed-window semantics the local counters use. Implementations must
    /// count and set that expiry atomically: an increment whose expiry never
    /// lands leaves the key permanently over its limit.
    async fn count(&self, key: &str, window: Seconds) -> Option<u32>;

    /// Records `delta` events against `key` at once and returns the running
    /// count for the current window.
    ///
    /// For a caller that sets several aside in one step, such as a token
    /// limit reserving a typical exchange's tokens before it forwards.
    async fn add(&self, key: &str, delta: u32, window: Seconds) -> Option<u32>;

    /// Settles `delta`, which may be negative, against `key`, and returns the
    /// running count.
    ///
    /// A positive `delta` counts like [`add`](Self::add), starting the
    /// window when it is new. A negative one takes from a window still
    /// counting, never below zero, and starts nothing: a refund for a window
    /// that has lapsed is dropped, `Some(0)`, so budget spent in an old
    /// window is never handed to a new one. For a token charge settled
    /// against its reservation, and a reservation given back when the
    /// request it was set aside for is refused.
    async fn adjust(&self, key: &str, delta: i64, window: Seconds) -> Option<u32>;

    /// The running count of `key`, without counting: `Some(0)` when nothing
    /// counted it or its window lapsed.
    async fn read(&self, key: &str) -> Option<u32>;

    /// Holds `key` for `lasts` from now, whether it was held or not, so
    /// each hold restarts the wait: a client that keeps hitting a decoy
    /// stays blocked for the whole block after its last hit. A held key
    /// reads as one until it lapses. `None` when the hold did not land.
    async fn hold(&self, key: &str, lasts: Seconds) -> Option<()>;

    /// Records `members` against `key` and returns how many distinct ones the
    /// window has seen from anywhere.
    ///
    /// Distinct-thing counts cannot be summed across instances, two instances
    /// each seeing ten paths may have seen ten between them or twenty, so this
    /// is a set rather than a counter.
    async fn add_distinct(&self, key: &str, members: &[String], window: Seconds) -> Option<u32>;

    /// Claims `key` for the first and only time within `ttl`.
    ///
    /// `Some(true)` means this caller claimed it, `Some(false)` that someone
    /// already had. `None` means the store could not say, which for a replay
    /// check is not the same as "unclaimed", and the caller refuses.
    async fn claim_once(&self, key: &str, ttl: Seconds) -> Option<bool>;
}
