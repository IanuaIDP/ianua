//! Cache: the short-lived state the platform counts and claims with, on
//! this node or shared by every node.
//!
//! Every port here is written once over [`SharedState`], so where the
//! state lives is the composition root's choice: [`MemoryState`] in this
//! process, for what each node counts on its own and for a deployment of
//! one node, or [`ServerState`] on a cache server every node reaches, any
//! that speaks the Redis wire protocol, every key there under the
//! deployment's [`Namespace`](crate::namespace::Namespace). Nothing kept
//! here is a record; every entry lapses with the window it was counted
//! for.
//!
//! The read-through store caches, such as [`CacheTokenLookup`],
//! [`CacheAccessRecordStore`] and [`CacheAppSessionCheck`], keep copies of
//! the hottest store reads in each node's memory, under versions held in
//! shared state and dropped by the events the bus carries. The gateway's
//! [`CacheResponseCache`] keeps the answers it may serve again on the
//! shared state itself, so every node serves what one kept.

mod alerts;
mod attempts;
mod counters;
mod flood;
mod health;
mod ledgers;
mod puzzles;
mod readiness;
mod responses;
mod state;
mod stores;
mod throttles;

pub use alerts::CacheAlertThrottle;
pub use attempts::CacheSignInAttemptCounts;
pub use counters::{
    CacheBudgetCounter, CacheBudgetUsageReader, CacheConsumerQuotaCounter, CacheFleetCounters,
};
pub use flood::CacheSignInFailureBudget;
pub use health::{CacheBackendHealthReader, CacheBackendHealthReports};
pub use ledgers::{CacheDpopReplayGuard, CacheNonceLedger, CacheTouchLedger};
pub use puzzles::{
    CacheChallengeIssuer, CacheChallengeVerifier, HARDEST_PUZZLE_BITS, PuzzleSettings, Puzzles,
};
pub use readiness::CacheReadinessProbe;
pub use responses::{CacheResponseCache, ResponseRoom};
pub use state::{CacheError, LogCapacity, LogEntry, MemoryState, ServerState, SharedState};
pub use stores::{
    CacheAccessRecordStore, CacheAppSessionCheck, CacheAssertionSigningKeys,
    CacheClassificationStore, CacheEventDispatcher, CacheTokenLookup, CacheUnitOfWork,
    CacheVerifyingKeyStore, EntryKeeping, StoreCacheFollower, StoreCaches,
};
pub use throttles::{
    Allowance, CacheBindThrottle, CacheMailThrottle, CacheRateLimiter, CacheVerificationThrottle,
    CacheWebhookSendThrottle,
};
