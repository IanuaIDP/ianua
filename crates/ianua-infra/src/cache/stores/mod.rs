//! Read-through store caches: copies of the hottest store reads, kept in
//! each node's memory in front of the Postgres stores, behind the same
//! ports.
//!
//! These reads are kept, each because it runs on every request and costs
//! far more than the one round trip to the cache server a cached read
//! makes:
//!
//! - [`CacheTokenLookup`]: the caller a bearer resolves to, which reads the
//!   platform database and every database of a tenant living apart;
//! - [`CacheAccessRecordStore`]: what decides one holder's holdings, a
//!   handful of queries in one transaction;
//! - [`CacheAppSessionCheck`]: whether an app session the gateway is shown
//!   is live, kept a few seconds and only while it is;
//! - [`CacheVerifyingKeyStore`] and [`CacheAssertionSigningKeys`]: the
//!   public halves of a tenant's signing keys, and its assertion key
//!   opened, which the gateway checks and signs with;
//! - [`CacheClassificationStore`]: a tenant's classification rules, which
//!   the gateway classifies and redacts by.
//!
//! The rules every entry keeps:
//!
//! - **Dropped by events, never by a call in a use case.** Which caches an
//!   event touches is one `match` over every event type, with no
//!   catch-all, so a new event does not compile until that is decided.
//! - **Kept under its owner's version.** Every node reads the owner's
//!   version, in shared state, before it reads the store; any event that
//!   changes what an entry was worked out from raises it, so every entry
//!   worked out before stops being read on every node at once.
//! - **The node that made the change drops its own at once**, once its
//!   unit of work has settled ([`CacheUnitOfWork`] with
//!   [`CacheEventDispatcher`]); every other node drops them when the event
//!   reaches it on the bus ([`StoreCacheFollower`]).
//! - **Every entry lapses**: its lifetime is the backstop for anything no
//!   event dropped. An opened assertion key is dropped by its lifetime
//!   alone, its rotation recording no event, which is why it lives a
//!   minute against the day a rotated key stays published.
//! - **No revocation is ever kept as "still allowed"**: a bearer that no
//!   longer answers is not kept, a grant found is kept only under the
//!   version a revocation raises, and when the versions cannot be read,
//!   the store is asked and nothing is kept.
//! - **A tenant's deletion drops every entry of the tenant.**

mod app_sessions;
mod classifications;
mod entries;
mod follower;
mod holdings;
mod invalidation;
mod keys;
mod owners;
mod tokens;
mod touched;
mod versions;
mod writes;

pub use app_sessions::CacheAppSessionCheck;
pub use classifications::CacheClassificationStore;
pub use entries::EntryKeeping;
pub use follower::StoreCacheFollower;
pub use holdings::CacheAccessRecordStore;
pub use invalidation::StoreCaches;
pub use keys::{CacheAssertionSigningKeys, CacheVerifyingKeyStore};
pub use tokens::CacheTokenLookup;
#[cfg(test)]
pub(crate) use versions::RefusingState;
pub use writes::{CacheEventDispatcher, CacheUnitOfWork};
