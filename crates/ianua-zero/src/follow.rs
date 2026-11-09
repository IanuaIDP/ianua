//! Keeping the gateway's tables current as the control plane changes what
//! it serves.
//!
//! The gateway answers every request from tables in memory: which tenant a
//! host belongs to, its routes, services, pipelines, stream routes, client
//! certificate authorities and sign-in hosts, and the certificate each
//! name is served with. [`ConfigFollower`] fills them and keeps them
//! current. It follows the events stream as the store caches do; an event
//! counts only when its seal holds, and each one reloads what it changed,
//! read again from the stores through the app's ports, never taken from
//! the event itself.
//!
//! One reload of a tenant runs at a time and every read has a timeout, so a
//! store that hangs holds up its own tenant and no other. A tenant whose
//! change was heard but whose reload fails stops being served: the gateway
//! no longer knows its configuration, and serving the old one could keep a
//! revoked route or authority alive. Suspending a tenant, deleting it, or
//! changing whom its client certificates are trusted from withdraws it
//! before the reload even starts.
//!
//! Only the tenants a change names are withdrawn that way; the rest keep
//! being served as held when a read fails. Whenever events may have gone
//! by unheard, the follower fell behind or the feed was lost, everything is
//! read again, and a full reload also runs on a timer; one that fails runs
//! again shortly. The tables count as loaded, for the readiness check,
//! once a full reload has finished whole while the feed was followed, and
//! as stale when one after unheard events fails: the node then serves what
//! it holds but leaves rotation until a full reload succeeds.

mod changes;
mod follower;
mod gate;
mod queue;
mod snapshot;
mod source;

use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) use follower::{ConfigFollower, FollowPorts, FollowSettings, Seals};
pub(crate) use snapshot::{OpenedClientKey, Tables, TenantSnapshot};
pub(crate) use source::{SnapshotStores, StoreSnapshotSource};

/// The value behind `mutex`, also after a holder panicked: every value
/// kept behind these locks is whole between statements, so a panic cannot
/// leave one half-written.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
