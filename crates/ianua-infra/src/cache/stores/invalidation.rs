//! What every store cache of a node shares: the versions every node reads,
//! and the entries of each cache, so a change drops them all in one place.
//!
//! A change is applied the same way wherever it is heard, after its unit
//! committed on the node that made it and from the bus on every node:
//! the caches it touches drop the owner's entries here, and the owner's
//! version in each is raised for every node. A version that could not be
//! raised is logged and left: no node reads an entry past its lifetime.

use std::hash::Hash;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use ianua_domain::types::EventType;

use crate::cache::state::SharedState;
use crate::cache::stores::entries::{Entries, EntryKeeping};
use crate::cache::stores::owners::Owner;
use crate::cache::stores::touched::touched_by;
use crate::cache::stores::versions::{Cached, Versions};

/// A change a node heard of, to apply to its store caches: an event of
/// one type, kept for one owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Change {
    event: EventType,
    owner: Owner,
}

impl Change {
    /// The change an event of type `event`, kept for `owner`, records.
    pub(crate) fn of(event: EventType, owner: Owner) -> Self {
        Self { event, owner }
    }

    /// Whether the change touches `owner`'s holdings.
    pub(crate) fn touches_holdings_of(self, owner: Owner) -> bool {
        self.owner == owner && touched_by(self.event).contains(&Cached::Holdings)
    }
}

/// The entries of one cache, as the changes see them.
trait Forgets: Send + Sync {
    /// Drops every entry an event of `owner` reaches.
    fn drop_owned(&self, owner: Owner);

    /// Drops every entry.
    fn drop_all(&self);
}

impl<K, V> Forgets for Entries<K, V>
where
    K: Hash + Eq + Send + Sync,
    V: Clone + Send + Sync,
{
    fn drop_owned(&self, owner: Owner) {
        self.forget_owned(owner);
    }

    fn drop_all(&self) {
        self.forget_all();
    }
}

/// The store caches of one node and the versions all nodes share.
pub struct StoreCaches {
    versions: Versions,
    kept: RwLock<Vec<(Cached, Arc<dyn Forgets>)>>,
}

impl std::fmt::Debug for StoreCaches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreCaches").finish_non_exhaustive()
    }
}

impl StoreCaches {
    /// Store caches keeping their versions in `state`, each kept
    /// `versions_kept` past its last raise. Give every node the same
    /// shared state, the cache server, so a change one node makes is seen
    /// by all at once; state in this process serves a deployment of one
    /// node, the others then seeing a change once its event reaches them.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, versions_kept: Duration) -> Self {
        Self {
            versions: Versions::new(state, versions_kept),
            kept: RwLock::new(Vec::new()),
        }
    }

    /// The versions every node reads.
    pub(crate) fn versions(&self) -> &Versions {
        &self.versions
    }

    /// New entries of `cached`, kept as `keeping` says, which every change
    /// that touches `cached` drops from.
    pub(crate) fn entries<K, V>(&self, cached: Cached, keeping: EntryKeeping) -> Arc<Entries<K, V>>
    where
        K: Hash + Eq + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let entries = Arc::new(Entries::new(keeping));
        let forgets: Arc<dyn Forgets> = Arc::clone(&entries) as Arc<dyn Forgets>;
        self.kept
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push((cached, forgets));
        entries
    }

    /// Applies `change`: the caches it touches drop what it reaches here,
    /// and the owner's versions are raised for every node.
    pub(crate) async fn apply(&self, change: Change) {
        self.touch(touched_by(change.event), change.owner).await;
    }

    /// Applies an event of a type this node does not know, as a newer node
    /// may raise: every cache of `owner` is touched.
    pub(crate) async fn apply_unknown(&self, owner: Owner) {
        self.touch(Cached::ALL, owner).await;
    }

    /// Drops every entry of every cache here, as when events may have gone
    /// by unheard. Versions are left: the entries are only this node's.
    pub(crate) fn forget_everything_here(&self) {
        for (_, forgets) in self.kept() {
            forgets.drop_all();
        }
    }

    /// Drops what an event of `owner` reaches in each of `touched` here,
    /// and raises `owner`'s version in each.
    async fn touch(&self, touched: &[Cached], owner: Owner) {
        for cached in touched {
            for forgets in self.kept_of(*cached) {
                forgets.drop_owned(owner);
            }
            if let Err(error) = self.versions.raise(*cached, owner).await {
                tracing::warn!(
                    %error,
                    "a store cache version could not be raised; other nodes' entries lapse with their lifetime"
                );
            }
        }
    }

    /// The entries of every cache kept, read out so no lock is held while
    /// they drop.
    fn kept(&self) -> Vec<(Cached, Arc<dyn Forgets>)> {
        self.kept
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(cached, forgets)| (*cached, Arc::clone(forgets)))
            .collect()
    }

    /// The entries of the caches of kind `cached`.
    fn kept_of(&self, cached: Cached) -> impl Iterator<Item = Arc<dyn Forgets>> {
        self.kept()
            .into_iter()
            .filter(move |(kind, _)| *kind == cached)
            .map(|(_, forgets)| forgets)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::stores::owners::Owners;

    fn caches() -> StoreCaches {
        StoreCaches::new(Arc::new(MemoryState::new(100)), Duration::from_secs(60))
    }

    fn keeping() -> EntryKeeping {
        EntryKeeping {
            lifetime: Duration::from_secs(60),
            capacity: 100,
        }
    }

    fn event(name: &str) -> EventType {
        EventType::parse(name).expect("a known event type")
    }

    /// Acme's deletion removes its cached callers and holdings and changes its holdings version;
    /// Globex's entries remain available.
    #[tokio::test]
    async fn a_deleted_tenants_entries_go() {
        let caches = caches();
        let callers = caches.entries::<&str, u8>(Cached::Callers, keeping());
        let holdings = caches.entries::<&str, u8>(Cached::Holdings, keeping());
        let (acme, globex) = (Owner::Tenant(Uuid::now_v7()), Owner::Tenant(Uuid::now_v7()));
        let version = caches
            .versions()
            .current(Cached::Holdings, acme)
            .await
            .unwrap();
        callers.put("acme", 1, Owners::only(acme));
        holdings.put("acme", 2, Owners::only(acme));
        holdings.put("globex", 3, Owners::only(globex));

        caches
            .apply(Change::of(event("tenant.deleted"), acme))
            .await;

        assert!(callers.get(&"acme").is_none());
        assert!(holdings.get(&"acme").is_none());
        assert!(holdings.get(&"globex").is_some());
        assert_ne!(
            caches
                .versions()
                .current(Cached::Holdings, acme)
                .await
                .unwrap(),
            version
        );
    }

    /// An event touching one cache drops that cache's entries only.
    #[tokio::test]
    async fn an_event_drops_only_the_caches_it_touches() {
        let caches = caches();
        let callers = caches.entries::<&str, u8>(Cached::Callers, keeping());
        let holdings = caches.entries::<&str, u8>(Cached::Holdings, keeping());
        let acme = Owner::Tenant(Uuid::now_v7());
        callers.put("acme", 1, Owners::only(acme));
        holdings.put("acme", 2, Owners::only(acme));

        caches
            .apply(Change::of(event("authorization.role_revoked"), acme))
            .await;

        assert!(callers.get(&"acme").is_some());
        assert!(holdings.get(&"acme").is_none());
    }
}
