//! The entries one store cache keeps in this process: bounded, each
//! lapsing a set time after it was kept, each tagged with whose it is so
//! an event drops exactly its owner's.
//!
//! Entries are spread over shards, each behind its own lock held only for
//! the step itself, never across an await. Unlike the counters of this
//! folder, an entry here is only a copy of what the store holds, so when a
//! shard is full the lapsed entries go first and then the one closest to
//! lapsing: dropping a copy early costs a store read, never a wrong answer.
//! The shard a key lands in is drawn from a hash keyed afresh in each
//! process, so nobody can write keys that all land in one shard.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hash};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::cache::stores::owners::{Owner, Owners};

/// The number of shards the entries are spread over.
const SHARDS: usize = 16;

/// How long a store cache keeps an entry, and how many it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryKeeping {
    /// How long an entry is served after it was kept. Every entry lapses,
    /// so a change no event dropped is seen this long after at the most.
    pub lifetime: Duration,
    /// How many entries are kept at most.
    pub capacity: usize,
}

/// One entry as it was kept.
#[derive(Debug, Clone)]
pub(crate) struct Seen<V> {
    /// What was kept.
    pub(crate) value: V,
    /// Identity and containing scope whose events invalidate this cached copy.
    pub(crate) owners: Owners,
}

struct Entry<V> {
    seen: Seen<V>,
    lapses: Instant,
}

type Shard<K, V> = Mutex<HashMap<K, Entry<V>>>;

/// The entries of one store cache.
pub(crate) struct Entries<K, V> {
    shards: Vec<Shard<K, V>>,
    per_shard: usize,
    lifetime: Duration,
    placing: RandomState,
}

impl<K: Hash + Eq, V: Clone> Entries<K, V> {
    /// Entries kept as `keeping` says.
    pub(crate) fn new(keeping: EntryKeeping) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            per_shard: keeping.capacity.div_ceil(SHARDS).max(1),
            lifetime: keeping.lifetime,
            placing: RandomState::new(),
        }
    }

    /// The shard `key` lives in, its lock taken.
    fn shard(&self, key: &K) -> Option<MutexGuard<'_, HashMap<K, Entry<V>>>> {
        let index = usize::try_from(self.placing.hash_one(key))
            .unwrap_or_default()
            .checked_rem(SHARDS)?;
        self.shards
            .get(index)
            .map(|shard| shard.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The live entry at `key`, or `None` when there is none or it lapsed.
    pub(crate) fn get(&self, key: &K) -> Option<Seen<V>> {
        let now = Instant::now();
        let mut shard = self.shard(key)?;
        let live = shard.get(key).is_some_and(|entry| entry.lapses > now);
        if !live {
            shard.remove(key);
            return None;
        }
        shard.get(key).map(|entry| entry.seen.clone())
    }

    /// Keeps `value` at `key` for `owners`, for the lifetime from now.
    pub(crate) fn put(&self, key: K, value: V, owners: Owners) {
        let now = Instant::now();
        let Some(mut shard) = self.shard(&key) else {
            return;
        };
        if !shard.contains_key(&key) {
            make_room(&mut shard, self.per_shard, now);
        }
        shard.insert(
            key,
            Entry {
                seen: Seen { value, owners },
                lapses: now.checked_add(self.lifetime).unwrap_or(now),
            },
        );
    }

    /// Drops the entry at `key`.
    pub(crate) fn remove(&self, key: &K) {
        if let Some(mut shard) = self.shard(key) {
            shard.remove(key);
        }
    }

    /// Drops every entry an event of `owner` reaches.
    pub(crate) fn forget_owned(&self, owner: Owner) {
        for shard in &self.shards {
            shard
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|_, entry| !entry.seen.owners.reached_by(owner));
        }
    }

    /// Drops every entry.
    pub(crate) fn forget_all(&self) {
        for shard in &self.shards {
            shard.lock().unwrap_or_else(PoisonError::into_inner).clear();
        }
    }

    /// How many entries are held, lapsed or not.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }
}

/// Makes room in `shard` for one more entry under `cap`: drops the lapsed
/// entries, then, when it is still full, the one closest to lapsing.
fn make_room<K: Hash + Eq, V>(shard: &mut HashMap<K, Entry<V>>, cap: usize, now: Instant) {
    if shard.len() < cap {
        return;
    }
    shard.retain(|_, entry| entry.lapses > now);
    if shard.len() < cap {
        return;
    }
    let Some(soonest) = shard.values().map(|entry| entry.lapses).min() else {
        return;
    };
    let mut dropped = false;
    shard.retain(|_, entry| {
        let drops = !dropped && entry.lapses == soonest;
        dropped |= drops;
        !drops
    });
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn entries(capacity: usize, lifetime: Duration) -> Entries<String, u32> {
        Entries::new(EntryKeeping { lifetime, capacity })
    }

    fn acme() -> Owner {
        Owner::Tenant(Uuid::now_v7())
    }

    /// An entry kept is served until its lifetime ends, and not after.
    #[tokio::test]
    async fn an_entry_is_served_until_it_lapses() {
        let entries = entries(100, Duration::from_millis(30));
        entries.put("k".to_owned(), 7, Owners::only(acme()));

        let served = entries.get(&"k".to_owned()).map(|seen| seen.value);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let lapsed = entries.get(&"k".to_owned());

        assert_eq!(served, Some(7));
        assert!(lapsed.is_none());
    }

    /// After 1,000 insertions, the entry cache stays within its 32-slot capacity
    /// and retains the newest value.
    #[test]
    fn the_bound_evicts() {
        let entries = entries(32, Duration::from_secs(60));

        for n in 0..1_000 {
            entries.put(format!("k{n}"), n, Owners::only(acme()));
        }

        assert!(entries.held() <= 32, "{} entries held", entries.held());
        assert_eq!(
            entries.get(&"k999".to_owned()).map(|seen| seen.value),
            Some(999)
        );
    }

    /// An event of one owner drops that owner's entries and those within
    /// it, and leaves another owner's alone.
    #[test]
    fn an_owners_event_drops_only_what_it_reaches() {
        let entries = entries(100, Duration::from_secs(60));
        let (acme, globex) = (acme(), Owner::Tenant(Uuid::now_v7()));
        let organization = Owner::Organization(Uuid::now_v7());
        entries.put("acme".to_owned(), 1, Owners::only(acme));
        entries.put(
            "member".to_owned(),
            2,
            Owners {
                owner: globex,
                within: Some(organization),
            },
        );
        entries.put("globex".to_owned(), 3, Owners::only(globex));

        entries.forget_owned(acme);
        entries.forget_owned(organization);

        assert!(entries.get(&"acme".to_owned()).is_none());
        assert!(entries.get(&"member".to_owned()).is_none());
        assert_eq!(
            entries.get(&"globex".to_owned()).map(|seen| seen.value),
            Some(3)
        );
    }
}
