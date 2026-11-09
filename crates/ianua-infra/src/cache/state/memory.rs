//! Shared state held in this process: for what each node counts on its
//! own, such as the API rate limit, for a deployment of one node, and for
//! tests.
//!
//! Entries are spread over shards, each behind its own lock held only for
//! the step itself, never across an await. Each shard holds at most its
//! share of the cap: past it, lapsed entries go, and when none has lapsed
//! the new key is refused, so a flood of new keys cannot grow the process
//! without bound. A live entry is never dropped to make room: a claim or a
//! count dropped early would let a spent nonce be spent again or a limit
//! start over, so a full state refuses and its callers refuse in turn. The
//! shard a key lands in is drawn from a hash keyed afresh in each process,
//! so nobody can write keys that all land in one shard.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::BuildHasher as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::cache::state::{CacheError, LogCapacity, LogEntry, SharedState};

/// The number of shards the entries are spread over.
const SHARDS: usize = 16;

/// What one entry holds.
#[derive(Debug)]
enum Held {
    Count(u64),
    Members(HashSet<String>),
    Text(String),
    Log(BTreeSet<(i64, String)>),
}

#[derive(Debug)]
struct Entry {
    held: Held,
    lapses: Instant,
}

type Shard = Mutex<HashMap<String, Entry>>;

/// The value and lifetime used only when an entry needs to be created.
struct NewEntry<F> {
    fresh: F,
    ttl: Duration,
}

/// Which log entries remain and how long the resulting log stays live.
#[derive(Clone, Copy)]
struct LogRetention {
    forget_before: i64,
    keep: Duration,
}

/// Shared state in this process's memory.
#[derive(Debug)]
pub struct MemoryState {
    shards: Vec<Shard>,
    per_shard: usize,
    placing: RandomState,
}

impl MemoryState {
    /// State holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            per_shard: capacity.div_ceil(SHARDS).max(1),
            placing: RandomState::new(),
        }
    }

    /// The shard `key` lives in, its lock taken.
    fn shard(
        &self,
        key: &str,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Entry>>, CacheError> {
        let index = usize::try_from(self.placing.hash_one(key))
            .unwrap_or_default()
            .checked_rem(SHARDS)
            .unwrap_or_default();
        self.shards
            .get(index)
            .ok_or(CacheError::Unexpected)?
            .lock()
            .map_err(|_| CacheError::Unexpected)
    }

    /// Runs `step` on the live entry at `key`, creating it with `new` when
    /// there is none.
    fn with_entry<T>(
        &self,
        key: &str,
        new: NewEntry<impl FnOnce() -> Held>,
        step: impl FnOnce(&mut Held) -> T,
    ) -> Result<T, CacheError> {
        let now = Instant::now();
        let mut shard = self.shard(key)?;
        if shard.get(key).is_some_and(|entry| entry.lapses <= now) {
            shard.remove(key);
        }
        if !shard.contains_key(key) {
            make_room(&mut shard, self.per_shard, now)?;
            shard.insert(
                key.to_owned(),
                Entry {
                    held: (new.fresh)(),
                    lapses: now.checked_add(new.ttl).unwrap_or(now),
                },
            );
        }
        let entry = shard.get_mut(key).ok_or(CacheError::Unexpected)?;
        Ok(step(&mut entry.held))
    }

    /// Keeps `held` at `key` until `ttl` from now, replacing what was
    /// there, live or not.
    fn replace(&self, key: &str, held: Held, ttl: Duration) -> Result<(), CacheError> {
        let now = Instant::now();
        let mut shard = self.shard(key)?;
        if shard.get(key).is_none_or(|entry| entry.lapses <= now) {
            make_room(&mut shard, self.per_shard, now)?;
        }
        shard.insert(
            key.to_owned(),
            Entry {
                held,
                lapses: now.checked_add(ttl).unwrap_or(now),
            },
        );
        Ok(())
    }

    /// Runs `step` on the log at `key`, started when none is live, once its
    /// entries outside `retention` are dropped and its lifetime renewed.
    fn with_log<T>(
        &self,
        key: &str,
        retention: LogRetention,
        step: impl FnOnce(&mut BTreeSet<(i64, String)>) -> T,
    ) -> Result<T, CacheError> {
        let now = Instant::now();
        let mut shard = self.shard(key)?;
        let live = shard.get(key).is_some_and(|held| held.lapses > now);
        if !live {
            shard.remove(key);
            make_room(&mut shard, self.per_shard, now)?;
        }
        let held = shard.entry(key.to_owned()).or_insert(Entry {
            held: Held::Log(BTreeSet::new()),
            lapses: now,
        });
        held.lapses = now.checked_add(retention.keep).unwrap_or(now);
        let Held::Log(log) = &mut held.held else {
            return Err(CacheError::Unexpected);
        };
        log.retain(|(at, _)| *at >= retention.forget_before);
        Ok(step(log))
    }

    /// The live entry at `key`, read by `read`.
    fn peek<T>(&self, key: &str, read: impl FnOnce(&Held) -> T) -> Result<Option<T>, CacheError> {
        let now = Instant::now();
        let shard = self.shard(key)?;
        Ok(shard
            .get(key)
            .filter(|entry| entry.lapses > now)
            .map(|entry| read(&entry.held)))
    }
}

/// Drops lapsed entries so `shard` has room for one more under `cap`, and
/// refuses when every entry it holds is still live.
fn make_room(
    shard: &mut HashMap<String, Entry>,
    cap: usize,
    now: Instant,
) -> Result<(), CacheError> {
    if shard.len() < cap {
        return Ok(());
    }
    shard.retain(|_, entry| entry.lapses > now);
    if shard.len() >= cap {
        return Err(CacheError::Full);
    }
    Ok(())
}

#[async_trait]
impl SharedState for MemoryState {
    async fn count(&self, key: &str, delta: u64, window: Duration) -> Result<u64, CacheError> {
        self.with_entry(
            key,
            NewEntry {
                ttl: window,
                fresh: || Held::Count(0),
            },
            |held| match held {
                Held::Count(count) => {
                    *count = count.saturating_add(delta);
                    Ok(*count)
                }
                Held::Members(_) | Held::Text(_) | Held::Log(_) => Err(CacheError::Unexpected),
            },
        )?
    }

    async fn read(&self, key: &str) -> Result<Option<u64>, CacheError> {
        self.peek(key, |held| match held {
            Held::Count(count) => Ok(*count),
            Held::Members(_) | Held::Text(_) | Held::Log(_) => Err(CacheError::Unexpected),
        })?
        .transpose()
    }

    async fn lower(&self, key: &str, by: u64) -> Result<Option<u64>, CacheError> {
        let now = Instant::now();
        let mut shard = self.shard(key)?;
        let Some(entry) = shard.get_mut(key).filter(|entry| entry.lapses > now) else {
            return Ok(None);
        };
        match &mut entry.held {
            Held::Count(count) => {
                *count = count.saturating_sub(by);
                Ok(Some(*count))
            }
            Held::Members(_) | Held::Text(_) | Held::Log(_) => Err(CacheError::Unexpected),
        }
    }

    async fn hold(&self, key: &str, ttl: Duration) -> Result<(), CacheError> {
        self.replace(key, Held::Count(1), ttl)
    }

    async fn add_distinct(
        &self,
        key: &str,
        members: &[String],
        window: Duration,
    ) -> Result<u64, CacheError> {
        self.with_entry(
            key,
            NewEntry {
                ttl: window,
                fresh: || Held::Members(HashSet::new()),
            },
            |held| match held {
                Held::Members(set) => {
                    set.extend(members.iter().cloned());
                    Ok(u64::try_from(set.len()).unwrap_or(u64::MAX))
                }
                Held::Count(_) | Held::Text(_) | Held::Log(_) => Err(CacheError::Unexpected),
            },
        )?
    }

    async fn distinct(&self, key: &str) -> Result<u64, CacheError> {
        Ok(self
            .peek(key, |held| match held {
                Held::Members(set) => Ok(u64::try_from(set.len()).unwrap_or(u64::MAX)),
                Held::Count(_) | Held::Text(_) | Held::Log(_) => Err(CacheError::Unexpected),
            })?
            .transpose()?
            .unwrap_or_default())
    }

    async fn claim_once(&self, key: &str, ttl: Duration) -> Result<bool, CacheError> {
        let mut claimed = false;
        self.with_entry(
            key,
            NewEntry {
                ttl,
                fresh: || {
                    claimed = true;
                    Held::Count(1)
                },
            },
            |_| (),
        )?;
        Ok(claimed)
    }

    async fn swap(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> Result<Option<String>, CacheError> {
        let now = Instant::now();
        let mut shard = self.shard(key)?;
        let live = shard.get(key).filter(|held| held.lapses > now);
        let before = live.and_then(|held| match &held.held {
            Held::Text(text) => Some(text.clone()),
            Held::Count(_) | Held::Members(_) | Held::Log(_) => None,
        });
        if live.is_none() {
            make_room(&mut shard, self.per_shard, now)?;
        }
        shard.insert(
            key.to_owned(),
            Entry {
                held: Held::Text(value.to_owned()),
                lapses: now.checked_add(ttl).unwrap_or(now),
            },
        );
        Ok(before)
    }

    async fn keep(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        self.replace(key, Held::Text(value.to_owned()), ttl)
    }

    async fn text(&self, key: &str) -> Result<Option<String>, CacheError> {
        self.peek(key, |held| match held {
            Held::Text(text) => Ok(text.clone()),
            Held::Count(_) | Held::Members(_) | Held::Log(_) => Err(CacheError::Unexpected),
        })?
        .transpose()
    }

    async fn forget(&self, key: &str) -> Result<(), CacheError> {
        self.shard(key)?.remove(key);
        Ok(())
    }

    async fn log(&self, key: &str, entry: &LogEntry<'_>, keep: Duration) -> Result<(), CacheError> {
        let retention = LogRetention {
            forget_before: entry.forget_before,
            keep,
        };
        self.with_log(key, retention, |log| {
            log.insert((entry.at, entry.text.to_owned()));
        })
    }

    async fn enroll(
        &self,
        key: &str,
        entry: &LogEntry<'_>,
        capacity: LogCapacity,
    ) -> Result<bool, CacheError> {
        let retention = LogRetention {
            forget_before: entry.forget_before,
            keep: capacity.keep,
        };
        self.with_log(key, retention, |log| {
            let held = log.len();
            log.retain(|(_, text)| text != entry.text);
            let full = u64::try_from(log.len()).unwrap_or(u64::MAX) >= capacity.entries;
            if held == log.len() && full {
                return false;
            }
            log.insert((entry.at, entry.text.to_owned()));
            true
        })
    }

    async fn log_since(&self, key: &str, since: i64) -> Result<Vec<String>, CacheError> {
        Ok(self
            .peek(key, |held| match held {
                Held::Log(log) => log
                    .iter()
                    .filter(|(at, _)| *at >= since)
                    .map(|(_, text)| text.clone())
                    .collect(),
                Held::Count(_) | Held::Members(_) | Held::Text(_) => Vec::new(),
            })?
            .unwrap_or_default())
    }

    async fn ping(&self) -> Result<(), CacheError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> MemoryState {
        MemoryState::new(1_000)
    }

    /// A roster entry with an explicit timestamp and expiry cutoff.
    fn entry(text: &str, at: i64, forget_before: i64) -> LogEntry<'_> {
        LogEntry {
            text,
            at,
            forget_before,
        }
    }

    /// Room for two roster entries, retained for one minute.
    fn roster_capacity() -> LogCapacity {
        LogCapacity {
            entries: 2,
            keep: Duration::from_secs(60),
        }
    }

    /// A counter counts within its window and starts again after it.
    #[tokio::test]
    async fn a_counter_counts_within_its_window() {
        let state = state();

        state
            .count("k", 1, Duration::from_millis(50))
            .await
            .unwrap();
        let second = state
            .count("k", 2, Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let after = state
            .count("k", 1, Duration::from_millis(50))
            .await
            .unwrap();

        assert_eq!(second, 3);
        assert_eq!(after, 1);
    }

    /// A counter is lowered while it counts, never below zero; one that
    /// lapsed is not started by lowering it.
    #[tokio::test]
    async fn a_counter_is_lowered_only_while_it_counts() {
        let state = state();
        state.count("k", 5, Duration::from_secs(60)).await.unwrap();

        let lowered = state.lower("k", 2).await.unwrap();
        let floored = state.lower("k", 10).await.unwrap();
        let nothing = state.lower("never", 1).await.unwrap();

        assert_eq!(lowered, Some(3));
        assert_eq!(floored, Some(0));
        assert_eq!(nothing, None);
        assert_eq!(state.read("never").await.unwrap(), None);
    }

    /// Renewing an in-memory hold extends its expiry; the counter stays at one
    /// until the renewed wait ends.
    #[tokio::test]
    async fn a_hold_restarts_its_wait() {
        let state = state();

        state.hold("b", Duration::from_millis(100)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        state.hold("b", Duration::from_millis(100)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let held = state.read("b").await.unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
        let lapsed = state.read("b").await.unwrap();

        assert_eq!(held, Some(1));
        assert_eq!(lapsed, None);
    }

    /// Kept text replaces what was there and reads back.
    #[tokio::test]
    async fn kept_text_reads_back() {
        let state = state();

        state
            .keep("t", "first", Duration::from_secs(60))
            .await
            .unwrap();
        state
            .keep("t", "second", Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(state.text("t").await.unwrap().as_deref(), Some("second"));
    }

    /// A claim is won once while it lasts.
    #[tokio::test]
    async fn a_claim_is_won_once() {
        let state = state();

        let first = state
            .claim_once("nonce", Duration::from_secs(60))
            .await
            .unwrap();
        let second = state
            .claim_once("nonce", Duration::from_secs(60))
            .await
            .unwrap();

        assert!(first);
        assert!(!second);
    }

    /// A swap answers what was kept before, and nothing the first time.
    #[tokio::test]
    async fn a_swap_answers_the_value_before() {
        let state = state();

        let first = state
            .swap("p", "normal", Duration::from_secs(60))
            .await
            .unwrap();
        let second = state
            .swap("p", "high", Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(first, None);
        assert_eq!(second.as_deref(), Some("normal"));
    }

    /// Text kept by a swap reads back until it lapses, and nothing after.
    #[tokio::test]
    async fn swapped_text_reads_back_until_it_lapses() {
        let state = state();
        state
            .swap("v", "first", Duration::from_millis(30))
            .await
            .unwrap();

        let kept = state.text("v").await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let lapsed = state.text("v").await.unwrap();

        assert_eq!(kept.as_deref(), Some("first"));
        assert_eq!(lapsed, None);
    }

    /// A forgotten counter starts again at its next count, and forgetting a
    /// key nothing holds is no error.
    #[tokio::test]
    async fn a_forgotten_counter_starts_again() {
        let state = state();
        state.count("k", 3, Duration::from_secs(60)).await.unwrap();

        state.forget("k").await.unwrap();
        state.forget("never-kept").await.unwrap();
        let again = state.count("k", 1, Duration::from_secs(60)).await.unwrap();

        assert_eq!(again, 1);
    }

    /// Among 32 concurrent swaps of one key, exactly one observes that no previous value existed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn swaps_at_once_see_the_value_before_once() {
        let state = std::sync::Arc::new(state());
        let swaps: Vec<_> = (0..32)
            .map(|_| {
                let state = std::sync::Arc::clone(&state);
                tokio::spawn(async move { state.swap("p", "high", Duration::from_secs(60)).await })
            })
            .collect();

        let mut first = 0;
        for swap in swaps {
            first += usize::from(swap.await.unwrap().unwrap().is_none());
        }

        assert_eq!(first, 1);
    }

    /// Inserting 1,000 keys into 32 slots retains at most 32 entries
    /// and reports capacity refusals for the excess.
    #[tokio::test]
    async fn a_flood_of_keys_stays_within_the_cap() {
        let state = MemoryState::new(32);
        let mut refused = 0;

        for n in 0..1_000 {
            let counted = state
                .count(&format!("k{n}"), 1, Duration::from_secs(60))
                .await;
            refused += usize::from(matches!(counted, Err(CacheError::Full)));
        }

        let held: usize = state
            .shards
            .iter()
            .map(|shard| shard.lock().unwrap().len())
            .sum();
        assert!(held <= 32, "{held} entries held");
        assert!(refused >= 1_000 - 32, "{refused} refused");
    }

    /// A live nonce claim survives a flood of new keys, so claiming it again still fails.
    #[tokio::test]
    async fn a_flood_never_drops_a_live_claim() {
        let state = MemoryState::new(32);
        let ttl = Duration::from_secs(60);
        assert!(state.claim_once("nonce", ttl).await.unwrap());

        for n in 0..1_000 {
            let _ = state.claim_once(&format!("flood{n}"), ttl).await;
        }
        let again = state.claim_once("nonce", ttl).await;

        assert!(matches!(again, Ok(false)));
    }

    /// Room freed by a lapsed entry is taken by the next new key.
    #[tokio::test]
    async fn a_lapsed_entry_makes_room() {
        let state = MemoryState::new(1);
        state
            .count("old", 1, Duration::from_millis(20))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        let fresh = state.count("new", 1, Duration::from_secs(60)).await;

        assert!(matches!(fresh, Ok(1)));
    }

    /// A log answers its entries since a moment, oldest first, and forgets
    /// those from before the cut it is given.
    #[tokio::test]
    async fn a_log_answers_since_and_forgets_before() {
        let state = state();
        let keep = Duration::from_secs(60);
        for (at, text) in [(10, "a"), (20, "b"), (30, "c")] {
            state
                .log(
                    "touches",
                    &LogEntry {
                        text,
                        at,
                        forget_before: 15,
                    },
                    keep,
                )
                .await
                .unwrap();
        }

        let since = state.log_since("touches", 20).await.unwrap();
        let all = state.log_since("touches", 0).await.unwrap();

        assert_eq!(since, ["b", "c"]);
        assert_eq!(all, ["b", "c"]);
    }

    /// A full roster takes no newcomer, keeps taking what it already holds,
    /// and takes a newcomer again once an entry lapses.
    #[tokio::test]
    async fn a_full_roster_takes_only_what_it_holds_until_one_lapses() {
        let state = state();
        let capacity = roster_capacity();
        state
            .enroll("held", &entry("a", 10, 0), capacity)
            .await
            .unwrap();
        state
            .enroll("held", &entry("b", 30, 0), capacity)
            .await
            .unwrap();

        let newcomer = state
            .enroll("held", &entry("c", 30, 0), capacity)
            .await
            .unwrap();
        let again = state
            .enroll("held", &entry("a", 40, 0), capacity)
            .await
            .unwrap();
        let after_lapse = state
            .enroll("held", &entry("c", 50, 35), capacity)
            .await
            .unwrap();

        assert!(!newcomer);
        assert!(again);
        assert!(after_lapse);
        assert_eq!(state.log_since("held", 0).await.unwrap(), ["a", "c"]);
    }
}
