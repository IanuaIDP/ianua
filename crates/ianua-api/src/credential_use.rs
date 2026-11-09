//! How often a request marks the credential it came with as used.
//!
//! A key shows its owners when it last signed in, and an organization
//! session left alone past its idle timeout stops counting. Both are marked
//! by the request that used them, but writing the mark on every request
//! would turn every read into a write. So a credential is marked once per
//! interval on this node: often enough to keep a session from timing out
//! mid-work and to date a key's last use to within the interval. A tenant
//! key's country is not held to the interval: every request reads the key
//! and notes a country new to it at once.
//!
//! Credentials are named by their id. Ids are UUIDs, so a key and a session
//! never collide.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

/// The credentials marked used lately on this node, and when.
///
/// The lock is held only to read and write one entry, never across an
/// await, so a plain mutex is the right tool.
pub struct RecentUse {
    marked: Mutex<HashMap<Uuid, Instant>>,
    interval: Duration,
    capacity: usize,
}

impl RecentUse {
    /// Marks each credential at most once per `interval`, remembering at
    /// most `capacity` of them at once.
    #[must_use]
    pub fn new(interval: Duration, capacity: usize) -> Self {
        Self {
            marked: Mutex::new(HashMap::new()),
            interval,
            capacity,
        }
    }

    /// Whether the credential `id` is due to be marked used now; when it
    /// is, it counts as marked from now on.
    ///
    /// A full memory forgets the marks older than the interval first, and
    /// everything when that is not enough: forgetting only costs a mark
    /// written early. A poisoned lock answers due, for the same reason.
    pub(crate) fn is_due(&self, id: Uuid, now: Instant) -> bool {
        let Ok(mut marked) = self.marked.lock() else {
            return true;
        };
        if marked
            .get(&id)
            .is_some_and(|at| now.saturating_duration_since(*at) < self.interval)
        {
            return false;
        }
        if marked.len() >= self.capacity {
            marked.retain(|_, at| now.saturating_duration_since(*at) < self.interval);
        }
        if marked.len() >= self.capacity {
            marked.clear();
        }
        marked.insert(id, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    /// A credential nobody marked yet is marked by the request it came with.
    #[test]
    fn a_credential_is_due_the_first_time_it_is_seen() {
        let recent = RecentUse::new(MINUTE, 10);

        assert!(recent.is_due(Uuid::now_v7(), Instant::now()));
    }

    /// Requests inside the interval write nothing, so reads stay reads.
    #[test]
    fn a_credential_is_not_due_again_within_the_interval() {
        let recent = RecentUse::new(MINUTE, 10);
        let (id, now) = (Uuid::now_v7(), Instant::now());
        recent.is_due(id, now);

        assert!(!recent.is_due(id, now + Duration::from_secs(59)));
    }

    /// Once the interval passes the credential is marked again, so a session
    /// in use keeps counting as active.
    #[test]
    fn a_credential_is_due_again_once_the_interval_passed() {
        let recent = RecentUse::new(MINUTE, 10);
        let (id, now) = (Uuid::now_v7(), Instant::now());
        recent.is_due(id, now);

        assert!(recent.is_due(id, now + MINUTE));
    }

    /// One credential's mark does not hold back another's.
    #[test]
    fn each_credential_is_counted_on_its_own() {
        let recent = RecentUse::new(MINUTE, 10);
        let now = Instant::now();
        recent.is_due(Uuid::now_v7(), now);

        assert!(recent.is_due(Uuid::now_v7(), now));
    }

    /// Fresh credentials keep the tracker within its capacity, evicting an
    /// older mark so that credential becomes due again.
    #[test]
    fn a_full_memory_forgets_rather_than_growing() {
        let recent = RecentUse::new(MINUTE, 2);
        let now = Instant::now();
        let first = Uuid::now_v7();
        recent.is_due(first, now);
        recent.is_due(Uuid::now_v7(), now);
        recent.is_due(Uuid::now_v7(), now);

        assert!(recent.marked.lock().is_ok_and(|marked| marked.len() <= 2));
        assert!(recent.is_due(first, now));
    }
}
