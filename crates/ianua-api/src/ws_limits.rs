//! Bounds on concurrent live WebSocket streams.
//!
//! A stream is a connection plus a loop that outlives the request that opened
//! it, so nothing in the normal request path: rate limits, plan limits :
//! constrains how many one caller may hold. Opening streams in a loop
//! otherwise consumes sockets, tasks, and database round-trips belonging to
//! everyone else on the node.
//!
//! Streams are counted against whichever identity is worth bounding, named by
//! its id: a run stream against its **tenant**, because a tenant's users all
//! poll the same runs, and a notification stream against the **caller**, whose
//! feed is theirs alone. Ids are UUIDs, so the two never collide.
//!
//! The permit is an RAII guard: the slot comes back when the stream task ends,
//! whichever way it ends.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ianua_domain::message;
use uuid::Uuid;

/// Counts the live streams each identity holds on this node.
pub struct StreamLimiter {
    open: Mutex<HashMap<Uuid, usize>>,
    max_per_owner: usize,
}

/// A held stream slot, returned to its owner's budget when dropped.
pub(crate) struct StreamPermit {
    limiter: Arc<StreamLimiter>,
    owner: Uuid,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let Ok(mut open) = self.limiter.open.lock() else {
            return;
        };
        let Some(count) = open.get_mut(&self.owner) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            open.remove(&self.owner);
        }
    }
}

impl StreamLimiter {
    /// A limiter letting each identity hold `max_per_owner` live streams.
    #[must_use]
    pub fn new(max_per_owner: usize) -> Self {
        Self {
            open: Mutex::new(HashMap::new()),
            max_per_owner,
        }
    }

    /// Takes a stream slot for `owner`, or `None` when it is at its limit.
    ///
    /// A poisoned lock denies: a limiter that cannot count is not a limiter.
    fn acquire(self: &Arc<Self>, owner: Uuid) -> Option<StreamPermit> {
        let mut open = self.open.lock().ok()?;
        let count = open.entry(owner).or_insert(0);
        if *count >= self.max_per_owner {
            return None;
        }
        *count += 1;
        Some(StreamPermit {
            limiter: Arc::clone(self),
            owner,
        })
    }

    /// Refuses the upgrade when `owner` already holds its share of streams.
    pub(crate) fn claim(
        self: &Arc<Self>,
        owner: Uuid,
    ) -> Result<StreamPermit, crate::error::ApiError> {
        self.acquire(owner).ok_or_else(|| {
            crate::error::ApiError(ianua_app::error::AppError::TooManyRequests(message!(
                "api-too-many-open-streams",
                "too many open streams"
            )))
        })
    }

    /// Refuses the upgrade when the person `who` names already holds their
    /// share of streams: a notification stream is counted against its
    /// caller.
    pub(crate) fn claim_for(
        self: &Arc<Self>,
        who: &ianua_app::context::CallerIdentity,
    ) -> Result<StreamPermit, crate::error::ApiError> {
        let owner = match who {
            ianua_app::context::CallerIdentity::Operator(id) => *id.as_uuid(),
            ianua_app::context::CallerIdentity::OrgUser(id) => *id.as_uuid(),
            ianua_app::context::CallerIdentity::TenantUser(id) => *id.as_uuid(),
        };
        self.claim(owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A limiter allowing each owner `max` open streams.
    fn limiter(max: usize) -> Arc<StreamLimiter> {
        Arc::new(StreamLimiter::new(max))
    }

    /// An owner holding both permitted streams cannot acquire a third.
    #[test]
    fn an_owner_is_capped_at_its_limit() {
        let limiter = limiter(2);
        let owner = Uuid::now_v7();

        let _first = limiter.acquire(owner).unwrap();
        let _second = limiter.acquire(owner).unwrap();

        assert!(limiter.acquire(owner).is_none());
    }

    /// Ann closes a stream and can open another in its place.
    #[test]
    fn dropping_a_stream_returns_its_slot() {
        let limiter = limiter(1);
        let owner = Uuid::now_v7();

        let permit = limiter.acquire(owner).unwrap();
        assert!(limiter.acquire(owner).is_none());
        drop(permit);

        assert!(limiter.acquire(owner).is_some());
    }

    /// One owner at the limit does not stop another from opening a stream.
    #[test]
    fn one_owner_at_its_limit_does_not_block_another() {
        let limiter = limiter(1);
        let noisy = Uuid::now_v7();
        let quiet = Uuid::now_v7();

        let _held = limiter.acquire(noisy).unwrap();

        assert!(limiter.acquire(quiet).is_some());
    }

    /// An owner with no open streams left is no longer kept in memory.
    #[test]
    fn an_owner_that_closed_everything_is_forgotten() {
        let limiter = limiter(4);
        let owner = Uuid::now_v7();

        drop(limiter.acquire(owner).unwrap());

        assert!(
            !limiter.open.lock().unwrap().contains_key(&owner),
            "a zeroed counter must not keep the owner in the map forever"
        );
    }
}
