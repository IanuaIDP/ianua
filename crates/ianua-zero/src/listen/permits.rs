//! How many connections are served at once.
//!
//! A connection takes a permit when it is accepted and gives it back when
//! it closes. With every permit taken, a new connection is closed at once
//! rather than queued: a queue would only move the unbounded wait from the
//! gateway's tasks into its memory.

use std::num::NonZeroUsize;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The permits connections are served under. Clones share them, so two
/// listeners can be held to one bound.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionPermits {
    slots: Arc<Semaphore>,
}

/// One connection's permit, given back when it is dropped.
#[derive(Debug)]
pub(crate) struct ConnectionPermit {
    _slot: OwnedSemaphorePermit,
}

impl ConnectionPermits {
    /// At most `limit` connections at once, and never more than the
    /// largest count a semaphore holds.
    #[must_use]
    pub(crate) fn new(limit: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limit.get().min(Semaphore::MAX_PERMITS))),
        }
    }

    /// A permit, or `None` when every one is taken.
    #[must_use]
    pub(crate) fn try_take(&self) -> Option<ConnectionPermit> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .ok()
            .map(|slot| ConnectionPermit { _slot: slot })
    }

    /// How many permits are free now.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn available(&self) -> usize {
        self.slots.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permits(limit: usize) -> ConnectionPermits {
        ConnectionPermits::new(NonZeroUsize::new(limit).unwrap())
    }

    /// With the one permit held, the next connection gets none.
    #[test]
    fn no_permit_is_given_past_the_limit() {
        let permits = permits(1);

        let first = permits.try_take();
        let second = permits.try_take();

        assert!(first.is_some());
        assert!(second.is_none());
    }

    /// A closed connection gives its permit back for the next one.
    #[test]
    fn a_dropped_permit_is_given_back() {
        let permits = permits(1);
        let first = permits.try_take();

        drop(first);

        assert_eq!(permits.available(), 1);
        assert!(permits.try_take().is_some());
    }

    /// Clones share one bound.
    #[test]
    fn clones_share_their_permits() {
        let permits = permits(1);
        let other = permits.clone();

        let _held = permits.try_take();

        assert!(other.try_take().is_none());
    }
}
