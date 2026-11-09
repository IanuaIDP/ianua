//! Whether the gateway's in-memory tables were loaded.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether the follower holds the tenant, route and certificate tables
/// whole and current.
///
/// Until its first full load the gateway would refuse every request for
/// want of a route, so it answers not ready and the orchestrator sends it
/// nothing. It goes back to not ready when events went by unheard and the
/// full reload after them failed: the node keeps serving what it holds, but
/// is taken out of rotation until a full reload succeeds. Shared: the
/// follower marks it, the readiness check reads it.
#[derive(Debug, Clone, Default)]
pub(crate) struct TablesLoaded(Arc<AtomicBool>);

impl TablesLoaded {
    /// Not loaded yet.
    #[must_use]
    pub(crate) fn not_yet() -> Self {
        Self::default()
    }

    /// Marks a full load as done: the tables are whole and current.
    pub(crate) fn mark_loaded(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Marks the tables as possibly out of date, until the next full load.
    pub(crate) fn mark_stale(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Whether the tables are whole and current.
    #[must_use]
    pub(crate) fn is_loaded(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The follower marks its clone; the readiness check reads its own.
    #[test]
    fn a_mark_on_one_clone_is_read_on_another() {
        let tables = TablesLoaded::not_yet();
        let follower = tables.clone();

        follower.mark_loaded();

        assert!(tables.is_loaded());
    }

    /// Tables that may have missed changes take the node out of rotation.
    #[test]
    fn stale_tables_are_not_loaded() {
        let tables = TablesLoaded::not_yet();
        tables.mark_loaded();

        tables.mark_stale();

        assert!(!tables.is_loaded());
    }
}
