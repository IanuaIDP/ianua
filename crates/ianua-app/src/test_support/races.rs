//! Two requests racing on one record, played one after the other.
//!
//! Requests running at once can each read a record before either writes
//! it. Tests run one call after another, so a store that reads from a copy
//! taken before the race began stands in for that: every plain read sees
//! the record as both requests found it, while every write, conditional
//! write and locking read reaches the store as it is now. A use case that
//! decides on what it read and then writes over it unconditionally loses
//! the other request's write; one that lets storage decide in one statement
//! does not.

use std::sync::Arc;

use crate::ports::TenantScoped;

/// A store whose plain reads come from `seen`, a copy of the store as both
/// racing requests found it, and whose writes go to `live`, the store as
/// it is now.
///
/// Each port the race tests need has its own impl next to its fake, which
/// says which of its methods are plain reads.
pub struct ReadBeforeWrite<S> {
    /// The store as both requests read it, before either wrote.
    pub seen: S,
    /// The store as it is now, which every write reaches.
    pub live: Arc<S>,
}

impl<S> ReadBeforeWrite<S> {
    /// Plain reads from `seen`, everything else to `live`.
    #[must_use]
    pub fn new(seen: S, live: Arc<S>) -> Self {
        Self { seen, live }
    }
}

impl<S> TenantScoped for ReadBeforeWrite<S> {}
