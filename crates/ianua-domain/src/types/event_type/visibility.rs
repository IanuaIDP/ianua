//! Which events one person or machine may see.

use crate::types::EventType;

/// Which events someone may see.
///
/// Anything that sends events onwards for someone asks this first. A
/// webhook receives no event its creator could not read in the dashboard.
/// A workflow starts on no event the person it acts for could not read.
pub trait EventVisibility {
    /// Whether events of `event_type` are visible to them.
    fn may_see(&self, event_type: &EventType) -> bool;
}
