//! Someone who holds rights in a tenant without being one of its users.

use crate::domains::authorization::authority::{ACTIVATES_POLICIES, Holdings};
#[cfg(any(test, feature = "test-support"))]
use crate::domains::authorization::permission::SystemPermission;
use crate::types::Human;

/// Someone who holds rights in a tenant without being one of its users: a
/// member of the organization that owns it, with what their ownership or
/// their tenant grants give them there now.
///
/// Only the organization makes one, from its members and their grants, and
/// only for a member who may sign in. Its fields are private, so nobody
/// claims a member holds a right.
#[derive(Debug, Clone)]
pub struct OutsideHolder {
    who: Human,
    holds: Holdings,
}

impl OutsideHolder {
    /// `who`, holding `holds` in the tenant, as the organization's records
    /// say.
    pub(crate) fn new(who: Human, holds: Holdings) -> Self {
        Self { who, holds }
    }

    /// `who`, holding `system`, as a test says, without the records behind
    /// it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(who: Human, system: &[SystemPermission]) -> Self {
        Self::new(who, Holdings::of(system.to_vec(), Vec::new()))
    }

    /// The member.
    #[must_use]
    pub fn who(&self) -> &Human {
        &self.who
    }

    /// Whether they may approve a policy instead of `approver`: another
    /// person, who may activate policies.
    pub(super) fn approves_instead_of(&self, approver: &Human) -> bool {
        !self.who.is_same_person_as(approver) && self.holds.holds(ACTIVATES_POLICIES)
    }
}
