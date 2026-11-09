//! Bounded scans of expired role assignments and group memberships.

use ianua_domain::domains::authorization::group::GroupMembership;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{GroupId, PrincipalRef, RoleId};
use time::OffsetDateTime;

/// The maximum number of expired holdings materialized by one read.
pub(crate) const HOLDING_BATCH_SIZE: usize = 500;

/// One scan of expired holdings, with a fixed cutoff and a complete last key.
#[derive(Debug, Clone, Copy)]
pub struct HoldingBatch<P> {
    /// The cutoff captured once for the whole sweep.
    pub now: OffsetDateTime,
    /// The last row attempted, including one whose mutation failed.
    pub after: Option<P>,
}

/// The last role assignment attempted in expiry, role, kind and principal order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignmentPosition {
    /// The assignment's expiry, which is present for every swept row.
    pub expires_at: OffsetDateTime,
    /// The role granted by the assignment.
    pub role_id: RoleId,
    /// The holder's complete identity, including its kind.
    pub principal: PrincipalRef,
}

impl AssignmentPosition {
    /// The complete cursor of an expiring assignment, or none for a permanent grant.
    #[must_use]
    pub fn of(assignment: &RoleAssignment<ResolvedTenant>) -> Option<Self> {
        Some(Self {
            expires_at: assignment.expires().instant()?,
            role_id: *assignment.role_id(),
            principal: *assignment.principal(),
        })
    }
}

/// The last membership attempted in expiry, group, kind and principal order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipPosition {
    /// The membership's expiry, which is present for every swept row.
    pub expires_at: OffsetDateTime,
    /// The group joined by the member.
    pub group_id: GroupId,
    /// The member's complete identity, including its kind.
    pub principal: PrincipalRef,
}

impl MembershipPosition {
    /// The complete cursor of an expiring membership, or none for permanent membership.
    #[must_use]
    pub fn of(membership: &GroupMembership<ResolvedTenant>) -> Option<Self> {
        Some(Self {
            expires_at: membership.expires().instant()?,
            group_id: *membership.group_id(),
            principal: *membership.principal(),
        })
    }
}
