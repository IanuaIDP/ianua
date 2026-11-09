//! An organization member as a check of their reach into a tenant reads
//! them: who they are, whose member, in what role and status, and nothing
//! of how they sign in.
//!
//! The gateway judges a request an agent makes for an organization member
//! while the member is signed out. Its role may not read a member's address
//! or password hash, so it reads these four, and the tenant rule on them is
//! the same one an [`OrgUser`](crate::domains::organization::members::org_user::OrgUser) is held to.

use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::types::{OrgUserId, OrganizationId};

/// An organization member's identity, organization, role and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberReach {
    id: OrgUserId,
    organization_id: OrganizationId,
    role: OrgRole,
    status: OrgUserStatus,
}

/// What a [`MemberReach`] is made of.
#[derive(Debug, Clone, Copy)]
pub struct MemberReachParts {
    /// The member.
    pub id: OrgUserId,
    /// The ownership boundary against which tenant access is checked.
    pub organization_id: OrganizationId,
    /// The membership authority used to derive permissions and tenant reach.
    pub role: OrgRole,
    /// Their account's status.
    pub status: OrgUserStatus,
}

impl MemberReach {
    /// The reach `parts` describe.
    #[must_use]
    pub fn new(parts: MemberReachParts) -> Self {
        Self {
            id: parts.id,
            organization_id: parts.organization_id,
            role: parts.role,
            status: parts.status,
        }
    }

    /// The member.
    #[must_use]
    pub fn id(&self) -> &OrgUserId {
        &self.id
    }

    /// The ownership boundary against which tenant access is checked.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The membership authority used to derive permissions and tenant reach.
    #[must_use]
    pub fn role(&self) -> OrgRole {
        self.role
    }

    /// Their account's status.
    #[must_use]
    pub fn status(&self) -> OrgUserStatus {
        self.status
    }
}
