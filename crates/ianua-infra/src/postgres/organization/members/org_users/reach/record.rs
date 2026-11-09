//! The limited member columns the gateway may read, checked as domain values.

use ianua_domain::domains::organization::members::reach::{MemberReach, MemberReachParts};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const MEMBER_REACH: Stored = Stored("organization member's reach");

/// A member's reach without their sign-in credentials or address.
pub(super) struct ReachRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) role: String,
    pub(super) status: String,
}

impl ReachRecord {
    /// Rebuilds the reach, refusing unknown roles or statuses as corrupt storage.
    pub(super) fn into_reach(self) -> Result<MemberReach, DomainError> {
        Ok(MemberReach::new(MemberReachParts {
            id: OrgUserId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            role: MEMBER_REACH.choice(&self.role)?,
            status: MEMBER_REACH.choice(&self.status)?,
        }))
    }
}
