//! The organization's members as they stand now, so a change keeps an
//! owner.
//!
//! An organization with no active owner cannot be run again. Nobody may
//! invite, grant tenants or change the sign-in settings, and on a
//! self-hosted install there is nobody to ask. The rule spans every member,
//! so one member's change is checked against all of them.

use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::message;
use crate::shared::errors::DomainError;

/// The members of one organization, freshly loaded.
#[derive(Debug, Clone, Copy)]
pub struct Owners<'a> {
    members: &'a [OrgUser],
}

impl<'a> Owners<'a> {
    /// The organization's members, as the caller loaded them just now.
    #[must_use]
    pub fn of(members: &'a [OrgUser]) -> Self {
        Self { members }
    }

    /// Refuses taking `leaving` away as an active owner unless another
    /// active owner of its organization stays.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when `leaving` is the last active owner.
    pub(crate) fn ensure_another_besides(&self, leaving: &OrgUser) -> Result<(), DomainError> {
        let another = self.members.iter().any(|member| {
            member.organization_id() == leaving.organization_id()
                && member.id() != leaving.id()
                && member.role() == OrgRole::Owner
                && member.status() == OrgUserStatus::Active
        });
        if !another {
            return Err(DomainError::conflict(message!(
                "organization-an-organization-keeps-at-least-one",
                "an organization keeps at least one active owner"
            )));
        }
        Ok(())
    }
}
