//! How an owner hands the organization over to another member in one step.
//!
//! Without it, a hand-over is two changes: make the heir an owner, then step
//! down. Between them the organization has two owners, and if the second
//! change never comes, it keeps both. One step leaves exactly the owners it
//! had, with the heir in place of the one who left.

use crate::domains::organization::events::members::{OrgOwnershipTransferred, OrgUserRoleChanged};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::message;
use crate::shared::errors::DomainError;

/// The role an owner keeps after handing the organization over.
const FORMER_OWNER_ROLE: OrgRole = OrgRole::Admin;

impl OrgUser {
    /// Hands this owner's ownership to `heir`, as the owner decides through
    /// `by`. The heir becomes an owner and this member an admin. Raises
    /// `organization.org_user_role_changed` for each, and
    /// `organization.ownership_transferred` once.
    ///
    /// Only the owner themselves hands their ownership over, from a session
    /// they signed in to. Mallory holds a key Ann minted. Without these
    /// checks, she makes her own account the owner and Ann a mere admin.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not this member, acts
    ///   through a key, or is not an active member of the organization now.
    /// - [`DomainError::Forbidden`] when this member is not an owner.
    /// - [`DomainError::Forbidden`] when `heir` belongs to another
    ///   organization.
    /// - [`DomainError::Validation`] when `heir` is this member.
    /// - [`DomainError::Conflict`] when `heir` is not active, or is already
    ///   an owner.
    pub fn hand_ownership_to(
        &mut self,
        heir: &mut OrgUser,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_hands_over_own(by)?;
        ensure_may_inherit(self, heir)?;
        let from = self.change_role_to(FORMER_OWNER_ROLE);
        let heir_from = heir.change_role_to(OrgRole::Owner);
        self.raise_role_change(from);
        heir.raise_role_change(heir_from);
        heir.raised.raise_organization(OrgOwnershipTransferred {
            organization_id: self.organization_id,
            from: self.id,
            from_label: self.label(),
            to: heir.id,
            to_label: heir.label(),
            occurred_at: heir.updated_at,
        });
        Ok(())
    }

    /// Refuses unless `by` is this owner, signed in, acting on their own
    /// organization now.
    fn ensure_hands_over_own(&self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        if !by.is_member(&self.id) || by.session().is_none() {
            return Err(DomainError::forbidden(message!(
                "organization-only-the-owner-signed-in-hands",
                "only the owner, signed in, hands over their own ownership"
            )));
        }
        by.ensure_genuine(&self.organization_id)?;
        if self.role != OrgRole::Owner {
            return Err(DomainError::forbidden(message!(
                "organization-only-an-owner-hands-over-ownership",
                "only an owner hands over ownership"
            )));
        }
        Ok(())
    }

    /// Gives this member `role`, returning the role it replaced.
    fn change_role_to(&mut self, role: OrgRole) -> OrgRole {
        let from = std::mem::replace(&mut self.role, role);
        self.touch();
        from
    }

    /// Raises the move from `from` to the role this member holds now.
    fn raise_role_change(&mut self, from: OrgRole) {
        self.raised.raise_organization(OrgUserRoleChanged {
            organization_id: self.organization_id,
            org_user_id: self.id,
            org_user_label: self.label(),
            from,
            to: self.role,
            occurred_at: self.updated_at,
        });
    }
}

/// Refuses `heir` taking over from `owner` unless they are another active
/// member of the same organization who is not an owner yet.
fn ensure_may_inherit(owner: &OrgUser, heir: &OrgUser) -> Result<(), DomainError> {
    if heir.organization_id() != owner.organization_id() {
        return Err(DomainError::forbidden(message!(
            "organization-ownership-goes-only-to-a-member",
            "ownership goes only to a member of the same organization"
        )));
    }
    if heir.id() == owner.id() {
        return Err(DomainError::invalid(message!(
            "organization-an-owner-hands-ownership-to-someone",
            "an owner hands ownership to someone else"
        )));
    }
    if heir.status() != OrgUserStatus::Active {
        return Err(DomainError::conflict(message!(
            "organization-ownership-goes-only-to-an-active",
            "ownership goes only to an active member"
        )));
    }
    if heir.role() == OrgRole::Owner {
        return Err(DomainError::conflict(message!(
            "organization-the-member-is-already-an-owner",
            "the member is already an owner"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::members::control::Carried;
    use crate::domains::organization::members::control::tests::{
        acting, founder, joined_as, key_of, session_of,
    };
    use crate::domains::organization::members::org_user::tests::row_of;
    use crate::domains::organization::status::{OrgStanding, OrganizationStatus};
    use crate::test_support::events::raised_complete_names;

    /// Ann, Acme's owner, hands Acme to Bob, an admin. Bob is now the owner
    /// and Ann an admin, and the hand-over is on record once.
    #[test]
    fn an_owner_hands_the_organization_to_an_admin() {
        let mut ann = founder();
        let mut bob = joined_as(&ann, OrgRole::Admin);
        let session = session_of(&ann);
        let snapshot = founder_copy(&ann);

        ann.hand_ownership_to(&mut bob, &acting(&snapshot, &session))
            .unwrap();

        assert_eq!(bob.role(), OrgRole::Owner);
        assert_eq!(ann.role(), OrgRole::Admin);
        assert!(
            raised_complete_names(&mut bob).contains(&"organization.ownership_transferred".into())
        );
        assert_eq!(
            raised_complete_names(&mut ann).last().map(String::as_str),
            Some("organization.org_user_role_changed")
        );
    }

    /// Mallory cannot transfer Ann's ownership through her admin session;
    /// Ann stays an owner and Mallory stays an admin.
    #[test]
    fn nobody_hands_over_someone_elses_ownership() {
        let mut ann = founder();
        let mut mallory = joined_as(&ann, OrgRole::Admin);
        let mallory_copy = founder_copy(&mallory);
        let session = session_of(&mallory_copy);

        let refused = ann.hand_ownership_to(&mut mallory, &acting(&mallory_copy, &session));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.role(), OrgRole::Owner);
        assert_eq!(mallory.role(), OrgRole::Admin);
    }

    /// An owner's fully scoped key cannot transfer ownership to Mallory,
    /// who remains a member.
    #[test]
    fn a_key_hands_over_no_ownership() {
        let mut ann = founder();
        let mut mallory = joined_as(&ann, OrgRole::Member);
        let snapshot = founder_copy(&ann);
        let key = key_of(&snapshot, &["org:*:*"]);
        let through_key = OrgControl::new(
            OrgStanding::new(*snapshot.organization_id(), OrganizationStatus::Active),
            &snapshot,
            Carried::Key(&key),
        );

        let refused = ann.hand_ownership_to(&mut mallory, &through_key);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(mallory.role(), OrgRole::Member);
    }

    /// Ann cannot transfer ownership to another organization's admin;
    /// the proposed recipient remains an admin.
    #[test]
    fn ownership_never_leaves_the_organization() {
        let mut ann = founder();
        let stranger = founder();
        let snapshot = founder_copy(&ann);
        let session = session_of(&snapshot);
        let mut outsider = joined_as(&stranger, OrgRole::Admin);

        let refused = ann.hand_ownership_to(&mut outsider, &acting(&snapshot, &session));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(outsider.role(), OrgRole::Admin);
    }

    /// Ann hands Acme to Carol, who is already a co-owner. Refused: nothing
    /// would move, and Ann would lose her role for no one.
    #[test]
    fn ownership_goes_to_someone_not_yet_an_owner() {
        let mut ann = founder();
        let mut carol = joined_as(&ann, OrgRole::Owner);
        let snapshot = founder_copy(&ann);
        let session = session_of(&snapshot);

        let refused = ann.hand_ownership_to(&mut carol, &acting(&snapshot, &session));

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(ann.role(), OrgRole::Owner);
    }

    /// A copy of `member` to act through, so the member can be changed while
    /// the copy signs the change.
    fn founder_copy(member: &OrgUser) -> OrgUser {
        OrgUser::reconstitute(row_of(member)).unwrap()
    }
}
