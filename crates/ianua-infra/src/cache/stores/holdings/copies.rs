//! A copy of access records, made through each record's own rebuild.
//!
//! The records hold aggregates that cannot be cloned, since each carries
//! the events it raised. A cached entry hands out a fresh copy each time:
//! roles and resource types are cloned, and every other record is read
//! into its row and rebuilt through `reconstitute`, so the domain checks
//! the copy as it checks a row read from the store.

use ianua_app::ports::authorization::AccessRecords;
use ianua_domain::domains::authorization::break_glass::{BreakGlassGrant, BreakGlassGrantRow};
use ianua_domain::domains::authorization::group::{
    Group, GroupMembership, GroupMembershipRow, GroupRow,
};
use ianua_domain::domains::authorization::role_assignment::{RoleAssignment, RoleAssignmentRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Revocation;

/// A copy of `records`.
///
/// # Errors
///
/// Returns the error a rebuild refused with, which a record read from the
/// store and kept unchanged never meets.
pub(crate) fn copied(records: &AccessRecords) -> Result<AccessRecords, DomainError> {
    Ok(AccessRecords {
        roles: records.roles.clone(),
        assignments: records
            .assignments
            .iter()
            .map(assignment)
            .collect::<Result<_, _>>()?,
        groups: records.groups.iter().map(group).collect::<Result<_, _>>()?,
        memberships: records
            .memberships
            .iter()
            .map(membership)
            .collect::<Result<_, _>>()?,
        catalogue: records.catalogue.clone(),
        break_glass: records
            .break_glass
            .iter()
            .map(break_glass)
            .collect::<Result<_, _>>()?,
    })
}

/// A copy of the assignment `kept`.
fn assignment(
    kept: &RoleAssignment<ResolvedTenant>,
) -> Result<RoleAssignment<ResolvedTenant>, DomainError> {
    RoleAssignment::reconstitute(RoleAssignmentRow {
        principal: *kept.principal(),
        role_id: *kept.role_id(),
        assigned_by: kept.assigned_by().clone(),
        assigned_at: kept.assigned_at(),
        expires: kept.expires(),
    })
}

/// A copy of the group `kept`.
fn group(kept: &Group<ResolvedTenant>) -> Result<Group<ResolvedTenant>, DomainError> {
    Group::reconstitute(GroupRow {
        id: *kept.id(),
        name: kept.name().clone(),
        origin: kept.origin(),
        place: *kept.place(),
        role_ids: kept.role_ids().to_vec(),
        created_at: kept.created_at(),
        updated_at: kept.updated_at(),
    })
}

/// A copy of the membership `kept`.
fn membership(
    kept: &GroupMembership<ResolvedTenant>,
) -> Result<GroupMembership<ResolvedTenant>, DomainError> {
    GroupMembership::reconstitute(GroupMembershipRow {
        principal: *kept.principal(),
        group_id: *kept.group_id(),
        joined_at: kept.joined_at(),
        expires: kept.expires(),
    })
}

/// A copy of the break-glass grant `kept`.
fn break_glass(kept: &BreakGlassGrant) -> Result<BreakGlassGrant, DomainError> {
    BreakGlassGrant::reconstitute(BreakGlassGrantRow {
        id: *kept.id(),
        tenant_id: *kept.tenant_id(),
        user_id: *kept.user_id(),
        grantee_person: kept.grantee_person().clone(),
        access: kept.access().clone(),
        reason: kept.reason().clone(),
        approved_by: kept.approved_by().clone(),
        expires_at: kept.expires_at(),
        revocation: Revocation::from_stored(kept.revoked_at()),
        created_at: kept.created_at(),
    })
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::authorization::{
        stored_assignment, stored_group, stored_membership, stored_role,
    };
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;

    /// A copy holds the same records as the original: the same roles,
    /// assignments, groups and memberships, field for field.
    #[test]
    fn a_copy_holds_the_same_records() {
        let ann = PrincipalRef::User(UserId::new());
        let viewer = stored_role(
            "viewer",
            vec![SystemPermission::Roles(RoleAction::View)],
            Vec::new(),
        );
        let staff = stored_group("Staff", GroupPlace::TopLevel, vec![*viewer.id()]);
        let records = AccessRecords {
            assignments: vec![stored_assignment(ann, *viewer.id())],
            memberships: vec![stored_membership(ann, *staff.id())],
            roles: vec![viewer],
            groups: vec![staff],
            ..AccessRecords::default()
        };

        let copy = copied(&records).unwrap();

        assert_eq!(copy.roles.len(), 1);
        assert_eq!(copy.roles[0].id(), records.roles[0].id());
        assert_eq!(copy.assignments[0].principal(), &ann);
        assert_eq!(copy.assignments[0].role_id(), records.roles[0].id());
        assert_eq!(copy.groups[0].id(), records.groups[0].id());
        assert_eq!(copy.groups[0].role_ids(), records.groups[0].role_ids());
        assert_eq!(copy.memberships[0].group_id(), records.groups[0].id());
    }
}
