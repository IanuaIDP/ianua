//! Refusing a change that would leave a tenant nobody can administer.
//!
//! Taking a role from someone, deleting or narrowing a role, taking a role
//! off a group, ending a membership, deleting a group and moving one can
//! each take the last administrator's rights away. The domain decides from
//! who administers before the change and who would after it.
//!
//! A change to named people alone, a role taken from them or a group they
//! leave, reads only their records and the tenant's count of
//! administrators. A change to a role or a group reaches everyone holding
//! it, so it is worked out on every record of the tenant, read once.

use ianua_domain::domains::authorization::group::{Group, GroupRow};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::{RoleAssignment, RoleAssignmentRow};
use ianua_domain::domains::authorization::stewardship::{self, AdministratorCount};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, PrincipalRef, RoleId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, AccessRecords, Holders};
use crate::services::authorization::administrators::administrators_in;
use crate::tenancy::ScopedTenant;

/// A change to a role or a group that can take rights away from everyone
/// holding it.
#[derive(Clone, Copy)]
pub(super) enum Withdrawal<'a> {
    /// `role` is gone. Its direct holders move onto `replacement`, if there
    /// is one, and the groups that carried it no longer do.
    RoleRemoved {
        /// The role deleted.
        role: &'a RoleId,
        /// Where its holders go.
        replacement: Option<&'a RoleId>,
    },
    /// The role grants only what this version of it grants.
    RoleNarrowed(&'a Role<ResolvedTenant>),
    /// `group` no longer carries `role`.
    GroupRole {
        /// The membership tree losing the inherited grant.
        group: &'a GroupId,
        /// The role it no longer carries.
        role: &'a RoleId,
    },
    /// The group is gone, and with it every membership of it.
    GroupDeleted(&'a GroupId),
    /// The group sits where this version of it sits, and its members no
    /// longer hold what the place it left brought.
    GroupMoved(&'a Group<ResolvedTenant>),
}

/// What named people lose: a role given to each of them straight, or their
/// place in a group.
#[derive(Clone, Copy)]
pub(super) enum Lost<'a> {
    /// The role, given straight.
    Role(&'a RoleId),
    /// The place in the group.
    Membership(&'a GroupId),
}

/// Refuses `change` when the tenant, as `before` holds it, has an
/// administrator and would have none after it.
///
/// `before` is every record of the tenant, read once by the caller; the
/// change is worked out on it, so nothing is read again.
///
/// # Errors
///
/// - `AppError::Conflict` when the change takes the last administrator's
///   rights away.
/// - `AppError::Internal` when the records name a role or group that is not
///   there.
pub(super) fn ensure_still_administered(
    tenant: &ScopedTenant,
    before: AccessRecords,
    change: Withdrawal<'_>,
) -> Result<(), AppError> {
    let administrators = administrators_in(&before, tenant)?;
    let after = withdrawn(before, change).map_err(AppError::from_domain)?;
    let remaining = administrators_in(&after, tenant)?;
    let counted = AdministratorCount::new(u64::try_from(administrators.len()).unwrap_or(u64::MAX));
    stewardship::ensure_administrators_remain(counted, &administrators, &remaining)
        .map_err(AppError::from_domain)
}

/// Refuses taking `lost` from each of `losing` when the tenant has
/// administrators and every one of them is among those losing it.
///
/// Only the records of the people `losing` are read, with the tenant's
/// count of administrators, never every record of the tenant. Both are
/// read under the tenant's hold on its grants, which lasts until the
/// request's unit of work settles, so two withdrawals from the last two
/// administrators at once are counted one after the other.
///
/// # Errors
///
/// - `AppError::Conflict` when the change takes the last administrator's
///   rights away.
/// - `AppError::Internal` when the records cannot be read, or name a role or
///   group that is not there.
pub(super) async fn ensure_administered_after_losing(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    losing: &[PrincipalRef],
    lost: Lost<'_>,
) -> Result<(), AppError> {
    if losing.is_empty() {
        return Ok(());
    }
    store.hold_grants(tenant).await.or_internal()?;
    let holders = Holders {
        principals: losing,
        groups: &[],
        roles: &[],
    };
    let held = store
        .load_held_by_all(tenant, holders)
        .await
        .or_internal()?
        .into_records();
    let counted = store.count_administrators(tenant).await.or_internal()?;
    let before = administrators_in(&held, tenant)?;
    let after = administrators_in(&taken_from(held, losing, lost), tenant)?;
    stewardship::ensure_administrators_remain(counted, &before, &after)
        .map_err(AppError::from_domain)
}

/// `records` once each of `losing` has lost `lost`.
fn taken_from(
    mut records: AccessRecords,
    losing: &[PrincipalRef],
    lost: Lost<'_>,
) -> AccessRecords {
    match lost {
        Lost::Role(role) => records
            .assignments
            .retain(|held| !(losing.contains(held.principal()) && held.role_id() == role)),
        Lost::Membership(group) => records
            .memberships
            .retain(|held| !(losing.contains(held.principal()) && held.group_id() == group)),
    }
    records
}

/// `records` as `change` would leave them.
fn withdrawn(
    mut records: AccessRecords,
    change: Withdrawal<'_>,
) -> Result<AccessRecords, DomainError> {
    match change {
        Withdrawal::RoleRemoved { role, replacement } => {
            records = without_role(records, role, replacement)?;
        }
        Withdrawal::RoleNarrowed(narrowed) => {
            records.roles.retain(|held| held.id() != narrowed.id());
            records.roles.push(narrowed.clone());
        }
        Withdrawal::GroupRole { group, role } => {
            records.groups = each_group(&records.groups, |held| {
                group_without(held, |id| !(held.id() == group && id == role))
            })?;
        }
        Withdrawal::GroupDeleted(group) => {
            records.groups.retain(|held| held.id() != group);
            records.memberships.retain(|held| held.group_id() != group);
        }
        Withdrawal::GroupMoved(moved) => {
            records.groups.retain(|held| held.id() != moved.id());
            records.groups.push(group_without(moved, |_| true)?);
        }
    }
    Ok(records)
}

/// `records` without `role`: no group carries it, and its holders hold
/// `replacement` instead, or nothing.
fn without_role(
    mut records: AccessRecords,
    role: &RoleId,
    replacement: Option<&RoleId>,
) -> Result<AccessRecords, DomainError> {
    records.roles.retain(|held| held.id() != role);
    records.groups = each_group(&records.groups, |held| group_without(held, |id| id != role))?;
    records.assignments = records
        .assignments
        .into_iter()
        .filter_map(|held| moved_onto(held, role, replacement).transpose())
        .collect::<Result<_, _>>()?;
    Ok(records)
}

/// `held`, moved onto `replacement` when it gives `role`, or dropped when
/// there is no replacement.
fn moved_onto(
    held: RoleAssignment<ResolvedTenant>,
    role: &RoleId,
    replacement: Option<&RoleId>,
) -> Result<Option<RoleAssignment<ResolvedTenant>>, DomainError> {
    if held.role_id() != role {
        return Ok(Some(held));
    }
    let Some(replacement) = replacement else {
        return Ok(None);
    };
    RoleAssignment::reconstitute(RoleAssignmentRow {
        principal: *held.principal(),
        role_id: *replacement,
        assigned_by: held.assigned_by().clone(),
        assigned_at: held.assigned_at(),
        expires: held.expires(),
    })
    .map(Some)
}

/// Every group of `groups`, each as `change` leaves it.
fn each_group(
    groups: &[Group<ResolvedTenant>],
    change: impl Fn(&Group<ResolvedTenant>) -> Result<Group<ResolvedTenant>, DomainError>,
) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
    groups.iter().map(change).collect()
}

/// `group`, carrying only the roles `keep` keeps.
fn group_without(
    group: &Group<ResolvedTenant>,
    keep: impl Fn(&RoleId) -> bool,
) -> Result<Group<ResolvedTenant>, DomainError> {
    Group::reconstitute(GroupRow {
        id: *group.id(),
        name: group.name().clone(),
        origin: group.origin(),
        place: *group.place(),
        role_ids: group.role_ids().iter().copied().filter(keep).collect(),
        created_at: group.created_at(),
        updated_at: group.updated_at(),
    })
}
