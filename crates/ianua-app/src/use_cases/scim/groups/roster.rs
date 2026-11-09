//! What the SCIM group use cases share: finding a group the directory
//! keeps, its users, putting users into it, and refusing a change that
//! leaves the tenant nobody to administer it or breaks its separation of
//! duties.
//!
//! A group a person keeps in the dashboard is not the directory's to see or
//! change, so to a SCIM call it does not exist.

use std::collections::HashMap;

use ianua_domain::domains::authorization::group::{Group, GroupMembership, GroupOrigin};
use ianua_domain::domains::authorization::stewardship;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, GroupId, Label, PrincipalRef, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, GroupMembershipStore, GroupStore, Holders};
use crate::ports::identity::UserStore;
use crate::services::authorization::administrators::administrators_in;
use crate::services::authorization::duties::{DutySources, ensure_joiners_keep_duties};
use crate::tenancy::ScopedTenant;
use crate::use_cases::authorization::holdings::lapsed::{RanOut, place_cleared};
use crate::use_cases::scim::groups::fields::ScimGroup;

/// A user of the tenant joining or leaving a group, with the label the
/// record names them by.
pub(super) struct Member {
    /// The user.
    pub(super) id: UserId,
    /// Their address, or their id when the account is gone.
    pub(super) label: EventLabel,
}

/// Users leaving a group, which can take rights away from them.
pub(super) struct Withdrawn<'a> {
    /// The group they leave.
    pub(super) group: &'a GroupId,
    /// Who leaves.
    pub(super) leaving: &'a [UserId],
}

/// The tenant's group with `group_id`, when the directory keeps it.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such group, or a person
///   keeps it in the dashboard.
/// - `AppError::Internal` on storage failure.
pub(super) async fn directory_group(
    groups: &dyn GroupStore,
    tenant: &ScopedTenant,
    group_id: &GroupId,
) -> Result<Group<ResolvedTenant>, AppError> {
    groups
        .find_by_id(tenant, group_id)
        .await
        .or_internal()?
        .filter(|group| group.origin() == GroupOrigin::Directory)
        .ok_or_else(|| {
            AppError::NotFound(message!("authorization-group-not-found", "group not found"))
        })
}

/// Refuses `name` when another group of the tenant carries it. The group
/// `keeping` it may keep its own name.
///
/// # Errors
///
/// - `AppError::Conflict` if another group has the name.
/// - `AppError::Internal` on storage failure.
pub(super) async fn ensure_display_name_free(
    groups: &dyn GroupStore,
    tenant: &ScopedTenant,
    name: &Label,
    keeping: Option<&GroupId>,
) -> Result<(), AppError> {
    let existing = groups.find_by_name(tenant, name).await.or_internal()?;
    let taken = existing.is_some_and(|group| Some(group.id()) != keeping);
    if taken {
        return Err(AppError::Conflict(message!(
            "scim-a-group-with-this-displayname-already",
            "a group with this displayName already exists"
        )));
    }
    Ok(())
}

/// Refuses `withdrawn` when the users leaving are every administrator the
/// tenant counts, read from the leavers' own records and the tenant's
/// count, never from every record. Both are read under the tenant's hold
/// on its grants, so two directory pushes taking the last administrators
/// out at once are counted one after the other.
///
/// # Errors
///
/// - `AppError::Conflict` when the tenant has an administrator and would
///   have none after `withdrawn`.
/// - `AppError::Internal` when the records cannot be read, or name a role
///   or group that is not there.
pub(super) async fn ensure_leaves_an_administrator(
    records: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    withdrawn: Withdrawn<'_>,
) -> Result<(), AppError> {
    let Withdrawn { group, leaving } = withdrawn;
    if leaving.is_empty() {
        return Ok(());
    }
    records.hold_grants(tenant).await.or_internal()?;
    let counted = records.count_administrators(tenant).await.or_internal()?;
    let principals: Vec<PrincipalRef> = leaving.iter().copied().map(PrincipalRef::User).collect();
    let holders = Holders {
        principals: &principals,
        groups: &[],
        roles: &[],
    };
    let mut theirs = records
        .load_held_by_all(tenant, holders)
        .await
        .or_internal()?
        .into_records();
    let before = administrators_in(&theirs, tenant)?;
    theirs.memberships.retain(|held| {
        held.group_id() != group
            || !leaving
                .iter()
                .any(|user| *held.principal() == PrincipalRef::User(*user))
    });
    let after = administrators_in(&theirs, tenant)?;
    stewardship::ensure_administrators_remain(counted, &before, &after)
        .map_err(AppError::from_domain)
}

/// Refuses `joining` `group` when one of them sitting in it would hold both
/// roles of one of the tenant's separation rules, through what the group
/// and the groups above it hold.
///
/// The directory asked for the change, so a member that breaks a rule
/// refuses the whole of it, before anything is written, and the directory
/// is told which rule.
///
/// # Errors
///
/// - `AppError::Conflict` naming the rule a member would break.
/// - `AppError::Internal` when the rules or the records cannot be read, or
///   the records name a role or group that is not there.
pub(super) async fn ensure_joining_keeps_duties(
    duties: DutySources<'_>,
    tenant: &ScopedTenant,
    group: &Group<ResolvedTenant>,
    joining: &[Member],
) -> Result<(), AppError> {
    let principals: Vec<PrincipalRef> = joining
        .iter()
        .map(|member| PrincipalRef::User(member.id))
        .collect();
    ensure_joiners_keep_duties(duties, tenant, group.id(), &principals).await
}

/// The users in `memberships`. Agents and other members are the tenant's
/// to manage, so the directory neither sees nor changes them.
pub(super) fn user_members<'a>(
    memberships: impl IntoIterator<Item = &'a GroupMembership<ResolvedTenant>>,
) -> Vec<UserId> {
    memberships
        .into_iter()
        .filter_map(|membership| match membership.principal() {
            PrincipalRef::User(user) => Some(*user),
            PrincipalRef::OrgUser(_) | PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => None,
        })
        .collect()
}

/// The places among `held` still in force now.
///
/// A place that ran out counts for nothing, whether or not the sweep has
/// cleared it yet. A directory shown it as present would never add its
/// member back, so every read and every change of a directory's groups
/// looks at these alone.
pub(super) fn in_force(
    held: Vec<GroupMembership<ResolvedTenant>>,
) -> Vec<GroupMembership<ResolvedTenant>> {
    let now = clock::now();
    held.into_iter()
        .filter(|membership| membership.is_in_force(now))
        .collect()
}

/// `group` with the users in it now, a place that ran out left out.
///
/// # Errors
///
/// - `AppError::Internal` when the memberships cannot be read.
pub(super) async fn with_members(
    memberships: &dyn GroupMembershipStore,
    tenant: &ScopedTenant,
    group: Group<ResolvedTenant>,
) -> Result<ScimGroup, AppError> {
    let held = memberships
        .find_by_group(tenant, group.id())
        .await
        .or_internal()?;
    let members = user_members(&in_force(held));
    Ok(ScimGroup { group, members })
}

/// Each of `ids`, read in one go, once every one is a user of the tenant.
///
/// # Errors
///
/// - `AppError::Domain` when one is not a user of the tenant.
/// - `AppError::Internal` on storage failure.
pub(super) async fn tenant_users(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    ids: &[UserId],
) -> Result<Vec<Member>, AppError> {
    let labels = member_labels(users, tenant, ids).await?;
    ids.iter()
        .map(|id| {
            let label = labels.get(id).cloned().ok_or_else(|| {
                AppError::from_domain(DomainError::invalid(message!(
                    "scim-a-member-is-not-a-user",
                    "a member is not a user of this tenant"
                )))
            })?;
            Ok(Member { id: *id, label })
        })
        .collect()
}

/// The address of each of `ids` the tenant has a user for, read in one go.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn member_labels(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    ids: &[UserId],
) -> Result<HashMap<UserId, EventLabel>, AppError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let found = users.find_by_ids(tenant, ids).await.or_internal()?;
    Ok(found
        .iter()
        .map(|user| (*user.id(), EventLabel::of(user.email().as_str())))
        .collect())
}

/// Puts each of `joining` into `group`, because the directory `endpoint`
/// speaks for says so, saving them together, and returns what each
/// membership raised.
///
/// # Errors
///
/// - `AppError::Forbidden` when the endpoint is switched off or a person
///   keeps the group.
/// - `AppError::Internal` when the memberships cannot be saved.
pub(super) async fn joined(
    memberships: &dyn GroupMembershipStore,
    tenant: &ScopedTenant,
    endpoint: &ScimEndpoint<ResolvedTenant>,
    group: &Group<ResolvedTenant>,
    joining: Vec<Member>,
) -> Result<Vec<DomainEvent>, AppError> {
    if joining.is_empty() {
        return Ok(Vec::new());
    }
    let mut made = joining
        .into_iter()
        .map(|member| GroupMembership::from_directory(member.id, group, endpoint, member.label))
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::from_domain)?;
    memberships.save_all(tenant, &made).await.or_internal()?;
    Ok(made
        .iter_mut()
        .flat_map(|membership| membership.take_events(tenant))
        .collect())
}

/// Clears away each of `joining`'s places in `group` that ran out and the
/// sweep has not cleared, and returns the record of each end, the
/// platform's, so the places a directory gives again do not replace them
/// unrecorded. A group the directory just made has none, so only a push to
/// an existing group asks.
///
/// # Errors
///
/// - `AppError::Internal` when the places cannot be read or cleared.
/// - `AppError::Domain` when a place found cannot be ended.
pub(super) async fn cleared_before_joining(
    memberships: &dyn GroupMembershipStore,
    tenant: &ScopedTenant,
    group: &Group<ResolvedTenant>,
    joining: &[Member],
) -> Result<Vec<DomainEvent>, AppError> {
    let now = clock::now();
    let mut ended = Vec::new();
    for member in joining {
        let principal = PrincipalRef::User(member.id);
        let ran_out = RanOut {
            principal: &principal,
            label: member.label.clone(),
            now,
        };
        ended.extend(place_cleared(memberships, tenant, group, ran_out).await?);
    }
    Ok(ended)
}
