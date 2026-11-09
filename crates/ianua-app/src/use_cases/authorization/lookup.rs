//! Loading the group, resource type, policy or access records a caller
//! names, which the use cases that change one start with, and refusing a
//! name another role or group already carries.

use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::version::PolicyHistory;
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{GroupId, Label, ResourceTypeId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, GroupStore, HeldRecords, Holder, Holders, PolicyStore,
    ResourceTypeStore, RoleStore,
};
use crate::tenancy::ScopedTenant;

/// Refuses a role name another role of the tenant already carries.
///
/// # Errors
///
/// - `AppError::Conflict` if the name is taken.
/// - `AppError::Internal` on storage failure.
pub(super) async fn ensure_role_name_free(
    store: &dyn RoleStore,
    tenant: &ScopedTenant,
    name: &Label,
) -> Result<(), AppError> {
    let existing = store.find_by_name(tenant, name).await.or_internal()?;
    match existing {
        Some(_) => Err(AppError::Conflict(message!(
            "authorization-role-name-already-exists",
            "role name already exists"
        ))),
        None => Ok(()),
    }
}

/// Refuses a group name another group of the tenant already carries. The
/// group `keeping` it may keep its own name.
///
/// # Errors
///
/// - `AppError::Conflict` if another group has the name.
/// - `AppError::Internal` on storage failure.
pub(super) async fn ensure_group_name_free(
    store: &dyn GroupStore,
    tenant: &ScopedTenant,
    name: &Label,
    keeping: Option<&GroupId>,
) -> Result<(), AppError> {
    let existing = store.find_by_name(tenant, name).await.or_internal()?;
    match existing {
        Some(group) if Some(group.id()) != keeping => Err(AppError::Conflict(message!(
            "authorization-group-name-already-exists",
            "group name already exists"
        ))),
        Some(_) | None => Ok(()),
    }
}

/// The tenant's group with `group_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such group.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_group(
    store: &dyn GroupStore,
    tenant: &ScopedTenant,
    group_id: &GroupId,
) -> Result<Group<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, group_id)
        .await
        .or_internal()?
        .or_not_found(message!("authorization-group-not-found", "group not found"))
}

/// The tenant's resource type with `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant's catalogue has no such entry.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_resource_type(
    store: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
    id: &ResourceTypeId,
) -> Result<ResourceType<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-resource-type-not-found",
            "resource type not found"
        ))
}

/// Every version of the tenant's policy, as stored now. Read through
/// `PolicyHistory::of`, which refuses a history no tenant can have.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn policy_versions(
    store: &dyn PolicyStore,
    tenant: &ScopedTenant,
) -> Result<Vec<PolicySet>, AppError> {
    store.find_versions(tenant).await.or_internal()
}

/// The tenant's open draft, being written or in review, for a caller about
/// to edit or move it.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no open draft.
/// - `AppError::Internal` on storage failure, or a history with two open
///   drafts or two live versions.
pub(super) async fn existing_draft(
    store: &dyn PolicyStore,
    tenant: &ScopedTenant,
) -> Result<PolicySet, AppError> {
    let versions = policy_versions(store, tenant).await?;
    PolicyHistory::of(&versions)
        .map_err(AppError::from_domain)?
        .open()
        .cloned()
        .or_not_found(message!(
            "authorization-this-tenant-has-no-open-policy",
            "this tenant has no open policy draft"
        ))
}

/// The tenant's policy that is currently deciding requests.
///
/// # Errors
///
/// - `AppError::NotFound` if no policy is active.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_active_policy(
    store: &dyn PolicyStore,
    tenant: &ScopedTenant,
) -> Result<PolicySet, AppError> {
    store
        .find_active(tenant)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-no-active-policy",
            "no active policy"
        ))
}

/// Everything the tenant stores about who holds what, as stored now, read
/// under the tenant's hold on its grants to change them: the hold lasts
/// until the unit of work settles, so a change checked against these
/// records is not raced by another, such as two group moves that together
/// close a loop.
///
/// # Errors
///
/// - `AppError::Internal` if the hold cannot be taken, or the records
///   cannot be read or one is broken.
pub(super) async fn access_records(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
) -> Result<AccessRecords, AppError> {
    store.hold_grants(tenant).await.or_internal()?;
    store.load(tenant).await.or_internal()
}

/// What decides `holder`'s holdings in the tenant, as stored now, and no
/// one else's.
///
/// # Errors
///
/// - `AppError::Internal` if the records cannot be read.
pub(super) async fn held_records(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    holder: Holder<'_>,
) -> Result<HeldRecords, AppError> {
    store.load_held_by(tenant, holder).await.or_internal()
}

/// What decides what sitting at `place` brings: the group it is under with
/// every group above it and the roles they carry, and nothing else of the
/// tenant's records. A place at the top reads no group.
///
/// # Errors
///
/// - `AppError::Internal` if the records cannot be read.
pub(super) async fn place_records(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    place: GroupPlace,
) -> Result<AccessRecords, AppError> {
    let groups: Vec<GroupId> = place.parent().copied().into_iter().collect();
    let holders = Holders {
        principals: &[],
        groups: &groups,
        roles: &[],
    };
    let held = store
        .load_held_by_all(tenant, holders)
        .await
        .or_internal()?;
    Ok(held.into_records())
}
