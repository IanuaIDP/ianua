//! Loading the request a caller names, and the role or group a request
//! asks for, which the access request use cases start with.

use ianua_domain::domains::authorization::access_request::{
    AccessRequest, AskedAccess, AskedGrant,
};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::domains::authorization::group_tree::Conferred;
use ianua_domain::domains::authorization::request_policy::AccessRequestPolicy;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{AccessRequestId, EventLabel};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{
    AccessRecordStore, AccessRequestPolicyStore, AccessRequestStore, GroupStore, RoleStore,
};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::lookup::{existing_group, place_records};

/// What a caller is told when their answer or withdrawal lost to another
/// one saved since they read the request.
pub(super) const ANSWERED_MEANWHILE: &str =
    "the request was answered, withdrawn or ran out meanwhile";

/// The stores the role or group a request asks for is read from.
#[derive(Clone, Copy)]
pub(super) struct AskedSources<'a> {
    /// The tenant's roles.
    pub(super) roles: &'a dyn RoleStore,
    /// The tenant's groups.
    pub(super) groups: &'a dyn GroupStore,
    /// Who holds what, for what sitting in a group brings.
    pub(super) records: &'a dyn AccessRecordStore,
}

impl<'a> AskedSources<'a> {
    /// The asked role or group read from `roles` and `groups`, and what a
    /// group brings from `records`.
    pub(super) fn of(
        roles: &'a dyn RoleStore,
        groups: &'a dyn GroupStore,
        records: &'a dyn AccessRecordStore,
    ) -> Self {
        Self {
            roles,
            groups,
            records,
        }
    }
}

/// The role or group a request asks for, loaded so an approver's rights
/// can be checked against what it gives.
pub(super) enum Asked {
    /// The requested permission bundle used to check the approver's reach.
    Role(Role<ResolvedTenant>),
    /// The group, with what sitting in it brings.
    Group(Group<ResolvedTenant>, Conferred),
}

impl Asked {
    /// What an approver gives, as the domain checks it.
    pub(super) fn grant(&self) -> AskedGrant<'_, ResolvedTenant> {
        match self {
            Self::Role(role) => AskedGrant::Role(role),
            Self::Group(group, conferred) => AskedGrant::Group(group, conferred),
        }
    }
}

/// The tenant's request `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such request.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_request(
    store: &dyn AccessRequestStore,
    tenant: &ScopedTenant,
    id: &AccessRequestId,
) -> Result<AccessRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-access-request-not-found",
            "access request not found"
        ))
}

/// The tenant's request `id`, read as missing unless `authority` is the
/// person who asked it, so nobody can tell someone else's request from one
/// that does not exist.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such request, or someone
///   else asked it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_request(
    store: &dyn AccessRequestStore,
    tenant: &ScopedTenant,
    id: &AccessRequestId,
    authority: &TenantAuthority,
) -> Result<AccessRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|request| request.requester().is_same_person_as(authority.who()))
        .or_not_found(message!(
            "authorization-access-request-not-found",
            "access request not found"
        ))
}

/// The role or group `asked` names, loaded with what it gives.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such role or group.
/// - `AppError::Internal` on storage failure, or a group tree naming a
///   group or role that is not there.
pub(super) async fn existing_asked(
    sources: AskedSources<'_>,
    tenant: &ScopedTenant,
    asked: AskedAccess,
) -> Result<Asked, AppError> {
    match asked {
        AskedAccess::Role(id) => Ok(Asked::Role(
            existing_role(sources.roles, tenant, &id).await?,
        )),
        AskedAccess::Group(id) => {
            let group = existing_group(sources.groups, tenant, &id).await?;
            let place = GroupPlace::Under(id);
            let records = place_records(sources.records, tenant, place).await?;
            let conferred = conferred_at(&records, place)?;
            Ok(Asked::Group(group, conferred))
        }
    }
}

/// How the audit trail names the role or group `asked` names.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such role or group.
/// - `AppError::Internal` on storage failure.
pub(super) async fn asked_label(
    roles: &dyn RoleStore,
    groups: &dyn GroupStore,
    tenant: &ScopedTenant,
    asked: AskedAccess,
) -> Result<EventLabel, AppError> {
    let name = match asked {
        AskedAccess::Role(id) => existing_role(roles, tenant, &id).await?.name().clone(),
        AskedAccess::Group(id) => existing_group(groups, tenant, &id).await?.name().clone(),
    };
    Ok(EventLabel::of(name.as_str()))
}

/// How the audit trail names the person who asked, as the request does.
pub(super) fn requester_label(request: &AccessRequest<ResolvedTenant>) -> EventLabel {
    EventLabel::of(request.requester().person().as_str())
}

/// The tenant's limit on how long its people may ask for access: the one it
/// set, or the longest anyone may when it never set one.
///
/// # Errors
///
/// - `AppError::Internal` if the stored limit cannot be read or is broken.
pub(super) async fn tenant_policy(
    store: &dyn AccessRequestPolicyStore,
    tenant: &ScopedTenant,
) -> Result<AccessRequestPolicy<ResolvedTenant>, AppError> {
    let stored = store.find(tenant).await.or_internal()?;
    Ok(stored.unwrap_or_else(AccessRequestPolicy::widest))
}
