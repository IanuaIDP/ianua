//! Refusing a grant that would break the tenant's separation of duties:
//! someone ending up with both roles of a rule, straight, through a group
//! they join, or through a role added to a group they are in.
//!
//! Every path that hands out a role or a membership checks here: an
//! administrator, an approved access request, an invitation, a provider's
//! default role, a role or group mapped from a provider, a SCIM group add,
//! and a group moved under another.
//! The domain decides from who holds what now; this reads the rules and the
//! records for it.
//!
//! The records are read under the tenant's hold on its grants
//! ([`AccessRecordStore::hold_grants`]), which lasts until the request's
//! unit of work settles with the grant it allowed. Two grants that each
//! keep the rules alone but break one together, Bob given "payments" while
//! he is given "approvals", are checked one after the other, and the
//! second sees the first.

use ianua_domain::domains::authorization::group::GroupPlace;
use ianua_domain::domains::authorization::group_tree::{Conferred, GroupTree};
use ianua_domain::domains::authorization::separation::DutySeparation;
use ianua_domain::types::{GroupId, PrincipalRef, RoleId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, HeldRecords, Holder, Holders, SeparationRuleStore,
};
use crate::tenancy::ScopedTenant;

/// A grant about to be made.
pub(crate) enum Granting<'a> {
    /// `principal` is given `role` straight.
    Role {
        /// Who receives it.
        principal: PrincipalRef,
        /// The permission bundle granted directly to the principal.
        role: &'a RoleId,
    },
    /// `principal` joins the group `conferred` was worked out for.
    Membership {
        /// Who joins.
        principal: PrincipalRef,
        /// What sitting in the group brings.
        conferred: &'a Conferred,
    },
    /// `group` is given `role`, reaching everyone in it and under it.
    GroupRole {
        /// The membership tree receiving the grant.
        group: &'a GroupId,
        /// The permission bundle inherited by members of the group.
        role: &'a RoleId,
    },
    /// `group` moves to the place `to` was worked out for, and everyone in
    /// it and under it gains what that place brings.
    GroupMove {
        /// The membership tree moving to a different parent.
        group: &'a GroupId,
        /// What the new place brings.
        to: &'a Conferred,
    },
}

/// The stores a separation check reads.
#[derive(Clone, Copy)]
pub(crate) struct DutySources<'a> {
    /// Who holds what across the tenant.
    pub(crate) records: &'a dyn AccessRecordStore,
    /// The tenant's separation rules.
    pub(crate) rules: &'a dyn SeparationRuleStore,
}

impl<'a> DutySources<'a> {
    /// The records read from `records` and the rules from `rules`.
    pub(crate) fn of(
        records: &'a dyn AccessRecordStore,
        rules: &'a dyn SeparationRuleStore,
    ) -> Self {
        Self { records, rules }
    }
}

/// Refuses `granting` when it leaves someone holding both roles of one of
/// the tenant's separation rules.
///
/// # Errors
///
/// - `AppError::Conflict` naming the rule the grant would break.
/// - `AppError::Internal` when the rules or the records cannot be read, or
///   the records name a role or group that is not there.
pub(crate) async fn ensure_duties_kept(
    sources: DutySources<'_>,
    tenant: &ScopedTenant,
    granting: Granting<'_>,
) -> Result<(), AppError> {
    let rules = sources.rules.list(tenant).await.or_internal()?;
    if rules.is_empty() {
        return Ok(());
    }
    sources.records.hold_grants(tenant).await.or_internal()?;
    let records = records_for(sources.records, tenant, &granting).await?;
    let access = records.access(**tenant);
    let separation = DutySeparation {
        rules: &rules,
        grants: &access.grants,
    };
    let kept = match granting {
        Granting::Role { principal, role } => separation.ensure_assignable(principal, role),
        Granting::Membership {
            principal,
            conferred,
        } => separation.ensure_joinable(principal, conferred),
        Granting::GroupRole { group, role } => separation.ensure_group_may_hold(group, role),
        Granting::GroupMove { group, to } => separation.ensure_group_may_move(group, to),
    };
    kept.map_err(AppError::from_domain)
}

/// The records `granting` is weighed against: only the receiver's own for
/// a grant to one principal, every one for a grant to a group, which
/// reaches everyone in it and under it.
///
/// # Errors
///
/// - `AppError::Internal` when the records cannot be read.
async fn records_for(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    granting: &Granting<'_>,
) -> Result<AccessRecords, AppError> {
    let principal = match granting {
        Granting::Role { principal, .. } | Granting::Membership { principal, .. } => *principal,
        Granting::GroupRole { .. } | Granting::GroupMove { .. } => {
            return store.load(tenant).await.or_internal();
        }
    };
    let held = store
        .load_held_by(tenant, Holder::of(principal))
        .await
        .or_internal()?;
    Ok(held.into_records())
}

/// Refuses `joining` `group` together when one of them sitting in it would
/// hold both roles of one of the tenant's separation rules, through what
/// the group and the groups above it hold.
///
/// The rules are read once, and the records once for all of the joiners:
/// their own holdings, and the group with the groups above it.
///
/// # Errors
///
/// - `AppError::Conflict` naming the rule a joiner would break.
/// - `AppError::Internal` when the rules or the records cannot be read, or
///   the records name a role or group that is not there.
pub(crate) async fn ensure_joiners_keep_duties(
    sources: DutySources<'_>,
    tenant: &ScopedTenant,
    group: &GroupId,
    joining: &[PrincipalRef],
) -> Result<(), AppError> {
    if joining.is_empty() {
        return Ok(());
    }
    let rules = sources.rules.list(tenant).await.or_internal()?;
    if rules.is_empty() {
        return Ok(());
    }
    sources.records.hold_grants(tenant).await.or_internal()?;
    let held = held_by_joiners(&sources, tenant, group, joining).await?;
    let records = held.records();
    let conferred = GroupTree::new(&records.groups)
        .conferred(GroupPlace::Under(*group), &records.roles)
        .map_err(AppError::from_domain)?;
    let access = held.access(**tenant);
    let separation = DutySeparation {
        rules: &rules,
        grants: &access.grants,
    };
    joining
        .iter()
        .try_for_each(|principal| separation.ensure_joinable(*principal, &conferred))
        .map_err(AppError::from_domain)
}

/// What the people `joining` `group` hold, with the chain of groups above
/// it, read in one go.
async fn held_by_joiners(
    sources: &DutySources<'_>,
    tenant: &ScopedTenant,
    group: &GroupId,
    joining: &[PrincipalRef],
) -> Result<HeldRecords, AppError> {
    let holders = Holders {
        principals: joining,
        groups: std::slice::from_ref(group),
        roles: &[],
    };
    sources
        .records
        .load_held_by_all(tenant, holders)
        .await
        .or_internal()
}
