//! Bounded access removal shared by manual and overdue review completion.

use std::collections::HashMap;

use ianua_domain::domains::authorization::access_review::{AccessReview, ReviewScope};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::GroupPlace;
use ianua_domain::domains::authorization::holding::HeldAccess;
use ianua_domain::domains::authorization::review_removals::ReviewRemovals;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{EventLabel, PrincipalRef};

use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, GroupMembershipStore, HeldRecords, Holders,
    RoleAssignmentStore,
};
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::tenancy::ScopedTenant;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::stewardship::{Lost, ensure_administered_after_losing};

/// Persistence needed to remove one bounded page of holdings.
#[derive(Clone, Copy)]
pub(super) struct CompletionStores<'a> {
    /// The records used for current holdings and administrator safety.
    pub(super) records: &'a dyn AccessRecordStore,
    /// Direct role assignments.
    pub(super) assignments: &'a dyn RoleAssignmentStore,
    /// Direct group memberships.
    pub(super) memberships: &'a dyn GroupMembershipStore,
}

/// Which domain authority must permit every removal.
#[derive(Clone, Copy)]
pub(super) enum RemovalAuthority<'a> {
    /// A manual completion may take only what its caller could take by hand.
    Caller(&'a TenantAuthority),
    /// A due review permits only its own verified page of removals.
    Overdue(&'a ReviewRemovals),
}

/// The immutable scope and bounded holders for one completion page.
pub(super) struct RemovalBatch<'a> {
    /// The tenant whose grant lock protects the transaction.
    pub(super) tenant: &'a ScopedTenant,
    /// The reviewed direct role or membership.
    pub(super) scope: ReviewScope,
    /// Only holders selected for removal on this page.
    pub(super) principals: &'a [PrincipalRef],
}

impl<'a> RemovalBatch<'a> {
    /// Keeps this page's removals tied to the locked review's immutable scope.
    pub(super) fn for_review(
        tenant: &'a ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        principals: &'a [PrincipalRef],
    ) -> Self {
        Self {
            tenant,
            scope: review.scope(),
            principals,
        }
    }
}

/// Reads one page's holdings together, validates each removal in the domain,
/// checks that an administrator remains, and deletes the bounded batch.
pub(super) async fn remove_batch(
    stores: CompletionStores<'_>,
    batch: &RemovalBatch<'_>,
    authority: RemovalAuthority<'_>,
    labels: &HashMap<PrincipalRef, EventLabel>,
) -> Result<Vec<HeldAccess<ResolvedTenant>>, AppError> {
    if batch.principals.is_empty() {
        return Ok(Vec::new());
    }
    let records = held_records(stores.records, batch).await?;
    let taken = withdrawn(records, batch, authority, labels)?;
    ensure_administered_after_losing(
        stores.records,
        batch.tenant,
        batch.principals,
        lost(&batch.scope),
    )
    .await?;
    delete_batch(stores, batch, &taken).await?;
    Ok(taken)
}

/// Deletes only the holdings the domain approved, using one scoped statement.
async fn delete_batch(
    stores: CompletionStores<'_>,
    batch: &RemovalBatch<'_>,
    taken: &[HeldAccess<ResolvedTenant>],
) -> Result<(), AppError> {
    let principals: Vec<_> = taken.iter().map(principal).collect();
    match batch.scope {
        ReviewScope::Role(role) => {
            stores
                .assignments
                .delete_for_principals(batch.tenant, &role, &principals)
                .await
        }
        ReviewScope::Group(group) => {
            stores
                .memberships
                .delete_all(batch.tenant, &group, &principals)
                .await
        }
    }
    .or_internal()
}

/// Loads only the page's principals and the reviewed scope's definition.
async fn held_records(
    store: &dyn AccessRecordStore,
    batch: &RemovalBatch<'_>,
) -> Result<AccessRecords, AppError> {
    let (roles, groups) = match batch.scope {
        ReviewScope::Role(role) => (vec![role], Vec::new()),
        ReviewScope::Group(group) => (Vec::new(), vec![group]),
    };
    store
        .load_held_by_all(
            batch.tenant,
            Holders {
                principals: batch.principals,
                groups: &groups,
                roles: &roles,
            },
        )
        .await
        .or_internal()
        .map(HeldRecords::into_records)
}

/// Applies domain changes to in-memory holdings without per-holder reads.
fn withdrawn(
    records: AccessRecords,
    batch: &RemovalBatch<'_>,
    authority: RemovalAuthority<'_>,
    labels: &HashMap<PrincipalRef, EventLabel>,
) -> Result<Vec<HeldAccess<ResolvedTenant>>, AppError> {
    match batch.scope {
        ReviewScope::Role(_) => revoked(records, batch, authority, labels),
        ReviewScope::Group(_) => ended(records, batch, authority, labels),
    }
}

/// Validates each direct role removal with the caller or overdue proof.
fn revoked(
    records: AccessRecords,
    batch: &RemovalBatch<'_>,
    authority: RemovalAuthority<'_>,
    labels: &HashMap<PrincipalRef, EventLabel>,
) -> Result<Vec<HeldAccess<ResolvedTenant>>, AppError> {
    let ReviewScope::Role(role_id) = batch.scope else {
        return Ok(Vec::new());
    };
    let mut taken = Vec::new();
    for mut held in records
        .assignments
        .into_iter()
        .filter(|held| *held.role_id() == role_id && batch.principals.contains(held.principal()))
    {
        let role = records
            .roles
            .iter()
            .find(|role| *role.id() == role_id)
            .or_not_found(message!("app-role-not-found", "role not found"))?;
        let label = holder_label(labels, held.principal());
        match &authority {
            RemovalAuthority::Caller(by) => held.revoke(role, &by.standing(), label),
            RemovalAuthority::Overdue(removals) => held.withdraw_by_review(role, removals, label),
        }
        .map_err(AppError::from_domain)?;
        taken.push(HeldAccess::Role(held));
    }
    Ok(taken)
}

/// Validates each direct membership removal against one shared scope projection.
fn ended(
    mut records: AccessRecords,
    batch: &RemovalBatch<'_>,
    authority: RemovalAuthority<'_>,
    labels: &HashMap<PrincipalRef, EventLabel>,
) -> Result<Vec<HeldAccess<ResolvedTenant>>, AppError> {
    let ReviewScope::Group(group_id) = batch.scope else {
        return Ok(Vec::new());
    };
    let memberships = std::mem::take(&mut records.memberships);
    let mut taken = Vec::new();
    for mut held in memberships
        .into_iter()
        .filter(|held| *held.group_id() == group_id && batch.principals.contains(held.principal()))
    {
        let group = records
            .groups
            .iter()
            .find(|group| *group.id() == group_id)
            .or_not_found(message!("authorization-group-not-found", "group not found"))?;
        let label = holder_label(labels, held.principal());
        match &authority {
            RemovalAuthority::Caller(by) => {
                let conferred = conferred_at(&records, GroupPlace::Under(group_id))?;
                held.end(group, &conferred, &by.standing(), label)
            }
            RemovalAuthority::Overdue(removals) => held.withdraw_by_review(group, removals, label),
        }
        .map_err(AppError::from_domain)?;
        taken.push(HeldAccess::Membership(held));
    }
    Ok(taken)
}

/// A holding's principal, for the one batch delete.
fn principal(held: &HeldAccess<ResolvedTenant>) -> PrincipalRef {
    match held {
        HeldAccess::Role(held) => *held.principal(),
        HeldAccess::Membership(held) => *held.principal(),
    }
}

/// Uses the resolved label or the same identifier fallback as individual reads.
fn holder_label(labels: &HashMap<PrincipalRef, EventLabel>, holder: &PrincipalRef) -> EventLabel {
    labels
        .get(holder)
        .cloned()
        .unwrap_or_else(|| EventLabel::of(&holder.id().to_string()))
}

/// Resolves one page's tenant labels and organization labels in batches.
pub(super) async fn caller_labels(
    resolver: &dyn AuditLabelResolver,
    control: &dyn ControlPlaneLabelResolver,
    ctx: &CallerContext,
    principals: &[PrincipalRef],
) -> Result<HashMap<PrincipalRef, EventLabel>, AppError> {
    let mut labels = resolver
        .principals(&ctx.tenant(), principals)
        .await
        .or_internal()?;
    let members: Vec<_> = principals
        .iter()
        .filter_map(|principal| match principal {
            PrincipalRef::OrgUser(id) => Some(*id),
            _ => None,
        })
        .collect();
    if !members.is_empty() {
        let named = control
            .org_users(&ctx.organization_id(), &members)
            .await
            .or_internal()?;
        labels.extend(
            named
                .into_iter()
                .map(|(id, label)| (PrincipalRef::OrgUser(id), label)),
        );
    }
    Ok(labels)
}

/// The rights the page's holders lose, used by administrator protection.
fn lost(scope: &ReviewScope) -> Lost<'_> {
    match scope {
        ReviewScope::Role(role) => Lost::Role(role),
        ReviewScope::Group(group) => Lost::Membership(group),
    }
}
