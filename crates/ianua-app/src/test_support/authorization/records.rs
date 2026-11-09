//! An in-memory store of each tenant's access records, read in one go.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::break_glass::BreakGlassGrant;
use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::authorization::stewardship::AdministratorCount;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, PrincipalRef, RoleId, TenantId, UserId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, AdministratorSortField, HeldRecords, Holder, Holders,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authorization::catalogue::FakeResourceTypeStore;
use crate::test_support::authorization::copies::{
    copy_assignment, copy_break_glass, copy_group, copy_membership,
};
use crate::test_support::authorization::groups::{FakeGroupMembershipStore, FakeGroupStore};
use crate::test_support::authorization::roles::{FakeRoleAssignmentStore, FakeRoleStore};
use crate::test_support::listing::page;

/// The stores a [`FakeAccessRecordStore`] reads a tenant's records from,
/// the way one database holds them all.
///
/// Hand the use case the same stores to have what it writes there show in
/// the records it reads next; the default reads empty ones.
#[derive(Default, Clone)]
pub struct AccessSources {
    /// Stores permission definitions read by authorization checks.
    pub roles: Arc<FakeRoleStore>,
    /// The roles given straight to principals.
    pub assignments: Arc<FakeRoleAssignmentStore>,
    /// Stores the membership tree read by authorization checks.
    pub groups: Arc<FakeGroupStore>,
    /// Who belongs to which group.
    pub memberships: Arc<FakeGroupMembershipStore>,
    /// The resource types whose ladders confer app permissions.
    pub catalogue: Arc<FakeResourceTypeStore>,
}

impl AccessSources {
    /// What the stores hold for `tenant_id`, each record read back the way
    /// storage reads it. Nobody holds a break-glass grant.
    fn records_of(&self, tenant_id: TenantId) -> Result<AccessRecords, DomainError> {
        Ok(AccessRecords {
            roles: self.roles.stored(tenant_id),
            assignments: self.assignments.of_tenant(tenant_id)?,
            groups: self.groups.of_tenant(tenant_id)?,
            memberships: self.memberships.of_tenant(tenant_id)?,
            catalogue: self.catalogue.of_tenant(tenant_id),
            break_glass: Vec::new(),
        })
    }
}

/// In-memory access records, tenant by tenant. A tenant the test handed
/// records has those; any other tenant has what its [`AccessSources`] hold,
/// which by default is nothing: no roles, no groups, no grants.
#[derive(Default)]
pub struct FakeAccessRecordStore {
    records: Mutex<Vec<(TenantId, AccessRecords)>>,
    sources: AccessSources,
    whole_reads: AtomicUsize,
    holder_reads: AtomicUsize,
    holds: AtomicUsize,
    unheld_counts: AtomicUsize,
}

impl TenantScoped for FakeAccessRecordStore {}

impl FakeAccessRecordStore {
    /// The number of narrowed holding reads, including shared batches.
    #[must_use]
    pub fn holder_reads(&self) -> usize {
        self.holder_reads.load(Ordering::SeqCst)
    }

    /// A store holding no tenant's records.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `records` as `tenant_id`'s.
    #[must_use]
    pub fn holding(tenant_id: TenantId, records: AccessRecords) -> Self {
        Self {
            records: Mutex::new(vec![(tenant_id, records)]),
            ..Self::default()
        }
    }

    /// A store reading every tenant's records from `sources`, as they are at
    /// each read.
    #[must_use]
    pub fn reading(sources: AccessSources) -> Self {
        Self {
            sources,
            ..Self::default()
        }
    }

    /// Makes `records` `tenant_id`'s, replacing what it had.
    pub fn replace(&self, tenant_id: TenantId, records: AccessRecords) {
        let mut held = self.records.lock().unwrap();
        held.retain(|(tenant, _)| *tenant != tenant_id);
        held.push((tenant_id, records));
    }

    /// How many times the tenant's records were read whole, so a test can
    /// show that working out one person's holdings never does.
    #[must_use]
    pub fn whole_reads(&self) -> usize {
        self.whole_reads.load(Ordering::SeqCst)
    }

    /// How many times the tenant's administrators were counted before any
    /// hold on its grants was taken, as storage counts them unguarded, so a
    /// test can show a withdrawal counts the last administrator under the
    /// hold. A hold, once taken, lasts the store's life, as it lasts the
    /// request's unit.
    #[must_use]
    pub fn counted_without_a_hold(&self) -> usize {
        self.unheld_counts.load(Ordering::SeqCst)
    }

    /// `tenant_id`'s records, read whole, without counting the read.
    fn stored(&self, tenant_id: TenantId) -> Result<AccessRecords, DomainError> {
        let held = self.records.lock().unwrap();
        let Some((_, records)) = held.iter().find(|(tenant, _)| *tenant == tenant_id) else {
            return self.sources.records_of(tenant_id);
        };
        copy_records(records)
    }
}

#[async_trait]
impl AccessRecordStore for FakeAccessRecordStore {
    async fn load(&self, tenant_id: &ScopedTenant) -> Result<AccessRecords, DomainError> {
        self.whole_reads.fetch_add(1, Ordering::SeqCst);
        self.stored(**tenant_id)
    }

    async fn load_held_by(
        &self,
        tenant_id: &ScopedTenant,
        holder: Holder<'_>,
    ) -> Result<HeldRecords, DomainError> {
        self.holder_reads.fetch_add(1, Ordering::SeqCst);
        let share = Share {
            principals: std::slice::from_ref(&holder.principal),
            groups: &[],
            granted_roles: holder.granted_roles,
        };
        Ok(HeldRecords::new(share.of(self.stored(**tenant_id)?)))
    }

    async fn load_held_by_all(
        &self,
        tenant_id: &ScopedTenant,
        holders: Holders<'_>,
    ) -> Result<HeldRecords, DomainError> {
        self.holder_reads.fetch_add(1, Ordering::SeqCst);
        let share = Share {
            principals: holders.principals,
            groups: holders.groups,
            granted_roles: holders.roles,
        };
        Ok(HeldRecords::new(share.of(self.stored(**tenant_id)?)))
    }

    async fn count_administrators(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<AdministratorCount, DomainError> {
        if self.holds.load(Ordering::SeqCst) == 0 {
            self.unheld_counts.fetch_add(1, Ordering::SeqCst);
        }
        self.stored(**tenant_id)?
            .access(**tenant_id)
            .grants
            .administrator_count()
    }

    async fn list_administrators(
        &self,
        tenant_id: &ScopedTenant,
        request: &PageRequest,
    ) -> Result<Page<UserId>, DomainError> {
        let found = self
            .stored(**tenant_id)?
            .access(**tenant_id)
            .grants
            .administrators()?;
        page(
            found,
            &SortOrder::<AdministratorSortField>::default(),
            request,
        )
    }

    async fn list_holders_of(
        &self,
        tenant_id: &ScopedTenant,
        right: SystemPermission,
        request: &PageRequest,
    ) -> Result<Page<UserId>, DomainError> {
        let found = self
            .stored(**tenant_id)?
            .access(**tenant_id)
            .grants
            .holders_of_right(right)?;
        page(
            found,
            &SortOrder::<AdministratorSortField>::default(),
            request,
        )
    }

    async fn hold_grants(&self, _tenant_id: &ScopedTenant) -> Result<(), DomainError> {
        self.holds.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// The share of `records` that decides what `holder` holds, as a store
/// narrows it: their own assignments and memberships, the groups above,
/// the roles those and the holder's grants name, and their break-glass
/// grants still running.
/// Whose share of the records a narrowed read keeps.
struct Share<'a> {
    principals: &'a [PrincipalRef],
    groups: &'a [GroupId],
    granted_roles: &'a [RoleId],
}

impl Share<'_> {
    /// The share of `records` this names, as a store narrows it: the
    /// principals' own assignments and memberships, the groups those and
    /// `groups` name with every group above, the roles all of them and the
    /// granted roles name, and the principals' break-glass grants still
    /// running.
    fn of(&self, records: AccessRecords) -> AccessRecords {
        let assignments: Vec<_> = records
            .assignments
            .into_iter()
            .filter(|held| self.principals.contains(held.principal()))
            .collect();
        let memberships: Vec<_> = records
            .memberships
            .into_iter()
            .filter(|held| self.principals.contains(held.principal()))
            .collect();
        let starts = memberships
            .iter()
            .map(|held| *held.group_id())
            .chain(self.groups.iter().copied());
        let groups = chain_of(records.groups, starts.collect());
        let named = self.roles_named(&assignments, &groups);
        AccessRecords {
            roles: records
                .roles
                .into_iter()
                .filter(|role| named.contains(role.id()))
                .collect(),
            assignments,
            groups,
            memberships,
            catalogue: records.catalogue,
            break_glass: self.running_grants(records.break_glass),
        }
    }

    /// The roles `assignments`, `groups` and the granted roles name.
    fn roles_named(
        &self,
        assignments: &[RoleAssignment<ResolvedTenant>],
        groups: &[Group<ResolvedTenant>],
    ) -> Vec<RoleId> {
        assignments
            .iter()
            .map(|held| *held.role_id())
            .chain(
                groups
                    .iter()
                    .flat_map(|group| group.role_ids().iter().copied()),
            )
            .chain(self.granted_roles.iter().copied())
            .collect()
    }

    /// The principals' break-glass grants among `grants` still running.
    fn running_grants(&self, grants: Vec<BreakGlassGrant>) -> Vec<BreakGlassGrant> {
        let now = clock::now();
        grants
            .into_iter()
            .filter(|grant| {
                self.principals
                    .contains(&PrincipalRef::User(*grant.user_id()))
            })
            .filter(|grant| grant.is_active(now))
            .collect()
    }
}

/// The groups `wanted` names and every group above them, as far as
/// `groups` holds them.
fn chain_of(
    groups: Vec<Group<ResolvedTenant>>,
    mut wanted: Vec<GroupId>,
) -> Vec<Group<ResolvedTenant>> {
    let mut found: Vec<GroupId> = Vec::new();
    while let Some(id) = wanted.pop() {
        let Some(group) = groups.iter().find(|group| *group.id() == id) else {
            continue;
        };
        if found.contains(&id) {
            continue;
        }
        found.push(id);
        if let GroupPlace::Under(parent) = group.place() {
            wanted.push(*parent);
        }
    }
    groups
        .into_iter()
        .filter(|group| found.contains(group.id()))
        .collect()
}

/// A copy of `records`, each record read back the way storage reads it.
fn copy_records(records: &AccessRecords) -> Result<AccessRecords, DomainError> {
    Ok(AccessRecords {
        roles: records.roles.clone(),
        assignments: records
            .assignments
            .iter()
            .map(copy_assignment)
            .collect::<Result<_, _>>()?,
        groups: records
            .groups
            .iter()
            .map(copy_group)
            .collect::<Result<_, _>>()?,
        memberships: records
            .memberships
            .iter()
            .map(copy_membership)
            .collect::<Result<_, _>>()?,
        catalogue: records.catalogue.clone(),
        break_glass: records
            .break_glass
            .iter()
            .map(copy_break_glass)
            .collect::<Result<_, _>>()?,
    })
}

impl Fake for Arc<dyn AccessRecordStore> {
    fn fake() -> Self {
        Arc::new(FakeAccessRecordStore::empty())
    }
}
