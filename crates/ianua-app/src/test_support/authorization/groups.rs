//! In-memory groups and their memberships.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::group::{
    Group, GroupMembership, GroupMembershipRow, GroupOrigin, GroupPlace, GroupRow,
};
use ianua_domain::domains::authorization::group_tree::GroupTree;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Expiry, GroupId, Label, PrincipalRef, RoleId, TenantId};
use time::{Duration, OffsetDateTime};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{
    GroupMemberSortField, GroupMembershipStore, GroupSortField, GroupStore, HOLDING_BATCH_SIZE,
    HoldingBatch, MembershipPosition,
};
use crate::ports::federation::{
    ScimCase, ScimGroupAttribute, ScimGroupQueries, ScimPage, ScimQuery, ScimWindow,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authorization::copies::{
    copy_group, copy_membership, principal_sort_word,
};
use crate::test_support::listing::page;

/// A dashboard group named `name`, sitting at `place` and carrying
/// `role_ids`, as storage would hand it back.
#[must_use]
pub fn stored_group(name: &str, place: GroupPlace, role_ids: Vec<RoleId>) -> Group<ResolvedTenant> {
    let now = clock::now();
    Group::reconstitute(GroupRow {
        id: GroupId::new(),
        name: Label::new("group_name", name).expect("a valid group name"),
        origin: GroupOrigin::Dashboard,
        place,
        role_ids,
        created_at: now,
        updated_at: now,
    })
    .expect("a group is a consistent row")
}

/// `principal` in the group `group_id`, as storage would hand it back.
#[must_use]
pub fn stored_membership(
    principal: PrincipalRef,
    group_id: GroupId,
) -> GroupMembership<ResolvedTenant> {
    stored_membership_until(principal, group_id, Expiry::Never)
}

/// `principal` in the group `group_id` since a month ago, ending at
/// `expires`, as storage would hand it back.
#[must_use]
pub fn stored_membership_until(
    principal: PrincipalRef,
    group_id: GroupId,
    expires: Expiry,
) -> GroupMembership<ResolvedTenant> {
    GroupMembership::reconstitute(GroupMembershipRow {
        principal,
        group_id,
        joined_at: clock::now() - Duration::days(30),
        expires,
    })
    .expect("a membership is a consistent row")
}

/// In-memory group store that keeps every group it is handed, tenant by
/// tenant.
#[derive(Default)]
pub struct FakeGroupStore {
    groups: Mutex<Vec<(TenantId, Group<ResolvedTenant>)>>,
    id_reads: Mutex<Vec<Vec<GroupId>>>,
}

impl TenantScoped for FakeGroupStore {}

impl FakeGroupStore {
    /// The group ids requested in each lookup, preserving batch boundaries.
    #[must_use]
    pub fn id_reads(&self) -> Vec<Vec<GroupId>> {
        self.id_reads.lock().unwrap().clone()
    }

    /// A store holding no group.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `groups` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        groups: impl IntoIterator<Item = Group<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store
            .groups
            .lock()
            .unwrap()
            .extend(groups.into_iter().map(|group| (tenant_id, group)));
        store
    }

    /// How many groups are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.groups.lock().unwrap().len()
    }

    /// Every group held in `tenant_id`, read back the way storage reads it.
    pub(crate) fn of_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        self.matching(tenant_id, |_| true)
    }

    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&Group<ResolvedTenant>) -> bool,
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        self.groups
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, group)| *tenant == tenant_id && keep(group))
            .map(|(_, group)| copy_group(group))
            .collect()
    }

    /// The roles `groups` confer in `tenant_id`, each group's own and those
    /// of every group above it. A group no longer held confers nothing.
    pub(crate) fn roles_conferred_by(
        &self,
        tenant_id: TenantId,
        groups: &[GroupId],
    ) -> Result<Vec<RoleId>, DomainError> {
        let held = self.matching(tenant_id, |_| true)?;
        let tree = GroupTree::new(&held);
        let mut roles = Vec::new();
        for group in groups
            .iter()
            .filter(|group| held.iter().any(|g| g.id() == *group))
        {
            for above in tree.lineage(group)? {
                roles.extend_from_slice(above.role_ids());
            }
        }
        Ok(roles)
    }
}

#[async_trait]
impl GroupStore for FakeGroupStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &GroupId,
    ) -> Result<Option<Group<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(vec![*id]);
        Ok(self.matching(**tenant_id, |group| group.id() == id)?.pop())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[GroupId],
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(ids.to_vec());
        self.matching(**tenant_id, |group| ids.contains(group.id()))
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<Group<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |group| group.name().as_str() == name.as_str())?
            .pop())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<GroupSortField>,
        request: &PageRequest,
    ) -> Result<Page<Group<ResolvedTenant>>, DomainError> {
        page(self.matching(**tenant_id, |_| true)?, sort, request)
    }

    async fn list_children(
        &self,
        tenant_id: &ScopedTenant,
        parent_id: &GroupId,
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        self.matching(**tenant_id, |group| {
            group.place().parent() == Some(parent_id)
        })
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        group: &Group<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_group(group)?;
        let mut groups = self.groups.lock().unwrap();
        let held = groups
            .iter_mut()
            .find(|(tenant, held)| *tenant == **tenant_id && held.id() == group.id());
        match held {
            Some((_, held)) => *held = copy,
            None => groups.push((**tenant_id, copy)),
        }
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &GroupId) -> Result<(), DomainError> {
        self.groups
            .lock()
            .unwrap()
            .retain(|(tenant, group)| !(*tenant == **tenant_id && group.id() == id));
        Ok(())
    }

    async fn count_carrying_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        let carrying = self.matching(**tenant_id, |group| group.role_ids().contains(role_id))?;
        Ok(u64::try_from(carrying.len()).unwrap_or(u64::MAX))
    }
}

/// In-memory store of who belongs to which group, tenant by tenant.
/// Joining a group one already belongs to changes nothing.
#[derive(Default)]
pub struct FakeGroupMembershipStore {
    memberships: Mutex<Vec<(TenantId, GroupMembership<ResolvedTenant>)>>,
    group_reads: Mutex<Vec<Vec<GroupId>>>,
    lapsed_reads: Mutex<Vec<usize>>,
}

impl TenantScoped for FakeGroupMembershipStore {}

impl FakeGroupMembershipStore {
    /// The size of each expired-membership batch returned to the sweep.
    #[must_use]
    pub fn lapsed_reads(&self) -> Vec<usize> {
        self.lapsed_reads.lock().unwrap().clone()
    }

    /// The groups requested by each membership read, for checking bounded
    /// directory work independently of the number of groups returned.
    #[must_use]
    pub fn group_reads(&self) -> Vec<Vec<GroupId>> {
        self.group_reads.lock().unwrap().clone()
    }

    /// A store holding no membership.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `memberships` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        memberships: impl IntoIterator<Item = GroupMembership<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store
            .memberships
            .lock()
            .unwrap()
            .extend(memberships.into_iter().map(|held| (tenant_id, held)));
        store
    }

    /// How many memberships are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.memberships.lock().unwrap().len()
    }

    /// The groups through which `principal` holds roles in `tenant_id`.
    /// Groups confer roles on tenant users only, so any other principal
    /// gets none this way.
    pub(crate) fn groups_of(&self, tenant_id: TenantId, principal: &PrincipalRef) -> Vec<GroupId> {
        let PrincipalRef::User(_) = principal else {
            return Vec::new();
        };
        self.memberships
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, held)| *tenant == tenant_id && held.principal() == principal)
            .map(|(_, held)| *held.group_id())
            .collect()
    }

    /// Every membership held in `tenant_id`, read back the way storage reads
    /// it.
    pub(crate) fn of_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.matching(tenant_id, |_| true)
    }

    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&GroupMembership<ResolvedTenant>) -> bool,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.memberships
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, held)| *tenant == tenant_id && keep(held))
            .map(|(_, held)| copy_membership(held))
            .collect()
    }

    /// Whether `principal` sits in `group_id` of `tenant_id` still in force
    /// at `at`, as storage answers whether a place is held.
    fn belongs(
        &self,
        tenant_id: TenantId,
        principal: &PrincipalRef,
        group_id: &GroupId,
        at: OffsetDateTime,
    ) -> bool {
        self.memberships
            .lock()
            .unwrap()
            .iter()
            .any(|(tenant, held)| {
                *tenant == tenant_id
                    && held.principal() == principal
                    && held.group_id() == group_id
                    && held.is_in_force(at)
            })
    }

    /// Takes `principal` out of `group_id` of `tenant_id` when their place
    /// had ended by `at`, and answers whether it did.
    fn take_lapsed(
        &self,
        tenant_id: TenantId,
        principal: &PrincipalRef,
        group_id: &GroupId,
        at: OffsetDateTime,
    ) -> bool {
        let mut memberships = self.memberships.lock().unwrap();
        let before = memberships.len();
        memberships.retain(|(tenant, held)| {
            !(*tenant == tenant_id
                && held.principal() == principal
                && held.group_id() == group_id
                && !held.is_in_force(at))
        });
        memberships.len() < before
    }
}

#[async_trait]
impl GroupMembershipStore for FakeGroupMembershipStore {
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.matching(**tenant_id, |held| held.principal() == principal)
    }

    async fn find_by_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.group_reads.lock().unwrap().push(vec![*group_id]);
        self.matching(**tenant_id, |held| held.group_id() == group_id)
    }

    async fn find_by_groups(
        &self,
        tenant_id: &ScopedTenant,
        group_ids: &[GroupId],
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.group_reads.lock().unwrap().push(group_ids.to_vec());
        self.matching(**tenant_id, |held| group_ids.contains(held.group_id()))
    }

    async fn list_by_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
        request: &PageRequest,
    ) -> Result<Page<GroupMembership<ResolvedTenant>>, DomainError> {
        let members = self.matching(**tenant_id, |held| held.group_id() == group_id)?;
        page(
            members,
            &SortOrder::<GroupMemberSortField>::default(),
            request,
        )
    }

    async fn exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        group_id: &GroupId,
    ) -> Result<bool, DomainError> {
        Ok(self.belongs(**tenant_id, principal, group_id, clock::now()))
    }

    async fn remove_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        membership: &GroupMembership<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        Ok(self.take_lapsed(
            **tenant_id,
            membership.principal(),
            membership.group_id(),
            now,
        ))
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        batch: &HoldingBatch<MembershipPosition>,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        let key = |position: MembershipPosition| {
            (
                position.expires_at,
                *position.group_id.as_uuid(),
                principal_sort_word(&position.principal),
                position.principal.id(),
            )
        };
        let after = batch.after.map(key);
        let mut rows = self.matching(**tenant_id, |held| {
            !held.is_in_force(batch.now)
                && MembershipPosition::of(held)
                    .is_some_and(|position| after.is_none_or(|after| key(position) > after))
        })?;
        rows.sort_by_key(|held| MembershipPosition::of(held).map(key));
        rows.truncate(HOLDING_BATCH_SIZE);
        self.lapsed_reads.lock().unwrap().push(rows.len());
        Ok(rows)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        membership: &GroupMembership<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let (principal, group_id) = (membership.principal(), membership.group_id());
        let joined_at = membership.joined_at();
        if self.belongs(**tenant_id, principal, group_id, joined_at) {
            return Ok(());
        }
        self.take_lapsed(**tenant_id, principal, group_id, joined_at);
        let copy = copy_membership(membership)?;
        self.memberships.lock().unwrap().push((**tenant_id, copy));
        Ok(())
    }

    async fn save_all(
        &self,
        tenant_id: &ScopedTenant,
        memberships: &[GroupMembership<ResolvedTenant>],
    ) -> Result<(), DomainError> {
        for membership in memberships {
            self.save(tenant_id, membership).await?;
        }
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        group_id: &GroupId,
    ) -> Result<(), DomainError> {
        self.memberships.lock().unwrap().retain(|(tenant, held)| {
            !(*tenant == **tenant_id
                && held.principal() == principal
                && held.group_id() == group_id)
        });
        Ok(())
    }

    async fn delete_all(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
        principals: &[PrincipalRef],
    ) -> Result<(), DomainError> {
        self.memberships.lock().unwrap().retain(|(tenant, held)| {
            !(*tenant == **tenant_id
                && held.group_id() == group_id
                && principals.contains(held.principal()))
        });
        Ok(())
    }
}

impl Fake for Arc<dyn GroupMembershipStore> {
    fn fake() -> Self {
        Arc::new(FakeGroupMembershipStore::empty())
    }
}

impl Fake for Arc<dyn GroupStore> {
    fn fake() -> Self {
        Arc::new(FakeGroupStore::empty())
    }
}

/// The same groups, found by SCIM filters as the adapter's query finds
/// them: the directory's own only, oldest first.
#[async_trait]
impl ScimGroupQueries for FakeGroupStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        query: &ScimQuery<ScimGroupAttribute>,
        window: ScimWindow,
    ) -> Result<ScimPage<Group<ResolvedTenant>>, DomainError> {
        let mut picked = self.matching(**tenant_id, |group| {
            group.origin() == GroupOrigin::Directory && scim_picks(query, group)
        })?;
        picked.sort_by_key(|group| (group.created_at(), *group.id().as_uuid()));
        Ok(window.cut(picked))
    }
}

impl Fake for Arc<dyn ScimGroupQueries> {
    fn fake() -> Self {
        Arc::new(FakeGroupStore::empty())
    }
}

/// Whether `query` picks `group`, its name compared ignoring case.
fn scim_picks(query: &ScimQuery<ScimGroupAttribute>, group: &Group<ResolvedTenant>) -> bool {
    match query {
        ScimQuery::All => true,
        ScimQuery::Compare {
            attribute: ScimGroupAttribute::DisplayName,
            operator,
            value,
        } => operator.holds(group.name().as_str(), value, ScimCase::Ignored),
        ScimQuery::And(left, right) => scim_picks(left, group) && scim_picks(right, group),
        ScimQuery::Or(left, right) => scim_picks(left, group) || scim_picks(right, group),
    }
}
