//! In-memory roles, the roles given to principals, and the unit of work
//! that deletes a role and moves its holders.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
use ianua_domain::domains::authorization::role_assignment::{RoleAssignment, RoleAssignmentRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, Expiry, Label, PrincipalRef, RoleId, TenantId};
use time::{Duration, OffsetDateTime};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{
    AssignmentPosition, HOLDING_BATCH_SIZE, HoldingBatch, RoleAssignmentStore,
    RoleDeletionUnitOfWork, RoleHolder, RoleHolderQueries, RoleHolderSortField, RoleSortField,
    RoleStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authorization::copies::{copy_assignment, principal_sort_word};
use crate::test_support::authorization::groups::{FakeGroupMembershipStore, FakeGroupStore};
use crate::test_support::listing::page;

/// A role named `name`, granting `system` and `custom`, given only when
/// assigned, as storage would hand it back.
#[must_use]
pub fn stored_role(
    name: &str,
    system: Vec<SystemPermission>,
    custom: Vec<CustomPermission>,
) -> Role<ResolvedTenant> {
    Role::provisioned(NewRole {
        id: RoleId::new(),
        name: Label::new("role_name", name).expect("a valid role name"),
        system_permissions: system,
        custom_permissions: custom,
        assignment: DefaultAssignment::Manual,
    })
}

/// `role_id` given straight to `principal` by the system, as storage would
/// hand it back.
#[must_use]
pub fn stored_assignment(
    principal: PrincipalRef,
    role_id: RoleId,
) -> RoleAssignment<ResolvedTenant> {
    stored_assignment_until(principal, role_id, Expiry::Never)
}

/// `role_id` given straight to `principal` by the system a month ago,
/// ending at `expires`, as storage would hand it back.
#[must_use]
pub fn stored_assignment_until(
    principal: PrincipalRef,
    role_id: RoleId,
    expires: Expiry,
) -> RoleAssignment<ResolvedTenant> {
    RoleAssignment::reconstitute(RoleAssignmentRow {
        principal,
        role_id,
        assigned_by: ActorRef::System,
        assigned_at: clock::now() - Duration::days(30),
        expires,
    })
    .expect("an assignment is a consistent row")
}

/// The stores a [`FakeRoleStore`] reads to answer who holds which role:
/// the roles given straight to principals, and the groups that confer them.
///
/// Hand a test's own stores in to have the role store answer from what the
/// test seeded there; the default reads empty ones, so nobody holds a role.
#[derive(Default)]
pub struct RoleHolders {
    /// The roles given straight to principals.
    pub assignments: Arc<FakeRoleAssignmentStore>,
    /// The groups, with the roles each confers.
    pub groups: Arc<FakeGroupStore>,
    /// Who belongs to which group.
    pub memberships: Arc<FakeGroupMembershipStore>,
}

/// In-memory role store that keeps every role it is handed, tenant by
/// tenant, and works out who holds a role from its [`RoleHolders`].
#[derive(Default)]
pub struct FakeRoleStore {
    roles: Mutex<Vec<(TenantId, Role<ResolvedTenant>)>>,
    holders: RoleHolders,
    default_reads: AtomicUsize,
    principal_reads: AtomicUsize,
    name_reads: AtomicUsize,
}

impl TenantScoped for FakeRoleStore {}

impl FakeRoleStore {
    /// How many reads resolve principals' directly assigned roles.
    #[must_use]
    pub fn principal_reads(&self) -> usize {
        self.principal_reads.load(Ordering::SeqCst)
    }

    /// A store holding no role, whose holders are empty too.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `roles` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        roles: impl IntoIterator<Item = Role<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store.add(tenant_id, roles);
        store
    }

    /// The same store, answering who holds a role from `holders`.
    #[must_use]
    pub fn reading(self, holders: RoleHolders) -> Self {
        Self { holders, ..self }
    }

    /// Puts `roles` into `tenant_id`.
    pub fn add(&self, tenant_id: TenantId, roles: impl IntoIterator<Item = Role<ResolvedTenant>>) {
        self.roles
            .lock()
            .unwrap()
            .extend(roles.into_iter().map(|role| (tenant_id, role)));
    }

    /// How many times a tenant's default roles were read, so a test can
    /// show a batch reads them once rather than once per account.
    #[must_use]
    pub fn default_reads(&self) -> usize {
        self.default_reads.load(Ordering::SeqCst)
    }

    /// How many reads resolve role names, allowing batch callers to prove bounded reads.
    #[must_use]
    pub fn name_reads(&self) -> usize {
        self.name_reads.load(Ordering::SeqCst)
    }

    /// How many roles are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.roles.lock().unwrap().len()
    }

    /// Every role held in `tenant_id`, in the order they were first saved.
    #[must_use]
    pub fn stored(&self, tenant_id: TenantId) -> Vec<Role<ResolvedTenant>> {
        self.matching(tenant_id, |_| true)
    }

    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&Role<ResolvedTenant>) -> bool,
    ) -> Vec<Role<ResolvedTenant>> {
        self.roles
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, role)| *tenant == tenant_id && keep(role))
            .map(|(_, role)| role.clone())
            .collect()
    }

    /// Drops the role `id` from `tenant_id`.
    pub(crate) fn remove(&self, tenant_id: TenantId, id: &RoleId) {
        self.roles
            .lock()
            .unwrap()
            .retain(|(tenant, role)| !(*tenant == tenant_id && role.id() == id));
    }

    fn effective_role_ids(
        &self,
        tenant_id: TenantId,
        principal: &PrincipalRef,
    ) -> Result<Vec<RoleId>, DomainError> {
        let mut ids = self.holders.assignments.role_ids_of(tenant_id, principal);
        let groups = self.holders.memberships.groups_of(tenant_id, principal);
        ids.extend(self.holders.groups.roles_conferred_by(tenant_id, &groups)?);
        Ok(ids)
    }
}

#[async_trait]
impl RoleStore for FakeRoleStore {
    async fn find_by_principals(
        &self,
        tenant_id: &ScopedTenant,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, Vec<Role<ResolvedTenant>>>, DomainError> {
        self.principal_reads.fetch_add(1, Ordering::SeqCst);
        Ok(principals
            .iter()
            .map(|principal| {
                let ids = self.holders.assignments.role_ids_of(**tenant_id, principal);
                let mut roles = self.matching(**tenant_id, |role| ids.contains(role.id()));
                roles.sort_by_key(|role| (role.created_at(), *role.id().as_uuid()));
                (*principal, roles)
            })
            .collect())
    }

    async fn find_by_names(
        &self,
        tenant_id: &ScopedTenant,
        names: &[Label],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        self.name_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.matching(**tenant_id, |role| names.contains(role.name())))
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RoleId,
    ) -> Result<Option<Role<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |role| role.id() == id).pop())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[RoleId],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |role| ids.contains(role.id())))
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<Role<ResolvedTenant>>, DomainError> {
        self.name_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .matching(**tenant_id, |role| role.name().as_str() == name.as_str())
            .pop())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<RoleSortField>,
        request: &PageRequest,
    ) -> Result<Page<Role<ResolvedTenant>>, DomainError> {
        page(self.stored(**tenant_id), sort, request)
    }

    async fn find_defaults(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        self.default_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.matching(**tenant_id, Role::is_default))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        role: &Role<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut roles = self.roles.lock().unwrap();
        let held = roles
            .iter_mut()
            .find(|(tenant, held)| *tenant == **tenant_id && held.id() == role.id());
        match held {
            Some((_, held)) => *held = role.clone(),
            None => roles.push((**tenant_id, role.clone())),
        }
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &RoleId) -> Result<(), DomainError> {
        self.remove(**tenant_id, id);
        Ok(())
    }

    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        self.principal_reads.fetch_add(1, Ordering::SeqCst);
        let ids = self.holders.assignments.role_ids_of(**tenant_id, principal);
        Ok(self.matching(**tenant_id, |role| ids.contains(role.id())))
    }

    async fn find_effective_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let ids = self.effective_role_ids(**tenant_id, principal)?;
        Ok(self.matching(**tenant_id, |role| ids.contains(role.id())))
    }
}

/// In-memory store of the roles given straight to principals, tenant by
/// tenant. Giving a principal a role they already hold changes nothing.
#[derive(Default)]
pub struct FakeRoleAssignmentStore {
    assignments: Mutex<Vec<(TenantId, RoleAssignment<ResolvedTenant>)>>,
    lapsed_reads: Mutex<Vec<usize>>,
}

impl TenantScoped for FakeRoleAssignmentStore {}

impl FakeRoleAssignmentStore {
    /// The size of each expired-assignment batch returned to the sweep.
    #[must_use]
    pub fn lapsed_reads(&self) -> Vec<usize> {
        self.lapsed_reads.lock().unwrap().clone()
    }

    /// A store holding no assignment.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `assignments` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        assignments: impl IntoIterator<Item = RoleAssignment<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store
            .assignments
            .lock()
            .unwrap()
            .extend(assignments.into_iter().map(|held| (tenant_id, held)));
        store
    }

    /// How many assignments are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.assignments.lock().unwrap().len()
    }

    /// Every principal holding `role_id` in `tenant_id`.
    #[must_use]
    pub fn holders_of(&self, tenant_id: TenantId, role_id: &RoleId) -> Vec<PrincipalRef> {
        self.assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, held)| *tenant == tenant_id && held.role_id() == role_id)
            .map(|(_, held)| *held.principal())
            .collect()
    }

    /// Every assignment held in `tenant_id`, read back the way storage reads
    /// it.
    pub(crate) fn of_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError> {
        self.assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, _)| *tenant == tenant_id)
            .map(|(_, held)| copy_assignment(held))
            .collect()
    }

    /// The roles given straight to `principal` in `tenant_id`.
    pub(crate) fn role_ids_of(&self, tenant_id: TenantId, principal: &PrincipalRef) -> Vec<RoleId> {
        self.assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, held)| *tenant == tenant_id && held.principal() == principal)
            .map(|(_, held)| *held.role_id())
            .collect()
    }

    /// Moves every holder of `change.from` in `tenant_id` onto `change.to`,
    /// keeping a holder's own assignment of `change.to`, and answers how
    /// many `change.from` assignments went.
    pub(crate) fn reassign(&self, tenant_id: TenantId, change: &Reassignment) -> u64 {
        let holders = self.holders_of(tenant_id, &change.from);
        let mut assignments = self.assignments.lock().unwrap();
        assignments
            .retain(|(tenant, held)| !(*tenant == tenant_id && *held.role_id() == change.from));
        for holder in &holders {
            let already = assignments.iter().any(|(tenant, held)| {
                *tenant == tenant_id && held.principal() == holder && *held.role_id() == change.to
            });
            if !already {
                assignments.push((tenant_id, change.given_to(*holder)));
            }
        }
        holders.len() as u64
    }

    /// Whether `principal` holds `role_id` in `tenant_id` still in force at
    /// `at`, as storage answers whether a role is held.
    fn holds_in_force(
        &self,
        tenant_id: TenantId,
        principal: &PrincipalRef,
        role_id: &RoleId,
        at: OffsetDateTime,
    ) -> bool {
        self.assignments
            .lock()
            .unwrap()
            .iter()
            .any(|(tenant, held)| {
                *tenant == tenant_id
                    && held.principal() == principal
                    && held.role_id() == role_id
                    && held.is_in_force(at)
            })
    }

    /// Takes away `role_id` from `principal` in `tenant_id` when its end
    /// had come by `at`, and answers whether it did.
    fn take_lapsed(
        &self,
        tenant_id: TenantId,
        principal: &PrincipalRef,
        role_id: &RoleId,
        at: OffsetDateTime,
    ) -> bool {
        let mut assignments = self.assignments.lock().unwrap();
        let before = assignments.len();
        assignments.retain(|(tenant, held)| {
            !(*tenant == tenant_id
                && held.principal() == principal
                && held.role_id() == role_id
                && !held.is_in_force(at))
        });
        assignments.len() < before
    }
}

/// Moving every holder of one role onto another, as `by` does it.
pub(crate) struct Reassignment {
    from: RoleId,
    to: RoleId,
    by: ActorRef,
}

impl Reassignment {
    fn given_to(&self, principal: PrincipalRef) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal,
            role_id: self.to,
            assigned_by: self.by.clone(),
            assigned_at: clock::now(),
            expires: Expiry::Never,
        })
        .expect("a fresh assignment is a consistent row")
    }
}

#[async_trait]
impl RoleAssignmentStore for FakeRoleAssignmentStore {
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError> {
        self.assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, held)| *tenant == **tenant_id && held.principal() == principal)
            .map(|(_, held)| copy_assignment(held))
            .collect()
    }

    async fn exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        role_id: &RoleId,
    ) -> Result<bool, DomainError> {
        Ok(self.holds_in_force(**tenant_id, principal, role_id, clock::now()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &RoleAssignment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let (principal, role_id) = (assignment.principal(), assignment.role_id());
        let given_at = assignment.assigned_at();
        if self.holds_in_force(**tenant_id, principal, role_id, given_at) {
            return Ok(());
        }
        self.take_lapsed(**tenant_id, principal, role_id, given_at);
        let copy = copy_assignment(assignment)?;
        self.assignments.lock().unwrap().push((**tenant_id, copy));
        Ok(())
    }

    async fn remove_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &RoleAssignment<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        Ok(self.take_lapsed(
            **tenant_id,
            assignment.principal(),
            assignment.role_id(),
            now,
        ))
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        role_id: &RoleId,
    ) -> Result<(), DomainError> {
        self.assignments.lock().unwrap().retain(|(tenant, held)| {
            !(*tenant == **tenant_id && held.principal() == principal && held.role_id() == role_id)
        });
        Ok(())
    }

    /// Mirrors one scoped batch delete without changing unrelated assignments.
    async fn delete_for_principals(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
        principals: &[PrincipalRef],
    ) -> Result<(), DomainError> {
        self.assignments.lock().unwrap().retain(|(tenant, held)| {
            !(*tenant == **tenant_id
                && held.role_id() == role_id
                && principals.contains(held.principal()))
        });
        Ok(())
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        batch: &HoldingBatch<AssignmentPosition>,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError> {
        let key = |position: AssignmentPosition| {
            (
                position.expires_at,
                *position.role_id.as_uuid(),
                principal_sort_word(&position.principal),
                position.principal.id(),
            )
        };
        let after = batch.after.map(key);
        let mut rows: Vec<_> = self
            .assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, held)| *tenant == **tenant_id && !held.is_in_force(batch.now))
            .filter(|(_, held)| {
                AssignmentPosition::of(held)
                    .is_some_and(|position| after.is_none_or(|after| key(position) > after))
            })
            .map(|(_, held)| copy_assignment(held))
            .collect::<Result<_, _>>()?;
        rows.sort_by_key(|held| AssignmentPosition::of(held).map(key));
        rows.truncate(HOLDING_BATCH_SIZE);
        self.lapsed_reads.lock().unwrap().push(rows.len());
        Ok(rows)
    }

    async fn count_by_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        Ok(self.holders_of(**tenant_id, role_id).len() as u64)
    }

    async fn count_by_roles(
        &self,
        tenant_id: &ScopedTenant,
        role_ids: &[RoleId],
    ) -> Result<HashMap<RoleId, u64>, DomainError> {
        Ok(role_ids
            .iter()
            .map(|role_id| (*role_id, self.holders_of(**tenant_id, role_id).len() as u64))
            .filter(|(_, count)| *count > 0)
            .collect())
    }
}

/// Unit of work over a [`FakeRoleStore`] and a [`FakeRoleAssignmentStore`],
/// so its reassign-and-delete shows through both.
pub struct FakeRoleDeletionUnitOfWork {
    /// The store whose role is deleted.
    pub role_store: Arc<FakeRoleStore>,
    /// The store whose holders are moved.
    pub assignment_store: Arc<FakeRoleAssignmentStore>,
}

impl TenantScoped for FakeRoleDeletionUnitOfWork {}

#[async_trait]
impl RoleDeletionUnitOfWork for FakeRoleDeletionUnitOfWork {
    async fn reassign_and_delete(
        &self,
        tenant_id: &ScopedTenant,
        target: &RoleId,
        replacement: &RoleId,
        reassigned_by: ActorRef,
    ) -> Result<u64, DomainError> {
        let change = Reassignment {
            from: *target,
            to: *replacement,
            by: reassigned_by,
        };
        let moved = self.assignment_store.reassign(**tenant_id, &change);
        self.role_store.remove(**tenant_id, target);
        Ok(moved)
    }
}

/// Reads who holds a role from the stores it is handed: the roles given
/// straight to principals, and the groups carrying them. The default reads
/// empty ones, so nobody holds a role.
#[derive(Default)]
pub struct FakeRoleHolderQueries {
    /// The roles given straight to principals.
    pub assignments: Arc<FakeRoleAssignmentStore>,
    /// The groups, with the roles each carries.
    pub groups: Arc<FakeGroupStore>,
}

impl TenantScoped for FakeRoleHolderQueries {}

impl FakeRoleHolderQueries {
    /// Every holder of `role_id` in `tenant_id` at `now`, in the order the
    /// port lists them.
    fn all_holders(
        &self,
        tenant_id: TenantId,
        role_id: &RoleId,
        now: OffsetDateTime,
    ) -> Result<Vec<RoleHolder>, DomainError> {
        let mut holders: Vec<RoleHolder> = Vec::new();
        let direct = self
            .assignments
            .of_tenant(tenant_id)?
            .into_iter()
            .filter(|held| held.role_id() == role_id && held.is_in_force(now))
            .map(|held| RoleHolder::Direct(*held.principal()));
        for holder in direct {
            if !holders.contains(&holder) {
                holders.push(holder);
            }
        }
        let groups = self.groups.of_tenant(tenant_id)?;
        holders.extend(
            groups
                .iter()
                .filter(|group| group.role_ids().contains(role_id))
                .map(|group| RoleHolder::Group(*group.id())),
        );
        Ok(holders)
    }
}

#[async_trait]
impl RoleHolderQueries for FakeRoleHolderQueries {
    async fn holders_of(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<RoleHolder>, DomainError> {
        let holders = self.all_holders(**tenant_id, role_id, now)?;
        page(
            holders,
            &SortOrder::<RoleHolderSortField>::default(),
            request,
        )
    }
}

impl Fake for Arc<dyn RoleHolderQueries> {
    fn fake() -> Self {
        Arc::new(FakeRoleHolderQueries::default())
    }
}

impl Fake for Arc<dyn RoleAssignmentStore> {
    fn fake() -> Self {
        Arc::new(FakeRoleAssignmentStore::empty())
    }
}

impl Fake for Arc<dyn RoleDeletionUnitOfWork> {
    fn fake() -> Self {
        Arc::new(FakeRoleDeletionUnitOfWork {
            role_store: Arc::new(FakeRoleStore::empty()),
            assignment_store: Arc::new(FakeRoleAssignmentStore::empty()),
        })
    }
}

impl Fake for Arc<dyn RoleStore> {
    fn fake() -> Self {
        Arc::new(FakeRoleStore::empty())
    }
}
