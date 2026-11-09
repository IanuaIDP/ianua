//! Access policies and the records of access granted.

use async_trait::async_trait;
use ianua_domain::domains::authorization::authority::TenantAccess;
use ianua_domain::domains::authorization::break_glass::BreakGlassGrant;
use ianua_domain::domains::authorization::group::{Group, GroupMembership};
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::authorization::stewardship::{AdministratorCount, TenantGrants};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, OrgUserId, PrincipalRef, RoleId, TenantId, UserId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order a tenant's administrators are listed in: by user id.
    pub enum AdministratorSortField {
        /// Order by the user's id.
        UserId => "user_id",
    }
    default = UserId;
}

impl SortKeys<AdministratorSortField> for UserId {
    fn sort_key(&self, field: AdministratorSortField) -> SortKey {
        match field {
            AdministratorSortField::UserId => self.as_uuid().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.as_uuid().into()
    }
}

/// Everything a tenant stores about who holds what, read together: its
/// roles, who was given them, its groups and their members, the resource
/// types whose ladders confer app permissions, and its break-glass grants.
///
/// What a caller holds is worked out from these by the domain, never written
/// by a use case.
#[derive(Debug, Default)]
pub struct AccessRecords {
    /// Every role of the tenant.
    pub roles: Vec<Role<ResolvedTenant>>,
    /// Every role given straight to someone.
    pub assignments: Vec<RoleAssignment<ResolvedTenant>>,
    /// Every group of the tenant.
    pub groups: Vec<Group<ResolvedTenant>>,
    /// Every membership of a group.
    pub memberships: Vec<GroupMembership<ResolvedTenant>>,
    /// The tenant's resource types.
    pub catalogue: Vec<ResourceType<ResolvedTenant>>,
    /// The tenant's break-glass grants.
    pub break_glass: Vec<BreakGlassGrant>,
}

impl AccessRecords {
    /// The records as the domain reads them, for `tenant`.
    #[must_use]
    pub fn access(&self, tenant: TenantId) -> TenantAccess<'_, ResolvedTenant> {
        TenantAccess {
            tenant,
            grants: TenantGrants {
                roles: &self.roles,
                assignments: &self.assignments,
                groups: &self.groups,
                memberships: &self.memberships,
            },
            catalogue: &self.catalogue,
            break_glass: &self.break_glass,
        }
    }
}

/// Whose records a narrowed read is for: a principal, and the roles named
/// for them elsewhere, such as an organization member's tenant grants.
#[derive(Debug, Clone, Copy)]
pub struct Holder<'a> {
    /// The principal whose assignments and memberships are read.
    pub principal: PrincipalRef,
    /// Roles to read besides those the principal's records name.
    pub granted_roles: &'a [RoleId],
}

impl Holder<'static> {
    /// `principal`, holding only what its own records name.
    #[must_use]
    pub fn of(principal: PrincipalRef) -> Self {
        Self {
            principal,
            granted_roles: &[],
        }
    }

    /// A tenant user, holding only what their own records name.
    #[must_use]
    pub fn user(user: UserId) -> Self {
        Self::of(PrincipalRef::User(user))
    }
}

impl<'a> Holder<'a> {
    /// An organization member, holding what their own records name and
    /// `granted_roles`, the roles their tenant grants give them.
    #[must_use]
    pub fn member(member: OrgUserId, granted_roles: &'a [RoleId]) -> Self {
        Self {
            principal: PrincipalRef::OrgUser(member),
            granted_roles,
        }
    }
}

/// Whose records a narrowed read of several holders at once is for: the
/// principals, groups whose place in the tree is asked about, such as a
/// group people are about to join, and roles about to be given.
#[derive(Debug, Clone, Copy)]
pub struct Holders<'a> {
    /// The principals whose assignments and memberships are read.
    pub principals: &'a [PrincipalRef],
    /// Groups read with every group above them and the roles they name,
    /// whoever is in them.
    pub groups: &'a [GroupId],
    /// Roles read besides those the principals' records and `groups` name.
    pub roles: &'a [RoleId],
}

/// One principal's share of a tenant's access records, or several's: what
/// a [`Holder`] or [`Holders`] read returns.
///
/// It holds the principal's own assignments and memberships, every group
/// above the groups they are in, the roles all of those and the holder's
/// granted roles name, the tenant's resource types, and the principal's
/// break-glass grants still running. What it says about this principal is
/// what the whole records say; it says nothing about anyone else.
#[derive(Debug, Default)]
pub struct HeldRecords(AccessRecords);

impl HeldRecords {
    /// `records`, read for one holder.
    #[must_use]
    pub fn new(records: AccessRecords) -> Self {
        Self(records)
    }

    /// The records as the domain reads them, for `tenant`.
    #[must_use]
    pub fn access(&self, tenant: TenantId) -> TenantAccess<'_, ResolvedTenant> {
        self.0.access(tenant)
    }

    /// The records read, to list where the holder's holdings come from.
    #[must_use]
    pub fn records(&self) -> &AccessRecords {
        &self.0
    }

    /// The records read, to work out what a change would leave the holders
    /// with.
    #[must_use]
    pub fn into_records(self) -> AccessRecords {
        self.0
    }
}

/// Dyn-safe port that reads a tenant's [`AccessRecords`], whole or for one
/// holder, and counts its administrators.
#[async_trait]
pub trait AccessRecordStore: Send + Sync + TenantScoped {
    /// The tenant's access records, as stored now, every one of them.
    ///
    /// Only for what spans the whole tenant: a change to a role or a group
    /// that reaches everyone holding it (deleting or narrowing a role,
    /// taking a role off a group, deleting or moving a group), starting an
    /// access review, policy approval and simulation. What one person holds
    /// is read with [`load_held_by`](Self::load_held_by), several people's
    /// with [`load_held_by_all`](Self::load_held_by_all), and whether the
    /// tenant keeps an administrator with
    /// [`count_administrators`](Self::count_administrators).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be read.
    async fn load(&self, tenant_id: &ScopedTenant) -> Result<AccessRecords, DomainError>;

    /// What decides `holder`'s holdings in the tenant, and nothing else:
    /// see [`HeldRecords`].
    ///
    /// A group, role or resource type their records name that is missing
    /// is left out, never made up, so the domain refuses the records as
    /// broken.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be read.
    async fn load_held_by(
        &self,
        tenant_id: &ScopedTenant,
        holder: Holder<'_>,
    ) -> Result<HeldRecords, DomainError>;

    /// What decides the holdings of every one of `holders.principals`, with
    /// `holders.groups` and the groups above them and the `holders.roles`,
    /// in one read: see [`HeldRecords`]. What it says of each principal is
    /// what the whole records say; it says nothing of anyone else. A role
    /// or group named that is missing is left out, never made up.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be read.
    async fn load_held_by_all(
        &self,
        tenant_id: &ScopedTenant,
        holders: Holders<'_>,
    ) -> Result<HeldRecords, DomainError>;

    /// How many users administer the tenant now, counted as
    /// [`AdministratorCount`] defines it, without reading every record.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be counted.
    async fn count_administrators(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<AdministratorCount, DomainError>;

    /// One page of the users who administer the tenant now, as
    /// [`AdministratorCount`] defines administering, ordered by id so pages
    /// hold: who hears what happens inside the tenant.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be read.
    async fn list_administrators(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<UserId>, DomainError>;

    /// One page of the users whose roles give `right` in the tenant now,
    /// through their own assignments or their groups, as
    /// `TenantGrants::holders_of_right` finds them, ordered by id so pages
    /// hold: who hears what only that right lets them act on, such as an
    /// alert about the tenant's mail.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the records cannot be read.
    async fn list_holders_of(
        &self,
        tenant_id: &ScopedTenant,
        right: SystemPermission,
        page: &PageRequest,
    ) -> Result<Page<UserId>, DomainError>;

    /// Holds who holds what in the tenant until the running unit of work
    /// settles: another hold of the tenant waits for it.
    ///
    /// A change checked against what the tenant's grants would become is
    /// held first and read after, in the unit that writes it. So two changes
    /// checked at the same moment, two grants that together break a
    /// separation of duties or two group moves that together close a loop,
    /// are checked one after the other, and the second sees the first.
    /// Outside a unit the hold ends at once.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the hold cannot be taken.
    async fn hold_grants(&self, tenant_id: &ScopedTenant) -> Result<(), DomainError>;
}

/// Dyn-safe port for persisting and retrieving the versions of a tenant's
/// access policy.
///
/// A tenant keeps one row per version, keyed by its number: at most one
/// live, at most one open draft beside it, and every past one. The domain's
/// `PolicyHistory` checks what is read back, so the store only keeps the
/// rows.
#[async_trait]
pub trait PolicyStore: Send + Sync + TenantScoped {
    /// Every version of the tenant's policy, whatever its state, in any
    /// order. Empty when the tenant never saved one.
    ///
    /// What the editor and the history read: the open draft and the live
    /// version are found among them by the domain, never asked for by state.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_versions(&self, tenant_id: &ScopedTenant) -> Result<Vec<PolicySet>, DomainError>;

    /// Finds the tenant's live version.
    ///
    /// What enforcement reads. A draft or a version in review answers
    /// `None` here, so nothing half-written can decide a real request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_active(&self, tenant_id: &ScopedTenant)
    -> Result<Option<PolicySet>, DomainError>;

    /// Saves one version, inserting it or replacing the row with its
    /// number.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the version cannot be written.
    async fn save(&self, tenant_id: &ScopedTenant, policy: &PolicySet) -> Result<(), DomainError>;

    /// Saves an approved version and the live version it replaced in one
    /// transaction, so the tenant never has two live versions, nor none
    /// between the two writes.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the versions cannot be written; then
    /// neither is.
    async fn save_activation(
        &self,
        tenant_id: &ScopedTenant,
        activated: &PolicySet,
        replaced: Option<&PolicySet>,
    ) -> Result<(), DomainError>;
}
