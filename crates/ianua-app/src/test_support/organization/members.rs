//! Organization members as tests need them, the in-memory member store, and
//! the tenant roles members hold.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::organization::members::membership::{OrgRole, TenantReach};
use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUser, OrgUserRow};
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::domains::organization::members::tenant_grant::{
    OrgTenantGrant, OrgTenantGrantRow,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::fakes::FakeHasher;
use ianua_domain::types::{
    ActedBy, CredentialChange, DisplayName, Email, Joining, OrgUserId, OrganizationId, Preference,
    RoleId, TenantId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::organization::{
    MembersInTenant, OrgTenantGrantStore, OrgUserFilter, OrgUserSortField, OrgUserStore,
    TenantMemberRoster,
};
use crate::test_support::listing::page;
use crate::test_support::organization::lifecycle::cfg;
use crate::test_support::{Fake, test_org_caller};

/// An active, verified member of `organization_id` in `role`, with no
/// password.
///
/// A test that needs a password sets one on what comes back, the way the
/// product does.
#[must_use]
pub fn test_org_user(organization_id: OrganizationId, email: &str, role: OrgRole) -> OrgUser {
    active_member(Member {
        id: OrgUserId::new(),
        organization_id,
        email,
        name: "Someone",
        password: OrgPassword::NotSet,
        role,
    })
}

/// An active, verified owner of `organization_id` who signs in with
/// `password`, hashed the way [`FakeHasher`] hashes it.
#[must_use]
pub fn test_org_owner(organization_id: OrganizationId, email: &str, password: &str) -> OrgUser {
    let hash = FakeHasher.hash(password).expect("the fake hasher hashes");
    active_member(Member {
        id: OrgUserId::new(),
        organization_id,
        email,
        name: "Admin",
        password: OrgPassword::Set(hash),
        role: OrgRole::Owner,
    })
}

/// The member every [`test_org_caller`] acts as, as stored: active,
/// verified, in `role`, signing in with `password` hashed the way
/// [`FakeHasher`] hashes it.
///
/// A use case acting on the caller's own account loads this record, while
/// the caller's proof comes from `acting`.
#[must_use]
pub fn stored_caller(role: OrgRole, password: &str) -> OrgUser {
    let caller = test_org_caller();
    let hash = FakeHasher.hash(password).expect("the fake hasher hashes");
    active_member(Member {
        id: *caller.member(),
        organization_id: caller.organization_id(),
        email: "caller@example.test",
        name: "Caller",
        password: OrgPassword::Set(hash),
        role,
    })
}

/// What tells one test member from another.
struct Member<'a> {
    id: OrgUserId,
    organization_id: OrganizationId,
    email: &'a str,
    name: &'a str,
    password: OrgPassword,
    role: OrgRole,
}

/// A member of `organization_id` at `email` who joined and verified their
/// address, now standing at `status`: active, locked or deactivated.
#[must_use]
pub fn test_org_member_at(
    organization_id: OrganizationId,
    email: &str,
    status: OrgUserStatus,
) -> OrgUser {
    joined_member(
        Member {
            id: OrgUserId::new(),
            organization_id,
            email,
            name: "Someone",
            password: OrgPassword::NotSet,
            role: OrgRole::Member,
        },
        status,
    )
}

fn active_member(member: Member<'_>) -> OrgUser {
    joined_member(member, OrgUserStatus::Active)
}

fn joined_member(member: Member<'_>, status: OrgUserStatus) -> OrgUser {
    let now = clock::now();
    OrgUser::reconstitute(OrgUserRow {
        id: member.id,
        organization_id: member.organization_id,
        email: Email::new(member.email).expect("a valid address"),
        display_name: DisplayName::new(member.name, &cfg().display_name).expect("a valid name"),
        password_hash: member.password,
        status,
        role: member.role,
        email_standing: AddressStanding::Verified,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        created_at: now,
        updated_at: now,
        joining: Joining::Joined { at: now },
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    })
    .expect("a joined, verified member is a consistent row")
}

/// A member store already holding `users`.
#[must_use]
pub fn org_user_store_with(users: impl IntoIterator<Item = OrgUser>) -> FakeOrgUserStore {
    let store = FakeOrgUserStore::empty();
    store.users.lock().unwrap().extend(users);
    store
}

/// A copy of `user`, read back the way storage reads it.
fn copy_org_user(user: &OrgUser) -> Result<OrgUser, DomainError> {
    OrgUser::reconstitute(OrgUserRow {
        id: *user.id(),
        organization_id: *user.organization_id(),
        email: user.email().clone(),
        display_name: user.display_name().clone(),
        password_hash: user.password_hash().clone(),
        status: user.status(),
        role: user.role(),
        email_standing: user.address().standing(),
        locale: user.locale().clone(),
        timezone: user.timezone().clone(),
        created_at: user.created_at(),
        updated_at: user.updated_at(),
        joining: Joining::from_stored(user.joined_at()),
        credentials_changed_at: user.credentials_changed_at(),
        vouching: user.vouching(),
    })
}

/// In-memory member store that keeps every member it is handed.
#[derive(Default)]
pub struct FakeOrgUserStore {
    users: Mutex<Vec<OrgUser>>,
    id_reads: Mutex<Vec<Vec<OrgUserId>>>,
    identity_reads_fail: AtomicBool,
}

impl FakeOrgUserStore {
    /// Makes identity lookups fail so callers must preserve storage errors.
    pub fn fail_identity_reads(&self) {
        self.identity_reads_fail.store(true, Ordering::Relaxed);
    }

    /// Refuses an identity read when its storage dependency is unavailable.
    fn ensure_identity_readable(&self) -> Result<(), DomainError> {
        if self.identity_reads_fail.load(Ordering::Relaxed) {
            return Err(DomainError::infra_msg(
                "organization identities unavailable",
            ));
        }
        Ok(())
    }

    /// The account ids requested together, exposing repeated identity reads.
    #[must_use]
    pub fn id_reads(&self) -> Vec<Vec<OrgUserId>> {
        self.id_reads.lock().unwrap().clone()
    }

    /// A store holding no member.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many members are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.users.lock().unwrap().len()
    }

    /// The status of the member `id`, if one is held.
    #[must_use]
    pub fn get_status(&self, id: &OrgUserId) -> Option<OrgUserStatus> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|user| user.id() == id)
            .map(OrgUser::status)
    }

    fn matching(&self, keep: impl Fn(&OrgUser) -> bool) -> Result<Vec<OrgUser>, DomainError> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .filter(|user| keep(user))
            .map(copy_org_user)
            .collect()
    }

    fn first(&self, matches: impl Fn(&OrgUser) -> bool) -> Result<Option<OrgUser>, DomainError> {
        Ok(self.matching(matches)?.into_iter().next())
    }
}

/// Whether `user` passes every part of `filter`.
fn passes(user: &OrgUser, filter: &OrgUserFilter) -> bool {
    filter.status.is_none_or(|status| user.status() == status)
        && filter
            .ids
            .as_ref()
            .is_none_or(|ids| ids.contains(user.id()))
        && filter.email_contains.as_ref().is_none_or(|part| {
            user.email()
                .as_str()
                .to_lowercase()
                .contains(&part.to_lowercase())
        })
}

#[async_trait]
impl OrgUserStore for FakeOrgUserStore {
    async fn find_by_id(&self, id: &OrgUserId) -> Result<Option<OrgUser>, DomainError> {
        self.id_reads.lock().unwrap().push(vec![*id]);
        self.ensure_identity_readable()?;
        self.first(|user| user.id() == id)
    }

    async fn find_by_ids(&self, ids: &[OrgUserId]) -> Result<Vec<OrgUser>, DomainError> {
        self.id_reads.lock().unwrap().push(ids.to_vec());
        self.ensure_identity_readable()?;
        self.matching(|user| ids.contains(user.id()))
    }

    async fn find_by_id_in_org(
        &self,
        organization_id: &OrganizationId,
        id: &OrgUserId,
    ) -> Result<Option<OrgUser>, DomainError> {
        self.first(|user| user.id() == id && user.organization_id() == organization_id)
    }

    async fn hold_by_id_in_org(
        &self,
        organization_id: &OrganizationId,
        id: &OrgUserId,
    ) -> Result<Option<OrgUser>, DomainError> {
        self.find_by_id_in_org(organization_id, id).await
    }

    async fn hold_ownership(&self, _: &OrganizationId) -> Result<(), DomainError> {
        Ok(())
    }

    async fn list_owners(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<OrgUser>, DomainError> {
        self.matching(|user| {
            user.organization_id() == organization_id && user.role() == OrgRole::Owner
        })
    }

    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<OrgUser>, DomainError> {
        self.first(|user| user.organization_id() == organization_id && user.email() == email)
    }

    async fn find_all_by_email(&self, email: &Email) -> Result<Vec<OrgUser>, DomainError> {
        self.matching(|user| user.email() == email)
    }

    async fn email_exists(&self, email: &Email) -> Result<bool, DomainError> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .any(|user| user.email() == email))
    }

    async fn list_by_org(
        &self,
        organization_id: &OrganizationId,
        filter: &OrgUserFilter,
        sort: &SortOrder<OrgUserSortField>,
        request: &PageRequest,
    ) -> Result<Page<OrgUser>, DomainError> {
        let users = self
            .matching(|user| user.organization_id() == organization_id && passes(user, filter))?;
        page(users, sort, request)
    }

    async fn save(&self, user: &OrgUser) -> Result<(), DomainError> {
        let copy = copy_org_user(user)?;
        let mut users = self.users.lock().unwrap();
        match users.iter_mut().find(|held| held.id() == user.id()) {
            Some(held) => *held = copy,
            None => users.push(copy),
        }
        Ok(())
    }

    async fn delete(&self, id: &OrgUserId) -> Result<(), DomainError> {
        self.users.lock().unwrap().retain(|user| user.id() != id);
        Ok(())
    }
}

/// A grant of a role made up for the test, which the platform gave
/// `member` in `tenant`.
#[must_use]
pub fn platform_grant(member: &OrgUser, tenant: TenantId) -> OrgTenantGrant {
    OrgTenantGrant::reconstitute(OrgTenantGrantRow {
        org_user_id: *member.id(),
        tenant_id: tenant,
        role_id: RoleId::new(),
        granted_by: ActedBy::Platform,
        granted_at: clock::now(),
    })
    .unwrap()
}

/// In-memory store of the tenant roles members hold.
#[derive(Default)]
pub struct FakeOrgTenantGrantStore {
    grants: Mutex<Vec<OrgTenantGrant>>,
}

impl FakeOrgTenantGrantStore {
    /// A store holding no grant.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `grants`.
    #[must_use]
    pub fn holding(grants: impl IntoIterator<Item = OrgTenantGrant>) -> Self {
        let store = Self::default();
        store.grants.lock().unwrap().extend(grants);
        store
    }

    fn matching(&self, keep: impl Fn(&OrgTenantGrant) -> bool) -> Vec<OrgTenantGrant> {
        self.grants
            .lock()
            .unwrap()
            .iter()
            .filter(|grant| keep(grant))
            .cloned()
            .collect()
    }
}

#[async_trait]
impl OrgTenantGrantStore for FakeOrgTenantGrantStore {
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgTenantGrant>, DomainError> {
        Ok(self.matching(|grant| grant.org_user_id() == org_user_id))
    }

    async fn list_by_user_in_tenant(
        &self,
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<OrgTenantGrant>, DomainError> {
        Ok(self
            .matching(|grant| grant.org_user_id() == org_user_id && grant.tenant_id() == tenant_id))
    }

    async fn list_tenant_ids(&self, org_user_id: &OrgUserId) -> Result<Vec<TenantId>, DomainError> {
        let mut ids = Vec::new();
        for grant in self.matching(|grant| grant.org_user_id() == org_user_id) {
            if !ids.contains(grant.tenant_id()) {
                ids.push(*grant.tenant_id());
            }
        }
        Ok(ids)
    }

    async fn replace_in_tenant(
        &self,
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
        grants: &[OrgTenantGrant],
    ) -> Result<(), DomainError> {
        let mut stored = self.grants.lock().unwrap();
        stored.retain(|grant| {
            !(grant.org_user_id() == org_user_id && grant.tenant_id() == tenant_id)
        });
        stored.extend(grants.iter().cloned());
        Ok(())
    }
}

/// A grant of a role made up for the test, which the platform gave the
/// member `org_user_id` in `tenant`, for a member a test knows by id alone.
#[must_use]
pub fn platform_grant_to(org_user_id: OrgUserId, tenant: TenantId) -> OrgTenantGrant {
    OrgTenantGrant::reconstitute(OrgTenantGrantRow {
        org_user_id,
        tenant_id: tenant,
        role_id: RoleId::new(),
        granted_by: ActedBy::Platform,
        granted_at: clock::now(),
    })
    .unwrap()
}

/// In-memory roster answering from the members and grants it holds.
#[derive(Default)]
pub struct FakeTenantMemberRoster {
    members: FakeOrgUserStore,
    grants: FakeOrgTenantGrantStore,
}

impl FakeTenantMemberRoster {
    /// A roster of `members`, holding `grants`.
    #[must_use]
    pub fn holding(
        members: impl IntoIterator<Item = OrgUser>,
        grants: impl IntoIterator<Item = OrgTenantGrant>,
    ) -> Self {
        Self {
            members: org_user_store_with(members),
            grants: FakeOrgTenantGrantStore::holding(grants),
        }
    }
}

#[async_trait]
impl TenantMemberRoster for FakeTenantMemberRoster {
    async fn members_in(
        &self,
        organization_id: &OrganizationId,
        tenant_id: &TenantId,
    ) -> Result<MembersInTenant, DomainError> {
        let grants = self.grants.matching(|grant| grant.tenant_id() == tenant_id);
        let members = self.members.matching(|member| {
            member.organization_id() == organization_id
                && (member.role().tenant_reach() == TenantReach::Every
                    || grants
                        .iter()
                        .any(|grant| grant.org_user_id() == member.id()))
        })?;
        let grants = grants
            .into_iter()
            .filter(|grant| {
                members
                    .iter()
                    .any(|member| member.id() == grant.org_user_id())
            })
            .collect();
        Ok(MembersInTenant { members, grants })
    }
}

impl Fake for Arc<dyn TenantMemberRoster> {
    fn fake() -> Self {
        Arc::new(FakeTenantMemberRoster::default())
    }
}

impl Fake for Arc<dyn OrgTenantGrantStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgTenantGrantStore::empty())
    }
}

impl Fake for Arc<dyn OrgUserStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgUserStore::empty())
    }
}
