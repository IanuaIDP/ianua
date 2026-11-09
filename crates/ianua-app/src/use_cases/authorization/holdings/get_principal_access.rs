//! Get principal access: what one person, agent or app holds in the tenant,
//! and where each piece comes from.
//!
//! An admin asking "why may Bob do this?" sees the roles given to Bob
//! straight, the groups he is in with the groups above them, and each role
//! that reaches him through a group, with when each ends. Holdings whose
//! end has passed are left out, since they grant nothing.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{Expiry, GroupId, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::{AccessRecordStore, AccessRecords, Holder};
use crate::use_case::Query;
use crate::use_cases::authorization::lookup::held_records;

/// The ports [`GetPrincipalAccessUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPrincipalAccessPorts {
    /// Reads who holds what across the tenant.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A role given straight to the principal.
#[derive(Debug, Clone)]
pub struct DirectRole {
    /// The permission bundle assigned without group inheritance.
    pub role: Role<ResolvedTenant>,
    /// When it is taken away again, or that it is not.
    pub until: Expiry,
}

/// A group the principal is in itself.
#[derive(Debug, Clone, Copy)]
pub struct DirectMembership {
    /// The membership container the principal joined directly.
    pub group: GroupId,
    /// When the membership ends, or that it does not.
    pub until: Expiry,
}

/// A role that reaches the principal through a group.
#[derive(Debug, Clone)]
pub struct RoleThroughGroup {
    /// The group carrying it: one the principal is in, or one above.
    pub group: GroupId,
    /// The permission bundle inherited through the carrying group.
    pub role: Role<ResolvedTenant>,
}

/// What a principal holds in the tenant now, with where each comes from.
#[derive(Debug, Clone)]
pub struct PrincipalAccess {
    /// The roles given to them straight.
    pub direct_roles: Vec<DirectRole>,
    /// The groups they are in themselves.
    pub memberships: Vec<DirectMembership>,
    /// Every group they are in, with every group above those.
    pub groups: Vec<GroupId>,
    /// The roles reaching them through those groups.
    pub through_groups: Vec<RoleThroughGroup>,
}

/// Reads what one principal holds in the caller's tenant.
pub struct GetPrincipalAccessUseCase {
    ports: GetPrincipalAccessPorts,
}

impl GetPrincipalAccessUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPrincipalAccessPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetPrincipalAccessUseCase {
    type Caller = CallerContext;
    type Input = PrincipalRef;
    type Output = Result<PrincipalAccess, AppError>;

    /// What `principal` holds now, and from where. A principal the tenant
    /// does not know holds nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::Internal` when the records cannot be read, or name a
    ///   role or group that is not there.
    async fn execute(
        &self,
        ctx: &CallerContext,
        principal: PrincipalRef,
    ) -> Result<PrincipalAccess, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.access_records.as_ref();
        let held = held_records(store, &tenant, Holder::of(principal)).await?;
        let groups = held
            .access(*tenant)
            .grants
            .groups_of(principal)
            .map_err(AppError::from_domain)?;
        let records = held.records();
        Ok(PrincipalAccess {
            direct_roles: direct_roles(records, principal),
            memberships: direct_memberships(records, principal),
            through_groups: roles_through(records, &groups),
            groups,
        })
    }
}

/// The roles given straight to `principal`, in force now.
fn direct_roles(records: &AccessRecords, principal: PrincipalRef) -> Vec<DirectRole> {
    let now = clock::now();
    records
        .assignments
        .iter()
        .filter(|held| *held.principal() == principal && held.is_in_force(now))
        .filter_map(|held| {
            let role = records
                .roles
                .iter()
                .find(|role| role.id() == held.role_id())?;
            Some(DirectRole {
                role: role.clone(),
                until: held.expires(),
            })
        })
        .collect()
}

/// The groups `principal` is in themselves, in force now.
fn direct_memberships(records: &AccessRecords, principal: PrincipalRef) -> Vec<DirectMembership> {
    let now = clock::now();
    records
        .memberships
        .iter()
        .filter(|held| *held.principal() == principal && held.is_in_force(now))
        .map(|held| DirectMembership {
            group: *held.group_id(),
            until: held.expires(),
        })
        .collect()
}

/// Each role `groups` carry, with the group carrying it.
fn roles_through(records: &AccessRecords, groups: &[GroupId]) -> Vec<RoleThroughGroup> {
    records
        .groups
        .iter()
        .filter(|group| groups.contains(group.id()))
        .flat_map(|group| {
            group.role_ids().iter().filter_map(|role_id| {
                let role = records.roles.iter().find(|role| role.id() == role_id)?;
                Some(RoleThroughGroup {
                    group: *group.id(),
                    role: role.clone(),
                })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::types::UserId;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleAssignmentStore, FakeRoleStore, stored_assignment_until, stored_group,
        stored_membership, stored_role,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Bob holds "billing" until tomorrow and sat in "Backend", under
    /// "Engineering", which carries "deploy". His "viewer" role ended an
    /// hour ago.
    fn bobs_tenant(bob: PrincipalRef) -> GetPrincipalAccessPorts {
        let tenant = test_ctx().tenant_id();
        let billing = stored_role("billing", Vec::new(), Vec::new());
        let viewer = stored_role("viewer", Vec::new(), Vec::new());
        let deploy = stored_role("deploy", Vec::new(), Vec::new());
        let engineering = stored_group("Engineering", GroupPlace::TopLevel, vec![*deploy.id()]);
        let backend = stored_group("Backend", GroupPlace::Under(*engineering.id()), Vec::new());
        let tomorrow = Expiry::At(clock::now() + Duration::days(1));
        let ended = Expiry::At(clock::now() - Duration::hours(1));
        let assignments = [
            stored_assignment_until(bob, *billing.id(), tomorrow),
            stored_assignment_until(bob, *viewer.id(), ended),
        ];
        let membership = stored_membership(bob, *backend.id());
        let sources = AccessSources {
            roles: Arc::new(FakeRoleStore::holding(tenant, [billing, viewer, deploy])),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, assignments)),
            groups: Arc::new(FakeGroupStore::holding(tenant, [engineering, backend])),
            memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, [membership])),
            ..AccessSources::default()
        };
        GetPrincipalAccessPorts {
            access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
            ..GetPrincipalAccessPorts::fakes()
        }
    }

    fn get(
        ports: GetPrincipalAccessPorts,
        principal: PrincipalRef,
    ) -> Result<PrincipalAccess, AppError> {
        block_on(GetPrincipalAccessUseCase::new(ports).execute(&test_ctx(), principal))
    }

    /// Ann asks why Bob may deploy. She sees "billing" given to him until
    /// tomorrow, his place in "Backend", both groups, and "deploy" reaching
    /// him through "Engineering". His ended "viewer" role is not listed.
    #[test]
    fn what_a_principal_holds_is_shown_with_its_source() {
        let bob = PrincipalRef::User(UserId::new());

        let access = get(bobs_tenant(bob), bob).unwrap();

        let direct: Vec<&str> = access
            .direct_roles
            .iter()
            .map(|held| held.role.name().as_str())
            .collect();
        assert_eq!(direct, ["billing"]);
        assert_eq!(access.memberships.len(), 1);
        assert_eq!(access.groups.len(), 2);
        assert_eq!(access.through_groups.len(), 1);
        assert_eq!(access.through_groups[0].role.name().as_str(), "deploy");
    }

    /// Ann asks about someone the tenant does not know. They hold nothing.
    #[test]
    fn an_unknown_principal_holds_nothing() {
        let bob = PrincipalRef::User(UserId::new());

        let access = get(bobs_tenant(bob), PrincipalRef::User(UserId::new())).unwrap();

        assert!(access.direct_roles.is_empty() && access.groups.is_empty());
    }

    /// Reading Bob's access is forbidden without role view permission.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let bob = PrincipalRef::User(UserId::new());
        let ports = GetPrincipalAccessPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..bobs_tenant(bob)
        };

        assert!(matches!(get(ports, bob), Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read Bob's current access.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bob = PrincipalRef::User(UserId::new());
        let ports = GetPrincipalAccessPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..bobs_tenant(bob)
        };

        assert!(matches!(get(ports, bob), Err(AppError::Unauthenticated)));
    }
}
