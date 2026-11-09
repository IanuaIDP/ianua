//! Unassign group role: take a role off a group of the tenant.
//!
//! Every member loses the role, so only someone who could have given it
//! takes it off, and never when that leaves the tenant without an
//! administrator.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{GroupId, RoleId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, GroupStore, RoleStore};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::{access_records, existing_group};
use crate::use_cases::authorization::stewardship::{Withdrawal, ensure_still_administered};

/// The ports [`UnassignRoleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UnassignRolePorts {
    /// Loads and saves groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Loads the role taken off.
    pub role_store: Arc<dyn RoleStore>,
    /// Reads who holds what across the tenant, to keep an administrator.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which role to take off which group.
pub struct UnassignRoleRequest {
    /// The group that loses the role.
    pub group_id: GroupId,
    /// The role to take off.
    pub role_id: RoleId,
}

/// Takes a role off a group of the caller's tenant.
pub struct UnassignRoleUseCase {
    ports: UnassignRolePorts,
}

impl UnassignRoleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UnassignRolePorts) -> Self {
        Self { ports }
    }

    /// Refuses taking `role_id` off `group_id` when that leaves the tenant
    /// nobody can administer.
    async fn ensure_administered_without(
        &self,
        tenant: &ScopedTenant,
        group_id: &GroupId,
        role_id: &RoleId,
    ) -> Result<(), AppError> {
        let before = access_records(self.ports.access_records.as_ref(), tenant).await?;
        let change = Withdrawal::GroupRole {
            group: group_id,
            role: role_id,
        };
        ensure_still_administered(tenant, before, change)
    }
}

impl Command for UnassignRoleUseCase {
    type Caller = CallerContext;
    type Input = UnassignRoleRequest;
    type Output = Result<(), AppError>;

    /// Takes `request.role_id` off `request.group_id`, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the group.
    /// - `AppError::NotFound` for a missing group, role or assignment; `Forbidden` when the caller could not grant all the role's rights.
    /// - `AppError::Conflict` when the role supplies the tenant's last administrator; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UnassignRoleRequest,
    ) -> Result<(), AppError> {
        let UnassignRoleRequest { group_id, role_id } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let mut group = existing_group(self.ports.group_store.as_ref(), &tenant, &group_id).await?;
        ensure_carried(&group, &role_id)?;
        let role = existing_role(self.ports.role_store.as_ref(), &tenant, &role_id).await?;
        group
            .unassign_role(&role, &authority.standing())
            .map_err(AppError::from_domain)?;
        self.ensure_administered_without(&tenant, &group_id, &role_id)
            .await?;

        self.ports
            .group_store
            .save(&tenant, &group)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), group.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Refuses taking off a role the group does not carry.
fn ensure_carried(group: &Group<ResolvedTenant>, role_id: &RoleId) -> Result<(), AppError> {
    if group.role_ids().contains(role_id) {
        return Ok(());
    }
    Err(AppError::NotFound(message!(
        "authorization-group-does-not-have-this-role",
        "group does not have this role"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleStore, stored_group, stored_membership, stored_role,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The group "Engineering" carrying one role, with its members, read by
    /// every port.
    struct Tenant {
        group_id: GroupId,
        role_id: RoleId,
        stores: AccessSources,
    }

    impl Tenant {
        fn carrying(role: Role<ResolvedTenant>, members: &[UserId]) -> Self {
            let tenant = test_ctx().tenant_id();
            let group = stored_group("Engineering", GroupPlace::TopLevel, vec![*role.id()]);
            let (group_id, role_id) = (*group.id(), *role.id());
            let memberships = members
                .iter()
                .map(|member| stored_membership(PrincipalRef::User(*member), group_id));
            Self {
                group_id,
                role_id,
                stores: AccessSources {
                    groups: Arc::new(FakeGroupStore::holding(tenant, [group])),
                    roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
                    memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, memberships)),
                    ..AccessSources::default()
                },
            }
        }

        fn carrying_editor() -> Self {
            Self::carrying(stored_role("editor", Vec::new(), Vec::new()), &[])
        }

        fn carrying_admin(members: &[UserId]) -> Self {
            let admin = stored_role(
                "admin",
                vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
                Vec::new(),
            );
            Self::carrying(admin, members)
        }

        fn ports(&self) -> UnassignRolePorts {
            UnassignRolePorts {
                group_store: self.stores.groups.clone(),
                role_store: self.stores.roles.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..UnassignRolePorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> UnassignRolePorts {
            UnassignRolePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn request(&self) -> UnassignRoleRequest {
            UnassignRoleRequest {
                group_id: self.group_id,
                role_id: self.role_id,
            }
        }

        fn carried(&self) -> Vec<RoleId> {
            let tenant = test_ctx().tenant();
            let group = block_on(self.stores.groups.find_by_id(&tenant, &self.group_id));
            group.unwrap().unwrap().role_ids().to_vec()
        }
    }

    fn unassign(
        ports: UnassignRolePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: UnassignRoleRequest,
    ) -> Result<(), AppError> {
        block_on(UnassignRoleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn quietly(ports: UnassignRolePorts, request: UnassignRoleRequest) -> Result<(), AppError> {
        unassign(ports, &Arc::new(FakeEventDispatcher::new()), request)
    }

    /// Ann takes "editor" off "Engineering". The group no longer carries
    /// it, and the record names the group and the role.
    #[test]
    fn a_role_is_taken_off_a_group_and_recorded() {
        let tenant = Tenant::carrying_editor();
        let sink = Arc::new(FakeEventDispatcher::new());

        unassign(tenant.ports(), &sink, tenant.request()).unwrap();

        let event = "authorization.group_role_unassigned";
        assert!(tenant.carried().is_empty());
        assert_eq!(sink.records.lock().unwrap().as_slice(), [event]);
        assert_eq!(
            sink.label_of(event, "group").as_deref(),
            Some("Engineering")
        );
        assert_eq!(sink.label_of(event, "role").as_deref(), Some("editor"));
    }

    /// Ann takes a role off a group the tenant does not have. It is not
    /// found and nothing is recorded.
    #[test]
    fn an_unknown_group_is_not_found_and_not_recorded() {
        let tenant = Tenant::carrying_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = UnassignRoleRequest {
            group_id: GroupId::new(),
            ..tenant.request()
        };

        let result = unassign(tenant.ports(), &sink, request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann takes off "Engineering" a role it does not carry. It is not
    /// found.
    #[test]
    fn a_role_the_group_does_not_carry_is_not_found() {
        let tenant = Tenant::carrying_editor();
        let request = UnassignRoleRequest {
            role_id: RoleId::new(),
            ..tenant.request()
        };

        let result = quietly(tenant.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.carried(), [tenant.role_id]);
    }

    /// Nobody belongs to "Engineering", so taking the admin role off it
    /// takes no administrator away. Ann does it and it goes through.
    #[test]
    fn a_role_nobody_administers_through_is_taken_off() {
        let tenant = Tenant::carrying_admin(&[]);

        quietly(tenant.ports(), tenant.request()).unwrap();

        assert!(tenant.carried().is_empty());
    }

    /// Removing the role that supplies the last administrator is a conflict;
    /// Engineering keeps its admin role.
    #[test]
    fn taking_off_the_role_of_the_last_administrator_is_refused() {
        let tenant = Tenant::carrying_admin(&[UserId::new()]);

        let result = quietly(tenant.ports(), tenant.request());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.carried(), [tenant.role_id]);
    }

    /// Assignment permission alone cannot remove an admin role the caller
    /// could not grant. Engineering keeps the role.
    #[test]
    fn a_caller_cannot_take_off_a_role_they_could_not_have_given() {
        let tenant = Tenant::carrying_admin(&[]);
        let sam = tenant.ports_holding(&[SystemPermission::Roles(RoleAction::Assign)]);

        let result = quietly(sam, tenant.request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.carried(), [tenant.role_id]);
    }

    /// Without assignment permission, removing Engineering's editor role is
    /// forbidden and leaves it carried by the group.
    #[test]
    fn a_caller_who_may_not_assign_roles_is_refused() {
        let tenant = Tenant::carrying_editor();

        let result = quietly(tenant.ports_holding(&[]), tenant.request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.carried(), [tenant.role_id]);
    }

    /// A signed-out session cannot remove a role from Engineering; it stays carried.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::carrying_editor();
        let ports = UnassignRolePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.carried(), [tenant.role_id]);
    }
}
