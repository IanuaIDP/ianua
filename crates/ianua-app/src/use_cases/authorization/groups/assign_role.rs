//! Assign group role: give a role to a group of the tenant.
//!
//! Every member of the group, and of the groups under it, holds the role.
//! So this is the grant `assign_role` makes, aimed at a set of principals,
//! and the domain checks it the same way: the caller can only give a group
//! a role they could hand out themselves. Nobody in the group, or under
//! it, may end up holding both roles of a separation-of-duties rule. An
//! admin role is given only once the company's "before admin given" rules
//! allow it.

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
use crate::ports::authorization::{AccessRecordStore, GroupStore, RoleStore, SeparationRuleStore};
use crate::ports::workflows::ChangeGuard;
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::existing_group;

/// The ports [`AssignRoleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AssignRolePorts {
    /// Loads and saves groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Loads the role given.
    pub role_store: Arc<dyn RoleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Reads who is in which group, for the separation-of-duties check.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's separation-of-duties rules.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// The company's "before" rules, asked before an admin role reaches a
    /// group.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Which role to give to which group.
pub struct AssignRoleRequest {
    /// The group that receives the role.
    pub group_id: GroupId,
    /// The role to give.
    pub role_id: RoleId,
}

/// Gives a role to a group of the caller's tenant.
pub struct AssignRoleUseCase {
    ports: AssignRolePorts,
}

impl AssignRoleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AssignRolePorts) -> Self {
        Self { ports }
    }

    /// Refuses giving `group_id` the role `role_id` when someone in it, or
    /// under it, would then hold both roles of a separation-of-duties rule.
    async fn ensure_duties_kept_with(
        &self,
        tenant: &ScopedTenant,
        group_id: &GroupId,
        role_id: &RoleId,
    ) -> Result<(), AppError> {
        let sources = DutySources {
            records: self.ports.access_records.as_ref(),
            rules: self.ports.separation_rules.as_ref(),
        };
        let granting = Granting::GroupRole {
            group: group_id,
            role: role_id,
        };
        ensure_duties_kept(sources, tenant, granting).await
    }
}

impl Command for AssignRoleUseCase {
    type Caller = CallerContext;
    type Input = AssignRoleRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.role_id` to `request.group_id`, granted by the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the group.
    /// - `AppError::NotFound` for a missing group/role; `Forbidden` when the caller cannot grant all the role's rights.
    /// - `AppError::Conflict` for an existing assignment or a member's separation-of-duties violation.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AssignRoleRequest,
    ) -> Result<(), AppError> {
        let AssignRoleRequest { group_id, role_id } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let mut group = existing_group(self.ports.group_store.as_ref(), &tenant, &group_id).await?;
        let role = existing_role(self.ports.role_store.as_ref(), &tenant, &role_id).await?;
        ensure_not_carried(&group, &role_id)?;
        group
            .assign_role(&role, &authority.standing())
            .map_err(AppError::from_domain)?;
        self.ensure_duties_kept_with(&tenant, &group_id, &role_id)
            .await?;
        let guard = self.ports.guard.as_ref();
        let holder = AdminHolder::Group(&group_id);
        ensure_admin_rules_allow(guard, &tenant, auditor, &role, holder).await?;

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

/// Refuses giving a group a role it already carries.
fn ensure_not_carried(group: &Group<ResolvedTenant>, role_id: &RoleId) -> Result<(), AppError> {
    if group.role_ids().contains(role_id) {
        return Err(AppError::Conflict(message!(
            "authorization-group-already-has-this-role",
            "group already has this role"
        )));
    }
    Ok(())
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
        FakeRoleAssignmentStore, FakeRoleStore, FakeSeparationRuleStore, separation_between,
        stored_assignment, stored_group, stored_membership, stored_role,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const ASSIGN_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Assign);

    /// The group "Engineering" and one role, in the test tenant.
    struct Tenant {
        group_id: GroupId,
        role_id: RoleId,
        groups: Arc<FakeGroupStore>,
        roles: Arc<FakeRoleStore>,
    }

    impl Tenant {
        fn with(role: Role<ResolvedTenant>, carried: Vec<RoleId>) -> Self {
            let tenant = test_ctx().tenant_id();
            let group = stored_group("Engineering", GroupPlace::TopLevel, carried);
            Self {
                group_id: *group.id(),
                role_id: *role.id(),
                groups: Arc::new(FakeGroupStore::holding(tenant, [group])),
                roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
            }
        }

        fn with_editor() -> Self {
            Self::with(stored_role("editor", Vec::new(), Vec::new()), Vec::new())
        }

        fn with_admin() -> Self {
            let admin = stored_role("admin", vec![SystemPermission::ManageUsers], Vec::new());
            Self::with(admin, Vec::new())
        }

        fn ports(&self) -> AssignRolePorts {
            AssignRolePorts {
                group_store: self.groups.clone(),
                role_store: self.roles.clone(),
                ..AssignRolePorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> AssignRolePorts {
            AssignRolePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn request(&self) -> AssignRoleRequest {
            AssignRoleRequest {
                group_id: self.group_id,
                role_id: self.role_id,
            }
        }

        fn carried(&self) -> Vec<RoleId> {
            let group = block_on(self.groups.find_by_id(&test_ctx().tenant(), &self.group_id));
            group.unwrap().unwrap().role_ids().to_vec()
        }
    }

    fn assign(
        ports: AssignRolePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: AssignRoleRequest,
    ) -> Result<(), AppError> {
        block_on(AssignRoleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn quietly(ports: AssignRolePorts, request: AssignRoleRequest) -> Result<(), AppError> {
        assign(ports, &Arc::new(FakeEventDispatcher::new()), request)
    }

    /// Ann gives "Engineering" the role "editor". The group carries it, and
    /// the record names the group and the role.
    #[test]
    fn a_role_is_given_to_a_group_and_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());

        assign(tenant.ports(), &sink, tenant.request()).unwrap();

        let event = "authorization.group_role_assigned";
        assert_eq!(tenant.carried(), [tenant.role_id]);
        assert_eq!(sink.records.lock().unwrap().as_slice(), [event]);
        assert_eq!(
            sink.label_of(event, "group").as_deref(),
            Some("Engineering")
        );
        assert_eq!(sink.label_of(event, "role").as_deref(), Some("editor"));
    }

    /// Ann gives a role to a group the tenant does not have. It is not found
    /// and nothing is recorded.
    #[test]
    fn an_unknown_group_is_not_found_and_not_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = AssignRoleRequest {
            group_id: GroupId::new(),
            ..tenant.request()
        };

        let result = assign(tenant.ports(), &sink, request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann gives "Engineering" a role the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = Tenant::with_editor();
        let request = AssignRoleRequest {
            role_id: RoleId::new(),
            ..tenant.request()
        };

        let result = quietly(tenant.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann gives "Engineering" a role it already carries. She is refused as
    /// a conflict.
    #[test]
    fn a_role_the_group_already_carries_is_a_conflict() {
        let editor = stored_role("editor", Vec::new(), Vec::new());
        let carried = vec![*editor.id()];
        let tenant = Tenant::with(editor, carried);

        let result = quietly(tenant.ports(), tenant.request());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Sam may assign roles and manage users. He gives "Engineering" the
    /// admin role, which he could have given anyone himself.
    #[test]
    fn a_caller_may_give_a_group_a_role_they_hold() {
        let tenant = Tenant::with_admin();
        let held = [ASSIGN_ROLES, SystemPermission::ManageUsers];

        quietly(tenant.ports_holding(&held), tenant.request()).unwrap();

        assert_eq!(tenant.carried(), [tenant.role_id]);
    }

    /// Sam cannot give Engineering a user-management role he lacks authority
    /// to grant. The refusal leaves the group without roles.
    #[test]
    fn a_caller_cannot_give_a_group_a_role_they_do_not_hold() {
        let tenant = Tenant::with_admin();

        let result = quietly(tenant.ports_holding(&[ASSIGN_ROLES]), tenant.request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.carried().is_empty());
    }

    /// Without assignment permission, adding a role is forbidden and Engineering
    /// continues to carry no roles.
    #[test]
    fn a_caller_who_may_not_assign_roles_is_refused() {
        let tenant = Tenant::with_editor();

        let result = quietly(tenant.ports_holding(&[]), tenant.request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.carried().is_empty());
    }

    /// A signed-out caller cannot assign a group role. Engineering keeps no roles.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_editor();
        let ports = AssignRolePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(tenant.carried().is_empty());
    }

    /// Bob's payment-raiser role conflicts with giving his group the approver
    /// role. The rejected assignment leaves Engineering without roles.
    #[test]
    fn a_group_role_breaking_a_separation_of_duties_is_refused() {
        let tenant_id = test_ctx().tenant_id();
        let raiser = stored_role("raiser", Vec::new(), Vec::new());
        let approver = stored_role("approver", Vec::new(), Vec::new());
        let rule = separation_between("raise or approve payments", &raiser, &approver);
        let bob = PrincipalRef::User(UserId::new());
        let raises = stored_assignment(bob, *raiser.id());
        let tenant = Tenant::with(approver, Vec::new());
        tenant.roles.add(tenant_id, [raiser]);
        let sources = AccessSources {
            roles: tenant.roles.clone(),
            groups: tenant.groups.clone(),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant_id, [raises])),
            memberships: Arc::new(FakeGroupMembershipStore::holding(
                tenant_id,
                [stored_membership(bob, tenant.group_id)],
            )),
            ..AccessSources::default()
        };
        let ports = AssignRolePorts {
            access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
            separation_rules: Arc::new(FakeSeparationRuleStore::holding(tenant_id, [rule])),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(tenant.carried().is_empty());
    }

    /// Ann's company rule refuses every admin role. Tess gives
    /// "Engineering" the role "admin": it is refused and the group carries
    /// nothing.
    #[test]
    fn a_company_rule_refusing_stops_an_admin_role_reaching_a_group() {
        let tenant = Tenant::with_admin();
        let ports = AssignRolePorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.carried().is_empty());
    }

    /// The same rule is not asked about "editor": the group carries it.
    #[test]
    fn a_group_role_doing_no_admin_work_is_not_asked_about() {
        let tenant = Tenant::with_editor();
        let ports = AssignRolePorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        quietly(ports, tenant.request()).unwrap();

        assert_eq!(tenant.carried(), [tenant.role_id]);
    }
}
