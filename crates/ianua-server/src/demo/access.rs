//! Who may do what in a tenant: its roles, the teams carrying them, and
//! who is in each team.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::authorization::{groups, roles};
use ianua_domain::domains::authorization::role::DefaultAssignment;
use ianua_domain::types::{Expiry, GroupId, Label, PrincipalRef, RoleId, UserId};

use crate::demo::DemoError;
use crate::demo::catalog::RoleSeed;
use crate::demo::seeder::{DemoTenant, Seed, Seeder};

/// The role `seed` names, found by its name or created by the owner.
///
/// # Errors
///
/// [`DemoError`] when the role cannot be looked up or created.
pub(super) async fn role(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    seed: &RoleSeed,
) -> Result<Seed<RoleId>, DemoError> {
    let name = Label::new("name", seed.name)?;
    let store = seeder.adapters.role_store.as_ref();
    if let Some(found) = store.find_by_name(&tenant.scoped(), &name).await? {
        return Ok(Seed::Found(*found.id()));
    }
    let request = roles::CreateRequest {
        name,
        system_permissions: seed.permissions.to_vec(),
        custom_permissions: Vec::new(),
        is_default: DefaultAssignment::Manual,
    };
    let acting = seeder.in_tenant(tenant).await?;
    let create = seeder.state.authorization.roles.create.as_ref();
    let id = seeder
        .kept(
            "a role",
            create.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(id))
}

/// The team called `name`, found by its name or created by the owner.
///
/// # Errors
///
/// [`DemoError`] when the group cannot be looked up or created.
pub(super) async fn team(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    name: &str,
) -> Result<Seed<GroupId>, DemoError> {
    let name = Label::new("name", name)?;
    let store = seeder.adapters.group_store.as_ref();
    if let Some(found) = store.find_by_name(&tenant.scoped(), &name).await? {
        return Ok(Seed::Found(*found.id()));
    }
    let request = groups::CreateRequest {
        name,
        parent_id: None,
    };
    let acting = seeder.in_tenant(tenant).await?;
    let create = seeder.state.authorization.groups.create.as_ref();
    let id = seeder
        .kept(
            "a team",
            create.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(id))
}

/// The team `group` carrying `role`, unless it does already.
///
/// # Errors
///
/// [`DemoError`] when the team cannot be read or given the role.
pub(super) async fn team_role(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    group: GroupId,
    role: RoleId,
) -> Result<Seed<()>, DemoError> {
    let store = seeder.adapters.group_store.as_ref();
    let found = store
        .find_by_id(&tenant.scoped(), &group)
        .await?
        .ok_or(DemoError::Vanished("a team"))?;
    if found.role_ids().contains(&role) {
        return Ok(Seed::Found(()));
    }
    let request = groups::AssignRoleRequest {
        group_id: group,
        role_id: role,
    };
    let acting = seeder.in_tenant(tenant).await?;
    let assign = seeder.state.authorization.groups.assign_role.as_ref();
    seeder
        .kept(
            "a team's role",
            assign.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(()))
}

/// `user` in the team `group`, for good, unless they are already.
///
/// # Errors
///
/// [`DemoError`] when the membership cannot be read or made.
pub(super) async fn member(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    group: GroupId,
    user: UserId,
) -> Result<Seed<()>, DemoError> {
    let principal = PrincipalRef::User(user);
    let store = seeder.adapters.group_membership_store.as_ref();
    if store.exists(&tenant.scoped(), &principal, &group).await? {
        return Ok(Seed::Found(()));
    }
    let request = groups::AddMemberRequest {
        group_id: group,
        member: principal,
        until: Expiry::Never,
    };
    let acting = seeder.in_tenant(tenant).await?;
    let add = seeder.state.authorization.groups.add_member.as_ref();
    seeder
        .kept(
            "a team member",
            add.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(()))
}
