//! What a caller holds when the gateway decides one of its requests: the
//! permissions, and the roles and groups a tenant's policy rules name.
//!
//! The gateway's decision reads all three from the tenant's records, never
//! from what a token claims. Worked out here, from [`TenantAccess`], so no
//! caller writes the list itself.

use time::OffsetDateTime;

use crate::domains::authorization::authority::{Holdings, TenantAccess};
#[cfg(any(test, feature = "test-support"))]
use crate::domains::authorization::permission::{CustomPermission, SystemPermission};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{GroupId, Label, PrincipalRef, RoleId};

/// What one principal holds in a tenant now, as a request decision reads
/// it.
///
/// Its fields are private, so only the tenant's records give someone a
/// role or a permission here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Held {
    holdings: Holdings,
    roles: Vec<RoleId>,
    role_names: Vec<Label>,
    groups: Vec<GroupId>,
}

impl Held {
    /// What `principal` holds at `now` by `access`: the permissions
    /// [`TenantAccess::permissions_held_by`] gives, the roles
    /// [`TenantAccess::roles_held_by`] names, and the groups it is in.
    ///
    /// A principal the records do not name holds nothing.
    ///
    /// # Errors
    ///
    /// - The cases
    ///   [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators)
    ///   lists, for records that name a role or group that is not there.
    pub fn of<T: TenantScope>(
        access: &TenantAccess<'_, T>,
        principal: PrincipalRef,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let held_roles = access.roles_held_by(principal)?;
        Ok(Self {
            holdings: access.permissions_held_by(principal, now)?,
            roles: held_roles.iter().map(|role| *role.id()).collect(),
            role_names: held_roles.iter().map(|role| role.name().clone()).collect(),
            groups: access.grants.groups_of(principal)?,
        })
    }

    /// What `principal` holds by `holdings`, worked out elsewhere from its
    /// standing, with the roles `granted` it beside any the records give it,
    /// and the groups it is in: an organization member's, whose tenant
    /// permissions and roles come from their role and grants, not the
    /// tenant's assignments.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when `granted` or the records name
    ///   a role or group the tenant does not have.
    pub(crate) fn granted<T: TenantScope>(
        access: &TenantAccess<'_, T>,
        principal: PrincipalRef,
        holdings: Holdings,
        granted: &[RoleId],
    ) -> Result<Self, DomainError> {
        let mut held_roles = access.roles_held_by(principal)?;
        for id in granted {
            let Some(role) = access.grants.roles.iter().find(|role| role.id() == id) else {
                return Err(DomainError::infra_msg(
                    "an organization tenant grant names a role the tenant does not have",
                ));
            };
            if !held_roles.iter().any(|held| held.id() == role.id()) {
                held_roles.push(role);
            }
        }
        Ok(Self {
            holdings,
            roles: held_roles.iter().map(|role| *role.id()).collect(),
            role_names: held_roles.iter().map(|role| role.name().clone()).collect(),
            groups: access.grants.groups_of(principal)?,
        })
    }

    /// Holding `system`, `custom`, `roles` and `groups`, as a test says,
    /// without the records behind it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(
        system: &[SystemPermission],
        custom: &[CustomPermission],
        roles: &[RoleId],
        groups: &[GroupId],
    ) -> Self {
        Self {
            holdings: Holdings::of(system.to_vec(), custom.to_vec()),
            roles: roles.to_vec(),
            role_names: Vec::new(),
            groups: groups.to_vec(),
        }
    }

    /// The permissions held, built-in and app-defined.
    #[must_use]
    pub fn holdings(&self) -> &Holdings {
        &self.holdings
    }

    /// The roles held, given straight or through a group, each once.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    /// The names of the roles held, as an upstream reads them. A test's
    /// assumed holder names none.
    #[must_use]
    pub fn role_names(&self) -> &[Label] {
        &self.role_names
    }

    /// The groups the principal is in, with every group above them, each
    /// once.
    #[must_use]
    pub fn groups(&self) -> &[GroupId] {
        &self.groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::UserAction;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::clock;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::types::{TenantId, UserId};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    fn viewer() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("viewer"),
            system_permissions: vec![VIEW_USERS],
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn held_by(
        roles: &[Role<ResolvedTenant>],
        assignments: &[RoleAssignment<ResolvedTenant>],
        principal: PrincipalRef,
    ) -> Held {
        let access = TenantAccess {
            tenant: TenantId::new(),
            grants: TenantGrants {
                roles,
                assignments,
                groups: &[] as &[Group<ResolvedTenant>],
                memberships: &[] as &[GroupMembership<ResolvedTenant>],
            },
            catalogue: &[],
            break_glass: &[],
        };
        Held::of(&access, principal, clock::now()).unwrap()
    }

    /// Ann is given the viewer role. What she holds names the role and the
    /// right it gives, so a policy rule on that role matches her.
    #[test]
    fn what_is_held_names_the_roles_behind_the_permissions() {
        let role = viewer();
        let ann = PrincipalRef::User(UserId::new());
        let given =
            RoleAssignment::create(ann, &role, anyone_holding(SystemPermission::all())).unwrap();

        let held = held_by(std::slice::from_ref(&role), &[given], ann);

        assert_eq!(held.roles(), [*role.id()]);
        assert_eq!(held.role_names(), [label("viewer")]);
        assert!(held.holdings().holds(VIEW_USERS));
        assert!(held.groups().is_empty());
    }

    /// A principal absent from the assignment records holds no permissions,
    /// roles or groups, even when another principal has the viewer role.
    #[test]
    fn a_principal_the_records_do_not_name_holds_nothing() {
        let role = viewer();
        let given = RoleAssignment::create(
            PrincipalRef::User(UserId::new()),
            &role,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();

        let held = held_by(
            std::slice::from_ref(&role),
            &[given],
            PrincipalRef::User(UserId::new()),
        );

        assert_eq!(held, Held::default());
    }
}
