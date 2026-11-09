//! The roles a new tenant starts with, made by the platform while it sets
//! the tenant up: Admin, granting every built-in permission, and Member,
//! granting a view of the metrics to every new user.
//!
//! No person makes them, so no granter is checked. In its place stands a
//! [`StartingRolesGrant`], which only a tenant's setup hands out, at its
//! starting-roles step: outside setup no code can make a role that grants
//! everything without the check [`Role::create`] makes.

use crate::domains::authorization::events::roles::RoleCreated;
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{Label, RoleId};

/// The proof that a tenant's setup is making its starting roles. Only the
/// setup makes one.
#[derive(Debug)]
pub struct StartingRolesGrant(());

impl StartingRolesGrant {
    /// The grant, for a setup at its starting-roles step.
    pub(crate) fn for_setup() -> Self {
        Self(())
    }
}

/// One of the roles a new tenant starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartingRole {
    /// Every built-in permission, assigned by hand.
    Admin,
    /// A view of the metrics, given to every new user.
    Member,
}

impl StartingRole {
    /// Every starting role, in the order they are made.
    pub const ALL: [Self; 2] = [Self::Admin, Self::Member];

    /// The initial display label seeded when the tenant is created.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Admin => "Admin",
            Self::Member => "Member",
        }
    }

    fn system_permissions(self) -> Vec<SystemPermission> {
        match self {
            Self::Admin => SystemPermission::all().to_vec(),
            Self::Member => vec![SystemPermission::ViewMetrics],
        }
    }

    fn assignment(self) -> DefaultAssignment {
        match self {
            Self::Admin => DefaultAssignment::Manual,
            Self::Member => DefaultAssignment::NewUsers,
        }
    }
}

impl<T: TenantScope> Role<T> {
    /// The starting role `kind`, made under `grant` by a tenant's setup.
    /// Raises `authorization.role_created`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Validation`] if the role's name no longer passes a
    /// label's rules.
    pub fn starting(kind: StartingRole, _grant: &StartingRolesGrant) -> Result<Self, DomainError> {
        let mut role = Self::assembled(NewRole {
            id: RoleId::new(),
            name: Label::new("name", kind.name())?,
            system_permissions: kind.system_permissions(),
            custom_permissions: Vec::new(),
            assignment: kind.assignment(),
        });
        role.raised.raise(RoleCreated {
            role_id: role.id,
            name: role.name.clone(),
            occurred_at: role.created_at,
        });
        Ok(role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;

    /// Admin grants every built-in permission and is assigned by hand;
    /// Member grants a view of the metrics to every new user.
    #[test]
    fn the_starting_roles_grant_what_a_new_tenant_needs() {
        let grant = StartingRolesGrant::for_setup();

        let admin = Role::<ResolvedTenant>::starting(StartingRole::Admin, &grant).unwrap();
        let member = Role::<ResolvedTenant>::starting(StartingRole::Member, &grant).unwrap();

        assert_eq!(admin.name().as_str(), "Admin");
        assert_eq!(
            admin.system_permissions().len(),
            SystemPermission::all().len()
        );
        assert!(!admin.is_default());
        assert_eq!(member.system_permissions(), [SystemPermission::ViewMetrics]);
        assert!(member.is_default());
    }
}
