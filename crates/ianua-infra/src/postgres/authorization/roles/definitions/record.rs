//! A role as its row holds it: read back into the aggregate, and written
//! out from it.

use std::collections::HashMap;

use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::authorization::role::{DefaultAssignment, Role, RoleRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, PrincipalRef, RoleId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::principal_from;
use crate::postgres::foundation::stored::Stored;

const ROLE: Stored = Stored("role");

/// A role as it is read. The store's checked queries fill it.
pub(crate) struct RoleRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) system_permissions: Vec<String>,
    pub(crate) custom_permissions: Vec<String>,
    pub(crate) is_default: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl RoleRecord {
    /// The role the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the name no longer passes
    /// its rules, a permission names nothing this release knows, or the row
    /// breaks a rule the role keeps.
    pub(crate) fn into_role(self) -> Result<Role<ResolvedTenant>, DomainError> {
        Role::reconstitute(RoleRow {
            id: RoleId::from_uuid(self.id),
            name: ROLE.value("name", Label::new("name", self.name))?,
            system_permissions: system_permissions_from(&self.system_permissions)?,
            custom_permissions: custom_permissions_from(&self.custom_permissions)?,
            is_default: DefaultAssignment::from(self.is_default),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// One directly assigned role and the principal holding it.
pub(super) struct DirectRoleRecord {
    pub(super) principal_kind: String,
    pub(super) principal_id: Uuid,
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) system_permissions: Vec<String>,
    pub(super) custom_permissions: Vec<String>,
    pub(super) is_default: bool,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl DirectRoleRecord {
    /// Rebuilds the role through the same checks used by single-principal reads.
    fn into_assignment(self) -> Result<(PrincipalRef, Role<ResolvedTenant>), DomainError> {
        let principal = principal_from(ROLE, &self.principal_kind, self.principal_id)?;
        let role = RoleRecord {
            id: self.id,
            name: self.name,
            system_permissions: self.system_permissions,
            custom_permissions: self.custom_permissions,
            is_default: self.is_default,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
        .into_role()?;
        Ok((principal, role))
    }
}

/// Groups directly assigned roles by principal, preserving their SQL order.
///
/// # Errors
///
/// Returns infrastructure errors when a principal or role cannot be reconstituted.
pub(super) fn direct_roles_from(
    records: Vec<DirectRoleRecord>,
) -> Result<HashMap<PrincipalRef, Vec<Role<ResolvedTenant>>>, DomainError> {
    let mut held = HashMap::<_, Vec<_>>::new();
    for record in records {
        let (principal, role) = record.into_assignment()?;
        held.entry(principal).or_default().push(role);
    }
    Ok(held)
}

/// The roles `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(crate) fn roles_from(
    records: Vec<RoleRecord>,
) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
    records.into_iter().map(RoleRecord::into_role).collect()
}

/// The built-in permissions `stored`, each written as `idp:area:action`,
/// name.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when one names no permission.
pub(crate) fn system_permissions_from(
    stored: &[String],
) -> Result<Vec<SystemPermission>, DomainError> {
    stored
        .iter()
        .map(|written| {
            SystemPermission::parse(written)
                .ok_or_else(|| DomainError::corrupt_row(ROLE.0, "an unknown system permission"))
        })
        .collect()
}

/// The tenant's own permissions `stored`, each written as
/// `resource:action`, name.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when one is not a permission.
pub(crate) fn custom_permissions_from(
    stored: &[String],
) -> Result<Vec<CustomPermission>, DomainError> {
    stored
        .iter()
        .map(|written| {
            CustomPermission::parse(written)
                .ok_or_else(|| DomainError::corrupt_row(ROLE.0, "an unknown custom permission"))
        })
        .collect()
}

/// `permissions` as their column holds them, each written out.
pub(crate) fn written<P: ToString>(permissions: &[P]) -> Vec<String> {
    permissions.iter().map(ToString::to_string).collect()
}

/// A role's columns, as they are written.
pub(crate) struct RoleColumns<'a> {
    pub(crate) id: &'a Uuid,
    pub(crate) name: &'a str,
    pub(crate) system_permissions: Vec<String>,
    pub(crate) custom_permissions: Vec<String>,
    pub(crate) is_default: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl<'a> RoleColumns<'a> {
    /// The columns `role` is written to.
    pub(crate) fn of(role: &'a Role<ResolvedTenant>) -> Self {
        Self {
            id: role.id().as_uuid(),
            name: role.name().as_str(),
            system_permissions: written(role.system_permissions()),
            custom_permissions: written(role.custom_permissions()),
            is_default: role.is_default(),
            created_at: role.created_at(),
            updated_at: role.updated_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, UserAction};

    use super::*;

    /// Every built-in permission is written in a form that reads back as
    /// the same permission.
    #[test]
    fn every_system_permission_reads_back_as_written() {
        let stored = written(SystemPermission::ALL_VARIANTS);

        let read = system_permissions_from(&stored).unwrap();

        assert_eq!(read, SystemPermission::ALL_VARIANTS);
    }

    /// Permissions are stored in the words other queries match on: the
    /// `idp:` form for built-in ones, `resource:action` for the tenant's.
    #[test]
    fn permissions_are_stored_in_their_written_form() {
        let system = [
            SystemPermission::Roles(RoleAction::Assign),
            SystemPermission::Users(UserAction::Manage),
        ];
        let custom = [CustomPermission::new("project", "write").unwrap()];

        assert_eq!(written(&system), ["idp:roles:assign", "idp:users:manage"]);
        assert_eq!(written(&custom), ["project:write"]);
    }

    /// An unknown stored system permission is refused as corrupt storage
    /// instead of being omitted from the role.
    #[test]
    fn an_unknown_permission_is_refused() {
        let read = system_permissions_from(&["idp:nothing:here".to_owned()]);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
