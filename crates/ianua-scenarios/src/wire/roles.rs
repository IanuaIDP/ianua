//! A tenant's roles and the permissions they carry: listing, making and
//! changing them, assigning them to users, and who holds them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::wire::routing::CustomPermission;

/// A built-in permission as the API writes it, `{"Users": "View"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SystemPermission(Value);

impl SystemPermission {
    /// The permission to do `action` on `resource`, such as `Users` and
    /// `View`.
    #[must_use]
    pub fn new(resource: &str, action: &str) -> Self {
        let mut written = serde_json::Map::new();
        written.insert(resource.to_owned(), Value::String(action.to_owned()));
        Self(Value::Object(written))
    }
}

/// One role of a tenant.
#[derive(Debug, Clone, Deserialize)]
pub struct Role {
    /// Handle used to edit permissions and manage assignments.
    pub id: String,
    /// Its name, such as `Admin`.
    pub name: String,
    /// The built-in permissions it carries.
    #[serde(default)]
    pub system_permissions: Vec<SystemPermission>,
    /// Whether new users get it.
    pub is_default: bool,
    /// How many users hold it.
    #[serde(default)]
    pub assigned_user_count: u64,
}

/// `POST …/authorization/roles`.
#[derive(Debug, Clone, Serialize)]
pub struct NewRole {
    /// Label shown when assigning this permission set to principals.
    pub name: String,
    /// The built-in permissions it carries.
    pub system_permissions: Vec<SystemPermission>,
}

/// `POST …/authorization/roles` for a role granting permissions of the
/// tenant's own app, the ones a route can ask for.
#[derive(Debug, Clone, Serialize)]
pub struct NewAppRole {
    /// Label shown when assigning this permission set to principals.
    pub name: String,
    /// The tenant's own permissions it carries.
    pub custom_permissions: Vec<CustomPermission>,
}

/// Creation response used to address the new permission set.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleMade {
    /// Handle used for subsequent assignments and permission changes.
    pub id: String,
}

/// `PATCH …/authorization/roles/{id}`: what changes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RoleChange {
    /// Its new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its whole new set of built-in permissions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_permissions: Option<Vec<SystemPermission>>,
}

/// `POST …/authorization/roles/{id}/assignments`.
#[derive(Debug, Clone, Serialize)]
pub struct AssignRole {
    /// The user who gets it.
    pub user_id: String,
}

/// Who holds a role: directly, or through a group.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub enum Holder {
    /// Held directly by a principal.
    Direct {
        /// Identity holding the assignment without group membership.
        principal: Principal,
    },
    /// Held by every member of a group.
    Group {
        /// The group's id.
        group_id: String,
    },
}

/// A principal holding a role.
#[derive(Debug, Clone, Deserialize)]
pub struct Principal {
    /// `user`, `org_user`, `agent` or `consumer`.
    pub kind: String,
    /// Identifier resolved within the accompanying identity kind.
    pub id: String,
}

/// One area of the permission catalogue, from `GET …/permissions`.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionArea {
    /// The area, such as `users`.
    pub label: String,
    /// Assignable actions grouped under this catalogue area.
    pub permissions: Vec<CataloguedPermission>,
}

/// One permission of the catalogue.
#[derive(Debug, Clone, Deserialize)]
pub struct CataloguedPermission {
    /// It, as roles carry it.
    pub value: SystemPermission,
    /// Its name, such as `idp:users:manage`.
    pub label: String,
}
