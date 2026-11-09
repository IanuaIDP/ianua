//! Role bodies: a role and its permissions, who holds it, and the catalogue
//! of built-in permissions a role can carry.

use std::collections::BTreeMap;

use ianua_app::use_cases::authorization::roles::{
    AssignRequest, CreateRequest, DeleteRequest, UpdateRequest, WithAssignments,
};
use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::authorization::role::DefaultAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Expiry, Label, RoleId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Names a new permission bundle and whether new users receive it by default.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateRoleBody {
    /// The role's name, unique in the tenant.
    pub name: String,
    /// Built-in permissions the role grants, such as `{"Users":"View"}`.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub system_permissions: Vec<SystemPermission>,
    /// The tenant's own `resource:action` permissions the role grants, each
    /// as `{ "resource", "action" }`.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub custom_permissions: Vec<CustomPermission>,
    /// Whether every newly registered user is given the role.
    #[serde(default)]
    pub is_default: bool,
}

impl TryFrom<CreateRoleBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateRoleBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            system_permissions: body.system_permissions,
            custom_permissions: body.custom_permissions,
            is_default: DefaultAssignment::from(body.is_default),
        })
    }
}

/// Fields to change on a role. Omitting a field leaves it alone.
///
/// `system_permissions` and `custom_permissions` are the role's whole set,
/// not additions to it: the same shape `create` takes, and the shape a
/// permission editor produces. Sending them replaces what the role had.
///
/// Unknown fields are refused rather than ignored, so a client sending a
/// shape this body does not read learns so instead of seeing its change
/// silently dropped.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateRoleBody {
    /// The new name, unique in the tenant.
    pub name: Option<String>,
    /// The role's whole set of built-in permissions.
    #[schema(value_type = Option<Vec<Object>>)]
    pub system_permissions: Option<Vec<SystemPermission>>,
    /// The role's whole set of the tenant's own permissions.
    #[schema(value_type = Option<Vec<Object>>)]
    pub custom_permissions: Option<Vec<CustomPermission>>,
    /// Whether every newly registered user is given the role.
    pub is_default: Option<bool>,
}

impl UpdateRoleBody {
    /// The change this body asks for on the role `role_id`.
    ///
    /// # Errors
    ///
    /// A validation error when the new name is not a valid one.
    pub(crate) fn into_request(self, role_id: RoleId) -> Result<UpdateRequest, ApiError> {
        let name = self
            .name
            .map(|name| Label::new("name", name))
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(UpdateRequest {
            role_id,
            name,
            system_permissions: self.system_permissions,
            custom_permissions: self.custom_permissions,
            is_default: self.is_default.map(DefaultAssignment::from),
        })
    }
}

/// How a role is deleted.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DeleteRoleBody {
    /// Role to move every current holder to before deletion. When omitted,
    /// the delete is refused while anyone still holds the role.
    #[serde(default)]
    pub replacement_role_id: Option<Uuid>,
}

impl DeleteRoleBody {
    /// The deletion of `role_id` that `body` asks for: its holders moved to
    /// the replacement it names, or none when there is no body.
    #[must_use]
    pub(crate) fn deleting(role_id: RoleId, body: Option<Self>) -> DeleteRequest {
        DeleteRequest {
            role_id,
            replacement_role_id: body
                .and_then(|body| body.replacement_role_id)
                .map(RoleId::from_uuid),
        }
    }
}

/// Whom to give a role, and for how long.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AssignRoleBody {
    /// The tenant user to give the role.
    pub user_id: Uuid,
    /// When the role stops counting (RFC 3339). Left out, it is held until
    /// it is taken away.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub until: Option<OffsetDateTime>,
}

impl AssignRoleBody {
    /// Giving `role_id` to the user this body names, until the time it
    /// gives.
    #[must_use]
    pub(crate) fn request(&self, role_id: RoleId) -> AssignRequest {
        AssignRequest {
            user_id: UserId::from_uuid(self.user_id),
            role_id,
            until: self.until.map_or(Expiry::Never, Expiry::At),
        }
    }
}

/// A role, with how many users hold it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RoleResponse {
    /// The role's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: RoleId,
    /// The role's name.
    pub name: String,
    /// Built-in permissions the role grants.
    #[schema(value_type = Vec<Object>)]
    pub system_permissions: Vec<SystemPermission>,
    /// The tenant's own permissions the role grants.
    #[schema(value_type = Vec<Object>)]
    pub custom_permissions: Vec<CustomPermission>,
    /// Whether every newly registered user is given the role.
    pub is_default: bool,
    /// Number of users currently assigned to this role.
    pub assigned_user_count: u64,
    /// When the role was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the role last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<WithAssignments<ResolvedTenant>> for RoleResponse {
    fn from(held: WithAssignments<ResolvedTenant>) -> Self {
        let WithAssignments {
            role,
            assigned_user_count,
        } = held;
        Self {
            id: *role.id(),
            name: role.name().as_str().to_owned(),
            system_permissions: role.system_permissions().to_vec(),
            custom_permissions: role.custom_permissions().to_vec(),
            is_default: role.is_default(),
            assigned_user_count,
            created_at: role.created_at(),
            updated_at: role.updated_at(),
        }
    }
}

/// The id of a newly created role.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateRoleResponse {
    /// The role's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: RoleId,
}

/// A single built-in permission, with its wire value and readable label.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PermissionEntry {
    /// The value to send back in role create and update requests.
    #[schema(value_type = Object)]
    pub value: SystemPermission,
    /// Human-readable label, such as `idp:users:manage`.
    pub label: String,
}

/// The built-in permissions of one area.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PermissionGroup {
    /// The area, such as `users` or `roles`.
    pub label: String,
    /// The permissions in this area.
    pub permissions: Vec<PermissionEntry>,
}

impl PermissionGroup {
    /// Every built-in permission, grouped by the area its label names and
    /// sorted by area.
    #[must_use]
    pub(crate) fn catalogue() -> Vec<Self> {
        let mut areas: BTreeMap<String, Vec<PermissionEntry>> = BTreeMap::new();
        for permission in SystemPermission::all() {
            let label = permission.to_string();
            areas
                .entry(area_of(&label))
                .or_default()
                .push(PermissionEntry {
                    value: *permission,
                    label,
                });
        }
        areas
            .into_iter()
            .map(|(label, permissions)| Self { label, permissions })
            .collect()
    }
}

/// The area a permission label such as `idp:users:manage` names.
fn area_of(label: &str) -> String {
    label.split(':').nth(1).unwrap_or("other").to_owned()
}
