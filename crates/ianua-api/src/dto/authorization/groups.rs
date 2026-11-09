//! Group bodies: a group, its place in the tree, its members and roles.

use ianua_app::use_cases::authorization::groups::{
    AddMemberRequest, AssignRoleRequest, CreateRequest, MemberView, MoveRequest, RenameRequest,
};
use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Expiry, GroupId, Label, RoleId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::principal::PrincipalKind;
use crate::error::ApiError;

/// Names a new membership group and its optional parent for role inheritance.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateGroupBody {
    /// The group's name, unique in the tenant.
    pub name: String,
    /// The group to nest it under, inheriting its roles. Omitted puts it at
    /// the top of the tree.
    pub parent_id: Option<Uuid>,
}

impl TryFrom<CreateGroupBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateGroupBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            parent_id: body.parent_id.map(GroupId::from_uuid),
        })
    }
}

/// A group's new name.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RenameGroupBody {
    /// The new name, unique in the tenant.
    pub name: String,
}

impl RenameGroupBody {
    /// Renaming `group_id` to the name this body gives.
    ///
    /// # Errors
    ///
    /// A validation error when the name is not a valid one.
    pub(crate) fn into_request(self, group_id: GroupId) -> Result<RenameRequest, ApiError> {
        Ok(RenameRequest {
            group_id,
            new_name: Label::new("name", self.name).map_err(ApiError::validation)?,
        })
    }
}

/// Where in the tree a group moves.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct MoveGroupBody {
    /// The group to move it under, inheriting its roles. `null` or omitted
    /// moves it to the top of the tree.
    pub parent_id: Option<Uuid>,
}

impl MoveGroupBody {
    /// Moving `group_id` to the place this body names.
    #[must_use]
    pub(crate) fn request(&self, group_id: GroupId) -> MoveRequest {
        MoveRequest {
            group_id,
            to: GroupPlace::from_stored(self.parent_id.map(GroupId::from_uuid)),
        }
    }
}

/// Who to add to a group.
///
/// The kind is required rather than assumed. A consumer or an agent in a
/// group holds its roles at the proxy exactly as a person does, so the
/// request has to say which of them it means, and a UUID alone does not.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddGroupMemberBody {
    /// The kind of principal.
    pub kind: PrincipalKind,
    /// The principal's id.
    pub id: Uuid,
    /// When the membership stops counting (RFC 3339). Left out, it lasts
    /// until the member is taken out.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub until: Option<OffsetDateTime>,
}

impl AddGroupMemberBody {
    /// Adding the principal this body names to `group_id`, until the time
    /// it gives.
    #[must_use]
    pub(crate) fn request(&self, group_id: GroupId) -> AddMemberRequest {
        AddMemberRequest {
            group_id,
            member: self.kind.with_id(self.id),
            until: self.until.map_or(Expiry::Never, Expiry::At),
        }
    }
}

/// A role to bind to a group.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AssignGroupRoleBody {
    /// The role every member inherits.
    pub role_id: Uuid,
}

impl AssignGroupRoleBody {
    /// Binding the role this body names to `group_id`.
    #[must_use]
    pub(crate) fn request(&self, group_id: GroupId) -> AssignRoleRequest {
        AssignRoleRequest {
            group_id,
            role_id: RoleId::from_uuid(self.role_id),
        }
    }
}

/// A membership group's position in the hierarchy and its assigned roles.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct GroupResponse {
    /// The group's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: GroupId,
    /// The group's name.
    pub name: String,
    /// The group it sits under, or `null` at the top of the tree.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub parent_id: Option<GroupId>,
    /// The roles bound to the group, which every member holds.
    #[schema(value_type = Vec<String>)]
    pub role_ids: Vec<RoleId>,
    /// When the group was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the group last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Group<ResolvedTenant>> for GroupResponse {
    fn from(group: Group<ResolvedTenant>) -> Self {
        Self {
            id: *group.id(),
            name: group.name().as_str().to_owned(),
            parent_id: group.place().parent().copied(),
            role_ids: group.role_ids().to_vec(),
            created_at: group.created_at(),
            updated_at: group.updated_at(),
        }
    }
}

/// The id of a newly created group.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateGroupResponse {
    /// The group's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: GroupId,
}

/// One member of a group.
///
/// Every kind of principal appears here. A membership confers the group's
/// roles whoever holds it, so an administrator reviewing who has a group's
/// authority sees the machine identities beside the people.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct GroupMemberResponse {
    /// The kind of principal.
    pub kind: PrincipalKind,
    /// The principal's id.
    pub id: Uuid,
    /// The principal's name, when it could be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// When the principal joined the group.
    #[serde(with = "time::serde::rfc3339")]
    pub joined_at: OffsetDateTime,
}

impl From<MemberView> for GroupMemberResponse {
    fn from(view: MemberView) -> Self {
        Self {
            kind: PrincipalKind::of(&view.principal),
            id: view.principal.id(),
            display_name: view.display_name,
            joined_at: view.joined_at,
        }
    }
}
