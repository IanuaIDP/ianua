//! Holding bodies: who holds a role, and what one person, agent or app
//! holds and where it comes from.

use ianua_app::ports::authorization::RoleHolder;
use ianua_app::use_cases::authorization::holdings::{
    DirectMembership, DirectRole, PrincipalAccess, RoleThroughGroup,
};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{GroupId, RoleId};
use serde::Serialize;
use time::OffsetDateTime;

use crate::dto::agents::principal::OwnerDto;

/// One holder of a role now, told apart by `via`.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "via", rename_all = "snake_case")]
pub(crate) enum RoleHolderResponse {
    /// A principal given the role straight.
    Direct {
        /// The account or automated actor receiving the direct grant.
        principal: OwnerDto,
    },
    /// A group carrying the role, whose members, and the members of the
    /// groups under it, all hold it.
    Group {
        /// The group's id.
        #[schema(value_type = String, format = Uuid)]
        group_id: GroupId,
    },
}

impl From<RoleHolder> for RoleHolderResponse {
    fn from(holder: RoleHolder) -> Self {
        match holder {
            RoleHolder::Direct(principal) => Self::Direct {
                principal: OwnerDto::from_principal(&principal),
            },
            RoleHolder::Group(group_id) => Self::Group { group_id },
        }
    }
}

/// A role, by id and name.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HeldRoleResponse {
    /// The role's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: RoleId,
    /// The role's name.
    pub name: String,
}

impl From<&Role<ResolvedTenant>> for HeldRoleResponse {
    fn from(role: &Role<ResolvedTenant>) -> Self {
        Self {
            id: *role.id(),
            name: role.name().as_str().to_owned(),
        }
    }
}

/// A role given to the principal straight.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DirectRoleResponse {
    /// Identifies the permission bundle assigned directly to the principal.
    pub role: HeldRoleResponse,
    /// When it stops counting, or `null` for good.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub until: Option<OffsetDateTime>,
}

impl From<&DirectRole> for DirectRoleResponse {
    fn from(held: &DirectRole) -> Self {
        Self {
            role: HeldRoleResponse::from(&held.role),
            until: held.until.instant(),
        }
    }
}

/// A group the principal was put in straight.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DirectMembershipResponse {
    /// The group's id.
    #[schema(value_type = String, format = Uuid)]
    pub group_id: GroupId,
    /// When the membership stops counting, or `null` for good.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub until: Option<OffsetDateTime>,
}

impl From<&DirectMembership> for DirectMembershipResponse {
    fn from(membership: &DirectMembership) -> Self {
        Self {
            group_id: membership.group,
            until: membership.until.instant(),
        }
    }
}

/// A role the principal holds through a group.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RoleThroughGroupResponse {
    /// The group carrying the role.
    #[schema(value_type = String, format = Uuid)]
    pub group_id: GroupId,
    /// Identifies the permission bundle inherited from this group.
    pub role: HeldRoleResponse,
}

impl From<&RoleThroughGroup> for RoleThroughGroupResponse {
    fn from(held: &RoleThroughGroup) -> Self {
        Self {
            group_id: held.group,
            role: HeldRoleResponse::from(&held.role),
        }
    }
}

/// What one principal holds now, and from where.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PrincipalAccessResponse {
    /// The roles given straight, each with its end.
    pub direct_roles: Vec<DirectRoleResponse>,
    /// The groups it was put in straight, each with its end.
    pub memberships: Vec<DirectMembershipResponse>,
    /// Every group it is in, straight or through a group above.
    #[schema(value_type = Vec<String>)]
    pub groups: Vec<GroupId>,
    /// The roles it holds through those groups, with the group each comes
    /// from.
    pub through_groups: Vec<RoleThroughGroupResponse>,
}

impl From<PrincipalAccess> for PrincipalAccessResponse {
    fn from(access: PrincipalAccess) -> Self {
        Self {
            direct_roles: access.direct_roles.iter().map(Into::into).collect(),
            memberships: access.memberships.iter().map(Into::into).collect(),
            groups: access.groups,
            through_groups: access.through_groups.iter().map(Into::into).collect(),
        }
    }
}
