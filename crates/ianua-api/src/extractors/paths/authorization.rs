//! The roles, groups, policy rules and versions, resource types,
//! principals, rules, requests, reviews and relationships an authorization
//! request names.

use ianua_app::use_cases::authorization::groups::{RemoveMemberRequest, UnassignRoleRequest};
use ianua_app::use_cases::authorization::roles::RevokeRequest;
use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::domains::authorization::policy::version::PolicyVersion;
use ianua_domain::types::{
    AccessRequestId, AccessReviewId, GroupId, Label, PrincipalRef, RelationshipId, ResourceTypeId,
    RoleId, SeparationRuleId, UserId,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::dto::agents::principal::PrincipalKind;
use crate::error::ApiError;

/// `.../authorization/roles/{id}`.
#[derive(Deserialize)]
pub(crate) struct RolePath {
    id: Uuid,
}

impl RolePath {
    /// The role named.
    #[must_use]
    pub(crate) fn role(&self) -> RoleId {
        RoleId::from_uuid(self.id)
    }
}

/// `.../authorization/roles/{id}/assignments/{user_id}`.
#[derive(Deserialize)]
pub(crate) struct RoleAssignmentPath {
    id: Uuid,
    user_id: Uuid,
}

impl RoleAssignmentPath {
    /// Taking the role named from the user named.
    #[must_use]
    pub(crate) fn revocation(&self) -> RevokeRequest {
        RevokeRequest {
            user_id: UserId::from_uuid(self.user_id),
            role_id: RoleId::from_uuid(self.id),
        }
    }
}

/// `.../authorization/groups/{id}`.
#[derive(Deserialize)]
pub(crate) struct GroupPath {
    id: Uuid,
}

impl GroupPath {
    /// The group named.
    #[must_use]
    pub(crate) fn group(&self) -> GroupId {
        GroupId::from_uuid(self.id)
    }
}

/// `.../authorization/groups/{id}/members/{principal_kind}/{principal_id}`.
#[derive(Deserialize)]
pub(crate) struct GroupMemberPath {
    id: Uuid,
    principal_kind: PrincipalKind,
    principal_id: Uuid,
}

impl GroupMemberPath {
    /// Taking the member named, of the kind the path says, out of the group
    /// named.
    #[must_use]
    pub(crate) fn removal(&self) -> RemoveMemberRequest {
        RemoveMemberRequest {
            group_id: GroupId::from_uuid(self.id),
            member: self.principal_kind.with_id(self.principal_id),
        }
    }
}

/// `.../authorization/groups/{id}/roles/{role_id}`.
#[derive(Deserialize)]
pub(crate) struct GroupRolePath {
    id: Uuid,
    role_id: Uuid,
}

impl GroupRolePath {
    /// Unbinding the role named from the group named.
    #[must_use]
    pub(crate) fn unassignment(&self) -> UnassignRoleRequest {
        UnassignRoleRequest {
            group_id: GroupId::from_uuid(self.id),
            role_id: RoleId::from_uuid(self.role_id),
        }
    }
}

/// `.../authorization/policy/rules/{rule_name}`.
#[derive(Deserialize)]
pub(crate) struct PolicyRulePath {
    rule_name: Label,
}

impl PolicyRulePath {
    /// The rule named.
    #[must_use]
    pub(crate) fn into_rule(self) -> Label {
        self.rule_name
    }
}

/// `.../authorization/policy/versions/{version}`.
#[derive(Deserialize)]
pub(crate) struct PolicyVersionPath {
    version: u32,
}

impl PolicyVersionPath {
    /// The version named.
    ///
    /// # Errors
    ///
    /// A validation error for version 0, which no policy has.
    pub(crate) fn version(&self) -> Result<PolicyVersion, ApiError> {
        PolicyVersion::parse(self.version).map_err(ApiError::validation)
    }
}

/// `.../authorization/principals/{principal_kind}/{principal_id}/access`.
#[derive(Deserialize)]
pub(crate) struct PrincipalPath {
    principal_kind: PrincipalKind,
    principal_id: Uuid,
}

impl PrincipalPath {
    /// The principal named, of the kind the path says.
    #[must_use]
    pub(crate) fn principal(&self) -> PrincipalRef {
        self.principal_kind.with_id(self.principal_id)
    }
}

/// `.../authorization/separation-rules/{id}`.
#[derive(Deserialize)]
pub(crate) struct SeparationRulePath {
    id: Uuid,
}

impl SeparationRulePath {
    /// The rule named.
    #[must_use]
    pub(crate) fn rule(&self) -> SeparationRuleId {
        SeparationRuleId::from_uuid(self.id)
    }
}

/// `.../authorization/access-requests/{id}`.
#[derive(Deserialize)]
pub(crate) struct AccessRequestPath {
    id: Uuid,
}

impl AccessRequestPath {
    /// The request named.
    #[must_use]
    pub(crate) fn request(&self) -> AccessRequestId {
        AccessRequestId::from_uuid(self.id)
    }
}

/// `.../authorization/access-reviews/{id}`.
#[derive(Deserialize)]
pub(crate) struct AccessReviewPath {
    id: Uuid,
}

impl AccessReviewPath {
    /// The review named.
    #[must_use]
    pub(crate) fn review(&self) -> AccessReviewId {
        AccessReviewId::from_uuid(self.id)
    }
}

/// `.../authorization/relationships/{id}`.
#[derive(Deserialize)]
pub(crate) struct RelationshipPath {
    id: Uuid,
}

impl RelationshipPath {
    /// The relationship named.
    #[must_use]
    pub(crate) fn relationship(&self) -> RelationshipId {
        RelationshipId::from_uuid(self.id)
    }
}

/// `.../authorization/clearance-rules/{resource}/{action}`.
#[derive(Deserialize)]
pub(crate) struct ClearanceRulePath {
    resource: String,
    action: String,
}

impl ClearanceRulePath {
    /// The app permission the rule names.
    ///
    /// # Errors
    ///
    /// A validation error when either part is not a valid permission
    /// segment.
    pub(crate) fn permission(&self) -> Result<CustomPermission, ApiError> {
        CustomPermission::new(self.resource.as_str(), self.action.as_str())
            .map_err(ApiError::validation)
    }
}

/// `.../resource-types/{id}`.
#[derive(Deserialize)]
pub(crate) struct ResourceTypePath {
    id: Uuid,
}

impl ResourceTypePath {
    /// The resource type named.
    #[must_use]
    pub(crate) fn resource_type(&self) -> ResourceTypeId {
        ResourceTypeId::from_uuid(self.id)
    }
}
