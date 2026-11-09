//! Resource types, roles and records the authorization context's tests
//! share.

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::break_glass::BreakGlassGrant;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::group::{Group, GroupMembership};
use crate::domains::authorization::permission::{
    CustomPermission, PermissionSegment, SystemPermission,
};
use crate::domains::authorization::resource_type::{
    ActionDefinition, NewResourceType, ResourceType,
};
use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
use crate::domains::authorization::stewardship::TenantGrants;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::ResolvedTenant;
use crate::test_support::builders::label;
use crate::types::{ResourceTypeId, RoleId, TenantId};

/// A segment of a permission or a ladder.
pub(crate) fn segment(value: &str) -> PermissionSegment {
    PermissionSegment::new("test", value).unwrap()
}

/// The custom permission written `text`, such as `project:write`.
pub(crate) fn custom(text: &str) -> CustomPermission {
    CustomPermission::parse(text).unwrap()
}

/// A resource type keyed `key` whose actions are `ladder`, each with the
/// actions it brings.
pub(crate) fn resource_type(key: &str, ladder: &[(&str, &[&str])]) -> ResourceType<ResolvedTenant> {
    ResourceType::create(
        NewResourceType {
            data_class: DataClassLevel::Internal,
            id: ResourceTypeId::new(),
            key: segment(key),
            display_name: label(key),
            description: None,
            actions: ladder
                .iter()
                .map(|(action, brings)| {
                    ActionDefinition::new(
                        segment(action),
                        label(action),
                        brings.iter().map(|b| segment(b)).collect(),
                    )
                })
                .collect(),
        },
        &HeldByGranter::assumed(SystemPermission::all(), &[]),
    )
    .unwrap()
}

/// `project`, whose `admin` brings `write` and `write` brings `read`.
pub(crate) fn projects() -> ResourceType<ResolvedTenant> {
    resource_type(
        "project",
        &[("read", &[]), ("write", &["read"]), ("admin", &["write"])],
    )
}

/// A manual role named `name` giving `system` and the custom permissions
/// written in `custom`.
pub(crate) fn role(
    name: &str,
    system: &[SystemPermission],
    custom_permissions: &[&str],
) -> Role<ResolvedTenant> {
    Role::provisioned(NewRole {
        id: RoleId::new(),
        name: label(name),
        system_permissions: system.to_vec(),
        custom_permissions: custom_permissions.iter().map(|text| custom(text)).collect(),
        assignment: DefaultAssignment::Manual,
    })
}

/// A tenant's records, owned, so a test can lend them out.
#[derive(Default)]
pub(crate) struct Records {
    pub(crate) roles: Vec<Role<ResolvedTenant>>,
    pub(crate) assignments: Vec<RoleAssignment<ResolvedTenant>>,
    pub(crate) groups: Vec<Group<ResolvedTenant>>,
    pub(crate) memberships: Vec<GroupMembership<ResolvedTenant>>,
    pub(crate) catalogue: Vec<ResourceType<ResolvedTenant>>,
    pub(crate) break_glass: Vec<BreakGlassGrant>,
}

impl Records {
    /// The records as an access check reads them.
    pub(crate) fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
        TenantAccess {
            tenant: TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            grants: TenantGrants {
                roles: &self.roles,
                assignments: &self.assignments,
                groups: &self.groups,
                memberships: &self.memberships,
            },
            catalogue: &self.catalogue,
            break_glass: &self.break_glass,
        }
    }
}
