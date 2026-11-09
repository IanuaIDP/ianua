//! Map provider groups: the groups a connection's provider puts people in
//! bring roles and groups here, at each sign-in.
//!
//! Every rule is a grant to everyone the provider puts in the group, so the
//! domain checks each role and group mapped as one: nothing with a built-in
//! permission, and nothing the admin could not hand out themselves.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::GroupPlace;
use ianua_domain::domains::authorization::group_tree::{Conferred, GroupTree};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::federation::connection::{
    GrantedThrough, MappedGrant, MappingRule, ProviderGroupName,
};
use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConnectionId, GroupId, Label, RoleId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, AccessRecords, Holders};
use crate::ports::federation::ConnectionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_connection;

/// One rule asked for: members of the provider's group get this here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRuleRequest {
    /// The provider's group, as its claim or attribute names it.
    pub provider_group: ProviderGroupName,
    /// The role or group its members get.
    pub grant: MappedGrant,
}

/// The mapping to set on a connection, replacing any before.
pub struct MapProviderGroupsRequest {
    /// The provider configuration receiving the replacement mapping.
    pub connection_id: ConnectionId,
    /// The claim or attribute the provider sends groups in, such as
    /// `groups` or `memberOf`.
    pub claim: Label,
    /// The provider-group matches and tenant grants to apply.
    pub rules: Vec<GroupRuleRequest>,
}

/// The ports [`MapProviderGroupsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct MapProviderGroupsPorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// The tenant's roles and groups, which each rule is checked against.
    pub access: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Maps a connection's provider groups to roles and groups here.
pub struct MapProviderGroupsUseCase {
    ports: MapProviderGroupsPorts,
}

/// What a rule's grant is, loaded from the tenant's records.
enum Loaded<'a> {
    Role(&'a Role<ResolvedTenant>),
    Group(Conferred),
}

impl MapProviderGroupsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: MapProviderGroupsPorts) -> Self {
        Self { ports }
    }

    /// The roles and groups `rules` name, each group with the groups above
    /// it and the roles they carry, and nothing else of the tenant's
    /// records.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the records cannot be read.
    async fn records_named(
        &self,
        tenant: &ScopedTenant,
        rules: &[GroupRuleRequest],
    ) -> Result<AccessRecords, AppError> {
        let (roles, groups) = named_by(rules);
        let holders = Holders {
            principals: &[],
            groups: &groups,
            roles: &roles,
        };
        let held = self
            .ports
            .access
            .load_held_by_all(tenant, holders)
            .await
            .or_internal()?;
        Ok(held.into_records())
    }
}

impl Command for MapProviderGroupsUseCase {
    type Caller = CallerContext;
    type Input = MapProviderGroupsRequest;
    type Output = Result<(), AppError>;

    /// Replaces the connection's group mapping with `request`'s rules and
    /// records `federation.connection_updated`. Needs the full federation
    /// right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not manage federation, or a
    ///   role or group mapped carries a built-in permission or one they may
    ///   not hand out.
    /// - `AppError::NotFound` if the connection, a role or a group doesn't
    ///   exist.
    /// - `AppError::Domain` if no rule is given, more than 200, one twice,
    ///   or a group is the top of the tree.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: MapProviderGroupsRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::TrustConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.connection_store.as_ref();
        let mut conn = existing_connection(store, &tenant, &request.connection_id).await?;
        let records = self.records_named(&tenant, &request.rules).await?;
        let loaded = loaded_grants(&records, &request.rules)?;
        conn.map_provider_groups(request.claim, mapping_rules(&loaded), &control)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &conn).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), conn.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The roles and the groups `rules` map to.
fn named_by(rules: &[GroupRuleRequest]) -> (Vec<RoleId>, Vec<GroupId>) {
    let roles = rules
        .iter()
        .filter_map(|rule| match rule.grant {
            MappedGrant::Role(role) => Some(role),
            MappedGrant::Group(_) => None,
        })
        .collect();
    let groups = rules
        .iter()
        .filter_map(|rule| match rule.grant {
            MappedGrant::Group(group) => Some(group),
            MappedGrant::Role(_) => None,
        })
        .collect();
    (roles, groups)
}

/// Each rule's grant, loaded from `records`.
///
/// # Errors
///
/// - `AppError::NotFound` if a role or group is not the tenant's.
/// - `AppError::Internal` if a group sits under a missing one, or names a
///   missing role.
fn loaded_grants<'a>(
    records: &'a AccessRecords,
    rules: &[GroupRuleRequest],
) -> Result<Vec<(ProviderGroupName, Loaded<'a>)>, AppError> {
    rules
        .iter()
        .map(|rule| Ok((rule.provider_group.clone(), loaded(records, rule.grant)?)))
        .collect()
}

/// What `grant` is, loaded from `records`.
fn loaded(records: &AccessRecords, grant: MappedGrant) -> Result<Loaded<'_>, AppError> {
    match grant {
        MappedGrant::Role(role_id) => records
            .roles
            .iter()
            .find(|role| *role.id() == role_id)
            .map(Loaded::Role)
            .ok_or_else(|| AppError::NotFound(message!("app-role-not-found", "role not found"))),
        MappedGrant::Group(group_id) => GroupTree::new(&records.groups)
            .conferred(GroupPlace::Under(group_id), &records.roles)
            .map(Loaded::Group)
            .map_err(AppError::from_domain),
    }
}

/// The rules the connection checks, borrowing what `loaded` holds.
fn mapping_rules<'a>(
    loaded: &'a [(ProviderGroupName, Loaded<'a>)],
) -> Vec<MappingRule<'a, ResolvedTenant>> {
    loaded
        .iter()
        .map(|(provider_group, grant)| MappingRule {
            provider_group: provider_group.clone(),
            grant: match grant {
                Loaded::Role(role) => GrantedThrough::Role(role),
                Loaded::Group(conferred) => GrantedThrough::Group(conferred),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        FederationAction, SystemPermission, UserAction,
    };
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole};
    use ianua_domain::domains::federation::connection::GroupMapping;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::federation::{FakeConnectionStore, test_connection};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn role(name: &str, system_permissions: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("name", name).unwrap(),
            system_permissions,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    struct Harness {
        store: Arc<FakeConnectionStore>,
        id: ConnectionId,
        engineer: RoleId,
        admin: RoleId,
        records: Arc<FakeAccessRecordStore>,
        use_case: MapProviderGroupsUseCase,
        audit: Arc<FakeEventDispatcher>,
    }

    fn harness(authorities: FakeTenantAuthorities) -> Harness {
        let id = ConnectionId::new();
        let conn = test_connection(id, ConnectionStatus::Active);
        let store = Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [conn]));
        let engineer = role("Engineer", Vec::new());
        let admin = role("Admin", vec![SystemPermission::ManageUsers]);
        let (engineer_id, admin_id) = (*engineer.id(), *admin.id());
        let records = AccessRecords {
            roles: vec![engineer, admin],
            ..AccessRecords::default()
        };
        let records = Arc::new(FakeAccessRecordStore::holding(
            test_ctx().tenant_id(),
            records,
        ));
        let use_case = MapProviderGroupsUseCase::new(MapProviderGroupsPorts {
            connection_store: store.clone(),
            access: records.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Harness {
            store,
            id,
            engineer: engineer_id,
            admin: admin_id,
            records,
            use_case,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn mapping(h: &Harness, grant: MappedGrant) -> Result<(), AppError> {
        let request = MapProviderGroupsRequest {
            connection_id: h.id,
            claim: Label::new("claim", "groups").unwrap(),
            rules: vec![GroupRuleRequest {
                provider_group: ProviderGroupName::new("engineering").unwrap(),
                grant,
            }],
        };
        block_on(
            h.use_case
                .execute(&test_ctx(), &test_auditor(h.audit.clone()), request),
        )
    }

    fn saved_mapping(h: &Harness) -> GroupMapping {
        block_on(h.store.find_by_id(&test_ctx().tenant(), &h.id))
            .unwrap()
            .unwrap()
            .group_mapping()
            .clone()
    }

    /// Fay maps Okta's `engineering` group to the Engineer role. The
    /// connection keeps the rule and the change is recorded.
    #[test]
    fn a_provider_group_is_mapped_to_a_role() {
        let h = harness(FakeTenantAuthorities::holding_everything());

        mapping(&h, MappedGrant::Role(h.engineer)).unwrap();

        let GroupMapping::On(rules) = saved_mapping(&h) else {
            panic!("the mapping is off");
        };
        assert_eq!(rules.claim().as_str(), "groups");
        assert_eq!(rules.rules()[0].grant, MappedGrant::Role(h.engineer));
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// Fay maps `engineering` to the Engineer role. Only that role is read
    /// from the tenant's records to check it, never every record.
    #[test]
    fn mapping_reads_only_the_roles_and_groups_it_names() {
        let h = harness(FakeTenantAuthorities::holding_everything());

        mapping(&h, MappedGrant::Role(h.engineer)).unwrap();

        assert_eq!(h.records.whole_reads(), 0);
    }

    /// Mapping a provider group to a role with user-management permission is
    /// forbidden. The mapping stays off and no update event is recorded.
    #[test]
    fn a_role_with_built_in_permissions_is_never_mapped() {
        let h = harness(FakeTenantAuthorities::holding_everything());

        let result = mapping(&h, MappedGrant::Role(h.admin));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved_mapping(&h), GroupMapping::Off);
        assert!(h.audit.records.lock().unwrap().is_empty());
    }

    /// Fay maps a role her tenant does not have. It is not found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let h = harness(FakeTenantAuthorities::holding_everything());

        let result = mapping(&h, MappedGrant::Role(RoleId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Connection-update and user-management rights do not permit mapping a
    /// provider group to a role. The refusal leaves the mapping off.
    #[test]
    fn the_update_right_does_not_map_groups() {
        let rights = [
            SystemPermission::Federation(FederationAction::Update),
            SystemPermission::Users(UserAction::Manage),
        ];
        let h = harness(FakeTenantAuthorities::holding(&rights));

        let result = mapping(&h, MappedGrant::Role(h.engineer));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved_mapping(&h), GroupMapping::Off);
    }

    /// A signed-out session cannot configure provider group mappings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let h = harness(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = mapping(&h, MappedGrant::Role(h.engineer));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
