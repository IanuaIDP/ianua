//! Move group: put a group somewhere else in the tenant's tree, at the top
//! or under another group.
//!
//! Its members stop holding what the place it leaves brings and start
//! holding what the new place brings, so a move is checked like taking
//! roles away and handing them out.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::domains::authorization::group_tree::Conferred;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::GroupId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, GroupStore, SeparationRuleStore,
};
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::lookup::{access_records, existing_group};
use crate::use_cases::authorization::stewardship::{Withdrawal, ensure_still_administered};

/// Which group to move, and where it goes.
pub struct MoveRequest {
    /// The group to move.
    pub group_id: GroupId,
    /// Where it sits afterwards: at the top, or under another group.
    pub to: GroupPlace,
}

/// The ports [`MoveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct MovePorts {
    /// Loads and saves groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads the tenant's groups, roles and who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's separation-of-duties rules.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Moves a group of the caller's tenant to another place in its tree.
pub struct MoveUseCase {
    ports: MovePorts,
}

impl MoveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: MovePorts) -> Self {
        Self { ports }
    }

    /// Refuses moving `group` to the place `inherited` was worked out for
    /// when someone in it would then hold both roles of one of the tenant's
    /// separation rules.
    async fn ensure_kept_apart(
        &self,
        tenant: &ScopedTenant,
        group: &GroupId,
        inherited: &Conferred,
    ) -> Result<(), AppError> {
        let duties = DutySources::of(
            self.ports.access_records.as_ref(),
            self.ports.separation_rules.as_ref(),
        );
        let granting = Granting::GroupMove {
            group,
            to: inherited,
        };
        ensure_duties_kept(duties, tenant, granting).await
    }
}

impl Command for MoveUseCase {
    type Caller = CallerContext;
    type Input = MoveRequest;
    type Output = Result<(), AppError>;

    /// Moves `request.group_id` to `request.to`, for the caller, and
    /// records where it was and where it is.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role-update rights, before reading the group.
    /// - `AppError::NotFound` for a missing group/parent; `Forbidden` for ungrantable rights at either location.
    /// - `AppError::Domain` for a move below itself or a descendant.
    /// - `AppError::Conflict` for loss of the last administrator or a separation-of-duties violation; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: MoveRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Update))
            .map_err(AppError::from_domain)?;
        let store = self.ports.group_store.as_ref();
        let records = access_records(self.ports.access_records.as_ref(), &tenant).await?;
        let mut group = existing_group(store, &tenant, &request.group_id).await?;
        let inherited = conferred_at(&records, request.to)?;
        move_group(&records, &authority, &mut group, &inherited)?;
        self.ensure_kept_apart(&tenant, &request.group_id, &inherited)
            .await?;
        let withdrawal = Withdrawal::GroupMoved(&group);
        ensure_still_administered(&tenant, records, withdrawal)?;

        store.save(&tenant, &group).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), group.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Moves `group` for `authority` to the place `inherited` was worked out
/// for, with what its current place brings worked out from `records`.
fn move_group(
    records: &AccessRecords,
    authority: &TenantAuthority,
    group: &mut Group<ResolvedTenant>,
    inherited: &Conferred,
) -> Result<(), AppError> {
    let current = conferred_at(records, *group.place())?;
    group
        .move_under(&current, inherited, &authority.standing())
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleStore, FakeSeparationRuleStore, separation_between, stored_group,
        stored_membership, stored_role,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, reference_label, test_auditor, test_ctx,
    };

    fn admin_role() -> Role<ResolvedTenant> {
        stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        )
    }

    fn top(name: &str) -> Group<ResolvedTenant> {
        stored_group(name, GroupPlace::TopLevel, Vec::new())
    }

    /// A tenant's groups, roles and members, read by every port.
    struct Tenant {
        stores: AccessSources,
    }

    impl Tenant {
        fn with(groups: Vec<Group<ResolvedTenant>>, roles: Vec<Role<ResolvedTenant>>) -> Self {
            let tenant = test_ctx().tenant_id();
            Self {
                stores: AccessSources {
                    groups: Arc::new(FakeGroupStore::holding(tenant, groups)),
                    roles: Arc::new(FakeRoleStore::holding(tenant, roles)),
                    ..AccessSources::default()
                },
            }
        }

        fn joined(self, member: UserId, group: GroupId) -> Self {
            let membership = stored_membership(PrincipalRef::User(member), group);
            let memberships =
                FakeGroupMembershipStore::holding(test_ctx().tenant_id(), [membership]);
            Self {
                stores: AccessSources {
                    memberships: Arc::new(memberships),
                    ..self.stores
                },
            }
        }

        fn ports(&self) -> MovePorts {
            MovePorts {
                group_store: self.stores.groups.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..MovePorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> MovePorts {
            MovePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn place_of(&self, group: GroupId) -> GroupPlace {
            let found = block_on(self.stores.groups.find_by_id(&test_ctx().tenant(), &group));
            *found.unwrap().unwrap().place()
        }
    }

    fn move_group(
        ports: MovePorts,
        sink: &Arc<FakeEventDispatcher>,
        group_id: GroupId,
        to: GroupPlace,
    ) -> Result<(), AppError> {
        block_on(MoveUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            MoveRequest { group_id, to },
        ))
    }

    fn quietly(ports: MovePorts, group_id: GroupId, to: GroupPlace) -> Result<(), AppError> {
        move_group(ports, &Arc::new(FakeEventDispatcher::new()), group_id, to)
    }

    /// Ann moves "Backend" from the top of the tree under "Engineering". It
    /// is saved there, and the record names the group and its new parent.
    #[test]
    fn a_group_is_moved_under_another_and_recorded() {
        let (engineering, backend) = (top("Engineering"), top("Backend"));
        let (parent, moving) = (*engineering.id(), *backend.id());
        let tenant = Tenant::with(vec![engineering, backend], Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        move_group(tenant.ports(), &sink, moving, GroupPlace::Under(parent)).unwrap();

        assert_eq!(tenant.place_of(moving), GroupPlace::Under(parent));
        let payload = sink.payload_of("authorization.group_moved");
        assert_eq!(reference_label(&payload, "group"), Some("Backend"));
        assert_eq!(reference_label(&payload, "parent"), Some("Engineering"));
        assert!(payload.value("previous_parent").is_none());
    }

    /// Ann moves "Backend" out from under "Engineering" to the top. The
    /// record names the parent it left.
    #[test]
    fn a_group_moved_to_the_top_records_the_parent_it_left() {
        let engineering = top("Engineering");
        let parent = *engineering.id();
        let backend = stored_group("Backend", GroupPlace::Under(parent), Vec::new());
        let moving = *backend.id();
        let tenant = Tenant::with(vec![engineering, backend], Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        move_group(tenant.ports(), &sink, moving, GroupPlace::TopLevel).unwrap();

        assert_eq!(tenant.place_of(moving), GroupPlace::TopLevel);
        let payload = sink.payload_of("authorization.group_moved");
        assert_eq!(
            reference_label(&payload, "previous_parent"),
            Some("Engineering")
        );
    }

    /// Ann moves a group the tenant does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_group_is_not_found() {
        let tenant = Tenant::with(Vec::new(), Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = move_group(tenant.ports(), &sink, GroupId::new(), GroupPlace::TopLevel);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann moves "Backend" under a group the tenant does not have. It is not
    /// found and "Backend" stays where it was.
    #[test]
    fn an_unknown_parent_is_not_found() {
        let backend = top("Backend");
        let moving = *backend.id();
        let tenant = Tenant::with(vec![backend], Vec::new());

        let result = quietly(tenant.ports(), moving, GroupPlace::Under(GroupId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::TopLevel);
    }

    /// Ann moves "Engineering" under "Backend", which sits under it. That
    /// would close a loop, so she is refused.
    #[test]
    fn a_group_cannot_go_under_its_own_subgroup() {
        let engineering = top("Engineering");
        let moving = *engineering.id();
        let backend = stored_group("Backend", GroupPlace::Under(moving), Vec::new());
        let below = *backend.id();
        let tenant = Tenant::with(vec![engineering, backend], Vec::new());

        let result = quietly(tenant.ports(), moving, GroupPlace::Under(below));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::TopLevel);
    }

    /// Role update permission alone cannot move Interns under Admins and
    /// confer its greater rights. Interns stays at the top level.
    #[test]
    fn a_group_cannot_inherit_more_than_the_mover_holds() {
        let admin = admin_role();
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
        let parent = *admins.id();
        let interns = top("Interns");
        let moving = *interns.id();
        let tenant = Tenant::with(vec![admins, interns], vec![admin]);
        let sam = tenant.ports_holding(&[SystemPermission::Roles(RoleAction::Update)]);

        let result = quietly(sam, moving, GroupPlace::Under(parent));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::TopLevel);
    }

    /// Sam cannot remove inherited admin rights he could not grant by moving
    /// Backend to the top level. It stays under Admins.
    #[test]
    fn a_group_cannot_leave_a_place_bringing_more_than_the_mover_holds() {
        let admin = admin_role();
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
        let parent = *admins.id();
        let backend = stored_group("Backend", GroupPlace::Under(parent), Vec::new());
        let moving = *backend.id();
        let tenant = Tenant::with(vec![admins, backend], vec![admin]);
        let sam = tenant.ports_holding(&[SystemPermission::Roles(RoleAction::Update)]);

        let result = quietly(sam, moving, GroupPlace::TopLevel);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::Under(parent));
    }

    /// Moving Backend away from its admin parent would remove the last
    /// administrator. The conflict leaves Backend under Admins.
    #[test]
    fn moving_the_group_of_the_last_administrator_out_is_refused() {
        let admin = admin_role();
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
        let parent = *admins.id();
        let backend = stored_group("Backend", GroupPlace::Under(parent), Vec::new());
        let moving = *backend.id();
        let tenant = Tenant::with(vec![admins, backend], vec![admin]).joined(UserId::new(), moving);

        let result = quietly(tenant.ports(), moving, GroupPlace::TopLevel);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::Under(parent));
    }

    /// Moving Finance under Approvers would give its member both separated
    /// payment roles. The conflict leaves Finance at the top level.
    #[test]
    fn a_move_that_breaks_a_separation_rule_is_refused() {
        let raiser = stored_role("raise payments", Vec::new(), Vec::new());
        let approver = stored_role("approve payments", Vec::new(), Vec::new());
        let rule = separation_between("raise or approve", &raiser, &approver);
        let approvers = stored_group("Approvers", GroupPlace::TopLevel, vec![*approver.id()]);
        let finance = stored_group("Finance", GroupPlace::TopLevel, vec![*raiser.id()]);
        let (parent, moving) = (*approvers.id(), *finance.id());
        let tenant = Tenant::with(vec![approvers, finance], vec![raiser, approver])
            .joined(UserId::new(), moving);
        let rules = FakeSeparationRuleStore::holding(test_ctx().tenant_id(), [rule]);
        let ports = MovePorts {
            separation_rules: Arc::new(rules),
            ..tenant.ports()
        };

        let result = quietly(ports, moving, GroupPlace::Under(parent));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::TopLevel);
    }

    /// Without role update permission, moving Backend is forbidden and it
    /// stays at the top level.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let (engineering, backend) = (top("Engineering"), top("Backend"));
        let (parent, moving) = (*engineering.id(), *backend.id());
        let tenant = Tenant::with(vec![engineering, backend], Vec::new());

        let result = quietly(tenant.ports_holding(&[]), moving, GroupPlace::Under(parent));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.place_of(moving), GroupPlace::TopLevel);
    }

    /// A signed-out session cannot move a group.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let backend = top("Backend");
        let moving = *backend.id();
        let tenant = Tenant::with(vec![backend], Vec::new());
        let ports = MovePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, moving, GroupPlace::TopLevel);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
