//! Create group: define a new group within the tenant, at the top of the
//! tree or under another group.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::{
    CreateGroupParams, Group, GroupOrigin, GroupPlace,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{GroupId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, GroupStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::lookup::{ensure_group_name_free, place_records};

/// Request to create a new group.
pub struct CreateRequest {
    /// Group name, unique within the tenant.
    pub name: Label,
    /// The group it sits under, or `None` for the top of the tree.
    pub parent_id: Option<GroupId>,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Loads and saves groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads the tenant's groups and roles, for what the new group inherits.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Enforces the plan's group limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Creates a group within the caller's tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<GroupId, AppError>;

    /// Creates the group `req` describes, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a full plan, missing role-creation rights or ungrantable inherited rights.
    /// - `AppError::Conflict` for an existing group name; `NotFound` for a missing parent group.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: CreateRequest,
    ) -> Result<GroupId, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::Groups)
            .await
            .map_err(AppError::from_domain)?;
        ensure_group_name_free(self.ports.group_store.as_ref(), &tenant, &req.name, None).await?;
        let mut group = new_group(&self.ports, &tenant, &authority, req).await?;

        self.ports
            .group_store
            .save(&tenant, &group)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), group.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*group.id())
    }
}

/// The group `req` describes, made by `authority`, inheriting what its
/// place in the tree brings.
async fn new_group(
    ports: &CreatePorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    req: CreateRequest,
) -> Result<Group<ResolvedTenant>, AppError> {
    let place = GroupPlace::from_stored(req.parent_id);
    let records = place_records(ports.access_records.as_ref(), tenant, place).await?;
    let inherited = conferred_at(&records, place)?;
    let params = CreateGroupParams {
        name: req.name,
        origin: GroupOrigin::Dashboard,
        place,
    };
    Group::create(params, &inherited, &authority.standing()).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::domains::authorization::role::Role;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupStore, stored_group, stored_role,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, reference_label, test_auditor,
        test_ctx,
    };

    fn name(value: &str) -> Label {
        Label::new("group_name", value).unwrap()
    }

    /// A tenant's groups and roles, read by every port.
    #[derive(Default)]
    struct Tenant {
        stores: AccessSources,
    }

    impl Tenant {
        fn with_group(group: Group<ResolvedTenant>) -> Self {
            Self {
                stores: AccessSources {
                    groups: Arc::new(FakeGroupStore::holding(test_ctx().tenant_id(), [group])),
                    ..AccessSources::default()
                },
            }
        }

        fn with_role(self, role: Role<ResolvedTenant>) -> Self {
            self.stores.roles.add(test_ctx().tenant_id(), [role]);
            self
        }

        fn ports(&self) -> CreatePorts {
            CreatePorts {
                group_store: self.stores.groups.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..CreatePorts::fakes()
            }
        }
    }

    fn create(
        ports: CreatePorts,
        sink: &Arc<FakeEventDispatcher>,
        req: CreateRequest,
    ) -> Result<GroupId, AppError> {
        block_on(CreateUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    fn at_top(group: &str) -> CreateRequest {
        CreateRequest {
            name: name(group),
            parent_id: None,
        }
    }

    fn under(group: &str, parent: GroupId) -> CreateRequest {
        CreateRequest {
            name: name(group),
            parent_id: Some(parent),
        }
    }

    /// Ann creates "Engineering" at the top of the tree. It is saved and the
    /// creation is recorded without a parent.
    #[test]
    fn a_group_is_created_at_the_top_and_recorded() {
        let tenant = Tenant::default();
        let sink = Arc::new(FakeEventDispatcher::new());

        create(tenant.ports(), &sink, at_top("Engineering")).unwrap();

        assert_eq!(tenant.stores.groups.count(), 1);
        let event = "authorization.group_created";
        assert_eq!(sink.records.lock().unwrap().as_slice(), [event]);
        assert!(sink.payload_of(event).value("parent").is_none());
    }

    /// Ann creates "Backend" under "Engineering". It is saved, and the
    /// record names the group and its parent.
    #[test]
    fn a_group_is_created_under_another() {
        let engineering = stored_group("Engineering", GroupPlace::TopLevel, Vec::new());
        let parent = *engineering.id();
        let tenant = Tenant::with_group(engineering);
        let sink = Arc::new(FakeEventDispatcher::new());

        create(tenant.ports(), &sink, under("Backend", parent)).unwrap();

        assert_eq!(tenant.stores.groups.count(), 2);
        let payload = sink.payload_of("authorization.group_created");
        assert_eq!(reference_label(&payload, "group"), Some("Backend"));
        assert_eq!(reference_label(&payload, "parent"), Some("Engineering"));
    }

    /// Ann creates a group under one the tenant does not have. It is not
    /// found and nothing is recorded.
    #[test]
    fn an_unknown_parent_is_not_found_and_not_recorded() {
        let tenant = Tenant::default();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = create(tenant.ports(), &sink, under("Orphan", GroupId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.stores.groups.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann creates "Engineering" twice. The second is refused as a conflict.
    #[test]
    fn a_name_already_taken_is_a_conflict() {
        let tenant = Tenant::default();
        let sink = Arc::new(FakeEventDispatcher::new());
        create(tenant.ports(), &sink, at_top("Engineering")).unwrap();

        let result = create(tenant.ports(), &sink, at_top("Engineering"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// The plan limit refuses group creation without saving a group.
    #[test]
    fn a_group_past_the_plan_limit_is_refused() {
        let tenant = Tenant::default();
        let ports = CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..tenant.ports()
        };

        let result = create(ports, &Arc::new(FakeEventDispatcher::new()), at_top("Test"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.groups.count(), 0);
    }

    /// Sam cannot create a child of Admins when its inherited user-management
    /// permission exceeds his rights. Only the parent group remains stored.
    #[test]
    fn a_group_cannot_inherit_more_than_its_creator_holds() {
        let admin = stored_role("admin", vec![SystemPermission::ManageUsers], Vec::new());
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
        let parent = *admins.id();
        let tenant = Tenant::with_group(admins).with_role(admin);
        let sam = CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::Create),
            ])),
            ..tenant.ports()
        };

        let result = create(
            sam,
            &Arc::new(FakeEventDispatcher::new()),
            under("Interns", parent),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.groups.count(), 1);
    }

    /// Group creation without role creation permission is forbidden and saves nothing.
    #[test]
    fn a_caller_who_may_not_create_roles_is_refused() {
        let tenant = Tenant::default();
        let ports = CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = create(ports, &Arc::new(FakeEventDispatcher::new()), at_top("Mine"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.groups.count(), 0);
    }

    /// A signed-out session cannot create a group, leaving the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::default();
        let ports = CreatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = create(ports, &Arc::new(FakeEventDispatcher::new()), at_top("Mine"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.stores.groups.count(), 0);
    }
}
