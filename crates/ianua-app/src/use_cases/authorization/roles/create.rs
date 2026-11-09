//! Create role: define a new role within a tenant.
//!
//! A role every new user gets that does admin work hands that work to
//! everyone who joins, so it is made only once the company's "before admin
//! given" rules allow it.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, RoleId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{ResourceTypeStore, RoleStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::workflows::ChangeGuard;
use crate::services::authorization::catalogue_check::ensure_declared;
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow};
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::ensure_role_name_free;

/// Request to create a new role.
pub struct CreateRequest {
    /// Role name, unique within the tenant.
    pub name: Label,
    /// System permissions to grant.
    pub system_permissions: Vec<SystemPermission>,
    /// Custom permissions to grant.
    pub custom_permissions: Vec<CustomPermission>,
    /// Whether this role is given to every new user.
    pub is_default: DefaultAssignment,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Loads and saves roles.
    pub role_store: Arc<dyn RoleStore>,
    /// Reads the tenant's permission catalogue.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// Enforces the plan's role limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The company's "before" rules, asked before every new user would be
    /// given admin work.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Creates a role within the caller's tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// Asks the company's "before admin given" rules about `role` when every
    /// new user gets it.
    async fn ensure_rules_allow(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        role: &Role<ResolvedTenant>,
    ) -> Result<(), AppError> {
        if !role.is_default() {
            return Ok(());
        }
        let guard = self.ports.guard.as_ref();
        let holder = AdminHolder::EveryNewUser;
        ensure_admin_rules_allow(guard, &ctx.tenant(), auditor, role, holder).await
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<RoleId, AppError>;

    /// Creates the role `req` describes, made by the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing creation/grant rights, a default role without user-update rights, or a full plan.
    /// - `AppError::Domain` for undeclared app permissions; `Conflict` for an existing role name.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: CreateRequest,
    ) -> Result<RoleId, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut role = new_role(req, &authority)?;
        ensure_declared(
            self.ports.resource_type_store.as_ref(),
            &ctx.tenant(),
            role.custom_permissions(),
        )
        .await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &ctx.tenant(), ResourceKind::Roles)
            .await
            .map_err(AppError::from_domain)?;
        ensure_role_name_free(self.ports.role_store.as_ref(), &ctx.tenant(), role.name()).await?;
        self.ensure_rules_allow(ctx, auditor, &role).await?;

        self.ports
            .role_store
            .save(&ctx.tenant(), &role)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), role.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(*role.id())
    }
}

/// The role `req` describes, made by `authority` under a fresh id, its
/// system permissions each named once.
///
/// # Errors
///
/// Returns `AppError::Forbidden` in the cases [`Role::create`] refuses.
fn new_role(
    req: CreateRequest,
    authority: &TenantAuthority,
) -> Result<Role<ResolvedTenant>, AppError> {
    Role::create(
        NewRole {
            id: RoleId::new(),
            name: req.name,
            system_permissions: SystemPermission::normalize(&req.system_permissions),
            custom_permissions: req.custom_permissions,
            assignment: req.is_default,
        },
        &authority.standing(),
    )
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {

    use ianua_domain::domains::authorization::permission::RoleAction;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeResourceTypeStore, FakeRoleStore};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    const CREATE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Create);

    fn custom(resource: &str, action: &str) -> CustomPermission {
        CustomPermission::new(resource, action).unwrap()
    }

    fn editor_request() -> CreateRequest {
        CreateRequest {
            name: Label::new("role_name", "editor").unwrap(),
            system_permissions: Vec::new(),
            custom_permissions: vec![custom("project", "read"), custom("project", "write")],
            is_default: DefaultAssignment::Manual,
        }
    }

    fn with_system(system: Vec<SystemPermission>) -> CreateRequest {
        CreateRequest {
            system_permissions: system,
            custom_permissions: Vec::new(),
            ..editor_request()
        }
    }

    fn use_case(store: Arc<FakeRoleStore>, held: Arc<dyn TenantAuthorities>) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            role_store: store,
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            tenant_authorities: held,
            ..CreatePorts::fakes()
        })
    }

    fn admin_use_case(store: Arc<FakeRoleStore>) -> CreateUseCase {
        use_case(store, Arc::new(FakeTenantAuthorities::holding_everything()))
    }

    fn holding(store: Arc<FakeRoleStore>, system: &[SystemPermission]) -> CreateUseCase {
        use_case(store, Arc::new(FakeTenantAuthorities::holding(system)))
    }

    fn create(use_case: &CreateUseCase, req: CreateRequest) -> Result<RoleId, AppError> {
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            req,
        ))
    }

    fn saved(store: &FakeRoleStore) -> Role<ResolvedTenant> {
        store.stored(test_ctx().tenant_id()).remove(0)
    }

    /// Ann, an admin, creates the role "editor". It is saved in her tenant
    /// and the creation is recorded.
    #[test]
    fn a_role_is_created_and_recorded() {
        let store = Arc::new(FakeRoleStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        block_on(admin_use_case(store.clone()).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            editor_request(),
        ))
        .unwrap();

        assert_eq!(store.stored(test_ctx().tenant_id()).len(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.role_created"]
        );
    }

    /// Ann creates "editor" and gets back the id it is saved under.
    #[test]
    fn the_new_role_is_saved_under_the_id_returned() {
        let store = Arc::new(FakeRoleStore::empty());

        let role_id = create(&admin_use_case(store.clone()), editor_request()).unwrap();

        let role = saved(&store);
        assert_eq!(*role.id(), role_id);
        assert_eq!(role.name().as_str(), "editor");
    }

    /// Ann creates a role managing users and reading the audit log. It is
    /// saved with both.
    #[test]
    fn a_role_keeps_the_system_permissions_it_is_created_with() {
        let store = Arc::new(FakeRoleStore::empty());
        let req = with_system(vec![
            SystemPermission::ManageUsers,
            SystemPermission::ViewAuditLog,
        ]);

        create(&admin_use_case(store.clone()), req).unwrap();

        assert_eq!(saved(&store).system_permissions().len(), 2);
    }

    /// Ann creates a role every new user gets. It is saved as a default.
    #[test]
    fn a_default_role_is_saved_as_one() {
        let store = Arc::new(FakeRoleStore::empty());
        let req = CreateRequest {
            is_default: DefaultAssignment::NewUsers,
            ..editor_request()
        };

        create(&admin_use_case(store.clone()), req).unwrap();

        assert!(saved(&store).is_default());
    }

    /// Sam may create roles and manage users. He creates a role that manages
    /// users.
    #[test]
    fn a_caller_can_grant_a_permission_they_hold() {
        let store = Arc::new(FakeRoleStore::empty());
        let uc = holding(
            store.clone(),
            &[CREATE_ROLES, SystemPermission::ManageUsers],
        );

        create(&uc, with_system(vec![SystemPermission::ManageUsers])).unwrap();

        assert_eq!(store.count(), 1);
    }

    /// Sam may only create roles. He creates a role that grants nothing.
    #[test]
    fn a_role_that_grants_nothing_needs_only_the_right_to_create_roles() {
        let store = Arc::new(FakeRoleStore::empty());

        create(
            &holding(store.clone(), &[CREATE_ROLES]),
            with_system(Vec::new()),
        )
        .unwrap();

        assert_eq!(store.count(), 1);
    }

    /// Role creation and audit access do not let Sam grant user management.
    /// The request is forbidden and no role is saved.
    #[test]
    fn a_caller_cannot_grant_a_permission_they_do_not_hold() {
        let store = Arc::new(FakeRoleStore::empty());
        let uc = holding(
            store.clone(),
            &[CREATE_ROLES, SystemPermission::ViewAuditLog],
        );

        let result = create(&uc, with_system(vec![SystemPermission::ManageUsers]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Sam holds role creation rights but neither project permission. A role
    /// granting `project:read` and `project:write` is refused without saving it.
    #[test]
    fn a_caller_cannot_put_app_permissions_they_do_not_hold_into_a_role() {
        let store = Arc::new(FakeRoleStore::empty());

        let result = create(&holding(store.clone(), &[CREATE_ROLES]), editor_request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Sam may create roles and holds `project:*`. He puts `project:read`
    /// and `project:write` into a role.
    #[test]
    fn app_permissions_the_caller_holds_can_go_into_a_role() {
        let store = Arc::new(FakeRoleStore::empty());
        let held =
            FakeTenantAuthorities::holding_with_app(&[CREATE_ROLES], &[custom("project", "*")]);

        create(&use_case(store.clone(), Arc::new(held)), editor_request()).unwrap();

        assert_eq!(store.count(), 1);
    }

    /// Ann may create roles and escalate. She puts app permissions she does
    /// not hold herself into a role.
    #[test]
    fn escalate_lets_a_caller_put_any_app_permission_into_a_role() {
        let store = Arc::new(FakeRoleStore::empty());
        let uc = holding(
            store.clone(),
            &[CREATE_ROLES, SystemPermission::Roles(RoleAction::Escalate)],
        );

        create(&uc, editor_request()).unwrap();

        assert_eq!(store.count(), 1);
    }

    /// Creating a default role also needs permission to update users. Sam
    /// lacks that permission, so the request is forbidden and no role is saved.
    #[test]
    fn a_default_role_needs_the_right_to_update_users() {
        let store = Arc::new(FakeRoleStore::empty());
        let req = CreateRequest {
            is_default: DefaultAssignment::NewUsers,
            ..with_system(Vec::new())
        };

        let result = create(&holding(store.clone(), &[CREATE_ROLES]), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Ann writes `invoice:read` into a role, but the tenant's catalogue
    /// declares no `invoice`. She is told so and nothing is saved.
    #[test]
    fn an_app_permission_the_catalogue_does_not_declare_is_refused() {
        let store = Arc::new(FakeRoleStore::empty());
        let req = CreateRequest {
            custom_permissions: vec![custom("invoice", "read")],
            ..editor_request()
        };

        let result = create(&admin_use_case(store.clone()), req);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// Ann creates "editor" twice. The second is refused as a conflict.
    #[test]
    fn a_name_already_taken_is_a_conflict() {
        let uc = admin_use_case(Arc::new(FakeRoleStore::empty()));
        create(&uc, editor_request()).unwrap();

        let result = create(&uc, editor_request());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A refused second "editor" leaves no record behind.
    #[test]
    fn a_refused_creation_is_not_recorded() {
        let uc = admin_use_case(Arc::new(FakeRoleStore::empty()));
        create(&uc, editor_request()).unwrap();
        let sink = Arc::new(FakeEventDispatcher::new());

        let _ = block_on(uc.execute(&test_ctx(), &test_auditor(sink.clone()), editor_request()));

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// With no room for another role under the tenant's plan, creation is
    /// forbidden and the role store stays empty.
    #[test]
    fn a_role_past_the_plan_limit_is_refused() {
        let store = Arc::new(FakeRoleStore::empty());
        let uc = CreateUseCase::new(CreatePorts {
            role_store: store.clone(),
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..CreatePorts::fakes()
        });

        let result = create(&uc, editor_request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Mallory lacks role creation rights. Her request is forbidden and
    /// leaves the role store empty.
    #[test]
    fn a_caller_without_the_right_to_create_roles_is_refused() {
        let store = Arc::new(FakeRoleStore::empty());

        let result = create(&holding(store.clone(), &[]), with_system(Vec::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Signed-out authority cannot create a role: the result is
    /// unauthenticated and no role is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeRoleStore::empty());
        let uc = use_case(
            store.clone(),
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        );

        let result = create(&uc, editor_request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// A use case whose company rule refuses every change, run by a caller
    /// holding everything.
    fn refusing(store: Arc<FakeRoleStore>) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            role_store: store,
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..CreatePorts::fakes()
        })
    }

    /// Ann's company rule refuses admin work being handed out. Tess creates
    /// "support", which manages users and every new user would get: it is
    /// refused and nothing is saved.
    #[test]
    fn a_company_rule_refusing_stops_a_default_admin_role() {
        let store = Arc::new(FakeRoleStore::empty());
        let req = CreateRequest {
            is_default: DefaultAssignment::NewUsers,
            ..with_system(vec![SystemPermission::ManageUsers])
        };

        let result = create(&refusing(store.clone()), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.stored(test_ctx().tenant_id()).is_empty());
    }

    /// The same rule is not asked about an admin role nobody holds yet: it
    /// is created, and giving it out later asks the rule then.
    #[test]
    fn an_admin_role_nobody_gets_yet_is_not_asked_about() {
        let store = Arc::new(FakeRoleStore::empty());

        create(
            &refusing(store.clone()),
            with_system(vec![SystemPermission::ManageUsers]),
        )
        .unwrap();

        assert_eq!(store.stored(test_ctx().tenant_id()).len(), 1);
    }
}
