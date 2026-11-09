//! Update role: rename it, change its permissions, or change whether new
//! users get it. Only the fields given change.
//!
//! A role that gains a built-in permission hands admin work to everyone
//! holding it, and one made a default hands it to every new user. Either
//! goes ahead only once the company's "before admin given" rules allow it.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{
    CustomPermission, RoleAction, SystemPermission,
};
use ianua_domain::domains::authorization::role::permission_moves::{
    PermissionsMoved, WantedPermissions,
};
use ianua_domain::domains::authorization::role::{DefaultAssignment, Role};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, RoleId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, ResourceTypeStore, RoleStore};
use crate::ports::workflows::ChangeGuard;
use crate::services::authorization::catalogue_check::ensure_declared;
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::{access_records, ensure_role_name_free};
use crate::use_cases::authorization::stewardship::{Withdrawal, ensure_still_administered};

/// The changes to make. `None` leaves that field as it is.
pub struct UpdateRequest {
    /// The role to update.
    pub role_id: RoleId,
    /// Its new name.
    pub name: Option<Label>,
    /// Its system permissions after the update: the whole set, not
    /// additions to it. Anything the role holds and this leaves out is
    /// revoked.
    pub system_permissions: Option<Vec<SystemPermission>>,
    /// Its custom permissions after the update, replacing the set the same
    /// way.
    pub custom_permissions: Option<Vec<CustomPermission>>,
    /// Whether every new user gets it.
    pub is_default: Option<DefaultAssignment>,
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Loads and saves roles.
    pub role_store: Arc<dyn RoleStore>,
    /// Reads the tenant's permission catalogue.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// Reads who holds what across the tenant, to keep an administrator.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The company's "before" rules, asked before an edit hands out admin
    /// work.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Changes a role of the caller's tenant.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }

    /// Asks the company's "before admin given" rules about whoever `role`
    /// now hands admin work it did not as `before`.
    async fn ensure_rules_allow(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        before: &Before,
        role: &Role<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let Some(holder) = before.admin_reach(role) else {
            return Ok(());
        };
        let guard = self.ports.guard.as_ref();
        ensure_admin_rules_allow(guard, tenant, auditor, role, holder).await
    }

    /// Refuses `custom` permissions the tenant's catalogue does not
    /// declare. Leaving them out declares nothing to check.
    async fn ensure_custom_declared(
        &self,
        tenant: &ScopedTenant,
        custom: Option<&[CustomPermission]>,
    ) -> Result<(), AppError> {
        let store = self.ports.resource_type_store.as_ref();
        ensure_declared(store, tenant, custom.unwrap_or_default()).await
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Makes the changes `req` asks for to its role, for the caller.
    ///
    /// A request that changes nothing saves and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without update rights, before reading the role.
    /// - `AppError::NotFound` for a missing role; `Domain` for undeclared custom permissions.
    /// - `AppError::Forbidden` for ungrantable existing/added rights or a default role without user-update rights.
    /// - `AppError::Conflict` for a taken name or loss of the last administrator; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::Update))
            .map_err(AppError::from_domain)?;
        let mut role = existing_role(self.ports.role_store.as_ref(), &tenant, &req.role_id).await?;
        self.ensure_custom_declared(&tenant, req.custom_permissions.as_deref())
            .await?;
        let editing = Editing {
            tenant: &tenant,
            authority: &authority,
        };
        let before = Before::of(&role);
        if edited(&self.ports, &editing, &mut role, &req).await? == Edited::Unchanged {
            return Ok(());
        }
        self.ensure_rules_allow(&tenant, auditor, &before, &role)
            .await?;

        self.ports
            .role_store
            .save(&tenant, &role)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), role.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Who changes a role, in which tenant.
struct Editing<'a> {
    /// The scope whose permission definition is being changed.
    tenant: &'a ScopedTenant,
    /// Who changes it.
    authority: &'a TenantAuthority,
}

/// What a role granted and who got it before an edit.
struct Before {
    system: Vec<SystemPermission>,
    assignment: DefaultAssignment,
}

impl Before {
    /// `role` as it stands.
    fn of(role: &Role<ResolvedTenant>) -> Self {
        Self {
            system: role.system_permissions().to_vec(),
            assignment: DefaultAssignment::from(role.is_default()),
        }
    }

    /// Who `role`, edited from this, hands admin work they did not have:
    /// its holders when it gained a built-in permission, every new user when
    /// it was made a default; nobody otherwise.
    fn admin_reach(&self, role: &Role<ResolvedTenant>) -> Option<AdminHolder<'static>> {
        let gained = role
            .system_permissions()
            .iter()
            .any(|permission| !self.system.contains(permission));
        let made_default = self.assignment == DefaultAssignment::Manual && role.is_default();
        match (gained, made_default) {
            (true, _) => Some(AdminHolder::EveryHolder),
            (false, true) => Some(AdminHolder::EveryNewUser),
            (false, false) => None,
        }
    }
}

/// Whether an update changed the role.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Edited {
    /// The role is as it was.
    Unchanged,
    /// Something about it changed.
    Changed,
}

impl Edited {
    /// Changed when either part changed.
    fn or(self, other: Self) -> Self {
        match self {
            Self::Changed => Self::Changed,
            Self::Unchanged => other,
        }
    }
}

impl From<PermissionsMoved> for Edited {
    fn from(moved: PermissionsMoved) -> Self {
        match moved {
            PermissionsMoved::Nothing => Self::Unchanged,
            PermissionsMoved::Widened | PermissionsMoved::Narrowed => Self::Changed,
        }
    }
}

/// Refuses narrowing a role to `narrowed` when that leaves the tenant
/// nobody can administer.
async fn ensure_administered_with(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    narrowed: &Role<ResolvedTenant>,
) -> Result<(), AppError> {
    let before = access_records(store, tenant).await?;
    ensure_still_administered(tenant, before, Withdrawal::RoleNarrowed(narrowed))
}

/// Makes the rename, the default change and the permission moves to
/// `role`, which raises what changed, and says whether anything did.
async fn edited(
    ports: &UpdatePorts,
    editing: &Editing<'_>,
    role: &mut Role<ResolvedTenant>,
    req: &UpdateRequest,
) -> Result<Edited, AppError> {
    let renamed = renamed(ports.role_store.as_ref(), editing, role, req.name.as_ref()).await?;
    let defaulted = reassigned_by_default(editing, role, req.is_default)?;
    let wanted = WantedPermissions {
        system: req.system_permissions.as_deref(),
        custom: req.custom_permissions.as_deref(),
    };
    let moved = role
        .change_permissions(&wanted, &editing.authority.standing())
        .map_err(AppError::from_domain)?;
    if moved == PermissionsMoved::Narrowed {
        ensure_administered_with(ports.access_records.as_ref(), editing.tenant, role).await?;
    }
    Ok(renamed.or(defaulted).or(Edited::from(moved)))
}

/// Renames `role` to `name` when it is new to it and free in the tenant.
async fn renamed(
    store: &dyn RoleStore,
    editing: &Editing<'_>,
    role: &mut Role<ResolvedTenant>,
    name: Option<&Label>,
) -> Result<Edited, AppError> {
    let Some(name) = name.filter(|name| name.as_str() != role.name().as_str()) else {
        return Ok(Edited::Unchanged);
    };
    ensure_role_name_free(store, editing.tenant, name).await?;
    role.rename(name.clone(), editing.authority)
        .map_err(AppError::from_domain)?;
    Ok(Edited::Changed)
}

/// Sets whether every new user gets `role`, when `assignment` is given.
fn reassigned_by_default(
    editing: &Editing<'_>,
    role: &mut Role<ResolvedTenant>,
    assignment: Option<DefaultAssignment>,
) -> Result<Edited, AppError> {
    let Some(assignment) = assignment else {
        return Ok(Edited::Unchanged);
    };
    let previous = DefaultAssignment::from(role.is_default());
    role.change_default_assignment(assignment, &editing.authority.standing())
        .map_err(AppError::from_domain)?;
    if previous == assignment {
        return Ok(Edited::Unchanged);
    }
    Ok(Edited::Changed)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, UserAction};
    use ianua_domain::domains::authorization::role::{NewRole, RoleAssignment, RoleAssignmentRow};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::data::{EventData, FieldValue};
    use ianua_domain::types::{ActorRef, Expiry, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeResourceTypeStore, FakeRoleAssignmentStore,
        FakeRoleStore,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, reference_label, test_auditor, test_ctx,
    };

    const UPDATE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Update);
    const UPDATE_USERS: SystemPermission = SystemPermission::Users(UserAction::Update);

    fn custom(resource: &str, action: &str) -> CustomPermission {
        CustomPermission::new(resource, action).unwrap()
    }

    fn label(name: &str) -> Label {
        Label::new("role_name", name).unwrap()
    }

    fn role(
        name: &str,
        system: Vec<SystemPermission>,
        app: Vec<CustomPermission>,
    ) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label(name),
            system_permissions: system,
            custom_permissions: app,
            assignment: DefaultAssignment::Manual,
        })
    }

    /// "editor": manages users and reads projects.
    fn editor() -> Role<ResolvedTenant> {
        role(
            "editor",
            vec![SystemPermission::ManageUsers],
            vec![custom("project", "read")],
        )
    }

    fn text<'a>(payload: &'a EventData, key: &str) -> Option<&'a str> {
        match payload.value(key)? {
            FieldValue::Text(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// A tenant whose roles are read by every port.
    struct Tenant {
        role_id: RoleId,
        stores: AccessSources,
    }

    impl Tenant {
        fn with(role: Role<ResolvedTenant>) -> Self {
            Self {
                role_id: *role.id(),
                stores: AccessSources {
                    roles: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [role])),
                    ..AccessSources::default()
                },
            }
        }

        fn with_editor() -> Self {
            Self::with(editor())
        }

        fn also(self, role: Role<ResolvedTenant>) -> Self {
            self.stores.roles.add(test_ctx().tenant_id(), [role]);
            self
        }

        fn held_by(self, user: UserId) -> Self {
            let assignment = RoleAssignment::reconstitute(RoleAssignmentRow {
                principal: PrincipalRef::User(user),
                role_id: self.role_id,
                assigned_by: ActorRef::System,
                assigned_at: clock::now(),
                expires: Expiry::Never,
            })
            .unwrap();
            let assignments =
                FakeRoleAssignmentStore::holding(test_ctx().tenant_id(), [assignment]);
            Self {
                stores: AccessSources {
                    assignments: Arc::new(assignments),
                    ..self.stores
                },
                ..self
            }
        }

        fn ports(&self) -> UpdatePorts {
            UpdatePorts {
                role_store: self.stores.roles.clone(),
                resource_type_store: Arc::new(FakeResourceTypeStore::seeded(
                    test_ctx().tenant_id(),
                )),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..UpdatePorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> UpdatePorts {
            UpdatePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn request(&self) -> UpdateRequest {
            UpdateRequest {
                role_id: self.role_id,
                name: None,
                system_permissions: None,
                custom_permissions: None,
                is_default: None,
            }
        }

        fn saved(&self) -> Role<ResolvedTenant> {
            self.stores
                .roles
                .stored(test_ctx().tenant_id())
                .into_iter()
                .find(|role| *role.id() == self.role_id)
                .unwrap()
        }
    }

    fn update(ports: UpdatePorts, req: UpdateRequest) -> Result<(), AppError> {
        update_recorded(ports, &Arc::new(FakeEventDispatcher::new()), req)
    }

    fn update_recorded(
        ports: UpdatePorts,
        sink: &Arc<FakeEventDispatcher>,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        block_on(UpdateUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    /// Ann renames "editor" to "admin". The role is saved under the new
    /// name and the rename is recorded.
    #[test]
    fn a_role_is_renamed_and_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            name: Some(label("admin")),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        assert_eq!(tenant.saved().name().as_str(), "admin");
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.role_renamed"]
        );
    }

    /// Ann renames "editor" to "admin", a name another role has. She is
    /// refused as a conflict.
    #[test]
    fn a_name_another_role_has_is_a_conflict() {
        let tenant = Tenant::with_editor().also(role("admin", Vec::new(), Vec::new()));
        let req = UpdateRequest {
            name: Some(label("admin")),
            ..tenant.request()
        };

        let result = update(tenant.ports(), req);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann gives "editor" the right to read the audit log. It holds it, and
    /// the grant is recorded.
    #[test]
    fn a_system_permission_is_granted() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            system_permissions: Some(vec![
                SystemPermission::ManageUsers,
                SystemPermission::ViewAuditLog,
            ]),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        assert!(
            tenant
                .saved()
                .has_system_permission(SystemPermission::ViewAuditLog)
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.permission_granted"]
        );
    }

    /// Ann takes every system permission from "editor". It no longer manages
    /// users, and the revocation is recorded.
    #[test]
    fn a_system_permission_is_revoked() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            system_permissions: Some(Vec::new()),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        assert!(
            !tenant
                .saved()
                .has_system_permission(SystemPermission::ManageUsers)
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.permission_revoked"]
        );
    }

    /// Ann adds `billing:read` to "editor". It holds it.
    #[test]
    fn a_custom_permission_is_granted() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            custom_permissions: Some(vec![custom("project", "read"), custom("billing", "read")]),
            ..tenant.request()
        };

        update(tenant.ports(), req).unwrap();

        assert!(tenant.saved().has_custom_permission("billing", "read"));
    }

    /// Ann takes every app permission from "editor". It no longer reads
    /// projects.
    #[test]
    fn a_custom_permission_is_revoked() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            custom_permissions: Some(Vec::new()),
            ..tenant.request()
        };

        update(tenant.ports(), req).unwrap();

        assert!(!tenant.saved().has_custom_permission("project", "read"));
    }

    /// Ann renames "editor" to "admin" and changes both kinds of permission
    /// in one save. Every permission record names the role "admin".
    #[test]
    fn permission_records_name_the_role_by_its_new_name() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            name: Some(label("admin")),
            system_permissions: Some(vec![SystemPermission::ViewAuditLog]),
            custom_permissions: Some(vec![custom("billing", "read")]),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        let payloads = sink.all_payloads();
        assert_eq!(payloads.len(), 5);
        for payload in &payloads {
            assert_eq!(reference_label(payload, "role"), Some("admin"));
        }
    }

    /// Ann gives "editor" every system permission there is. One save is one
    /// act, so it raises one record, which counts every permission that
    /// moved: all of them but the one it already held.
    #[test]
    fn granting_many_permissions_raises_one_record_not_one_each() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let all = SystemPermission::all().to_vec();
        let newly_granted = all.len() - 1;
        let req = UpdateRequest {
            system_permissions: Some(all),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        let payloads = sink.all_payloads();
        assert_eq!(payloads.len(), 1);
        assert_eq!(text(&payloads[0], "permission_type"), Some("system"));
        assert_eq!(
            text(&payloads[0], "permission_count"),
            Some(newly_granted.to_string().as_str())
        );
    }

    /// Ann adds two system and two app permissions to "editor" in one save.
    /// One record comes out for each kind, each counting its two.
    #[test]
    fn a_save_touching_both_kinds_raises_one_record_of_each() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            system_permissions: Some(vec![
                SystemPermission::ManageUsers,
                SystemPermission::ViewAuditLog,
                SystemPermission::ManageRoles,
            ]),
            custom_permissions: Some(vec![
                custom("project", "read"),
                custom("billing", "read"),
                custom("billing", "write"),
            ]),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        let payloads = sink.all_payloads();
        let kinds: Vec<_> = payloads
            .iter()
            .filter_map(|payload| text(payload, "permission_type"))
            .collect();
        assert_eq!(kinds, ["system", "custom"]);
        for payload in &payloads {
            assert_eq!(text(payload, "permission_count"), Some("2"));
        }
    }

    /// Ann adds two permissions to "editor". The record names each one that
    /// moved, and not the one the role already held.
    #[test]
    fn the_record_names_every_permission_it_counts() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            system_permissions: Some(vec![
                SystemPermission::ManageUsers,
                SystemPermission::ViewAuditLog,
                SystemPermission::ManageRoles,
            ]),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        let listed = text(&sink.all_payloads()[0], "permissions")
            .unwrap()
            .to_owned();
        assert!(listed.contains(&SystemPermission::ViewAuditLog.to_string()));
        assert!(listed.contains(&SystemPermission::ManageRoles.to_string()));
        assert!(!listed.contains(&SystemPermission::ManageUsers.to_string()));
    }

    /// Ann saves "editor" without changing anything. Nothing is recorded.
    #[test]
    fn a_request_changing_nothing_records_nothing() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());

        update_recorded(tenant.ports(), &sink, tenant.request()).unwrap();

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann sends "editor" the permissions it already holds. Nothing came or
    /// went, so nothing is recorded.
    #[test]
    fn resending_the_same_permissions_records_nothing() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            system_permissions: Some(vec![SystemPermission::ManageUsers]),
            custom_permissions: Some(vec![custom("project", "read")]),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann narrows "editor" from managing agents to viewing them. It keeps
    /// the right to view, though managing covered it.
    #[test]
    fn narrowing_full_access_to_one_action_keeps_that_action() {
        let tenant = Tenant::with(role(
            "editor",
            vec![SystemPermission::Agents(AgentAction::Manage)],
            Vec::new(),
        ));
        let req = UpdateRequest {
            system_permissions: Some(vec![SystemPermission::Agents(AgentAction::View)]),
            ..tenant.request()
        };

        update(tenant.ports(), req).unwrap();

        assert_eq!(
            tenant.saved().system_permissions(),
            [SystemPermission::Agents(AgentAction::View)]
        );
    }

    /// Ann replaces managing agents with three agent actions in one save.
    /// All three are kept.
    #[test]
    fn replacing_full_access_with_several_actions_keeps_them_all() {
        let tenant = Tenant::with(role(
            "editor",
            vec![SystemPermission::Agents(AgentAction::Manage)],
            Vec::new(),
        ));
        let chosen = [
            SystemPermission::Agents(AgentAction::View),
            SystemPermission::Agents(AgentAction::Update),
            SystemPermission::Agents(AgentAction::Approve),
        ];
        let req = UpdateRequest {
            system_permissions: Some(chosen.to_vec()),
            ..tenant.request()
        };

        update(tenant.ports(), req).unwrap();

        assert_eq!(tenant.saved().system_permissions(), chosen);
    }

    /// Ann narrows `project:*` to `project:read`. The role keeps
    /// `project:read`, though the wildcard covered it.
    #[test]
    fn narrowing_a_wildcard_custom_permission_keeps_the_named_action() {
        let tenant = Tenant::with(role("editor", Vec::new(), vec![custom("project", "*")]));
        let req = UpdateRequest {
            custom_permissions: Some(vec![custom("project", "read")]),
            ..tenant.request()
        };

        update(tenant.ports(), req).unwrap();

        assert_eq!(
            tenant.saved().custom_permissions(),
            [custom("project", "read")]
        );
    }

    /// Ann renames "editor" and says nothing about its permissions. It keeps
    /// them all.
    #[test]
    fn leaving_out_the_permission_sets_keeps_them() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            name: Some(label("renamed")),
            ..tenant.request()
        };

        update(tenant.ports(), req).unwrap();

        let saved = tenant.saved();
        assert!(saved.has_system_permission(SystemPermission::ManageUsers));
        assert!(saved.has_custom_permission("project", "read"));
    }

    /// Ann adds `invoice:read` to "editor", but the catalogue declares no
    /// `invoice`. She is told so and the role is unchanged.
    #[test]
    fn an_undeclared_app_permission_is_refused() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            custom_permissions: Some(vec![custom("invoice", "read")]),
            ..tenant.request()
        };

        let result = update(tenant.ports(), req);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(tenant.saved().has_custom_permission("project", "read"));
    }

    /// Ann renames a role the tenant does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_role_is_not_found_and_not_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            role_id: RoleId::new(),
            name: Some(label("ghost")),
            ..tenant.request()
        };

        let result = update_recorded(tenant.ports(), &sink, req);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Sam may update and escalate roles and manage users. He adds the right
    /// to read the audit log, which he holds, to "editor".
    #[test]
    fn a_caller_can_add_a_permission_they_hold() {
        let tenant = Tenant::with_editor();
        let held = [
            SystemPermission::ManageRoles,
            SystemPermission::ManageUsers,
            SystemPermission::ViewAuditLog,
        ];
        let req = UpdateRequest {
            system_permissions: Some(vec![
                SystemPermission::ManageUsers,
                SystemPermission::ViewAuditLog,
            ]),
            ..tenant.request()
        };

        update(tenant.ports_holding(&held), req).unwrap();

        assert_eq!(tenant.saved().system_permissions().len(), 2);
    }

    /// Managing roles and users does not let Sam add audit-log access he
    /// lacks. The request is forbidden and editor keeps its one permission.
    #[test]
    fn a_caller_cannot_add_a_permission_they_do_not_hold() {
        let tenant = Tenant::with_editor();
        let held = [SystemPermission::ManageRoles, SystemPermission::ManageUsers];
        let req = UpdateRequest {
            system_permissions: Some(vec![
                SystemPermission::ManageUsers,
                SystemPermission::ViewAuditLog,
            ]),
            ..tenant.request()
        };

        let result = update(tenant.ports_holding(&held), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.saved().system_permissions().len(), 1);
    }

    /// Adding project permissions requires holding them or permission to
    /// escalate. Sam has neither and is refused; Ann can escalate and
    /// successfully adds both permissions.
    #[test]
    fn adding_an_app_permission_needs_holding_it_or_escalate() {
        let tenant = Tenant::with(role("blank", Vec::new(), Vec::new()));
        let req = || UpdateRequest {
            custom_permissions: Some(vec![custom("project", "read"), custom("project", "write")]),
            ..tenant.request()
        };
        let escalating = [UPDATE_ROLES, SystemPermission::Roles(RoleAction::Escalate)];

        let refused = update(tenant.ports_holding(&[UPDATE_ROLES]), req());
        let allowed = update(tenant.ports_holding(&escalating), req());

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(allowed.is_ok());
    }

    /// Ann, who may update roles and users and escalate, and who manages
    /// users, makes "editor" a role every new user gets.
    #[test]
    fn a_caller_holding_what_a_role_grants_can_make_it_a_default() {
        let tenant = Tenant::with_editor();
        let held = [SystemPermission::ManageRoles, SystemPermission::ManageUsers];
        let req = UpdateRequest {
            is_default: Some(DefaultAssignment::NewUsers),
            ..tenant.request()
        };

        update(tenant.ports_holding(&held), req).unwrap();

        assert!(tenant.saved().is_default());
    }

    /// Ann makes "editor" a role every new user gets. Everyone joining from
    /// now on is handed it, so the change is recorded.
    #[test]
    fn making_a_role_a_default_is_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            is_default: Some(DefaultAssignment::NewUsers),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.role_default_assignment_changed"]
        );
    }

    /// Ann sends "editor" as assigned by hand, which it already is. Nothing
    /// changed, so nothing is recorded.
    #[test]
    fn keeping_a_roles_default_records_nothing() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = UpdateRequest {
            is_default: Some(DefaultAssignment::Manual),
            ..tenant.request()
        };

        update_recorded(tenant.ports(), &sink, req).unwrap();

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Sam manages roles but lacks the rights editor grants. Making it a
    /// default is forbidden, and the role remains manually assigned.
    #[test]
    fn making_a_role_a_default_needs_every_permission_it_grants() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            is_default: Some(DefaultAssignment::NewUsers),
            ..tenant.request()
        };

        let result = update(tenant.ports_holding(&[SystemPermission::ManageRoles]), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!tenant.saved().is_default());
    }

    /// Editor's project permission prevents Sam from making it a default:
    /// he can update roles and users but lacks that permission and cannot
    /// escalate. The request is forbidden and editor stays non-default.
    #[test]
    fn making_a_role_a_default_needs_its_app_permissions_too() {
        let tenant = Tenant::with_editor();
        let held = [UPDATE_ROLES, UPDATE_USERS, SystemPermission::ManageUsers];
        let req = UpdateRequest {
            is_default: Some(DefaultAssignment::NewUsers),
            ..tenant.request()
        };

        let result = update(tenant.ports_holding(&held), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!tenant.saved().is_default());
    }

    /// Ann makes "editor" a default and later stops it being one.
    #[test]
    fn a_role_stops_being_a_default() {
        let tenant = Tenant::with_editor();
        let to = |assignment| UpdateRequest {
            is_default: Some(assignment),
            ..tenant.request()
        };
        update(tenant.ports(), to(DefaultAssignment::NewUsers)).unwrap();

        update(tenant.ports(), to(DefaultAssignment::Manual)).unwrap();

        assert!(!tenant.saved().is_default());
    }

    /// Ann's admin role is the tenant's last source of administration.
    /// Removing its user-management permission conflicts and leaves both
    /// existing permissions intact.
    #[test]
    fn narrowing_the_last_administrators_role_is_refused() {
        let admin = role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        );
        let tenant = Tenant::with(admin).held_by(UserId::new());
        let req = UpdateRequest {
            system_permissions: Some(vec![SystemPermission::ManageRoles]),
            ..tenant.request()
        };

        let result = update(tenant.ports(), req);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.saved().system_permissions().len(), 2);
    }

    /// Renaming editor without role-update permission is forbidden; the
    /// saved role keeps its name.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let tenant = Tenant::with(role("editor", Vec::new(), Vec::new()));
        let req = UpdateRequest {
            name: Some(label("mine")),
            ..tenant.request()
        };

        let result = update(tenant.ports_holding(&[]), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.saved().name().as_str(), "editor");
    }

    /// An unknown role does not bypass the role-update check. A caller
    /// without that permission receives forbidden rather than not found.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused_for_an_unknown_role_too() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            role_id: RoleId::new(),
            name: Some(label("mine")),
            ..tenant.request()
        };

        let result = update(tenant.ports_holding(&[]), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Updating a role with signed-out authority returns unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_editor();
        let ports = UpdatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };
        let req = UpdateRequest {
            name: Some(label("mine")),
            ..tenant.request()
        };

        let result = update(ports, req);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ports for `tenant` whose company rule refuses every change.
    fn refusing(tenant: &Tenant) -> UpdatePorts {
        UpdatePorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        }
    }

    /// Ann's company rule refuses admin work being handed out. Tess adds
    /// user updates to "editor", which everyone holding it would gain: it
    /// is refused and the role is as it was.
    #[test]
    fn a_company_rule_refusing_stops_a_role_gaining_a_built_in_permission() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            system_permissions: Some(vec![SystemPermission::ManageUsers, UPDATE_USERS]),
            ..tenant.request()
        };

        let result = update(refusing(&tenant), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            tenant.saved().system_permissions(),
            [SystemPermission::ManageUsers]
        );
    }

    /// The same rule refuses making "editor" a role every new user gets.
    #[test]
    fn a_company_rule_refusing_stops_an_admin_role_becoming_a_default() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            is_default: Some(DefaultAssignment::NewUsers),
            ..tenant.request()
        };

        let result = update(refusing(&tenant), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!tenant.saved().is_default());
    }

    /// Renaming "editor" hands nobody anything new, so the rule is not
    /// asked and the rename goes through.
    #[test]
    fn an_edit_handing_out_nothing_new_is_not_asked_about() {
        let tenant = Tenant::with_editor();
        let req = UpdateRequest {
            name: Some(label("support")),
            ..tenant.request()
        };

        update(refusing(&tenant), req).unwrap();

        assert_eq!(tenant.saved().name().as_str(), "support");
    }
}
