/// Moving a role to hold exactly the permissions wanted.
pub mod permission_moves;
/// The roles a new tenant starts with, made during its setup.
pub mod starting;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::roles::{
    PermissionGranted, PermissionRevoked, RoleCreated, RoleDefaultAssignmentChanged, RoleDeleted,
    RoleRenamed,
};
use crate::domains::authorization::granter::{Handout, HeldByGranter};
use crate::domains::authorization::permission::{
    CustomPermission, PermissionSet, RoleAction, SystemPermission, UserAction,
};
pub use crate::domains::authorization::role_assignment::{
    RoleAssignment, RoleAssignmentRow, assignment_right,
};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::two_cases::two_cases;
use crate::shared::validation::distinct::{first_repeat, without_repeats};
use crate::types::{EventLabel, Label, RoleId};

/// A [`Role`] as storage holds it, read back through [`Role::reconstitute`].
pub struct RoleRow {
    /// The role's id.
    pub id: RoleId,
    /// The role's name.
    pub name: Label,
    /// The built-in permissions it grants.
    pub system_permissions: Vec<SystemPermission>,
    /// The tenant-defined permissions it grants.
    pub custom_permissions: Vec<CustomPermission>,
    /// Whether new users get it.
    pub is_default: DefaultAssignment,
    /// When it was created.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

two_cases! {
    /// Whether a role is given to new users without anyone assigning it.
    /// Storage keeps it as the `is_default` flag.
    pub enum DefaultAssignment {
        /// Every new user gets it.
        NewUsers => true,
        /// It is only held when assigned.
        Manual => false,
    }
}

impl DefaultAssignment {
    /// The name an audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewUsers => "new_users",
            Self::Manual => "manual",
        }
    }
}

/// A named set of permissions within a tenant.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// A role holds two kinds of permissions:
/// - [`SystemPermission`]: built into the `IdP`. They allow admin work such
///   as managing users, sign-in settings and audit logs. The `IdP` checks them.
/// - [`CustomPermission`]: defined by the customer. The gateway can require
///   them on a route and passes them to the app in its signed assertion.
///   Beyond that, the customer's application checks them.
///
/// Changing a role changes what every holder may do. So only someone who
/// may update roles, and who holds all the role grants, changes it. That
/// covers taking permissions away and renaming too: Sam may edit roles but
/// not manage users, and must not strip the admin role of what he could
/// never have given it.
#[derive(Debug, Clone)]
pub struct Role<T: TenantScope> {
    id: RoleId,
    name: Label,
    system_permissions: Vec<SystemPermission>,
    custom_permissions: Vec<CustomPermission>,
    is_default: DefaultAssignment,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Everything a role is created with.
pub struct NewRole {
    /// The caller-selected identity retained by assignments to this permission bundle.
    pub id: RoleId,
    /// The display label used when people select this permission bundle.
    pub name: Label,
    /// The built-in permissions it grants.
    pub system_permissions: Vec<SystemPermission>,
    /// The tenant-defined permissions it grants.
    pub custom_permissions: Vec<CustomPermission>,
    /// Whether new users get it.
    pub assignment: DefaultAssignment,
}

impl<T: TenantScope> Role<T> {
    /// Creates a role someone defines. Raises `authorization.role_created`.
    ///
    /// Whoever later holds the role gains all it grants. So `granter` must
    /// be allowed to create roles, and able to hand out every permission it
    /// starts with, as if they added each one later. A role every new user
    /// gets is given to people, so that also needs the right to update
    /// users.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `granter` may not create roles.
    /// - [`DomainError::Forbidden`] when the role goes to every new user and
    ///   `granter` may not update users.
    /// - [`DomainError::Forbidden`] when `granter` may not hand out one of its
    ///   permissions.
    pub fn create(role: NewRole, granter: &HeldByGranter<'_>) -> Result<Self, DomainError> {
        granter.ensure_holds(SystemPermission::Roles(RoleAction::Create))?;
        ensure_may_make_default(role.assignment, granter)?;
        granter.ensure_may_hand_out(&role.system_permissions, &role.custom_permissions)?;
        let mut created = Self::assembled(role);
        created.raised.raise(RoleCreated {
            role_id: created.id,
            name: created.name.clone(),
            occurred_at: created.created_at,
        });
        Ok(created)
    }

    /// A role made with no granter checked. For tests only.
    ///
    /// Outside tests, every role goes through [`Self::create`]. Sam may only
    /// view users. Without this limit, Sam builds a role that manages users
    /// with no check, assigns it to himself and gains it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn provisioned(role: NewRole) -> Self {
        Self::assembled(role)
    }

    fn assembled(role: NewRole) -> Self {
        let NewRole {
            id,
            name,
            system_permissions,
            custom_permissions,
            assignment,
        } = role;
        let now = crate::shared::clock::now();
        Self {
            id,
            name,
            system_permissions: without_repeats(system_permissions),
            custom_permissions: without_repeats(custom_permissions),
            is_default: assignment,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a role from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row names a permission twice.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: RoleRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            system_permissions: row.system_permissions,
            custom_permissions: row.custom_permissions,
            is_default: row.is_default,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &RoleRow) -> Result<(), DomainError> {
        RowCheck::of("role")
            .holds(
                first_repeat(&row.system_permissions).is_none(),
                "a system permission named twice",
            )
            .holds(
                first_repeat(&row.custom_permissions).is_none(),
                "a custom permission named twice",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The role's id.
    #[must_use]
    pub fn id(&self) -> &RoleId {
        &self.id
    }

    /// The role's name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The built-in permissions this role grants. The `IdP` checks them for
    /// admin work.
    #[must_use]
    pub fn system_permissions(&self) -> &[SystemPermission] {
        &self.system_permissions
    }

    /// Whether the role lets its holder do admin work: it grants a built-in
    /// permission. Giving such a role is what a company's "before admin
    /// given" rule decides.
    #[must_use]
    pub fn grants_admin_work(&self) -> bool {
        !self.system_permissions.is_empty()
    }

    /// The customer-defined permissions this role grants.
    #[must_use]
    pub fn custom_permissions(&self) -> &[CustomPermission] {
        &self.custom_permissions
    }

    /// Everything this role grants, as a hand-out to check a granter
    /// against.
    #[must_use]
    pub fn grants(&self) -> Handout<'_> {
        Handout {
            system: &self.system_permissions,
            custom: &self.custom_permissions,
        }
    }

    /// Whether every new user gets this role without anyone assigning it.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.is_default == DefaultAssignment::NewUsers
    }

    /// When this role was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this role last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether this role grants `permission`, directly or through a wider one.
    ///
    /// A role with `ManageUsers` also passes a check for `Users(View)`.
    #[must_use]
    pub fn has_system_permission(&self, permission: SystemPermission) -> bool {
        self.system_permissions
            .iter()
            .any(|held| held.implies(&permission))
    }

    /// Whether this role grants `action` on `resource`.
    ///
    /// A held wildcard matches too, so `project:*` grants `project:read`.
    #[must_use]
    pub fn has_custom_permission(&self, resource: &str, action: &str) -> bool {
        self.custom_permissions
            .iter()
            .any(|p| p.matches(resource, action))
    }

    /// Records that the role gained `permissions`, when there are any.
    fn record_grant(&mut self, permissions: PermissionSet) {
        if permissions.is_empty() {
            return;
        }
        self.touch();
        self.raised.raise(PermissionGranted {
            role_id: self.id,
            role_label: self.label(),
            permissions,
            occurred_at: self.updated_at,
        });
    }

    /// Records that the role lost `permissions`, when there are any.
    fn record_revocation(&mut self, permissions: PermissionSet) {
        if permissions.is_empty() {
            return;
        }
        self.touch();
        self.raised.raise(PermissionRevoked {
            role_id: self.id,
            role_label: self.label(),
            permissions,
            occurred_at: self.updated_at,
        });
    }

    /// Replaces the role's name, for `editor`. Raises
    /// `authorization.role_renamed`, keeping the old name. The name it
    /// already has changes nothing and raises nothing.
    ///
    /// A new name hands nothing out, so it needs only the right to update
    /// roles, and an active break-glass grant counts.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    pub fn rename(&mut self, name: Label, editor: &TenantAuthority) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Update))?;
        if name.as_str() == self.name.as_str() {
            return Ok(());
        }
        let old_name = std::mem::replace(&mut self.name, name);
        self.touch();
        self.raised.raise(RoleRenamed {
            role_id: self.id,
            old_name,
            new_name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes whether every new user is given this role. Raises
    /// `authorization.role_default_assignment_changed` with both settings,
    /// unless it already was so.
    ///
    /// Giving the role to every new user hands out all it grants, to
    /// people. So it also needs the right to update users.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases [`Self::ensure_editable_by`]
    ///   lists.
    /// - [`DomainError::Forbidden`] when the role would go to every new user
    ///   and `editor` may not update users.
    pub fn change_default_assignment(
        &mut self,
        assignment: DefaultAssignment,
        editor: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        ensure_may_make_default(assignment, editor)?;
        let previous = std::mem::replace(&mut self.is_default, assignment);
        self.touch();
        if previous == assignment {
            return Ok(());
        }
        self.raised.raise(RoleDefaultAssignmentChanged {
            role_id: self.id,
            role_label: self.label(),
            previous,
            current: assignment,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this role once `granter` may. Raises
    /// `authorization.role_deleted`, taken once the role is removed from
    /// storage.
    ///
    /// Every holder loses all the role grants. So only someone who may
    /// delete roles, and could have given all of it, deletes it. Whether
    /// someone can still run the tenant afterwards is
    /// [`ensure_still_administered`](crate::domains::authorization::stewardship::ensure_still_administered).
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `granter` may not delete roles, or
    ///   may not hand out all the role grants.
    pub fn delete(&mut self, granter: &HeldByGranter<'_>) -> Result<(), DomainError> {
        granter.ensure_controls(SystemPermission::Roles(RoleAction::Delete), &self.grants())?;
        self.raised.raise(RoleDeleted {
            role_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `editor` unless they may update roles and hold all this role
    /// grants.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    /// - [`DomainError::Forbidden`] when the role grants more than `editor`
    ///   holds.
    pub fn ensure_editable_by(&self, editor: &HeldByGranter<'_>) -> Result<(), DomainError> {
        editor.ensure_controls(SystemPermission::Roles(RoleAction::Update), &self.grants())
    }

    /// How the audit trail names this role: its name when the record was
    /// made, kept after the role is renamed or gone.
    pub(crate) fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }

    /// Sets `updated_at` to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

/// Refuses making a role go to every new user, unless `granter` may update
/// users. A manual role needs nothing.
fn ensure_may_make_default(
    assignment: DefaultAssignment,
    granter: &HeldByGranter<'_>,
) -> Result<(), DomainError> {
    match assignment {
        DefaultAssignment::NewUsers => {
            granter.ensure_holds(SystemPermission::Users(UserAction::Update))
        }
        DefaultAssignment::Manual => Ok(()),
    }
}

impl<T: TenantScope> Raises for Role<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// The system permissions a set of roles grants together, each named once.
///
/// This is what a caller holds across all their roles.
#[must_use]
pub fn effective_permissions<T: TenantScope>(roles: &[Role<T>]) -> Vec<SystemPermission> {
    let mut perms = Vec::new();
    for role in roles {
        for perm in role.system_permissions() {
            if !perms.contains(perm) {
                perms.push(*perm);
            }
        }
    }
    perms
}

/// A role is a tenant-scoped aggregate root that owns its permissions.
impl<T: TenantScope> Aggregate for Role<T> {
    /// A [`RoleId`].
    type Id = RoleId;

    /// The role's id.
    fn id(&self) -> &Self::Id {
        &self.id
    }

    /// When this role was created.
    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this role last changed.
    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

impl<T: TenantScope> crate::domains::identity::sealed::Sealed for Role<T> {}

impl<'g, T: TenantScope>
    crate::domains::identity::invitations::invited_role::InvitedRole<T, HeldByGranter<'g>>
    for Role<T>
{
    fn invited_role_id(&self) -> RoleId {
        self.id
    }

    fn ensure_offered_by(&self, inviter: &HeldByGranter<'g>) -> Result<(), DomainError> {
        inviter.ensure_holds(SystemPermission::Users(UserAction::Create))?;
        inviter.ensure_may_give(&self.grants())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::role::permission_moves::{
        PermissionsMoved, WantedPermissions,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};

    fn admin_role() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("admin"),
            system_permissions: vec![
                SystemPermission::ManageUsers,
                SystemPermission::ManageRoles,
                SystemPermission::ViewAuditLog,
            ],
            custom_permissions: vec![
                CustomPermission::new("project", "read").unwrap(),
                CustomPermission::new("project", "write").unwrap(),
                CustomPermission::new("billing", "admin").unwrap(),
            ],
            assignment: DefaultAssignment::Manual,
        })
    }

    fn viewer_role() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("viewer"),
            system_permissions: vec![],
            custom_permissions: vec![
                CustomPermission::new("project", "read").unwrap(),
                CustomPermission::new("dashboard", "read").unwrap(),
            ],
            assignment: DefaultAssignment::NewUsers,
        })
    }

    /// Someone who holds every built-in permission, so may escalate too.
    /// Only the rule being tested limits them.
    fn owner() -> HeldByGranter<'static> {
        HeldByGranter::assumed(SystemPermission::all(), &[])
    }

    /// Sam, who may edit roles and nothing else.
    fn role_editor() -> HeldByGranter<'static> {
        HeldByGranter::assumed(&[SystemPermission::Roles(RoleAction::Update)], &[])
    }

    fn custom(resource: &str, action: &str) -> CustomPermission {
        CustomPermission::new(resource, action).unwrap()
    }

    /// A change to exactly `system`, keeping the custom permissions.
    fn system_only(system: &[SystemPermission]) -> WantedPermissions<'_> {
        WantedPermissions {
            system: Some(system),
            custom: None,
        }
    }

    /// A change to exactly `custom`, keeping the system permissions.
    fn custom_only(custom: &[CustomPermission]) -> WantedPermissions<'_> {
        WantedPermissions {
            system: None,
            custom: Some(custom),
        }
    }

    /// The admin role is set up with three built-in and three app
    /// permissions. It keeps all six and is not given to new users.
    #[test]
    fn create_role_with_both_permission_types() {
        let role = admin_role();

        assert_eq!(role.name().as_str(), "admin");
        assert_eq!(role.system_permissions().len(), 3);
        assert_eq!(role.custom_permissions().len(), 3);
        assert!(!role.is_default());
    }

    /// The viewer role goes to every new user and holds only two app
    /// permissions. It has no built-in permissions.
    #[test]
    fn create_default_role_with_no_system_permissions() {
        let role = viewer_role();

        assert!(role.is_default());
        assert!(role.system_permissions().is_empty());
        assert_eq!(role.custom_permissions().len(), 2);
    }

    /// The admin role holds "manage users" and "manage roles". A check for
    /// either passes.
    #[test]
    fn has_system_permission_granted() {
        let role = admin_role();
        assert!(role.has_system_permission(SystemPermission::ManageUsers));
        assert!(role.has_system_permission(SystemPermission::ManageRoles));
    }

    /// The admin role does not hold "manage branding". A check for it fails.
    #[test]
    fn lacks_system_permission_not_granted() {
        let role = admin_role();
        assert!(!role.has_system_permission(SystemPermission::ManageBranding));
    }

    /// The viewer role holds only app permissions. A check for any area's
    /// widest built-in permission fails.
    #[test]
    fn viewer_has_no_system_permissions() {
        let role = viewer_role();
        for perm in SystemPermission::all() {
            assert!(!role.has_system_permission(*perm));
        }
    }

    /// The admin role holds `project:read`. A check for it passes, and one
    /// for `invoice:read` fails.
    #[test]
    fn has_custom_permission_exact_match() {
        let role = admin_role();
        assert!(role.has_custom_permission("project", "read"));
        assert!(!role.has_custom_permission("invoice", "read"));
    }

    /// A role holds `project:*`. It passes a check for `project:read` and
    /// fails one for `billing:read`.
    #[test]
    fn custom_permission_wildcard_action() {
        let role = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("project-admin"),
            system_permissions: vec![],
            custom_permissions: vec![CustomPermission::new("project", "*").unwrap()],
            assignment: DefaultAssignment::Manual,
        });
        assert!(role.has_custom_permission("project", "read"));
        assert!(!role.has_custom_permission("billing", "read"));
    }

    /// A role holds no permissions at all. Checks for "manage users" and for
    /// `project:read` both fail.
    #[test]
    fn empty_permissions_grants_nothing() {
        let role = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("empty"),
            system_permissions: vec![],
            custom_permissions: vec![],
            assignment: DefaultAssignment::Manual,
        });
        assert!(!role.has_system_permission(SystemPermission::ManageUsers));
        assert!(!role.has_custom_permission("project", "read"));
    }

    /// An owner adds "view audit log" to the viewer role. The role then
    /// passes a check for it.
    #[test]
    fn granting_a_system_permission_takes_effect() {
        let mut role = viewer_role();

        role.change_permissions(&system_only(&[SystemPermission::ViewAuditLog]), &owner())
            .unwrap();

        assert!(role.has_system_permission(SystemPermission::ViewAuditLog));
    }

    /// A role editor lacking the added rights cannot grant user management or
    /// invoice refunds, or make the admin role a default. User management stays
    /// absent from the empty role and the admin role stays manual.
    #[test]
    fn widening_a_role_takes_holding_what_it_adds() {
        let granter = role_editor();
        let mut role = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("empty"),
            system_permissions: vec![],
            custom_permissions: vec![],
            assignment: DefaultAssignment::Manual,
        });
        let mut admin = admin_role();

        let system = role
            .change_permissions(&system_only(&[SystemPermission::ManageUsers]), &granter)
            .map(drop);
        let app = role
            .change_permissions(&custom_only(&[custom("invoice", "refund")]), &granter)
            .map(drop);
        let default = admin.change_default_assignment(DefaultAssignment::NewUsers, &granter);

        for refused in [system, app, default] {
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
        assert!(!role.has_system_permission(SystemPermission::ManageUsers));
        assert!(!admin.is_default());
    }

    /// A role editor without the admin role's rights cannot remove its
    /// permissions or change its default-assignment setting. User management
    /// and all three custom permissions remain.
    #[test]
    fn narrowing_a_role_takes_holding_all_it_grants() {
        let sam = role_editor();
        let mut admin = admin_role();

        let revoked = admin
            .change_permissions(
                &system_only(&[
                    SystemPermission::ManageRoles,
                    SystemPermission::ViewAuditLog,
                ]),
                &sam,
            )
            .map(drop);
        let cut = admin.change_permissions(&custom_only(&[]), &sam).map(drop);
        let manual = admin.change_default_assignment(DefaultAssignment::Manual, &sam);

        for refused in [revoked, cut, manual] {
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
        assert!(admin.has_system_permission(SystemPermission::ManageUsers));
        assert_eq!(admin.custom_permissions().len(), 3);
    }

    /// A role editor without the admin role's rights cannot remove its billing
    /// administration permission. The role keeps that permission after refusal.
    #[test]
    fn taking_an_app_permission_off_a_role_takes_holding_all_it_grants() {
        let sam = role_editor();
        let mut admin = admin_role();
        let result = admin.change_permissions(
            &custom_only(&[custom("project", "read"), custom("project", "write")]),
            &sam,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(admin.has_custom_permission("billing", "admin"));
    }

    /// User management covers viewing users, but does not permit adding that
    /// permission to an empty role without the right to update roles.
    #[test]
    fn changing_a_role_needs_the_right_to_update_roles() {
        let bob = HeldByGranter::assumed(&[SystemPermission::ManageUsers], &[]);
        let mut role = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("empty"),
            system_permissions: vec![],
            custom_permissions: vec![],
            assignment: DefaultAssignment::Manual,
        });

        let result = role.change_permissions(
            &system_only(&[SystemPermission::Users(UserAction::View)]),
            &bob,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An owner cuts the admin role down to `project:read` and makes it
    /// manual. Both take effect.
    #[test]
    fn an_owner_narrows_a_role() {
        let mut admin = admin_role();

        admin
            .change_permissions(&custom_only(&[custom("project", "read")]), &owner())
            .unwrap();
        admin
            .change_default_assignment(DefaultAssignment::Manual, &owner())
            .unwrap();

        assert_eq!(admin.custom_permissions().len(), 1);
        assert!(!admin.is_default());
    }

    /// An admin takes "manage users" off the admin role. The role then fails
    /// a check for it.
    #[test]
    fn revoking_a_system_permission_takes_effect() {
        let mut role = admin_role();

        role.change_permissions(
            &system_only(&[
                SystemPermission::ManageRoles,
                SystemPermission::ViewAuditLog,
            ]),
            &owner(),
        )
        .unwrap();

        assert!(!role.has_system_permission(SystemPermission::ManageUsers));
    }

    /// An owner adds `invoice:read` to the viewer role. The role then passes
    /// a check for it.
    #[test]
    fn granting_a_custom_permission_takes_effect() {
        let mut role = viewer_role();

        role.change_permissions(
            &custom_only(&[
                custom("project", "read"),
                custom("dashboard", "read"),
                custom("invoice", "read"),
            ]),
            &owner(),
        )
        .unwrap();

        assert!(role.has_custom_permission("invoice", "read"));
    }

    /// An admin takes `billing:admin` off the admin role. The role then fails
    /// a check for it.
    #[test]
    fn revoking_a_custom_permission_takes_effect() {
        let mut role = admin_role();

        role.change_permissions(
            &custom_only(&[custom("project", "read"), custom("project", "write")]),
            &owner(),
        )
        .unwrap();

        assert!(!role.has_custom_permission("billing", "admin"));
    }

    /// An admin renames the admin role to "super-admin". The role reports
    /// the new name.
    #[test]
    fn rename_updates_name() {
        let mut role = admin_role();
        role.rename(
            label("super-admin"),
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();
        assert_eq!(role.name().as_str(), "super-admin");
    }

    /// Ann may update roles only through a break-glass grant during an
    /// incident. Renaming hands nothing out, so she renames the admin role.
    /// Sam's grant lets him only view roles, and his rename is refused.
    #[test]
    fn a_break_glass_grant_counts_for_renaming_a_role() {
        let mut role = admin_role();
        let ann = TenantAuthority::in_emergency(&[SystemPermission::Roles(RoleAction::Update)]);
        let sam = TenantAuthority::in_emergency(&[SystemPermission::Roles(RoleAction::View)]);

        role.rename(label("incident-admin"), ann).unwrap();
        let by_sam = role.rename(label("sams-admin"), sam);

        assert_eq!(role.name().as_str(), "incident-admin");
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
    }

    /// An owner makes the viewer role go to new users, then makes it manual.
    /// Each change shows.
    #[test]
    fn the_default_assignment_toggles() {
        let mut role = viewer_role();
        role.change_default_assignment(DefaultAssignment::NewUsers, &owner())
            .unwrap();
        assert!(role.is_default());
        role.change_default_assignment(DefaultAssignment::Manual, &owner())
            .unwrap();
        assert!(!role.is_default());
    }

    /// Role deletion and user viewing do not permit deleting the admin role
    /// without holding its rights. An owner holding those rights may delete it.
    #[test]
    fn only_someone_holding_all_a_role_grants_deletes_it() {
        let sam = HeldByGranter::assumed(
            &[
                SystemPermission::Roles(RoleAction::Delete),
                SystemPermission::Users(UserAction::View),
            ],
            &[],
        );
        let mut admin = admin_role();

        assert!(matches!(admin.delete(&sam), Err(DomainError::Forbidden(_))));
        assert!(admin.delete(&owner()).is_ok());
    }

    /// A stored admin role is read back. Its id, name, permissions, default
    /// flag and times come back as stored.
    #[test]
    fn reconstitute_role_preserves_all_fields() {
        let id = RoleId::new();
        let now = crate::shared::clock::now();
        let sys = vec![SystemPermission::ManageUsers];
        let custom = vec![CustomPermission::new("project", "read").unwrap()];

        let role = Role::<ResolvedTenant>::reconstitute(RoleRow {
            id,
            name: label("admin"),
            system_permissions: sys.clone(),
            custom_permissions: custom.clone(),
            is_default: DefaultAssignment::NewUsers,
            created_at: now,
            updated_at: now,
        })
        .unwrap();

        assert_eq!(*role.id(), id);
        assert_eq!(role.name().as_str(), "admin");
        assert_eq!(role.system_permissions(), &sys);
        assert!(role.is_default());
        assert_eq!(role.created_at(), now);
        assert_eq!(role.updated_at(), now);
    }

    /// An admin takes "manage roles" and `project:write` off the admin role.
    /// Only those two go, and the other permissions stay in order.
    #[test]
    fn revoking_a_permission_removes_that_one_and_leaves_the_rest() {
        let mut role = admin_role();

        role.change_permissions(
            &WantedPermissions {
                system: Some(&[
                    SystemPermission::ManageUsers,
                    SystemPermission::ViewAuditLog,
                ]),
                custom: Some(&[custom("project", "read"), custom("billing", "admin")]),
            },
            &owner(),
        )
        .unwrap();

        assert_eq!(
            role.system_permissions(),
            &[
                SystemPermission::ManageUsers,
                SystemPermission::ViewAuditLog
            ]
        );
        assert_eq!(
            role.custom_permissions(),
            &[
                CustomPermission::new("project", "read").unwrap(),
                CustomPermission::new("billing", "admin").unwrap(),
            ]
        );
    }

    /// An owner replaces the admin role's app permissions with
    /// `report:export`. The role then holds exactly it.
    #[test]
    fn replacing_the_custom_permissions_takes_effect() {
        let mut role = admin_role();

        role.change_permissions(&custom_only(&[custom("report", "export")]), &owner())
            .unwrap();

        assert_eq!(
            role.custom_permissions(),
            &[CustomPermission::new("report", "export").unwrap()]
        );
    }

    /// A caller holds the admin and viewer roles. Their built-in permissions
    /// include "manage users" and "view audit log", each listed once.
    #[test]
    fn the_effective_permissions_are_the_union_of_every_role() {
        let roles = vec![admin_role(), viewer_role()];

        let effective = effective_permissions(&roles);

        assert!(effective.contains(&SystemPermission::ManageUsers));
        assert!(effective.contains(&SystemPermission::ViewAuditLog));
        assert_eq!(
            effective
                .iter()
                .filter(|p| **p == SystemPermission::ViewAuditLog)
                .count(),
            1,
            "a permission held by two roles appears once"
        );
    }

    /// A role keeps the id it was made with, through both id getters.
    /// Renaming it five minutes later moves its update time and leaves its
    /// creation time alone.
    #[test]
    fn a_role_carries_its_id_and_moves_its_timestamp_when_edited() {
        let id = RoleId::new();
        let mut role = Role::<ResolvedTenant>::provisioned(NewRole {
            id,
            name: label("admin"),
            system_permissions: Vec::new(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });
        let created = role.created_at();
        let later = role.updated_at() + time::Duration::minutes(5);

        assert_eq!(*role.id(), id);
        assert_eq!(Aggregate::id(&role), role.id());

        let _frozen = crate::shared::clock::freeze(later);
        role.rename(
            label("administrator"),
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();

        assert_eq!(role.updated_at(), later);
        assert_eq!(role.created_at(), created);
    }

    /// Role creation is refused when the proposed role grants user management
    /// and its creator holds only the right to create roles.
    #[test]
    fn a_role_starts_only_with_what_its_creator_holds() {
        let granter = HeldByGranter::assumed(&[SystemPermission::Roles(RoleAction::Create)], &[]);

        let result = Role::<ResolvedTenant>::create(
            NewRole {
                id: RoleId::new(),
                name: label("ops"),
                system_permissions: vec![SystemPermission::ManageUsers],
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::Manual,
            },
            &granter,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A user manager cannot create a role granting user viewing without also
    /// holding the right to create roles.
    #[test]
    fn creating_a_role_needs_the_right_to_create_roles() {
        let bob = HeldByGranter::assumed(&[SystemPermission::ManageUsers], &[]);

        let result = Role::<ResolvedTenant>::create(
            NewRole {
                id: RoleId::new(),
                name: label("ops"),
                system_permissions: vec![SystemPermission::Users(UserAction::View)],
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::Manual,
            },
            &bob,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Creating a role assigned to every new user is refused when its creator
    /// can create roles and view users but cannot update users.
    #[test]
    fn a_role_for_every_new_user_needs_the_right_to_update_users() {
        let sam = HeldByGranter::assumed(
            &[
                SystemPermission::Roles(RoleAction::Create),
                SystemPermission::Users(UserAction::View),
            ],
            &[],
        );

        let result = Role::<ResolvedTenant>::create(
            NewRole {
                id: RoleId::new(),
                name: label("peek"),
                system_permissions: vec![SystemPermission::Users(UserAction::View)],
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::NewUsers,
            },
            &sam,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An owner creates "ops" with "manage users". The role is created and
    /// grants it.
    #[test]
    fn a_role_starts_with_what_its_creator_holds() {
        let role = Role::<ResolvedTenant>::create(
            NewRole {
                id: RoleId::new(),
                name: label("ops"),
                system_permissions: vec![SystemPermission::ManageUsers],
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::Manual,
            },
            &owner(),
        )
        .unwrap();

        assert!(role.has_system_permission(SystemPermission::ManageUsers));
    }

    fn stored(role: &Role<ResolvedTenant>) -> RoleRow {
        RoleRow {
            id: role.id,
            name: role.name.clone(),
            system_permissions: role.system_permissions.clone(),
            custom_permissions: role.custom_permissions.clone(),
            is_default: role.is_default,
            created_at: role.created_at,
            updated_at: role.updated_at,
        }
    }

    /// A role is set up with "manage users" twice. It holds it once, and the
    /// stored row reads back fine.
    #[test]
    fn a_role_names_each_permission_once_however_often_it_was_given() {
        let role = Role::<ResolvedTenant>::provisioned(NewRole {
            id: RoleId::new(),
            name: label("ops"),
            system_permissions: vec![SystemPermission::ManageUsers, SystemPermission::ManageUsers],
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });

        assert_eq!(role.system_permissions(), [SystemPermission::ManageUsers]);
        assert!(Role::<ResolvedTenant>::reconstitute(stored(&role)).is_ok());
    }

    /// A stored admin role lists "manage users" twice. Reading it back is
    /// refused as a corrupt row.
    #[test]
    fn a_stored_role_naming_a_permission_twice_is_refused() {
        let mut row = stored(&admin_role());
        row.system_permissions.push(SystemPermission::ManageUsers);

        assert!(refused_as_corrupt(&Role::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// The text a role event stores under `key`.
    fn field(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    /// The label a role event links the role under.
    fn role_label_of(event: &DomainEvent) -> String {
        match event.payload().value("role") {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("role is not a reference: {other:?}"),
        }
    }

    /// An owner creates "ops". The creation is raised, naming the role.
    #[test]
    fn creating_a_role_raises_authorization_role_created() {
        let mut role = Role::<ResolvedTenant>::create(
            NewRole {
                id: RoleId::new(),
                name: label("ops"),
                system_permissions: Vec::new(),
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::Manual,
            },
            &owner(),
        )
        .unwrap();

        let events = raised(&mut role);

        assert_eq!(
            events[0].event_type().to_string(),
            "authorization.role_created"
        );
        assert_eq!(role_label_of(&events[0]), "ops");
    }

    /// Ann renames the admin role to "super-admin", makes it go to every new
    /// user and deletes it. Each step is raised, in order, the rename under
    /// the new name.
    #[test]
    fn renaming_defaulting_and_deleting_are_raised_in_order() {
        let mut role = admin_role();

        role.rename(
            label("super-admin"),
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();
        role.change_default_assignment(DefaultAssignment::NewUsers, &owner())
            .unwrap();
        role.delete(&owner()).unwrap();
        let events = raised(&mut role);

        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "authorization.role_renamed",
                "authorization.role_default_assignment_changed",
                "authorization.role_deleted",
            ]
        );
        assert_eq!(role_label_of(&events[0]), "super-admin");
    }

    /// Ann gives the admin role the name it has and keeps it manual. Nothing
    /// changes, so nothing is raised.
    #[test]
    fn a_change_to_what_the_role_already_is_raises_nothing() {
        let mut role = admin_role();

        role.rename(label("admin"), anyone_holding(SystemPermission::all()))
            .unwrap();
        role.change_default_assignment(DefaultAssignment::Manual, &owner())
            .unwrap();

        assert!(raised_names(&mut role).is_empty());
    }

    /// Ann saves the viewer role with "view audit log" and `invoice:read`
    /// added and `dashboard:read` dropped. One grant is raised per kind, then
    /// one revoke, and the change is a narrowing.
    #[test]
    fn changing_permissions_raises_one_event_per_kind_and_direction() {
        let mut role = viewer_role();
        let custom = [
            CustomPermission::new("project", "read").unwrap(),
            CustomPermission::new("invoice", "read").unwrap(),
        ];

        let moved = role
            .change_permissions(
                &WantedPermissions {
                    system: Some(&[SystemPermission::ViewAuditLog]),
                    custom: Some(&custom),
                },
                &owner(),
            )
            .unwrap();
        let events = raised(&mut role);

        assert_eq!(moved, PermissionsMoved::Narrowed);
        let shapes: Vec<(String, String)> = events
            .iter()
            .map(|e| (e.event_type().to_string(), field(e, "permission_type")))
            .collect();
        assert_eq!(
            shapes,
            [
                ("authorization.permission_granted", "system"),
                ("authorization.permission_granted", "custom"),
                ("authorization.permission_revoked", "custom"),
            ]
            .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
        );
        assert_eq!(field(&events[2], "permissions"), "dashboard:read");
    }

    /// Ann saves the viewer role with the permissions it holds. Nothing moves
    /// and nothing is raised, even for Sam, who could not have changed it.
    #[test]
    fn asking_for_what_a_role_holds_moves_nothing() {
        let mut role = viewer_role();
        let held = role.custom_permissions().to_vec();

        let moved = role
            .change_permissions(
                &WantedPermissions {
                    system: None,
                    custom: Some(&held),
                },
                &role_editor(),
            )
            .unwrap();

        assert_eq!(moved, PermissionsMoved::Nothing);
        assert!(raised_names(&mut role).is_empty());
    }

    /// Removing the admin role's rights without holding them, deleting it
    /// without deletion authority, and renaming it with viewing authority are
    /// all refused. None of these attempts raises an event.
    #[test]
    fn a_refused_role_change_raises_nothing() {
        let mut admin = admin_role();
        let sam = role_editor();

        let stripped = admin.change_permissions(
            &WantedPermissions {
                system: Some(&[]),
                custom: None,
            },
            &sam,
        );
        let deleted = admin.delete(&sam);
        let renamed = admin.rename(
            label("sams"),
            anyone_holding(&[SystemPermission::Roles(RoleAction::View)]),
        );

        assert!(stripped.is_err());
        assert!(deleted.is_err());
        assert!(renamed.is_err());
        assert!(raised_names(&mut admin).is_empty());
    }

    /// The admin role is read back from storage. Reading it raises nothing.
    #[test]
    fn a_role_read_back_from_storage_has_raised_nothing() {
        let mut role = Role::<ResolvedTenant>::reconstitute(stored(&admin_role())).unwrap();

        assert!(raised_names(&mut role).is_empty());
    }
}
