//! Groups: named sets of members that share roles.
//!
//! A tenant puts its members into teams, departments or projects. Every
//! member holds the roles given to their group. Groups can be nested, and a
//! child group holds its parent's roles as well as its own.
//!
//! Shaping groups needs the role rights the API names: creating one needs
//! the right to create roles, renaming or moving one the right to update
//! them, deleting one the right to delete them, and giving out roles or
//! members the right to assign them.

mod membership;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::directory::TenantDirectory;
use crate::domains::authorization::events::groups::{
    GroupCreated, GroupDeleted, GroupMoved, GroupRenamed, GroupRoleAssigned, GroupRoleUnassigned,
    NestedUnder,
};
use crate::domains::authorization::granter::HeldByGranter;
pub(crate) use crate::domains::authorization::group::membership::ensure_joined_automatically;
pub use crate::domains::authorization::group::membership::{GroupMembership, GroupMembershipRow};
use crate::domains::authorization::group_tree::{Conferred, GroupTree};
use crate::domains::authorization::permission::{RoleAction, SystemPermission};
use crate::domains::authorization::role::Role;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{EventLabel, GroupId, Label, RoleId};

/// Where a group sits in the tree: at the top, or under a parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPlace {
    /// A root of the tree.
    TopLevel,
    /// Under this group, inheriting its roles.
    Under(GroupId),
}

impl GroupPlace {
    /// The place a stored parent column records. No parent means the top.
    #[must_use]
    pub fn from_stored(parent: Option<GroupId>) -> Self {
        parent.map_or(Self::TopLevel, Self::Under)
    }

    /// The parent, when there is one. This is the value storage keeps.
    #[must_use]
    pub fn parent(&self) -> Option<&GroupId> {
        match self {
            Self::TopLevel => None,
            Self::Under(parent) => Some(parent),
        }
    }
}

/// Who keeps a group's members: the tenant's directory, or people in the
/// dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOrigin {
    /// The tenant's directory keeps it, through SCIM provisioning.
    Directory,
    /// People with the right to manage groups keep it in the dashboard.
    Dashboard,
}

impl GroupOrigin {
    /// The name stored for the origin.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Dashboard => "dashboard",
        }
    }

    /// Reads a stored origin.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored name is not one of
    ///   the known names. The row is corrupt, not the caller's input.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "directory" => Ok(Self::Directory),
            "dashboard" => Ok(Self::Dashboard),
            _ => Err(DomainError::corrupt_row("group", "an unknown origin")),
        }
    }
}

/// A group within a tenant.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// Groups form a tree, and each group has at most one parent. A child
/// group holds its parent's roles. "Backend" sits under "Engineering", so a
/// user in Backend gets the roles of both.
///
/// A group is kept either by the tenant's directory or in the dashboard,
/// its [`GroupOrigin`]. The directory adds members only to its own groups.
#[derive(Debug)]
pub struct Group<T: TenantScope> {
    /// The group's id.
    id: GroupId,
    /// Group name, unique within the tenant.
    name: Label,
    /// Who keeps its members.
    origin: GroupOrigin,
    /// Where the group sits in the tree: at the top, or under a parent.
    place: GroupPlace,
    /// Roles directly assigned to this group.
    role_ids: Vec<RoleId>,
    /// When this group was created.
    created_at: OffsetDateTime,
    /// When this group last changed.
    updated_at: OffsetDateTime,
    /// What the group raised since it was last saved.
    raised: Raised<T>,
    /// Which plane this belongs to (see [`crate::isolation`]).
    _scope: PhantomData<T>,
}

/// What a new group is created with.
pub struct CreateGroupParams {
    /// Group name, unique within the tenant.
    pub name: Label,
    /// Who keeps its members.
    pub origin: GroupOrigin,
    /// Where the group sits: at the top, or under a parent.
    pub place: GroupPlace,
}

/// A [`Group`] as storage holds it, read back through [`Group::reconstitute`].
pub struct GroupRow {
    /// The group's id.
    pub id: GroupId,
    /// The group's name.
    pub name: Label,
    /// Who keeps its members.
    pub origin: GroupOrigin,
    /// Where the group sits in the tree.
    pub place: GroupPlace,
    /// Roles directly assigned to this group.
    pub role_ids: Vec<RoleId>,
    /// When this group was created.
    pub created_at: OffsetDateTime,
    /// When this group last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> Group<T> {
    /// Creates a group beneath its chosen parent, inheriting `inherited` permissions.
    /// Raises `authorization.group_created`, naming that parent.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without role-creation rights, for inherited permissions
    /// computed for another parent, or when the granter cannot delegate all of them.
    pub fn create(
        params: CreateGroupParams,
        inherited: &Conferred,
        granter: &HeldByGranter<'_>,
    ) -> Result<Self, DomainError> {
        granter.ensure_holds(SystemPermission::Roles(RoleAction::Create))?;
        inherited.ensure_for(params.place)?;
        granter.ensure_may_give(&inherited.handout())?;
        Ok(Self::fresh(params, inherited.parent().clone()))
    }

    /// Creates a group the tenant's directory keeps, because `directory`
    /// says so, through SCIM provisioning. Raises
    /// `authorization.group_created`, at the top of the tree.
    ///
    /// No person in the tenant creates it, so no granter is checked. The
    /// directory must be the one the tenant switched on. The group sits at
    /// the top and holds no roles, so it brings nothing. Giving it roles, or
    /// moving it under a group that holds some, is done by a person through
    /// [`Self::assign_role`] or [`Self::move_under`], each checked there.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the tenant switched `directory`
    ///   off.
    pub fn from_directory(
        name: Label,
        directory: &impl TenantDirectory<T>,
    ) -> Result<Self, DomainError> {
        directory.ensure_speaks()?;
        let params = CreateGroupParams {
            name,
            origin: GroupOrigin::Directory,
            place: GroupPlace::TopLevel,
        };
        Ok(Self::fresh(params, NestedUnder::TopLevel))
    }

    /// A new group from `params`, sitting where `parent` names, with its
    /// creation raised.
    fn fresh(params: CreateGroupParams, parent: NestedUnder) -> Self {
        let now = crate::shared::clock::now();
        let mut group = Self {
            id: GroupId::new(),
            name: params.name,
            origin: params.origin,
            place: params.place,
            role_ids: Vec::new(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        group.raised.raise(GroupCreated {
            group_id: group.id,
            name: group.name.clone(),
            parent,
            occurred_at: now,
        });
        group
    }

    /// Rebuilds a group from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row places the group under
    ///   itself.
    /// - [`DomainError::Infrastructure`] when it assigns a role twice.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: GroupRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            origin: row.origin,
            place: row.place,
            role_ids: row.role_ids,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &GroupRow) -> Result<(), DomainError> {
        RowCheck::of("group")
            .holds(
                row.place != GroupPlace::Under(row.id),
                "a group under itself",
            )
            .holds(
                first_repeat(&row.role_ids).is_none(),
                "a role assigned twice",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The group's id.
    #[must_use]
    pub fn id(&self) -> &GroupId {
        &self.id
    }

    /// The group's name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Who keeps the group's members.
    #[must_use]
    pub fn origin(&self) -> GroupOrigin {
        self.origin
    }

    /// Where the group sits in the tree: at the top, or under a parent.
    #[must_use]
    pub fn place(&self) -> &GroupPlace {
        &self.place
    }

    /// Whether this group has no parent.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.place == GroupPlace::TopLevel
    }

    /// Roles directly assigned to this group.
    #[must_use]
    pub fn role_ids(&self) -> &[RoleId] {
        &self.role_ids
    }

    /// When this group was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this group last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Renames the group for `editor`. Raises `authorization.group_renamed`
    /// with the name it had and the one it has now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    pub fn rename(&mut self, name: Label, editor: &HeldByGranter<'_>) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Update))?;
        self.apply_name(name);
        Ok(())
    }

    /// Moves this group from where it sits, which brings `current`, to the
    /// place `inherited` was worked out for. Raises
    /// `authorization.group_moved`, naming the group it left and the one it
    /// went under.
    ///
    /// Every member loses what the place it leaves brings. That is
    /// `current`, and only someone who could have given it takes it away.
    /// Backend sits under "Admins", which holds the admin role. Sam may
    /// update roles. Without this, he moves Backend to the top and every
    /// member of it loses the admin role.
    ///
    /// Every member then holds what the new place brings. That is
    /// `inherited`, and `granter` must be able to hand all of it out.
    ///
    /// The group may not go under itself, or under any group below it.
    /// `inherited` names every group above the new place, so a move that
    /// would close a loop is seen here.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `current` was worked out for another
    ///   place than the one the group sits in.
    /// - [`DomainError::Forbidden`] if `granter` may not update roles, or
    ///   may not hand out what the place it leaves brings.
    /// - [`DomainError::Validation`] if the new place is under this group
    ///   itself, or under one of its subgroups.
    /// - [`DomainError::Forbidden`] if `granter` may not hand out what the
    ///   members would inherit.
    pub fn move_under(
        &mut self,
        current: &Conferred,
        inherited: &Conferred,
        granter: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        current.ensure_for(self.place)?;
        granter.ensure_controls(
            SystemPermission::Roles(RoleAction::Update),
            &current.handout(),
        )?;
        if inherited.lineage().contains(&self.id) {
            return Err(DomainError::invalid(message!(
                "authorization-a-group-cannot-sit-under-itself",
                "a group cannot sit under itself or one of its subgroups"
            )));
        }
        granter.ensure_may_give(&inherited.handout())?;
        self.place = inherited.place();
        self.touch();
        self.raised.raise(GroupMoved {
            group_id: self.id,
            group_label: self.label(),
            from: current.parent().clone(),
            to: inherited.parent().clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Gives this group `role`. Raises `authorization.group_role_assigned`.
    ///
    /// Members of this group, and of the groups under it, gain all the role
    /// grants. So `granter` must be able to hand all of it out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `granter` may not assign roles.
    /// - [`DomainError::Forbidden`] if `granter` may not hand out what the
    ///   role grants.
    pub fn assign_role(
        &mut self,
        role: &Role<T>,
        granter: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        granter.ensure_holds(SystemPermission::Roles(RoleAction::Assign))?;
        granter.ensure_may_give(&role.grants())?;
        if !self.role_ids.contains(role.id()) {
            self.role_ids.push(*role.id());
            self.touch();
        }
        self.raised.raise(GroupRoleAssigned {
            group_id: self.id,
            group_label: self.label(),
            role_id: *role.id(),
            role_label: EventLabel::of(role.name().as_str()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Takes `role` away from this group. Raises
    /// `authorization.group_role_unassigned`.
    ///
    /// Only someone who could have given the role takes it away. Sam may
    /// assign roles and view users. Without this, he takes the admin role
    /// off "Admins" and every admin loses their rights.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `granter` may not assign roles, or
    ///   may not hand out what the role grants.
    pub fn unassign_role(
        &mut self,
        role: &Role<T>,
        granter: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        granter.ensure_controls(SystemPermission::Roles(RoleAction::Assign), &role.grants())?;
        let before = self.role_ids.len();
        self.role_ids.retain(|id| id != role.id());
        if self.role_ids.len() != before {
            self.touch();
        }
        self.raised.raise(GroupRoleUnassigned {
            group_id: self.id,
            group_label: self.label(),
            role_id: *role.id(),
            role_label: EventLabel::of(role.name().as_str()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Deletes this group once `granter` may. Raises
    /// `authorization.group_deleted`, taken once the group is removed from
    /// storage.
    ///
    /// Members lose all the group brings, `conferred`, so `granter` must be
    /// able to hand it out. A group with subgroups is kept: they would be
    /// left under a group that no longer exists.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `conferred` was worked out for
    ///   another group.
    /// - [`DomainError::Forbidden`] if `granter` may not delete roles, or may
    ///   not hand out what the group brings.
    /// - [`DomainError::Conflict`] if another group sits under this one.
    pub fn delete(
        &mut self,
        tree: &GroupTree<'_, T>,
        conferred: &Conferred,
        granter: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        conferred.ensure_for(GroupPlace::Under(self.id))?;
        granter.ensure_controls(
            SystemPermission::Roles(RoleAction::Delete),
            &conferred.handout(),
        )?;
        self.ensure_no_subgroups(tree)?;
        self.raise_deleted();
        Ok(())
    }

    /// Renames a directory-owned group through the tenant's enabled SCIM connection.
    /// No person's grant is checked. Raises `authorization.group_renamed`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the directory is off or the group is dashboard-owned.
    pub fn rename_by_directory(
        &mut self,
        name: Label,
        directory: &impl TenantDirectory<T>,
    ) -> Result<(), DomainError> {
        directory.ensure_speaks()?;
        self.ensure_kept_by_directory()?;
        self.apply_name(name);
        Ok(())
    }

    /// Deletes a directory-owned group without subgroups through enabled SCIM.
    /// Raises `authorization.group_deleted`, taken after storage removes the group.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the directory is off or the group is dashboard-owned.
    /// [`DomainError::Conflict`] if another group sits beneath it.
    pub fn delete_by_directory(
        &mut self,
        tree: &GroupTree<'_, T>,
        directory: &impl TenantDirectory<T>,
    ) -> Result<(), DomainError> {
        directory.ensure_speaks()?;
        self.ensure_kept_by_directory()?;
        self.ensure_no_subgroups(tree)?;
        self.raise_deleted();
        Ok(())
    }

    /// How the audit trail names this group: its name, copied into each
    /// event so the entry stays readable once the group is gone.
    pub(crate) fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }

    /// Gives the group `name`, and raises the rename with the name it had.
    fn apply_name(&mut self, name: Label) {
        let old_name = std::mem::replace(&mut self.name, name);
        self.touch();
        self.raised.raise(GroupRenamed {
            group_id: self.id,
            old_name,
            new_name: self.name.clone(),
            occurred_at: self.updated_at,
        });
    }

    /// Raises the group's deletion.
    fn raise_deleted(&mut self) {
        self.raised.raise(GroupDeleted {
            group_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Refuses a change while another group sits under this one.
    fn ensure_no_subgroups(&self, tree: &GroupTree<'_, T>) -> Result<(), DomainError> {
        if tree.has_subgroups(&self.id) {
            return Err(DomainError::conflict(message!(
                "authorization-move-or-delete-the-groups-under",
                "move or delete the groups under this one first"
            )));
        }
        Ok(())
    }

    /// Sets `updated_at` to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// Refuses a directory change to a group kept in the dashboard.
    fn ensure_kept_by_directory(&self) -> Result<(), DomainError> {
        match self.origin {
            GroupOrigin::Directory => Ok(()),
            GroupOrigin::Dashboard => Err(DomainError::forbidden(message!(
                "authorization-the-directory-changes-only-the-groups",
                "the directory changes only the groups it keeps"
            ))),
        }
    }
}

impl<T: TenantScope> Raises for Group<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::access_review::ReviewScope;
    use crate::domains::authorization::holding::NewHolding;
    use crate::domains::authorization::permission::UserAction;
    use crate::domains::authorization::review_removals::ReviewRemovals;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole};
    use crate::domains::federation::fixtures::{federation_admin, switched_on_directory};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{AccessReviewId, Expiry, PrincipalRef, UserId};

    fn engineering() -> Group<ResolvedTenant> {
        kept_by(GroupOrigin::Dashboard)
    }

    /// The name the application read for the member joining or leaving.
    fn member_label() -> EventLabel {
        EventLabel::of("ann@acme.test")
    }

    fn kept_by(origin: GroupOrigin) -> Group<ResolvedTenant> {
        Group::create(
            CreateGroupParams {
                name: label("Engineering"),
                origin,
                place: GroupPlace::TopLevel,
            },
            &Conferred::at_top(),
            &owner(),
        )
        .unwrap()
    }

    fn role_granting(system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("team"),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn a_role() -> Role<ResolvedTenant> {
        role_granting(vec![SystemPermission::Users(UserAction::View)])
    }

    /// Someone who holds every built-in permission.
    fn owner() -> HeldByGranter<'static> {
        HeldByGranter::assumed(SystemPermission::all(), &[])
    }

    /// Sam, who may assign, create and update roles and view users.
    fn sam() -> HeldByGranter<'static> {
        HeldByGranter::assumed(
            &[
                SystemPermission::Roles(RoleAction::Assign),
                SystemPermission::Roles(RoleAction::Create),
                SystemPermission::Roles(RoleAction::Update),
                SystemPermission::Users(UserAction::View),
            ],
            &[],
        )
    }

    fn give(group: &mut Group<ResolvedTenant>, role: &Role<ResolvedTenant>) {
        group.assign_role(role, &owner()).unwrap();
    }

    /// What sitting under `group` brings, read from `groups` and `roles`.
    fn under(
        group: &Group<ResolvedTenant>,
        groups: &[Group<ResolvedTenant>],
        roles: &[Role<ResolvedTenant>],
    ) -> Conferred {
        GroupTree::new(groups)
            .conferred(GroupPlace::Under(*group.id()), roles)
            .unwrap()
    }

    /// Engineering holding the admin role, as the only group, with that role.
    fn admins() -> (Vec<Group<ResolvedTenant>>, Vec<Role<ResolvedTenant>>) {
        let admin = role_granting(vec![SystemPermission::ManageUsers]);
        let mut group = engineering();
        give(&mut group, &admin);
        (vec![group], vec![admin])
    }

    /// Sam may assign and update roles but cannot grant user management.
    /// Giving his group the admin role or moving it beneath the admin group
    /// is refused. It remains at the top with no roles.
    #[test]
    fn a_group_gains_only_what_its_granter_may_hand_out() {
        let (groups, roles) = admins();
        let admin = &roles[0];
        let mut group = engineering();
        let inherited = under(&groups[0], &groups, &roles);

        let given = group.assign_role(admin, &sam());
        let moved = group.move_under(&Conferred::at_top(), &inherited, &sam());

        assert!(matches!(given, Err(DomainError::Forbidden(_))));
        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert!(group.role_ids().is_empty());
        assert!(group.is_root());
    }

    /// An admin moves Engineering under Engineering. It is refused and the
    /// group stays at the top, since a walk up the tree would never end.
    #[test]
    fn a_group_cannot_be_made_its_own_parent() {
        let groups = vec![engineering()];
        let inherited = under(&groups[0], &groups, &[]);
        let mut group = groups.into_iter().next().unwrap();

        let result = group.move_under(&Conferred::at_top(), &inherited, &owner());

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(group.is_root());
    }

    /// With Backend beneath Engineering, moving Engineering beneath Backend
    /// is refused as a cycle. Engineering remains at the top.
    #[test]
    fn a_group_cannot_be_moved_under_its_own_subgroup() {
        let mut parent = engineering();
        let mut backend = stored(&engineering());
        backend.id = GroupId::new();
        backend.place = GroupPlace::Under(*parent.id());
        let groups = vec![
            Group::reconstitute(stored(&parent)).unwrap(),
            Group::reconstitute(backend).unwrap(),
        ];
        let into_backend = under(&groups[1], &groups, &[]);

        let result = parent.move_under(&Conferred::at_top(), &into_backend, &owner());

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(parent.is_root());
    }

    /// Engineering holding the admin role, with Backend under it, and that
    /// role.
    fn backend_under_admins() -> (
        Vec<Group<ResolvedTenant>>,
        Vec<Role<ResolvedTenant>>,
        Group<ResolvedTenant>,
    ) {
        let (groups, roles) = admins();
        let backend = Group::create(
            CreateGroupParams {
                name: label("Backend"),
                origin: GroupOrigin::Dashboard,
                place: GroupPlace::Under(*groups[0].id()),
            },
            &under(&groups[0], &groups, &roles),
            &owner(),
        )
        .unwrap();
        (groups, roles, backend)
    }

    /// Backend inherits user management from Engineering. Sam may update
    /// roles but cannot grant that permission, so moving Backend to the top
    /// is refused and it remains beneath Engineering.
    #[test]
    fn a_group_leaves_a_place_only_for_someone_who_could_give_what_it_brings() {
        let (groups, roles, mut backend) = backend_under_admins();
        let leaving = under(&groups[0], &groups, &roles);

        let result = backend.move_under(&leaving, &Conferred::at_top(), &sam());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(backend.place(), &GroupPlace::Under(*groups[0].id()));
    }

    /// Backend cannot move using top-level permissions as proof of what it
    /// leaves behind. That proof names the wrong place, so the move is
    /// refused and Backend remains beneath Engineering.
    #[test]
    fn a_group_does_not_leave_with_what_another_place_brings() {
        let (groups, _, mut backend) = backend_under_admins();

        let result = backend.move_under(&Conferred::at_top(), &Conferred::at_top(), &sam());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(backend.place(), &GroupPlace::Under(*groups[0].id()));
    }

    /// Sam may create groups but cannot grant user management. Creating a
    /// directory group beneath Engineering is refused because it would
    /// inherit that permission.
    #[test]
    fn a_group_is_created_only_under_a_place_its_granter_could_give() {
        let (groups, roles) = admins();
        let inherited = under(&groups[0], &groups, &roles);

        let result = Group::<ResolvedTenant>::create(
            CreateGroupParams {
                name: label("Synced"),
                origin: GroupOrigin::Directory,
                place: GroupPlace::Under(*groups[0].id()),
            },
            &inherited,
            &sam(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Creating a group beneath Engineering is refused when the inherited
    /// permissions supplied were computed for the top of the tree.
    #[test]
    fn a_group_is_not_created_with_what_another_place_brings() {
        let (groups, _) = admins();

        let result = Group::<ResolvedTenant>::create(
            CreateGroupParams {
                name: label("Synced"),
                origin: GroupOrigin::Directory,
                place: GroupPlace::Under(*groups[0].id()),
            },
            &Conferred::at_top(),
            &sam(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// User-management rights alone do not permit creating or renaming
    /// groups or adding members. All three requests are refused, and
    /// Engineering keeps its name.
    #[test]
    fn shaping_groups_needs_a_role_right() {
        let bob = HeldByGranter::assumed(&[SystemPermission::ManageUsers], &[]);
        let mut group = engineering();

        let created = Group::<ResolvedTenant>::create(
            CreateGroupParams {
                name: label("Ops"),
                origin: GroupOrigin::Dashboard,
                place: GroupPlace::TopLevel,
            },
            &Conferred::at_top(),
            &bob,
        );
        let renamed = group.rename(label("Platform"), &bob);
        let joined = GroupMembership::join_until(
            NewHolding::standing(PrincipalRef::User(UserId::new()), member_label()),
            &group,
            &under(&group, std::slice::from_ref(&group), &[]),
            &bob,
        );

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert!(matches!(joined, Err(DomainError::Forbidden(_))));
        assert_eq!(group.name().as_str(), "Engineering");
    }

    /// A tenant creates "Engineering" with no parent. It sits at the top of
    /// the tree and holds no roles yet.
    #[test]
    fn create_root_group() {
        let group = engineering();
        assert_eq!(group.name().as_str(), "Engineering");
        assert!(group.is_root());
        assert!(group.role_ids().is_empty());
    }

    /// A tenant creates "Backend" under "Engineering". Backend is not a root
    /// and names Engineering as its parent.
    #[test]
    fn create_nested_group() {
        let parent = engineering();
        let child = Group::<ResolvedTenant>::create(
            CreateGroupParams {
                name: label("Backend"),
                origin: GroupOrigin::Dashboard,
                place: GroupPlace::Under(*parent.id()),
            },
            &under(&parent, std::slice::from_ref(&parent), &[]),
            &owner(),
        )
        .unwrap();

        assert!(!child.is_root());
        assert_eq!(child.place(), &GroupPlace::Under(*parent.id()));
    }

    /// An owner gives Engineering a role that lets members view users. The
    /// group then lists that one role.
    #[test]
    fn a_role_assigned_to_a_group_is_held_by_it() {
        let mut group = engineering();
        let role = a_role();

        give(&mut group, &role);

        assert_eq!(group.role_ids().len(), 1);
        assert!(group.role_ids().contains(role.id()));
    }

    /// An owner gives Engineering the same role twice. The group lists it
    /// once.
    #[test]
    fn assign_role_is_idempotent() {
        let mut group = engineering();
        let role = a_role();

        give(&mut group, &role);
        give(&mut group, &role);

        assert_eq!(group.role_ids().len(), 1);
    }

    /// An owner gives Engineering a role and then takes it away. The group
    /// holds no roles afterwards.
    #[test]
    fn an_unassigned_role_is_no_longer_held() {
        let mut group = engineering();
        let role = a_role();

        give(&mut group, &role);
        group.unassign_role(&role, &owner()).unwrap();

        assert!(group.role_ids().is_empty());
    }

    /// Sam may assign roles but cannot grant user management. Removing that
    /// permission's role from Engineering is refused, and the role remains.
    #[test]
    fn only_someone_who_could_give_a_role_takes_it_off_a_group() {
        let (mut groups, roles) = admins();

        let result = groups[0].unassign_role(&roles[0], &sam());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(groups[0].role_ids(), [*roles[0].id()]);
    }

    /// An admin renames Engineering to "Platform Engineering". The group
    /// reports the new name.
    #[test]
    fn a_renamed_group_shows_its_new_name() {
        let mut group = engineering();
        group
            .rename(label("Platform Engineering"), &owner())
            .unwrap();
        assert_eq!(group.name().as_str(), "Platform Engineering");
    }

    /// An owner moves Engineering under another group, then back to the
    /// top. Each move takes effect, ending with Engineering as a root.
    #[test]
    fn a_group_moves_under_a_parent_and_back_to_the_root() {
        let groups = vec![kept_by(GroupOrigin::Dashboard)];
        let new_parent = *groups[0].id();
        let into_parent = under(&groups[0], &groups, &[]);
        let mut group = engineering();

        group
            .move_under(&Conferred::at_top(), &into_parent, &owner())
            .unwrap();
        assert_eq!(group.place(), &GroupPlace::Under(new_parent));

        group
            .move_under(&into_parent, &Conferred::at_top(), &owner())
            .unwrap();
        assert!(group.is_root());
    }

    /// Deleting Engineering requires control of the user-management rights
    /// it grants. A caller with role-deletion and user-viewing rights is
    /// refused, while an owner is allowed to delete it.
    #[test]
    fn only_someone_who_could_give_what_a_group_brings_deletes_it() {
        let (groups, roles) = admins();
        let tree = GroupTree::new(&groups);
        let conferred = under(&groups[0], &groups, &roles);
        let deleter = HeldByGranter::assumed(
            &[
                SystemPermission::Roles(RoleAction::Delete),
                SystemPermission::Users(UserAction::View),
            ],
            &[],
        );

        let mut target = Group::reconstitute(stored(&groups[0])).unwrap();

        let by_sam = target.delete(&tree, &conferred, &deleter);
        let by_owner = target.delete(&tree, &conferred, &owner());

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_owner.is_ok());
    }

    /// Backend sits under Engineering. Deleting Engineering is refused as a
    /// conflict, so Backend is never left under a group that is gone.
    #[test]
    fn a_group_with_subgroups_is_not_deleted() {
        let parent = engineering();
        let child = Group::<ResolvedTenant>::create(
            CreateGroupParams {
                name: label("Backend"),
                origin: GroupOrigin::Dashboard,
                place: GroupPlace::Under(*parent.id()),
            },
            &under(&parent, std::slice::from_ref(&parent), &[]),
            &owner(),
        )
        .unwrap();
        let groups = vec![parent, child];
        let tree = GroupTree::new(&groups);
        let conferred = under(&groups[0], &groups, &[]);

        let mut parent = Group::reconstitute(stored(&groups[0])).unwrap();

        let result = parent.delete(&tree, &conferred, &owner());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    fn joined(
        member: PrincipalRef,
        group: &Group<ResolvedTenant>,
    ) -> GroupMembership<ResolvedTenant> {
        let conferred = under(group, std::slice::from_ref(group), &[]);
        GroupMembership::join_until(
            NewHolding::standing(member, member_label()),
            group,
            &conferred,
            &owner(),
        )
        .unwrap()
    }

    /// A user joins Engineering. The membership names that user and that
    /// group.
    #[test]
    fn a_membership_names_its_member_and_group() {
        let group = engineering();
        let member = PrincipalRef::User(UserId::new());

        let membership = joined(member, &group);

        assert_eq!(*membership.principal(), member);
        assert_eq!(membership.group_id(), group.id());
    }

    /// A partner app joins Engineering. The membership keeps it as a
    /// consumer, so apps share roles through a group as people do.
    #[test]
    fn a_consumer_can_belong_to_a_group() {
        let group = engineering();
        let member = PrincipalRef::Consumer(crate::types::ConsumerId::new());

        let membership = joined(member, &group);

        assert_eq!(*membership.principal(), member);
        assert_eq!(membership.principal().kind(), "consumer");
    }

    /// Sam may assign roles but cannot grant user management. Adding a
    /// member to Engineering is refused because its admin role grants that
    /// permission.
    #[test]
    fn a_member_joins_only_with_what_the_granter_may_hand_out() {
        let (groups, roles) = admins();
        let conferred = under(&groups[0], &groups, &roles);

        let result = GroupMembership::<ResolvedTenant>::join_until(
            NewHolding::standing(PrincipalRef::User(UserId::new()), member_label()),
            &groups[0],
            &conferred,
            &sam(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Adding a member to Engineering is refused when the supplied
    /// permissions were computed for another group with no roles.
    #[test]
    fn a_member_does_not_join_with_what_another_group_brings() {
        let (groups, _) = admins();
        let harmless = engineering();
        let elsewhere = under(&harmless, std::slice::from_ref(&harmless), &[]);

        let result = GroupMembership::<ResolvedTenant>::join_until(
            NewHolding::standing(PrincipalRef::User(UserId::new()), member_label()),
            &groups[0],
            &elsewhere,
            &sam(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Removing Ann from Engineering requires control of its user-management
    /// rights. Sam cannot grant those rights and is refused, while an owner
    /// is allowed to end her membership.
    #[test]
    fn only_someone_who_could_give_what_a_group_brings_ends_a_membership() {
        let (groups, roles) = admins();
        let conferred = under(&groups[0], &groups, &roles);
        let mut ann = GroupMembership::<ResolvedTenant>::join_until(
            NewHolding::standing(PrincipalRef::User(UserId::new()), member_label()),
            &groups[0],
            &conferred,
            &owner(),
        )
        .unwrap();

        assert!(matches!(
            ann.end(&groups[0], &conferred, &sam(), member_label()),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            ann.end(&groups[0], &conferred, &owner(), member_label())
                .is_ok()
        );
    }

    /// The tenant's directory puts Ann into its own Engineering group over
    /// SCIM. The membership names her as a user and that group, with no
    /// granter asked.
    #[test]
    fn a_directory_puts_a_user_into_a_group_it_keeps() {
        let group = kept_by(GroupOrigin::Directory);
        let ann = UserId::new();

        let membership =
            GroupMembership::from_directory(ann, &group, &switched_on_directory(), member_label())
                .unwrap();

        assert_eq!(*membership.principal(), PrincipalRef::User(ann));
        assert_eq!(membership.group_id(), group.id());
    }

    /// After SCIM is disabled, adding a user to a directory-owned group is
    /// refused even though the directory owns the group.
    #[test]
    fn a_switched_off_directory_puts_nobody_into_a_group() {
        let group = kept_by(GroupOrigin::Directory);
        let mut scim = switched_on_directory();
        scim.disable(&federation_admin()).unwrap();

        let result = GroupMembership::from_directory(UserId::new(), &group, &scim, member_label());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The tenant's directory creates "Synced" over SCIM, with no person
    /// granting it. It sits at the top, holds no roles and so brings
    /// nothing, and the directory may put Ann into it.
    #[test]
    fn a_directory_creates_a_top_level_group_that_brings_nothing() {
        let scim = switched_on_directory();
        let group = Group::<ResolvedTenant>::from_directory(label("Synced"), &scim).unwrap();
        let ann = UserId::new();

        let conferred = under(&group, std::slice::from_ref(&group), &[]);
        let membership =
            GroupMembership::from_directory(ann, &group, &scim, member_label()).unwrap();

        assert!(group.is_root());
        assert_eq!(group.origin(), GroupOrigin::Directory);
        assert!(conferred.roles().is_empty());
        assert!(conferred.handout().system.is_empty());
        assert!(conferred.handout().custom.is_empty());
        assert_eq!(*membership.principal(), PrincipalRef::User(ann));
        assert_eq!(membership.group_id(), group.id());
    }

    /// An enabled directory cannot add a user to a dashboard-owned group.
    /// The membership request is refused as forbidden.
    #[test]
    fn a_directory_cannot_add_members_to_a_dashboard_group() {
        let group = kept_by(GroupOrigin::Dashboard);
        let scim = switched_on_directory();

        let result = GroupMembership::from_directory(UserId::new(), &group, &scim, member_label());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An enabled directory may end a membership in its own group. Ending
    /// a dashboard membership or supplying a different group for a
    /// directory membership is refused.
    #[test]
    fn a_directory_ends_memberships_only_of_its_own_groups() {
        let scim = switched_on_directory();
        let synced = kept_by(GroupOrigin::Directory);
        let admins = kept_by(GroupOrigin::Dashboard);
        let mut in_synced =
            GroupMembership::from_directory(UserId::new(), &synced, &scim, member_label()).unwrap();
        let mut in_admins = joined(PrincipalRef::User(UserId::new()), &admins);

        assert!(
            in_synced
                .end_by_directory(&synced, &scim, member_label())
                .is_ok()
        );
        assert!(matches!(
            in_admins.end_by_directory(&admins, &scim, member_label()),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            in_synced.end_by_directory(&admins, &scim, member_label()),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Ann joins a directory-owned group while SCIM is enabled. After it
    /// is disabled, the directory is refused when ending her membership.
    #[test]
    fn a_switched_off_directory_ends_no_membership() {
        let mut scim = switched_on_directory();
        let synced = kept_by(GroupOrigin::Directory);
        let mut ann =
            GroupMembership::from_directory(UserId::new(), &synced, &scim, member_label()).unwrap();
        scim.disable(&federation_admin()).unwrap();

        let result = ann.end_by_directory(&synced, &scim, member_label());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Okta renames the team it keeps as "Synced" to "Platform". The group
    /// takes the new name.
    #[test]
    fn a_directory_renames_a_group_it_keeps() {
        let mut synced = kept_by(GroupOrigin::Directory);

        synced
            .rename_by_directory(label("Platform"), &switched_on_directory())
            .unwrap();

        assert_eq!(synced.name().as_str(), "Platform");
    }

    /// A directory cannot rename a dashboard-owned group, and a disabled
    /// directory cannot rename its own group. Both refusals preserve the
    /// Engineering name.
    #[test]
    fn a_directory_renames_only_its_own_groups_while_it_is_on() {
        let mut dashboard = kept_by(GroupOrigin::Dashboard);
        let mut synced = kept_by(GroupOrigin::Directory);
        let on = switched_on_directory();
        let mut off = switched_on_directory();
        off.disable(&federation_admin()).unwrap();

        let of_dashboard = dashboard.rename_by_directory(label("Interns"), &on);
        let while_off = synced.rename_by_directory(label("Interns"), &off);

        assert!(matches!(of_dashboard, Err(DomainError::Forbidden(_))));
        assert!(matches!(while_off, Err(DomainError::Forbidden(_))));
        assert_eq!(dashboard.name().as_str(), "Engineering");
        assert_eq!(synced.name().as_str(), "Engineering");
    }

    /// Okta removes a team it keeps, and the group is deleted. Sam, over
    /// SCIM, deletes the dashboard group "Engineering". It is refused.
    #[test]
    fn a_directory_deletes_only_its_own_groups() {
        let groups = vec![
            kept_by(GroupOrigin::Directory),
            kept_by(GroupOrigin::Dashboard),
        ];
        let tree = GroupTree::new(&groups);
        let scim = switched_on_directory();

        let mut copies = groups
            .iter()
            .map(|group| Group::reconstitute(stored(group)).unwrap());
        let (mut synced, mut dashboard) = (copies.next().unwrap(), copies.next().unwrap());

        let synced = synced.delete_by_directory(&tree, &scim);
        let dashboard = dashboard.delete_by_directory(&tree, &scim);

        assert!(synced.is_ok());
        assert!(matches!(dashboard, Err(DomainError::Forbidden(_))));
    }

    /// A disabled directory is refused when deleting its own group.
    #[test]
    fn a_switched_off_directory_deletes_no_group() {
        let groups = vec![kept_by(GroupOrigin::Directory)];
        let tree = GroupTree::new(&groups);
        let mut scim = switched_on_directory();
        scim.disable(&federation_admin()).unwrap();

        let mut synced = Group::reconstitute(stored(&groups[0])).unwrap();

        let result = synced.delete_by_directory(&tree, &scim);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Each origin is stored by its name and read back as itself. A name
    /// nobody wrote is refused as an infrastructure error, since the row is
    /// corrupt.
    #[test]
    fn a_group_origin_reads_back_from_its_stored_name() {
        for origin in [GroupOrigin::Directory, GroupOrigin::Dashboard] {
            assert_eq!(GroupOrigin::from_stored(origin.as_str()).unwrap(), origin);
        }
        assert!(matches!(
            GroupOrigin::from_stored("scim"),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// A directory group is written to storage and read back. It is still
    /// kept by the directory, so SCIM can go on adding to it.
    #[test]
    fn a_stored_group_keeps_its_origin() {
        let row = stored(&kept_by(GroupOrigin::Directory));

        let group = Group::<ResolvedTenant>::reconstitute(row).unwrap();

        assert_eq!(group.origin(), GroupOrigin::Directory);
    }

    /// Engineering holds two roles and an admin takes one away. The other
    /// role stays, so members keep the access nobody asked to revoke.
    #[test]
    fn unassigning_a_role_removes_that_role_and_leaves_the_rest() {
        let mut group = engineering();
        let kept = a_role();
        let removed = a_role();
        give(&mut group, &kept);
        give(&mut group, &removed);

        group.unassign_role(&removed, &owner()).unwrap();

        assert_eq!(group.role_ids(), &[*kept.id()]);
    }

    /// A new group has a real id. Giving it a role five minutes later moves
    /// its update time to then and leaves its creation time alone.
    #[test]
    fn a_group_carries_its_id_and_moves_its_timestamp_when_edited() {
        let mut group = engineering();
        let created = group.created_at();
        let later = group.updated_at() + time::Duration::minutes(5);

        assert!(!group.id().as_uuid().is_nil());

        let role = a_role();
        let _frozen = crate::shared::clock::freeze(later);
        give(&mut group, &role);

        assert_eq!(group.updated_at(), later);
        assert_eq!(group.created_at(), created);
    }

    fn stored(group: &Group<ResolvedTenant>) -> GroupRow {
        GroupRow {
            id: group.id,
            name: group.name.clone(),
            origin: group.origin,
            place: group.place,
            role_ids: group.role_ids.clone(),
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }

    /// A stored group names itself as its parent. Reading it back is
    /// refused as a corrupt row.
    #[test]
    fn a_stored_group_under_itself_is_refused() {
        let mut row = stored(&engineering());
        row.place = GroupPlace::Under(row.id);

        assert!(refused_as_corrupt(&Group::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// A stored group lists the same role twice. Reading it back is
    /// refused as a corrupt row.
    #[test]
    fn a_stored_group_holding_a_role_twice_is_refused() {
        let role = RoleId::new();
        let mut row = stored(&engineering());
        row.role_ids = vec![role, role];

        assert!(refused_as_corrupt(&Group::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// The reference `key` of an event's payload, as (id, label).
    fn reference_of(event: &DomainEvent, key: &str) -> Option<(String, String)> {
        match event.payload().value(key) {
            Some(FieldValue::Reference(reference)) => {
                Some((reference.id().to_owned(), reference.label().to_owned()))
            }
            _ => None,
        }
    }

    /// Ann creates Engineering at the top, then Backend under it. Each
    /// creation is raised, and Backend's names Engineering as its parent.
    #[test]
    fn creating_a_group_raises_it_with_the_group_it_sits_under() {
        let mut parent = engineering();
        let mut child = Group::<ResolvedTenant>::create(
            CreateGroupParams {
                name: label("Backend"),
                origin: GroupOrigin::Dashboard,
                place: GroupPlace::Under(*parent.id()),
            },
            &under(&parent, std::slice::from_ref(&parent), &[]),
            &owner(),
        )
        .unwrap();

        let at_top = raised(&mut parent);
        let nested = raised(&mut child);

        assert_eq!(
            at_top[0].event_type().to_string(),
            "authorization.group_created"
        );
        assert_eq!(reference_of(&at_top[0], "parent"), None);
        assert_eq!(
            reference_of(&nested[0], "parent"),
            Some((parent.id().to_string(), "Engineering".to_owned()))
        );
    }

    /// The directory creates "Synced". Its creation is raised at the top of
    /// the tree.
    #[test]
    fn a_directory_group_is_raised_at_the_top() {
        let mut synced =
            Group::<ResolvedTenant>::from_directory(label("Synced"), &switched_on_directory())
                .unwrap();

        let events = raised(&mut synced);

        assert_eq!(events.len(), 1);
        assert_eq!(reference_of(&events[0], "parent"), None);
    }

    /// Ann renames Engineering, gives it a role and takes it off again.
    /// Each step is raised, in order.
    #[test]
    fn renaming_and_shaping_a_group_are_raised_in_order() {
        let mut group = engineering();
        raised_names(&mut group);
        let role = a_role();

        group.rename(label("Platform"), &owner()).unwrap();
        give(&mut group, &role);
        group.unassign_role(&role, &owner()).unwrap();

        assert_eq!(
            raised_names(&mut group),
            [
                "authorization.group_renamed",
                "authorization.group_role_assigned",
                "authorization.group_role_unassigned",
            ]
        );
    }

    /// Ann renames Engineering to Platform. The record keeps both names.
    #[test]
    fn a_rename_records_the_name_before_and_after() {
        let mut group = engineering();
        raised_names(&mut group);

        group.rename(label("Platform"), &owner()).unwrap();

        let payload = raised(&mut group)[0].payload();
        let Some(FieldValue::Change(change)) = payload.value("name") else {
            panic!("the name is recorded as a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("Engineering"), Some("Platform"))
        );
    }

    /// Ann moves Backend from under Engineering to the top. The move is
    /// raised naming Engineering as the group it left.
    #[test]
    fn a_move_is_raised_with_the_place_it_left() {
        let (groups, roles, mut backend) = backend_under_admins();
        raised_names(&mut backend);
        let leaving = under(&groups[0], &groups, &roles);

        backend
            .move_under(&leaving, &Conferred::at_top(), &owner())
            .unwrap();

        let events = raised(&mut backend);
        assert_eq!(
            events[0].event_type().to_string(),
            "authorization.group_moved"
        );
        assert_eq!(
            reference_of(&events[0], "previous_parent"),
            Some((groups[0].id().to_string(), "Engineering".to_owned()))
        );
        assert_eq!(reference_of(&events[0], "parent"), None);
    }

    /// Ann deletes Engineering, and the directory deletes its own group.
    /// Each deletion is raised.
    #[test]
    fn deleting_a_group_is_raised() {
        let groups = vec![
            kept_by(GroupOrigin::Dashboard),
            kept_by(GroupOrigin::Directory),
        ];
        let tree = GroupTree::new(&groups);
        let conferred = under(&groups[0], &groups, &[]);
        let mut dashboard = Group::reconstitute(stored(&groups[0])).unwrap();
        let mut synced = Group::reconstitute(stored(&groups[1])).unwrap();

        dashboard.delete(&tree, &conferred, &owner()).unwrap();
        synced
            .delete_by_directory(&tree, &switched_on_directory())
            .unwrap();

        assert_eq!(
            raised_names(&mut dashboard),
            ["authorization.group_deleted"]
        );
        assert_eq!(raised_names(&mut synced), ["authorization.group_deleted"]);
    }

    /// Assigning an admin role without its user-management rights is
    /// refused, as is renaming through a disabled directory. Neither
    /// request raises an event.
    #[test]
    fn a_refused_group_change_raises_nothing() {
        let (mut groups, roles) = admins();
        raised_names(&mut groups[0]);
        let mut off = switched_on_directory();
        off.disable(&federation_admin()).unwrap();

        let given = groups[0].assign_role(&roles[0], &sam());
        let renamed = groups[0].rename_by_directory(label("Interns"), &off);

        assert!(given.is_err());
        assert!(renamed.is_err());
        assert!(raised_names(&mut groups[0]).is_empty());
    }

    /// Engineering is read back from storage. Nothing is raised: reading
    /// changes nothing.
    #[test]
    fn a_group_read_back_from_storage_has_raised_nothing() {
        let mut group = Group::<ResolvedTenant>::reconstitute(stored(&engineering())).unwrap();

        assert!(raised_names(&mut group).is_empty());
    }

    /// Ann joins Engineering and is taken out again. The join and the
    /// leave are raised, each naming her by the label the application read.
    #[test]
    fn joining_and_leaving_a_group_are_raised_with_the_member_named() {
        let group = engineering();
        let groups = [Group::reconstitute(stored(&group)).unwrap()];
        let conferred = under(&group, &groups, &[]);
        let mut ann = joined(PrincipalRef::User(UserId::new()), &group);

        ann.end(&group, &conferred, &owner(), member_label())
            .unwrap();

        let events = raised(&mut ann);
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "authorization.group_member_added",
                "authorization.group_member_removed",
            ]
        );
        for event in &events {
            let (_, label) = reference_of(event, "member").unwrap();
            assert_eq!(label, "ann@acme.test");
        }
    }

    /// The directory puts Ann into its group and takes her out. Both are
    /// raised.
    #[test]
    fn a_directory_join_and_leave_are_raised() {
        let scim = switched_on_directory();
        let synced = kept_by(GroupOrigin::Directory);
        let mut ann =
            GroupMembership::from_directory(UserId::new(), &synced, &scim, member_label()).unwrap();

        ann.end_by_directory(&synced, &scim, member_label())
            .unwrap();

        assert_eq!(
            raised_names(&mut ann),
            [
                "authorization.group_member_added",
                "authorization.group_member_removed",
            ]
        );
    }

    /// Ending Ann's membership through a different group is refused even
    /// for an owner. No removal event is raised.
    #[test]
    fn a_membership_is_not_ended_through_another_group() {
        let group = engineering();
        let other = engineering();
        let groups = [Group::reconstitute(stored(&other)).unwrap()];
        let conferred = under(&other, &groups, &[]);
        let mut ann = joined(PrincipalRef::User(UserId::new()), &group);
        raised_names(&mut ann);

        let result = ann.end(&other, &conferred, &owner(), member_label());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut ann).is_empty());
    }

    /// Ann's membership is read back from storage. Nothing is raised.
    #[test]
    fn a_membership_read_back_from_storage_has_raised_nothing() {
        let mut membership = GroupMembership::<ResolvedTenant>::reconstitute(GroupMembershipRow {
            principal: PrincipalRef::User(UserId::new()),
            group_id: GroupId::new(),
            joined_at: crate::shared::clock::now(),
            expires: Expiry::Never,
        })
        .unwrap();

        assert!(raised_names(&mut membership).is_empty());
    }

    /// Ann joins Engineering for the night. The membership counts until
    /// the morning and not after, and the record says when it ends.
    #[test]
    fn a_membership_given_until_a_time_counts_until_then() {
        let group = engineering();
        let morning = crate::shared::clock::now() + time::Duration::hours(8);
        let conferred = under(&group, std::slice::from_ref(&group), &[]);

        let mut ann = GroupMembership::join_until(
            NewHolding {
                principal: PrincipalRef::User(UserId::new()),
                label: member_label(),
                until: Expiry::At(morning),
            },
            &group,
            &conferred,
            &owner(),
        )
        .unwrap();

        assert!(ann.is_in_force(morning - time::Duration::seconds(1)));
        assert!(!ann.is_in_force(morning));
        assert_eq!(
            raised(&mut ann)[0].payload().get("expires_at"),
            Some(morning.to_string().as_str())
        );
    }

    /// User-viewing rights do not permit adding a member to Engineering,
    /// even when the membership expires in an hour.
    #[test]
    fn a_membership_for_a_while_needs_the_same_rights() {
        let group = engineering();
        let conferred = under(&group, std::slice::from_ref(&group), &[]);
        let viewer = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);

        let refused = GroupMembership::join_until(
            NewHolding {
                principal: PrincipalRef::User(UserId::new()),
                label: member_label(),
                until: Expiry::At(crate::shared::clock::now() + time::Duration::hours(1)),
            },
            &group,
            &conferred,
            &viewer,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann's night in Engineering is over. The sweep ends it and records
    /// it; a membership with no end, or swept through another group, is
    /// refused.
    #[test]
    fn only_an_ended_membership_is_swept_and_only_through_its_group() {
        let group = engineering();
        let now = crate::shared::clock::now();
        let stored = |expires| {
            GroupMembership::<ResolvedTenant>::reconstitute(GroupMembershipRow {
                principal: PrincipalRef::User(UserId::new()),
                group_id: group.id,
                joined_at: now - time::Duration::days(1),
                expires,
            })
            .unwrap()
        };
        let mut ended = stored(Expiry::At(now - time::Duration::hours(1)));
        let mut standing = stored(Expiry::Never);

        let elsewhere = ended.lapse(&engineering(), now, member_label());
        ended.lapse(&group, now, member_label()).unwrap();
        let never = standing.lapse(&group, now, member_label());

        assert!(matches!(elsewhere, Err(DomainError::Forbidden(_))));
        assert_eq!(
            raised_names(&mut ended),
            ["authorization.group_membership_expired"]
        );
        assert!(matches!(never, Err(DomainError::Conflict(_))));
    }

    /// A review's removal proof names Bob in Engineering. Removing Ann or
    /// supplying another group for Bob is refused. Removing Bob from
    /// Engineering succeeds and raises one membership-removal event.
    #[test]
    fn a_review_withdraws_only_the_members_it_named_from_its_group() {
        let group = engineering();
        let stored = |principal| {
            GroupMembership::<ResolvedTenant>::reconstitute(GroupMembershipRow {
                principal,
                group_id: group.id,
                joined_at: crate::shared::clock::now(),
                expires: Expiry::Never,
            })
            .unwrap()
        };
        let bob = PrincipalRef::User(UserId::new());
        let (mut ann, mut bobs) = (stored(PrincipalRef::User(UserId::new())), stored(bob));
        let removals = ReviewRemovals::of(
            AccessReviewId::new(),
            ReviewScope::Group(group.id),
            vec![bob],
        );

        let not_named = ann.withdraw_by_review(&group, &removals, member_label());
        let elsewhere = bobs.withdraw_by_review(&engineering(), &removals, member_label());
        bobs.withdraw_by_review(&group, &removals, member_label())
            .unwrap();

        assert!(matches!(not_named, Err(DomainError::Forbidden(_))));
        assert!(matches!(elsewhere, Err(DomainError::Forbidden(_))));
        assert_eq!(
            raised_names(&mut bobs),
            ["authorization.group_member_removed"]
        );
    }

    /// Rebuilding a stored membership whose expiry precedes its joining
    /// time is refused as corrupt storage.
    #[test]
    fn a_stored_membership_ending_before_it_began_is_refused() {
        let now = crate::shared::clock::now();

        let stored = GroupMembership::<ResolvedTenant>::reconstitute(GroupMembershipRow {
            principal: PrincipalRef::User(UserId::new()),
            group_id: GroupId::new(),
            joined_at: now,
            expires: Expiry::At(now - time::Duration::hours(1)),
        });

        assert!(refused_as_corrupt(&stored));
    }
}
