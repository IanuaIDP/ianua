//! A tenant's groups read as one tree, and what sitting at a place in it
//! brings.
//!
//! A member of "Backend" holds the roles of Backend and of every group
//! above it. So what joining a group gives is worked out across the tree,
//! never from the group alone. Sam may only view users, and "Engineering"
//! holds the admin role. Without the walk up, Sam adds himself to
//! "Backend", a harmless-looking group under Engineering, and manages
//! users.

use crate::domains::authorization::events::groups::NestedUnder;
use crate::domains::authorization::granter::Handout;
use crate::domains::authorization::group::{Group, GroupPlace};
use crate::domains::authorization::permission::{CustomPermission, SystemPermission};
use crate::domains::authorization::role::Role;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::without_repeats;
use crate::types::{EventLabel, GroupId, RoleId};

/// Every group of one tenant, read whole.
///
/// The caller loads all of the tenant's groups. A group missing from the
/// list is never read as having no roles: a walk that needs it is refused.
#[derive(Debug)]
pub struct GroupTree<'a, T: TenantScope> {
    groups: &'a [Group<T>],
}

/// What sitting at one place in the tree brings: the roles of the group
/// there and of every group above it, and what those roles grant.
///
/// Only [`GroupTree::conferred`] works one out, so a caller cannot hand in
/// less than a group really gives. It names the place it was worked out
/// for, and is refused anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conferred {
    place: GroupPlace,
    parent: NestedUnder,
    lineage: Vec<GroupId>,
    roles: Vec<RoleId>,
    system: Vec<SystemPermission>,
    custom: Vec<CustomPermission>,
}

impl Conferred {
    /// What the top of the tree brings: nothing, since no group is above.
    #[must_use]
    pub fn at_top() -> Self {
        Self {
            place: GroupPlace::TopLevel,
            parent: NestedUnder::TopLevel,
            lineage: Vec::new(),
            roles: Vec::new(),
            system: Vec::new(),
            custom: Vec::new(),
        }
    }

    /// The place this was worked out for.
    #[must_use]
    pub fn place(&self) -> GroupPlace {
        self.place
    }

    /// The place as the audit trail names it: the top, or the group there
    /// with its name as it is now.
    pub(crate) fn parent(&self) -> &NestedUnder {
        &self.parent
    }

    /// The groups whose roles it brings, nearest first.
    #[must_use]
    pub fn lineage(&self) -> &[GroupId] {
        &self.lineage
    }

    /// The roles it brings, each named once.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    /// What those roles grant, as a hand-out to check a granter against.
    #[must_use]
    pub fn handout(&self) -> Handout<'_> {
        Handout {
            system: &self.system,
            custom: &self.custom,
        }
    }

    /// Refuses this when it was worked out for another place.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `place` is not the place it names.
    pub(crate) fn ensure_for(&self, place: GroupPlace) -> Result<(), DomainError> {
        if self.place != place {
            return Err(DomainError::forbidden(message!(
                "authorization-what-a-group-gives-was-worked",
                "what a group gives was worked out for another group"
            )));
        }
        Ok(())
    }
}

impl<'a, T: TenantScope> GroupTree<'a, T> {
    /// The tree of `groups`, every group of one tenant.
    #[must_use]
    pub fn new(groups: &'a [Group<T>]) -> Self {
        Self { groups }
    }

    /// The groups from `group` up to the top of the tree, `group` first.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when `group` is not in the tree.
    /// - [`DomainError::Infrastructure`] when a group above it is missing,
    ///   or the walk up comes back to a group already passed.
    pub fn lineage(&self, group: &GroupId) -> Result<Vec<&'a Group<T>>, DomainError> {
        let mut chain = vec![self.find(group).ok_or(DomainError::NotFound)?];
        while let Some(parent) = chain.last().and_then(|g| g.place().parent().copied()) {
            if chain.iter().any(|passed| *passed.id() == parent) {
                return Err(DomainError::corrupt_row(
                    "group",
                    "sits under one of its own subgroups",
                ));
            }
            let above = self.find(&parent).ok_or_else(|| {
                DomainError::corrupt_row("group", "sits under a group that does not exist")
            })?;
            chain.push(above);
        }
        Ok(chain)
    }

    /// What sitting at `place` brings, from the roles in `roles`.
    ///
    /// For a member of a group, `place` is under that group. For a group
    /// put somewhere, it is the place it goes.
    ///
    /// # Errors
    ///
    /// - The cases [`Self::lineage`] lists.
    /// - [`DomainError::Infrastructure`] when a group on the way names a
    ///   role that is not in `roles`. An unknown role is never read as one
    ///   that grants nothing.
    pub fn conferred(
        &self,
        place: GroupPlace,
        roles: &[Role<T>],
    ) -> Result<Conferred, DomainError> {
        let GroupPlace::Under(group) = place else {
            return Ok(Conferred::at_top());
        };
        let lineage = self.lineage(&group)?;
        let role_ids = without_repeats(
            lineage
                .iter()
                .flat_map(|g| g.role_ids().iter().copied())
                .collect(),
        );
        let granting = role_ids
            .iter()
            .map(|id| role_named(roles, id, "group"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Conferred {
            place,
            parent: named_parent(&lineage)?,
            lineage: lineage.iter().map(|g| *g.id()).collect(),
            roles: role_ids,
            system: system_granted_by(&granting),
            custom: custom_granted_by(&granting),
        })
    }

    /// Whether any group sits directly under `group`.
    #[must_use]
    pub fn has_subgroups(&self, group: &GroupId) -> bool {
        self.groups
            .iter()
            .any(|g| g.place() == &GroupPlace::Under(*group))
    }

    fn find(&self, id: &GroupId) -> Option<&'a Group<T>> {
        self.groups.iter().find(|g| g.id() == id)
    }
}

/// The group a walk up started from, as the audit trail names a place
/// under it: its id and its name now.
///
/// # Errors
///
/// - [`DomainError::NotFound`] when the walk is empty, which
///   [`GroupTree::lineage`] never returns.
fn named_parent<T: TenantScope>(lineage: &[&Group<T>]) -> Result<NestedUnder, DomainError> {
    let here = lineage.first().ok_or(DomainError::NotFound)?;
    Ok(NestedUnder::Group {
        id: *here.id(),
        label: EventLabel::of(here.name().as_str()),
    })
}

/// The role in `roles` with `id`, which a stored `holder` names.
///
/// An unknown role is never read as one that grants nothing. Read that way,
/// a caller who loaded too few roles would see a group bring nothing, or a
/// tenant have no administrator, and let a change through.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when no role in `roles` has `id`.
pub(crate) fn role_named<'r, T: TenantScope>(
    roles: &'r [Role<T>],
    id: &RoleId,
    holder: &'static str,
) -> Result<&'r Role<T>, DomainError> {
    roles
        .iter()
        .find(|role| role.id() == id)
        .ok_or_else(|| DomainError::corrupt_row(holder, "names a role that does not exist"))
}

/// The built-in permissions `roles` grant together, each named once.
fn system_granted_by<T: TenantScope>(roles: &[&Role<T>]) -> Vec<SystemPermission> {
    without_repeats(
        roles
            .iter()
            .flat_map(|role| role.system_permissions().iter().copied())
            .collect(),
    )
}

/// The app-defined permissions `roles` grant together, each named once.
fn custom_granted_by<T: TenantScope>(roles: &[&Role<T>]) -> Vec<CustomPermission> {
    without_repeats(
        roles
            .iter()
            .flat_map(|role| role.custom_permissions().iter().cloned())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{GroupOrigin, GroupRow};
    use crate::domains::authorization::permission::UserAction;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;

    fn group(id: GroupId, place: GroupPlace, roles: Vec<RoleId>) -> Group<ResolvedTenant> {
        let now = crate::shared::clock::now();
        Group::reconstitute(GroupRow {
            id,
            name: label("team"),
            origin: GroupOrigin::Dashboard,
            place,
            role_ids: roles,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    fn role(system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("team"),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// Engineering holds the admin role, and Backend sits under it with a
    /// viewer role. Sitting in Backend brings both roles, and "manage
    /// users" with them.
    #[test]
    fn a_place_brings_the_roles_of_every_group_above_it() {
        let admin = role(vec![SystemPermission::ManageUsers]);
        let viewer = role(vec![SystemPermission::Users(UserAction::View)]);
        let engineering = GroupId::new();
        let backend = GroupId::new();
        let groups = [
            group(engineering, GroupPlace::TopLevel, vec![*admin.id()]),
            group(backend, GroupPlace::Under(engineering), vec![*viewer.id()]),
        ];
        let roles = [admin, viewer];

        let conferred = GroupTree::new(&groups)
            .conferred(GroupPlace::Under(backend), &roles)
            .unwrap();

        assert_eq!(conferred.lineage(), [backend, engineering]);
        assert_eq!(conferred.roles().len(), 2);
        assert!(
            conferred
                .handout()
                .system
                .contains(&SystemPermission::ManageUsers)
        );
    }

    /// The top of the tree brings nothing, whatever the groups hold.
    #[test]
    fn the_top_of_the_tree_brings_nothing() {
        let groups: [Group<ResolvedTenant>; 0] = [];

        let conferred = GroupTree::new(&groups)
            .conferred(GroupPlace::TopLevel, &[])
            .unwrap();

        assert_eq!(conferred, Conferred::at_top());
    }

    /// Computing Backend's inherited rights fails with an infrastructure error
    /// when its parent group is missing from the loaded tree.
    #[test]
    fn a_missing_group_above_is_refused() {
        let backend = GroupId::new();
        let groups = [group(
            backend,
            GroupPlace::Under(GroupId::new()),
            Vec::new(),
        )];

        let result = GroupTree::new(&groups).conferred(GroupPlace::Under(backend), &[]);

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A cycle between Backend and Ops is rejected as corrupt when reading their lineage.
    #[test]
    fn a_loop_in_the_tree_is_refused() {
        let backend = GroupId::new();
        let ops = GroupId::new();
        let groups = [
            group(backend, GroupPlace::Under(ops), Vec::new()),
            group(ops, GroupPlace::Under(backend), Vec::new()),
        ];

        let result = GroupTree::new(&groups).lineage(&backend);

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Computing Engineering's rights fails with an infrastructure error when a
    /// role it names was not loaded.
    #[test]
    fn a_role_that_was_not_loaded_is_refused() {
        let engineering = GroupId::new();
        let groups = [group(
            engineering,
            GroupPlace::TopLevel,
            vec![RoleId::new()],
        )];

        let result = GroupTree::new(&groups).conferred(GroupPlace::Under(engineering), &[]);

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// An admin asks what a group that does not exist would bring. It is
    /// refused as not found, since the id came from the request.
    #[test]
    fn an_unknown_group_is_not_found() {
        let groups: [Group<ResolvedTenant>; 0] = [];

        let result = GroupTree::new(&groups).conferred(GroupPlace::Under(GroupId::new()), &[]);

        assert!(matches!(result, Err(DomainError::NotFound)));
    }

    /// Backend sits under Engineering. Engineering has a subgroup and
    /// Backend has none.
    #[test]
    fn a_group_knows_whether_others_sit_under_it() {
        let engineering = GroupId::new();
        let backend = GroupId::new();
        let groups = [
            group(engineering, GroupPlace::TopLevel, Vec::new()),
            group(backend, GroupPlace::Under(engineering), Vec::new()),
        ];
        let tree = GroupTree::new(&groups);

        assert!(tree.has_subgroups(&engineering));
        assert!(!tree.has_subgroups(&backend));
    }
}
