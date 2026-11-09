//! Whether someone can still run a tenant's access after a change.
//!
//! A tenant has no built-in owner role. Its first admin role is a role like
//! any other, and can be stripped, deleted or taken from its last holder.
//! Ann is the only admin. Without this check, she takes the admin role from
//! herself by mistake, or deletes it, and nobody in the tenant can ever
//! give out a role again.

use crate::domains::authorization::group::{Group, GroupMembership};
use crate::domains::authorization::group_tree::{Conferred, GroupTree, role_named};
use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
use crate::domains::authorization::role::{Role, RoleAssignment};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::without_repeats;
use crate::types::{GroupId, PrincipalRef, RoleId, UserId};

/// Who holds which roles across one tenant, read whole, or narrowed to one
/// person.
///
/// The caller passes the grants of active accounts only. A deactivated
/// admin cannot sign in, so they run nothing.
///
/// The caller loads every role, group and membership, or for a question
/// about one person, every one of theirs, the groups above those and the
/// roles they all name. A role or a group that something names but that is
/// missing is never read as granting nothing: the tenant would then seem to
/// have no administrator, and the change that takes the last one away would
/// go through.
///
/// An assignment or a membership whose end has passed counts for nothing,
/// whether or not a sweep has removed it yet. Bob's admin role ran out at
/// noon; at one o'clock he neither holds it nor counts as an administrator.
#[derive(Debug)]
pub struct TenantGrants<'a, T: TenantScope> {
    /// Every role of the tenant.
    pub roles: &'a [Role<T>],
    /// Every role given straight to someone.
    pub assignments: &'a [RoleAssignment<T>],
    /// Every group of the tenant.
    pub groups: &'a [Group<T>],
    /// Every membership of a group.
    pub memberships: &'a [GroupMembership<T>],
}

impl<T: TenantScope> TenantGrants<'_, T> {
    /// The users who administer the tenant, each named once.
    ///
    /// A user administers it when the roles given to them, or to a group
    /// they are in or one above it, together hold every action of the roles
    /// area and every action of the users area. Each area's `Manage` covers
    /// them, and so does a role with every action ticked one by one. An
    /// agent or an app never counts, since no person stands behind it.
    ///
    /// Over grants narrowed to one person, it says only whether that person
    /// administers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when an assignment or a group names
    ///   a role that is not in `roles`.
    /// - [`DomainError::Infrastructure`] when a membership names a group
    ///   that is not in `groups`.
    /// - [`DomainError::Infrastructure`] in the cases [`GroupTree::lineage`]
    ///   lists for a group above a membership's group.
    pub fn administrators(&self) -> Result<Vec<UserId>, DomainError> {
        let tree = GroupTree::new(self.groups);
        let mut found = Vec::new();
        for user in self.users() {
            if self.administers(&tree, user)? {
                found.push(user);
            }
        }
        Ok(found)
    }

    /// How many users administer the tenant, as
    /// [`administrators`](Self::administrators) finds them: what a store
    /// answers with a count, worked out here over records read whole.
    ///
    /// # Errors
    ///
    /// - The cases [`administrators`](Self::administrators) lists.
    pub fn administrator_count(&self) -> Result<AdministratorCount, DomainError> {
        let found = self.administrators()?;
        Ok(AdministratorCount::new(
            u64::try_from(found.len()).unwrap_or(u64::MAX),
        ))
    }

    /// Every user named by an assignment or a membership in force, each
    /// once.
    pub(crate) fn users(&self) -> Vec<UserId> {
        let direct = self.assignments_in_force().map(RoleAssignment::principal);
        let grouped = self.memberships_in_force().map(GroupMembership::principal);
        without_repeats(direct.chain(grouped).filter_map(person_of).collect())
    }

    /// Who holds `role` given straight to them now, each once. A group's
    /// members hold it too, through the group; they are not listed here.
    #[must_use]
    pub fn holders_of(&self, role: &RoleId) -> Vec<PrincipalRef> {
        without_repeats(
            self.assignments_in_force()
                .filter(|assignment| assignment.role_id() == role)
                .map(|assignment| *assignment.principal())
                .collect(),
        )
    }

    /// Who is in `group` itself now, each once. Members of the groups
    /// under it are not listed here.
    #[must_use]
    pub fn members_of(&self, group: &GroupId) -> Vec<PrincipalRef> {
        without_repeats(
            self.memberships_in_force()
                .filter(|membership| membership.group_id() == group)
                .map(|membership| *membership.principal())
                .collect(),
        )
    }

    /// Who is in `group`, or in a group under it, now, each once: everyone
    /// a role given to `group` reaches.
    ///
    /// # Errors
    ///
    /// - The cases [`administrators`](Self::administrators) lists for a
    ///   membership's group.
    pub fn members_within(&self, group: &GroupId) -> Result<Vec<PrincipalRef>, DomainError> {
        let principals: Vec<PrincipalRef> = without_repeats(
            self.memberships_in_force()
                .map(|membership| *membership.principal())
                .collect(),
        );
        let mut within = Vec::new();
        for principal in principals {
            if self.groups_of(principal)?.contains(group) {
                within.push(principal);
            }
        }
        Ok(within)
    }

    /// The groups `principal` is in now, with every group above them, each
    /// once: what a policy's group condition reads.
    ///
    /// # Errors
    ///
    /// - The cases [`administrators`](Self::administrators) lists for a
    ///   membership's group.
    pub fn groups_of(&self, principal: PrincipalRef) -> Result<Vec<GroupId>, DomainError> {
        let tree = GroupTree::new(self.groups);
        let mut found = Vec::new();
        for membership in self
            .memberships_in_force()
            .filter(|membership| *membership.principal() == principal)
        {
            found.extend(stored_lineage(&tree, membership)?.iter().map(|g| *g.id()));
        }
        Ok(without_repeats(found))
    }

    /// The assignments whose end, if any, has not passed.
    fn assignments_in_force(&self) -> impl Iterator<Item = &RoleAssignment<T>> {
        let now = crate::shared::clock::now();
        self.assignments
            .iter()
            .filter(move |assignment| assignment.is_in_force(now))
    }

    /// The memberships whose end, if any, has not passed.
    fn memberships_in_force(&self) -> impl Iterator<Item = &GroupMembership<T>> {
        let now = crate::shared::clock::now();
        self.memberships
            .iter()
            .filter(move |membership| membership.is_in_force(now))
    }

    /// The users whose roles, given to them or to a group they are in or
    /// one above it, hold `right` now, each named once: everyone who may
    /// act on what the right covers, administrator or not. An area's
    /// `Manage` holds each of its actions.
    ///
    /// # Errors
    ///
    /// - The cases [`administrators`](Self::administrators) lists.
    pub fn holders_of_right(&self, right: SystemPermission) -> Result<Vec<UserId>, DomainError> {
        let tree = GroupTree::new(self.groups);
        let mut found = Vec::new();
        for user in self.users() {
            let held = self.rights_of(&tree, user)?;
            if SystemPermission::can_delegate(&held, &[right]) {
                found.push(user);
            }
        }
        Ok(found)
    }

    /// Whether `user` holds every right [`administering`] names.
    fn administers(&self, tree: &GroupTree<'_, T>, user: UserId) -> Result<bool, DomainError> {
        let held = self.rights_of(tree, user)?;
        Ok(SystemPermission::can_delegate(&held, &administering()))
    }

    /// Every system right the roles `user` holds give.
    fn rights_of(
        &self,
        tree: &GroupTree<'_, T>,
        user: UserId,
    ) -> Result<Vec<SystemPermission>, DomainError> {
        Ok(self
            .roles_in(tree, PrincipalRef::User(user))?
            .into_iter()
            .flat_map(|role| role.system_permissions().iter().copied())
            .collect())
    }

    /// Every role `principal` holds, given to them or to a group they are
    /// in or one above it.
    ///
    /// # Errors
    ///
    /// - The cases [`administrators`](Self::administrators) lists.
    pub(crate) fn roles_held_by(
        &self,
        principal: PrincipalRef,
    ) -> Result<Vec<&Role<T>>, DomainError> {
        self.roles_in(&GroupTree::new(self.groups), principal)
    }

    /// The roles `principal` would hold once `group` sits at the place `to`
    /// was worked out for, each named once.
    ///
    /// A membership of `group`, or of a group under it, then brings the
    /// roles from its own group up to `group`, and those of the new place.
    /// Every other holding brings what it brings now.
    ///
    /// # Errors
    ///
    /// - The cases [`administrators`](Self::administrators) lists.
    pub(crate) fn roles_after_move(
        &self,
        principal: PrincipalRef,
        group: &GroupId,
        to: &Conferred,
    ) -> Result<Vec<RoleId>, DomainError> {
        let tree = GroupTree::new(self.groups);
        let mut held: Vec<RoleId> = self
            .assigned_roles(principal)?
            .into_iter()
            .map(|role| *role.id())
            .collect();
        for membership in self
            .memberships_in_force()
            .filter(|membership| *membership.principal() == principal)
        {
            held.extend(moved_lineage_roles(&tree, membership, group, to)?);
        }
        Ok(without_repeats(held))
    }

    /// Every role `principal` holds, read through `tree`.
    fn roles_in(
        &self,
        tree: &GroupTree<'_, T>,
        principal: PrincipalRef,
    ) -> Result<Vec<&Role<T>>, DomainError> {
        let mut roles = self.assigned_roles(principal)?;
        roles.extend(self.group_roles(tree, principal)?);
        Ok(roles)
    }

    /// The roles given straight to `principal`, in force now.
    fn assigned_roles(&self, principal: PrincipalRef) -> Result<Vec<&Role<T>>, DomainError> {
        self.assignments_in_force()
            .filter(|assignment| *assignment.principal() == principal)
            .map(|assignment| role_named(self.roles, assignment.role_id(), "role assignment"))
            .collect()
    }

    /// The roles `principal` holds through the groups they are in now and
    /// the groups above those.
    fn group_roles(
        &self,
        tree: &GroupTree<'_, T>,
        principal: PrincipalRef,
    ) -> Result<Vec<&Role<T>>, DomainError> {
        let lineages = self
            .memberships_in_force()
            .filter(|membership| *membership.principal() == principal)
            .map(|membership| stored_lineage(tree, membership))
            .collect::<Result<Vec<_>, _>>()?;
        lineages
            .iter()
            .flatten()
            .flat_map(|group| group.role_ids())
            .map(|id| role_named(self.roles, id, "group"))
            .collect()
    }
}

/// The groups from a stored membership's group up to the top of the tree.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when the membership's group is not in
///   `tree`. The membership came from storage, not from a request.
/// - [`DomainError::Infrastructure`] in the cases [`GroupTree::lineage`]
///   lists for a group above it.
fn stored_lineage<'g, T: TenantScope>(
    tree: &GroupTree<'g, T>,
    membership: &GroupMembership<T>,
) -> Result<Vec<&'g Group<T>>, DomainError> {
    tree.lineage(membership.group_id()).map_err(|error| {
        if matches!(error, DomainError::NotFound) {
            return DomainError::corrupt_row(
                "group membership",
                "names a group that does not exist",
            );
        }
        error
    })
}

/// The roles a stored membership brings once `moved` sits where `to` was
/// worked out for: its lineage up to `moved`, then the new place's, when
/// `moved` is on it; its lineage as it is otherwise.
///
/// # Errors
///
/// - The cases [`stored_lineage`] lists.
fn moved_lineage_roles<T: TenantScope>(
    tree: &GroupTree<'_, T>,
    membership: &GroupMembership<T>,
    moved: &GroupId,
    to: &Conferred,
) -> Result<Vec<RoleId>, DomainError> {
    let lineage = stored_lineage(tree, membership)?;
    let moved_at = lineage.iter().position(|group| group.id() == moved);
    let kept = moved_at.map_or(lineage.len(), |at| at.saturating_add(1));
    let mut roles: Vec<RoleId> = lineage
        .iter()
        .take(kept)
        .flat_map(|group| group.role_ids().iter().copied())
        .collect();
    if moved_at.is_some() {
        roles.extend_from_slice(to.roles());
    }
    Ok(roles)
}

/// Every action of the roles area and of the users area, each area's
/// `Manage` left out. Whoever holds all of them may shape roles and change
/// which roles people hold, whether through `Manage` or with every action
/// spelled out.
fn administering() -> Vec<SystemPermission> {
    SystemPermission::ALL_VARIANTS
        .iter()
        .copied()
        .filter(|right| {
            matches!(right, SystemPermission::Roles(action) if *action != RoleAction::Manage)
                || matches!(right, SystemPermission::Users(action) if *action != UserAction::Manage)
        })
        .collect()
}

/// The tenant user `principal` is, when it is one.
fn person_of(principal: &PrincipalRef) -> Option<UserId> {
    match principal {
        PrincipalRef::User(user) => Some(*user),
        PrincipalRef::OrgUser(_) | PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => None,
    }
}

/// How many users administer a tenant, as
/// [`TenantGrants::administrators`] defines administering: the roles given
/// to them, or to a group they are in or one above it, together hold every
/// action of the roles area and of the users area, counting only
/// assignments and memberships in force and active accounts.
///
/// A store counts it without reading every record, so a check on one
/// account need not load the whole tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdministratorCount(u64);

impl AdministratorCount {
    /// `count` administrators.
    #[must_use]
    pub fn new(count: u64) -> Self {
        Self(count)
    }

    /// The number counted.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Whether the account someone acts on is the tenant's last
/// administrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stewardship {
    /// Someone else administers the tenant too, or nobody does yet.
    OthersAdminister,
    /// Only this account administers the tenant.
    LastAdministrator,
}

impl Stewardship {
    /// Determines whether `account` is the last tenant administrator.
    /// `grants` must include every assignment, group ancestor and role reaching the account;
    /// `counted` covers the whole tenant. A stale zero count still protects an administrator.
    ///
    /// # Errors
    /// Propagates the cases listed by [`TenantGrants::administrators`].
    pub fn of<T: TenantScope>(
        grants: &TenantGrants<'_, T>,
        account: &UserId,
        counted: AdministratorCount,
    ) -> Result<Self, DomainError> {
        if !grants.administrators()?.contains(account) || counted.get() > 1 {
            return Ok(Self::OthersAdminister);
        }
        Ok(Self::LastAdministrator)
    }

    /// Refuses taking away the tenant's last administrator.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when this is the last administrator.
    pub(crate) fn ensure_not_last(self) -> Result<(), DomainError> {
        match self {
            Self::OthersAdminister => Ok(()),
            Self::LastAdministrator => Err(DomainError::conflict(message!(
                "authorization-this-is-the-tenant-s-last",
                "this is the tenant's last administrator; give someone else the rights first"
            ))),
        }
    }
}

/// Refuses a change that leaves a tenant nobody can administer.
///
/// `before` is the tenant as it is, and `after` as the change would leave
/// it. Only a change that takes the last administrator away is refused. A
/// tenant that already had none is not made worse, so its changes go on.
///
/// The caller asks this for every change that can take rights away:
/// taking a role from someone, deleting or narrowing a role, taking a role
/// off a group, ending a membership, moving or deleting a group, and
/// shutting out or erasing an account.
///
/// # Errors
///
/// - [`DomainError::Conflict`] when `before` had an administrator and
///   `after` has none.
/// - The cases [`TenantGrants::administrators`] lists, for either side.
pub fn ensure_still_administered<T: TenantScope>(
    before: &TenantGrants<'_, T>,
    after: &TenantGrants<'_, T>,
) -> Result<(), DomainError> {
    if before.administrators()?.is_empty() || !after.administrators()?.is_empty() {
        return Ok(());
    }
    Err(DomainError::conflict(message!(
        "authorization-this-would-leave-nobody-able-to",
        "this would leave nobody able to manage roles and users"
    )))
}

/// Refuses a change that leaves a tenant nobody can administer, read from
/// the people it touches and the tenant's count, not from every record.
///
/// `before` and `after` are the administrators among the people the change
/// touches, as [`TenantGrants::administrators`] finds them in records
/// narrowed to those people, before the change and as it would leave them.
/// `counted` is how many administrators the whole tenant has now. The
/// change is refused when the tenant has some and every one of them is an
/// administrator the change takes away. A tenant that had none is not made
/// worse, so its changes go on.
///
/// # Errors
///
/// - [`DomainError::Conflict`] when the change takes away every
///   administrator the tenant counts.
pub fn ensure_administrators_remain(
    counted: AdministratorCount,
    before: &[UserId],
    after: &[UserId],
) -> Result<(), DomainError> {
    let lost = before.iter().filter(|admin| !after.contains(admin)).count();
    let lost = u64::try_from(lost).unwrap_or(u64::MAX);
    if counted.get() == 0 || counted.get() > lost {
        return Ok(());
    }
    Err(DomainError::conflict(message!(
        "authorization-this-would-leave-nobody-able-to",
        "this would leave nobody able to manage roles and users"
    )))
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::granter::HeldByGranter;
    use crate::domains::authorization::group::{
        CreateGroupParams, GroupMembershipRow, GroupOrigin, GroupPlace,
    };
    use crate::domains::authorization::group_tree::Conferred;
    use crate::domains::authorization::holding::NewHolding;
    use crate::domains::authorization::permission::BrandingAction;
    use crate::domains::authorization::role::permission_moves::WantedPermissions;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, RoleAssignmentRow};
    use crate::domains::federation::fixtures::switched_on_directory;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::types::{ActorRef, AgentId, EventLabel, Expiry};

    fn owner() -> HeldByGranter<'static> {
        HeldByGranter::assumed(SystemPermission::all(), &[])
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

    fn admin() -> Role<ResolvedTenant> {
        role(SystemPermission::all().to_vec())
    }

    /// Creates a dashboard group at a place whose inherited permissions were resolved.
    fn group(name: &str, place: GroupPlace, conferred: &Conferred) -> Group<ResolvedTenant> {
        Group::create(
            CreateGroupParams {
                name: label(name),
                origin: GroupOrigin::Dashboard,
                place,
            },
            conferred,
            &owner(),
        )
        .unwrap()
    }

    /// Restores yesterday's membership with the expiry used by the stewardship check.
    fn membership(
        principal: PrincipalRef,
        group_id: GroupId,
        expires: Expiry,
    ) -> GroupMembership<ResolvedTenant> {
        GroupMembership::reconstitute(GroupMembershipRow {
            principal,
            group_id,
            joined_at: crate::shared::clock::now() - Duration::days(1),
            expires,
        })
        .unwrap()
    }

    fn given(
        principal: PrincipalRef,
        role: &Role<ResolvedTenant>,
    ) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::create(principal, role, anyone_holding(SystemPermission::all())).unwrap()
    }

    fn grants<'a>(
        roles: &'a [Role<ResolvedTenant>],
        assignments: &'a [RoleAssignment<ResolvedTenant>],
    ) -> TenantGrants<'a, ResolvedTenant> {
        TenantGrants {
            roles,
            assignments,
            groups: &[],
            memberships: &[],
        }
    }

    /// Mia may only view branding, Ann holds the admin role and Sam may only
    /// view users. The holders of `branding: view` are Mia and Ann, not Sam.
    #[test]
    fn the_holders_of_a_right_are_whoever_its_roles_reach() {
        let view_branding = SystemPermission::Branding(BrandingAction::View);
        let roles = [
            role(vec![view_branding]),
            admin(),
            role(vec![SystemPermission::Users(UserAction::View)]),
        ];
        let (mia, ann, sam) = (UserId::new(), UserId::new(), UserId::new());
        let assignments = [
            given(PrincipalRef::User(mia), &roles[0]),
            given(PrincipalRef::User(ann), &roles[1]),
            given(PrincipalRef::User(sam), &roles[2]),
        ];

        let holders = grants(&roles, &assignments)
            .holders_of_right(view_branding)
            .unwrap();

        assert_eq!(holders.len(), 2);
        assert!(holders.contains(&mia) && holders.contains(&ann));
        assert!(!holders.contains(&sam));
    }

    /// Removing both administrators from a tenant that counts two is refused as
    /// a conflict.
    #[test]
    fn taking_away_every_counted_administrator_is_refused() {
        let (ann, bob) = (UserId::new(), UserId::new());

        let result = ensure_administrators_remain(AdministratorCount::new(2), &[ann, bob], &[]);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// The directory takes Ann out of Admins. The tenant counts three
    /// administrators, so two remain, and it goes through. A tenant that
    /// counts none is not made worse either.
    #[test]
    fn an_administrator_may_go_while_the_count_keeps_others() {
        let ann = UserId::new();

        let others_remain = ensure_administrators_remain(AdministratorCount::new(3), &[ann], &[]);
        let none_before = ensure_administrators_remain(AdministratorCount::new(0), &[], &[]);

        assert!(others_remain.is_ok());
        assert!(none_before.is_ok());
    }

    /// Removing the tenant's only administrator assignment is refused as a conflict.
    #[test]
    fn the_last_administrator_is_kept() {
        let roles = [admin()];
        let ann = [given(PrincipalRef::User(UserId::new()), &roles[0])];

        let result = ensure_still_administered(&grants(&roles, &ann), &grants(&roles, &[]));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// Ann and Bob are both admins. Ann's role is taken away, and Bob still
    /// runs the tenant, so it is allowed.
    #[test]
    fn an_administrator_goes_while_another_stays() {
        let roles = [admin()];
        let before = [
            given(PrincipalRef::User(UserId::new()), &roles[0]),
            given(PrincipalRef::User(UserId::new()), &roles[0]),
        ];
        let after = [given(*before[1].principal(), &roles[0])];

        let result = ensure_still_administered(&grants(&roles, &before), &grants(&roles, &after));

        assert!(result.is_ok());
    }

    /// Removing user management from the sole administrator's role fails the
    /// check that the tenant remains administered.
    #[test]
    fn narrowing_the_last_admin_role_is_refused() {
        let before_roles = [admin()];
        let ann = [given(PrincipalRef::User(UserId::new()), &before_roles[0])];
        let mut narrowed = before_roles[0].clone();
        let kept: Vec<_> = SystemPermission::all()
            .iter()
            .copied()
            .filter(|held| *held != SystemPermission::ManageUsers)
            .collect();
        narrowed
            .change_permissions(
                &WantedPermissions {
                    system: Some(&kept),
                    custom: None,
                },
                &owner(),
            )
            .unwrap();
        let after_roles = [narrowed];

        let result =
            ensure_still_administered(&grants(&before_roles, &ann), &grants(&after_roles, &ann));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// Ann is an admin through the group Admins, and Bob holds the admin
    /// role himself. Each counts. An agent holding the admin role does not,
    /// since no person stands behind it.
    #[test]
    fn administrators_come_through_groups_and_never_as_agents() {
        let roles = [admin()];
        let mut admins = group("Admins", GroupPlace::TopLevel, &Conferred::at_top());
        admins.assign_role(&roles[0], &owner()).unwrap();
        let groups = [admins];
        let conferred = GroupTree::new(&groups)
            .conferred(GroupPlace::Under(*groups[0].id()), &roles)
            .unwrap();
        let ann = UserId::new();
        let bob = UserId::new();
        let memberships = [GroupMembership::join_until(
            NewHolding::standing(PrincipalRef::User(ann), EventLabel::of("ann")),
            &groups[0],
            &conferred,
            &owner(),
        )
        .unwrap()];
        let assignments = [
            given(PrincipalRef::User(bob), &roles[0]),
            given(PrincipalRef::Agent(AgentId::new()), &roles[0]),
        ];
        let tenant = TenantGrants {
            roles: &roles,
            assignments: &assignments,
            groups: &groups,
            memberships: &memberships,
        };

        let found = tenant.administrators().unwrap();

        assert_eq!(found.len(), 2);
        assert!(found.contains(&ann) && found.contains(&bob));
    }

    /// Holding every individual role and user action makes Ann an administrator,
    /// so removing her sole assignment is refused.
    #[test]
    fn a_spelled_out_admin_role_makes_an_administrator() {
        let roles = [role(vec![
            SystemPermission::Roles(RoleAction::View),
            SystemPermission::Roles(RoleAction::Create),
            SystemPermission::Roles(RoleAction::Update),
            SystemPermission::Roles(RoleAction::Delete),
            SystemPermission::Roles(RoleAction::Assign),
            SystemPermission::Roles(RoleAction::Escalate),
            SystemPermission::Users(UserAction::View),
            SystemPermission::Users(UserAction::Create),
            SystemPermission::Users(UserAction::Update),
            SystemPermission::Users(UserAction::Deactivate),
            SystemPermission::Users(UserAction::Delete),
        ])];
        let ann = UserId::new();
        let held = [given(PrincipalRef::User(ann), &roles[0])];

        let found = grants(&roles, &held).administrators().unwrap();
        let taken = ensure_still_administered(&grants(&roles, &held), &grants(&roles, &[]));

        assert_eq!(found, [ann]);
        assert!(matches!(taken, Err(DomainError::Conflict(_))));
    }

    /// Administrator lookup rejects records as corrupt when an assignment names
    /// a role that was not loaded.
    #[test]
    fn an_assignment_naming_a_role_not_loaded_is_refused() {
        let roles = [admin()];
        let ann = [given(PrincipalRef::User(UserId::new()), &roles[0])];

        let result = grants(&[], &ann).administrators();

        assert!(refused_as_corrupt(&result));
    }

    /// Administrator lookup rejects records as corrupt when a member's group
    /// names a role that was not loaded.
    #[test]
    fn a_group_naming_a_role_not_loaded_is_refused() {
        let roles = [admin()];
        let scim = switched_on_directory();
        let mut admins = Group::<ResolvedTenant>::from_directory(label("Admins"), &scim).unwrap();
        admins.assign_role(&roles[0], &owner()).unwrap();
        let groups = [admins];
        let memberships = [GroupMembership::from_directory(
            UserId::new(),
            &groups[0],
            &scim,
            EventLabel::of("ann"),
        )
        .unwrap()];
        let tenant = TenantGrants {
            roles: &[],
            assignments: &[],
            groups: &groups,
            memberships: &memberships,
        };

        let result = tenant.administrators();

        assert!(refused_as_corrupt(&result));
    }

    /// Administrator lookup rejects a stored membership whose group was not loaded
    /// as corrupt storage.
    #[test]
    fn a_membership_of_a_group_not_loaded_is_refused() {
        let scim = switched_on_directory();
        let synced = Group::<ResolvedTenant>::from_directory(label("Synced"), &scim).unwrap();
        let memberships =
            [
                GroupMembership::from_directory(
                    UserId::new(),
                    &synced,
                    &scim,
                    EventLabel::of("ann"),
                )
                .unwrap(),
            ];
        let tenant = TenantGrants {
            roles: &[],
            assignments: &[],
            groups: &[],
            memberships: &memberships,
        };

        let result = tenant.administrators();

        assert!(refused_as_corrupt(&result));
    }

    /// An assignment of `role` to `principal` stored as ending at `expires`.
    fn stored_until(
        principal: PrincipalRef,
        role: &Role<ResolvedTenant>,
        expires: Expiry,
    ) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal,
            role_id: *role.id(),
            assigned_by: ActorRef::System,
            assigned_at: crate::shared::clock::now() - Duration::days(7),
            expires,
        })
        .unwrap()
    }

    /// Bob's expired assignment grants no roles and does not count him as an
    /// administrator or holder. Ann's unexpired assignment still counts for both.
    #[test]
    fn an_ended_assignment_gives_nothing_before_it_is_swept() {
        let roles = [admin()];
        let bob = UserId::new();
        let ann = UserId::new();
        let ended = Expiry::At(crate::shared::clock::now() - Duration::hours(1));
        let held = [
            stored_until(PrincipalRef::User(bob), &roles[0], ended),
            stored_until(PrincipalRef::User(ann), &roles[0], Expiry::Never),
        ];
        let tenant = grants(&roles, &held);

        assert_eq!(tenant.administrators().unwrap(), [ann]);
        assert!(
            tenant
                .roles_held_by(PrincipalRef::User(bob))
                .unwrap()
                .is_empty()
        );
        assert_eq!(tenant.holders_of(roles[0].id()), [PrincipalRef::User(ann)]);
    }

    /// Ann is in Backend, under Engineering. Her groups are both, which a
    /// policy's group condition reads. Bob's ended membership of Backend
    /// gives him none.
    #[test]
    fn a_principals_groups_are_those_they_are_in_and_those_above() {
        let engineering = group("Engineering", GroupPlace::TopLevel, &Conferred::at_top());
        let mut groups = vec![engineering];
        let backend_place = GroupPlace::Under(*groups[0].id());
        let backend_brings = GroupTree::new(&groups)
            .conferred(backend_place, &[])
            .unwrap();
        let backend = group("Backend", backend_place, &backend_brings);
        groups.push(backend);
        let ann = PrincipalRef::User(UserId::new());
        let bob = PrincipalRef::User(UserId::new());
        let ended = Expiry::At(crate::shared::clock::now() - Duration::hours(1));
        let memberships = [
            membership(ann, *groups[1].id(), Expiry::Never),
            membership(bob, *groups[1].id(), ended),
        ];
        let tenant = TenantGrants {
            roles: &[],
            assignments: &[],
            groups: &groups,
            memberships: &memberships,
        };

        let anns = tenant.groups_of(ann).unwrap();

        assert_eq!(anns.len(), 2);
        assert!(anns.contains(groups[0].id()) && anns.contains(groups[1].id()));
        assert!(tenant.groups_of(bob).unwrap().is_empty());
        assert_eq!(tenant.members_of(groups[1].id()), [ann]);
    }

    /// A tenant whose admins all lost their rights long ago has none. Taking
    /// a viewer role from Carol is not refused, since it leaves the tenant
    /// no worse.
    #[test]
    fn a_tenant_without_administrators_is_not_made_worse() {
        let roles = [role(vec![SystemPermission::Users(UserAction::View)])];
        let carol = [given(PrincipalRef::User(UserId::new()), &roles[0])];

        let result = ensure_still_administered(&grants(&roles, &carol), &grants(&roles, &[]));

        assert!(result.is_ok());
    }
}
