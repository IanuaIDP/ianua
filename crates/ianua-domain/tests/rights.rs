// Failed fixture construction or assertions must stop this test target immediately.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Properties of handing out rights, checked over generated sequences of
//! changes.
//!
//! Random granters, each holding a random set of built-in permissions,
//! create roles, add permissions to them, give roles to people and groups,
//! and put people into groups. Each change is either refused or leaves every
//! person holding only what someone who acted on them held. Sam may view
//! users. No order of changes lets him leave Bob holding "manage users".

use std::collections::{HashMap, HashSet};

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::granter::HeldByGranter;
use ianua_domain::domains::authorization::group::{
    CreateGroupParams, Group, GroupMembership, GroupOrigin, GroupPlace,
};
use ianua_domain::domains::authorization::group_tree::{Conferred, GroupTree};
use ianua_domain::domains::authorization::holding::NewHolding;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::role::permission_moves::WantedPermissions;
use ianua_domain::domains::authorization::role::{
    DefaultAssignment, NewRole, Role, RoleAssignment,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    EventLabel, GroupId, Human, HumanAccount, Label, PersonKey, PrincipalRef, RoleId, TenantId,
    UserId,
};
use proptest::prelude::*;
use proptest::sample::{Index, select, subsequence};

/// How many people each sequence works on.
const PEOPLE: usize = 4;
/// How many groups each sequence works on.
const GROUPS: usize = 3;

/// The built-in permissions one granter holds.
type Held = Vec<SystemPermission>;

/// One change a granter tries to make.
#[derive(Debug, Clone)]
enum Step {
    CreateRole {
        granter: Held,
        permissions: Held,
    },
    GrantPermission {
        granter: Held,
        role: Index,
        permission: SystemPermission,
    },
    AssignRole {
        granter: Held,
        person: Index,
        role: Index,
    },
    GiveGroupRole {
        granter: Held,
        group: Index,
        role: Index,
    },
    JoinGroup {
        granter: Held,
        person: Index,
        group: Index,
    },
}

/// A granter: mostly a few random permissions, now and then everything.
fn granter() -> impl Strategy<Value = Held> {
    prop_oneof![
        3 => subsequence(SystemPermission::ALL_VARIANTS, 0..5),
        1 => Just(SystemPermission::ALL_VARIANTS.to_vec()),
    ]
}

fn permission() -> impl Strategy<Value = SystemPermission> {
    select(SystemPermission::ALL_VARIANTS)
}

/// A role creation with independently generated held and requested permissions.
fn role_creation() -> impl Strategy<Value = Step> {
    (granter(), subsequence(SystemPermission::ALL_VARIANTS, 0..4)).prop_map(
        |(granter, permissions)| Step::CreateRole {
            granter,
            permissions,
        },
    )
}

/// A request to add one permission to an existing role.
fn permission_grant() -> impl Strategy<Value = Step> {
    (granter(), any::<Index>(), permission()).prop_map(|(granter, role, permission)| {
        Step::GrantPermission {
            granter,
            role,
            permission,
        }
    })
}

/// Each kind of rights change is generated with equal weight.
fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        role_creation(),
        permission_grant(),
        (granter(), any::<Index>(), any::<Index>()).prop_map(|(granter, person, role)| {
            Step::AssignRole {
                granter,
                person,
                role,
            }
        }),
        (granter(), any::<Index>(), any::<Index>()).prop_map(|(granter, group, role)| {
            Step::GiveGroupRole {
                granter,
                group,
                role,
            }
        }),
        (granter(), any::<Index>(), any::<Index>()).prop_map(|(granter, person, group)| {
            Step::JoinGroup {
                granter,
                person,
                group,
            }
        }),
    ]
}

fn held(granter: &[SystemPermission]) -> HeldByGranter<'_> {
    HeldByGranter::assumed(granter, &[])
}

/// Someone signed in to the tenant who holds `granter`.
fn signed_in(granter: &[SystemPermission]) -> TenantAuthority {
    let someone = Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new("granter@acme.test").unwrap(),
    );
    TenantAuthority::assumed(someone, TenantId::new(), granter, &[])
}

/// The people, roles and groups a sequence works on, and who acted on each.
struct World {
    people: Vec<PrincipalRef>,
    roles: Vec<Role<ResolvedTenant>>,
    groups: Vec<Group<ResolvedTenant>>,
    assignments: Vec<RoleAssignment<ResolvedTenant>>,
    memberships: Vec<GroupMembership<ResolvedTenant>>,
    acted_on_person: HashMap<PrincipalRef, Vec<Held>>,
    acted_on_role: HashMap<RoleId, Vec<Held>>,
    acted_on_group: HashMap<GroupId, Vec<Held>>,
}

impl World {
    fn new() -> Self {
        Self {
            people: (0..PEOPLE)
                .map(|_| PrincipalRef::User(UserId::new()))
                .collect(),
            roles: Vec::new(),
            groups: (0..GROUPS).map(dashboard_group).collect(),
            assignments: Vec::new(),
            memberships: Vec::new(),
            acted_on_person: HashMap::new(),
            acted_on_role: HashMap::new(),
            acted_on_group: HashMap::new(),
        }
    }

    fn apply(&mut self, step: Step) {
        match step {
            Step::CreateRole {
                granter,
                permissions,
            } => self.create_role(granter, permissions),
            Step::GrantPermission {
                granter,
                role,
                permission,
            } => self.grant_permission(granter, role, permission),
            Step::AssignRole {
                granter,
                person,
                role,
            } => self.assign_role(granter, person, role),
            Step::GiveGroupRole {
                granter,
                group,
                role,
            } => self.give_group_role(granter, group, role),
            Step::JoinGroup {
                granter,
                person,
                group,
            } => self.join_group(granter, person, group),
        }
    }

    fn create_role(&mut self, granter: Held, permissions: Held) {
        let new = NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", "team").unwrap(),
            system_permissions: permissions,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        };
        let Ok(role) = Role::<ResolvedTenant>::create(new, &held(&granter)) else {
            return;
        };
        self.acted_on_role
            .entry(*role.id())
            .or_default()
            .push(granter);
        self.roles.push(role);
    }

    fn grant_permission(&mut self, granter: Held, role: Index, permission: SystemPermission) {
        if self.roles.is_empty() {
            return;
        }
        let at = role.index(self.roles.len());
        let role = &mut self.roles[at];
        let wanted = [role.system_permissions(), &[permission]].concat();
        let change = WantedPermissions {
            system: Some(&wanted),
            custom: None,
        };
        if role.change_permissions(&change, &held(&granter)).is_err() {
            return;
        }
        self.acted_on_role
            .entry(*role.id())
            .or_default()
            .push(granter);
    }

    fn assign_role(&mut self, granter: Held, person: Index, role: Index) {
        if self.roles.is_empty() {
            return;
        }
        let person = self.people[person.index(PEOPLE)];
        let role = &self.roles[role.index(self.roles.len())];
        let Ok(assignment) = RoleAssignment::create(person, role, &signed_in(&granter)) else {
            return;
        };
        self.assignments.push(assignment);
        self.acted_on_person
            .entry(person)
            .or_default()
            .push(granter);
    }

    fn give_group_role(&mut self, granter: Held, group: Index, role: Index) {
        if self.roles.is_empty() {
            return;
        }
        let role = &self.roles[role.index(self.roles.len())];
        let group = &mut self.groups[group.index(GROUPS)];
        if group.assign_role(role, &held(&granter)).is_err() {
            return;
        }
        self.acted_on_group
            .entry(*group.id())
            .or_default()
            .push(granter);
    }

    fn join_group(&mut self, granter: Held, person: Index, group: Index) {
        let person = self.people[person.index(PEOPLE)];
        let group = &self.groups[group.index(GROUPS)];
        let tree = GroupTree::new(&self.groups);
        let Ok(conferred) = tree.conferred(GroupPlace::Under(*group.id()), &self.roles) else {
            return;
        };
        let member_label = EventLabel::of(&person.id().to_string());
        let Ok(membership) = GroupMembership::join_until(
            NewHolding::standing(person, member_label),
            group,
            &conferred,
            &held(&granter),
        ) else {
            return;
        };
        self.memberships.push(membership);
        self.acted_on_person
            .entry(person)
            .or_default()
            .push(granter);
    }

    /// Every built-in permission the roles named by `role_ids` grant.
    fn permissions_of(&self, role_ids: &[RoleId]) -> Held {
        self.roles
            .iter()
            .filter(|role| role_ids.contains(role.id()))
            .flat_map(|role| role.system_permissions().iter().copied())
            .collect()
    }

    /// The groups `person` is in.
    fn groups_of(&self, person: PrincipalRef) -> Vec<&Group<ResolvedTenant>> {
        let joined: HashSet<GroupId> = self
            .memberships
            .iter()
            .filter(|membership| *membership.principal() == person)
            .map(|membership| *membership.group_id())
            .collect();
        self.groups
            .iter()
            .filter(|group| joined.contains(group.id()))
            .collect()
    }

    /// The roles `person` holds, directly or through a group.
    fn roles_of(&self, person: PrincipalRef) -> Vec<RoleId> {
        let direct = self
            .assignments
            .iter()
            .filter(|assignment| *assignment.principal() == person)
            .map(|assignment| *assignment.role_id());
        let through_groups = self
            .groups_of(person)
            .into_iter()
            .flat_map(|group| group.role_ids().iter().copied());
        direct.chain(through_groups).collect()
    }

    /// Everyone who acted on `person`: on them, on a role they hold, or on a
    /// group they are in.
    fn acted_on(&self, person: PrincipalRef) -> Vec<&Held> {
        let on_person = self.acted_on_person.get(&person).into_iter().flatten();
        let roles = self.roles_of(person);
        let on_roles = roles
            .iter()
            .filter_map(|role| self.acted_on_role.get(role))
            .flatten();
        let on_groups = self
            .groups_of(person)
            .into_iter()
            .filter_map(|group| self.acted_on_group.get(group.id()))
            .flatten();
        on_person.chain(on_roles).chain(on_groups).collect()
    }

    /// The first permission someone holds that nobody who acted on them held.
    fn unvouched_permission(&self) -> Option<(PrincipalRef, SystemPermission)> {
        self.people.iter().find_map(|person| {
            let acted = self.acted_on(*person);
            self.permissions_of(&self.roles_of(*person))
                .into_iter()
                .find(|permission| !vouched(&acted, permission))
                .map(|permission| (*person, permission))
        })
    }
}

/// Whether one of `granters` held `permission`, as it is or through a wider one.
fn vouched(granters: &[&Held], permission: &SystemPermission) -> bool {
    granters
        .iter()
        .any(|granter| granter.iter().any(|held| held.implies(permission)))
}

fn dashboard_group(n: usize) -> Group<ResolvedTenant> {
    Group::create(
        CreateGroupParams {
            name: Label::new("group_name", format!("group {n}")).unwrap(),
            origin: GroupOrigin::Dashboard,
            place: GroupPlace::TopLevel,
        },
        &Conferred::at_top(),
        &held(SystemPermission::ALL_VARIANTS),
    )
    .unwrap()
}

proptest! {
    /// After each generated role, permission or group change, every permission
    /// a person holds is vouched for by a granter who acted on that person,
    /// role or group.
    #[test]
    fn nobody_holds_a_permission_no_granter_who_acted_on_them_held(
        steps in prop::collection::vec(step(), 1..40)
    ) {
        let mut world = World::new();

        for step in steps {
            world.apply(step.clone());

            prop_assert_eq!(world.unvouched_permission(), None, "after {:?}", step);
        }
    }
}
