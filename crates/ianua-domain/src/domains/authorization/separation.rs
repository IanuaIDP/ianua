//! Separation of duties: pairs of roles nobody may hold together.
//!
//! Whoever raises a payment should not also approve it. A tenant names the
//! two roles once, and from then on nobody is given the second while
//! holding the first, whether straight, through a group they join, or
//! through a role added to a group they are in.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::separation::{
    SeparationRuleAdded, SeparationRuleRemoved,
};
use crate::domains::authorization::group_tree::Conferred;
use crate::domains::authorization::permission::{RoleAction, SystemPermission};
use crate::domains::authorization::role::Role;
use crate::domains::authorization::stewardship::TenantGrants;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{GroupId, Label, PrincipalRef, RoleId, SeparationRuleId};

/// The right that adds and lifts a rule: the right to update roles.
const SHAPES_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Update);

/// Two roles nobody in the tenant may hold together.
#[derive(Debug)]
pub struct SeparationRule<T: TenantScope> {
    id: SeparationRuleId,
    name: Label,
    first: RoleId,
    second: RoleId,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A [`SeparationRule`] as storage holds it, read back through
/// [`SeparationRule::reconstitute`].
pub struct SeparationRuleRow {
    /// The rule.
    pub id: SeparationRuleId,
    /// What it is called, such as "raise or approve payments".
    pub name: Label,
    /// One of the two roles.
    pub first: RoleId,
    /// The other.
    pub second: RoleId,
    /// When it was added.
    pub created_at: OffsetDateTime,
}

impl<T: TenantScope> SeparationRule<T> {
    /// Declares that nobody holds `first` and `second` together, for `by`.
    /// Raises `authorization.separation_rule_added`.
    ///
    /// It applies to what is given from now on. People who already hold
    /// both are found by an access review, not taken out by this.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update roles.
    /// - [`DomainError::Validation`] when both are one role.
    pub fn declare(
        name: Label,
        first: &Role<T>,
        second: &Role<T>,
        by: &TenantAuthority,
    ) -> Result<Self, DomainError> {
        by.ensure_holds(SHAPES_ROLES)?;
        if first.id() == second.id() {
            return Err(DomainError::invalid(message!(
                "authorization-a-role-cannot-be-kept-apart",
                "a role cannot be kept apart from itself"
            )));
        }
        let mut rule = Self {
            id: SeparationRuleId::new(),
            name,
            first: *first.id(),
            second: *second.id(),
            created_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        rule.raised.raise(SeparationRuleAdded {
            rule_id: rule.id,
            name: rule.name.clone(),
            first: first.label(),
            second: second.label(),
            occurred_at: rule.created_at,
        });
        Ok(rule)
    }

    /// Lifts the rule, for `by`: the two roles may be held together again.
    /// Raises `authorization.separation_rule_removed`, taken once the rule
    /// is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update roles.
    pub fn lift(&mut self, by: &TenantAuthority) -> Result<(), DomainError> {
        by.ensure_holds(SHAPES_ROLES)?;
        self.raised.raise(SeparationRuleRemoved {
            rule_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Rebuilds a rule from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when both roles are one.
    pub fn reconstitute(row: SeparationRuleRow) -> Result<Self, DomainError> {
        RowCheck::of("separation rule")
            .holds(row.first != row.second, "a role kept apart from itself")
            .finish()?;
        Ok(Self {
            id: row.id,
            name: row.name,
            first: row.first,
            second: row.second,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The rule.
    #[must_use]
    pub fn id(&self) -> &SeparationRuleId {
        &self.id
    }

    /// What it is called.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The two roles kept apart.
    #[must_use]
    pub fn roles(&self) -> (&RoleId, &RoleId) {
        (&self.first, &self.second)
    }

    /// When it was added.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether `held` holds both roles.
    #[must_use]
    pub fn is_broken_by(&self, held: &[RoleId]) -> bool {
        held.contains(&self.first) && held.contains(&self.second)
    }
}

impl<T: TenantScope> Raises for SeparationRule<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// The tenant's separation rules, read with who holds what, to ask before
/// a role reaches someone.
#[derive(Debug)]
pub struct DutySeparation<'a, T: TenantScope> {
    /// Every separation rule of the tenant.
    pub rules: &'a [SeparationRule<T>],
    /// Who holds which roles now.
    pub grants: &'a TenantGrants<'a, T>,
}

impl<T: TenantScope> DutySeparation<'_, T> {
    /// Refuses giving `role` to `principal` when they would then hold both
    /// roles of a rule.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] naming the rule broken.
    /// - The cases [`TenantGrants::administrators`] lists.
    pub fn ensure_assignable(
        &self,
        principal: PrincipalRef,
        role: &RoleId,
    ) -> Result<(), DomainError> {
        self.ensure_may_add(principal, std::slice::from_ref(role))
    }

    /// Refuses putting `principal` into the group `conferred` was worked out
    /// for when they would then hold both roles of a rule.
    ///
    /// # Errors
    ///
    /// - As [`ensure_assignable`](Self::ensure_assignable).
    pub fn ensure_joinable(
        &self,
        principal: PrincipalRef,
        conferred: &Conferred,
    ) -> Result<(), DomainError> {
        self.ensure_may_add(principal, conferred.roles())
    }

    /// Refuses giving `role` to `group` when someone in it, or in a group
    /// under it, would then hold both roles of a rule.
    ///
    /// # Errors
    ///
    /// - As [`ensure_assignable`](Self::ensure_assignable).
    pub fn ensure_group_may_hold(&self, group: &GroupId, role: &RoleId) -> Result<(), DomainError> {
        for principal in self.grants.members_within(group)? {
            self.ensure_may_add(principal, std::slice::from_ref(role))?;
        }
        Ok(())
    }

    /// Refuses moving `group` to the place `to` was worked out for when
    /// someone in it, or in a group under it, would then hold both roles of
    /// a rule they do not both hold now.
    ///
    /// The members leave what the old place brings and gain what the new
    /// one does, so a rule already broken before the move is left to an
    /// access review, as with any rule added after the fact.
    ///
    /// # Errors
    ///
    /// - As [`ensure_assignable`](Self::ensure_assignable).
    pub fn ensure_group_may_move(
        &self,
        group: &GroupId,
        to: &Conferred,
    ) -> Result<(), DomainError> {
        for principal in self.grants.members_within(group)? {
            let before = self.held_by(principal)?;
            let after = self.grants.roles_after_move(principal, group, to)?;
            let newly_broken = self
                .rules
                .iter()
                .find(|rule| rule.is_broken_by(&after) && !rule.is_broken_by(&before));
            if let Some(broken) = newly_broken {
                return Err(broken_rule(broken));
            }
        }
        Ok(())
    }

    /// The ids of the roles `principal` holds now.
    fn held_by(&self, principal: PrincipalRef) -> Result<Vec<RoleId>, DomainError> {
        Ok(self
            .grants
            .roles_held_by(principal)?
            .into_iter()
            .map(|role| *role.id())
            .collect())
    }

    /// Refuses `adding` to what `principal` holds now when a rule would
    /// then be broken.
    fn ensure_may_add(
        &self,
        principal: PrincipalRef,
        adding: &[RoleId],
    ) -> Result<(), DomainError> {
        let mut held = self.held_by(principal)?;
        held.extend_from_slice(adding);
        let Some(broken) = self.rules.iter().find(|rule| rule.is_broken_by(&held)) else {
            return Ok(());
        };
        Err(broken_rule(broken))
    }
}

/// The refusal naming `rule`, which a grant would break.
fn broken_rule<T: TenantScope>(rule: &SeparationRule<T>) -> DomainError {
    DomainError::conflict(message!(
        "authorization-this-breaks-the-separation-of-duties",
        format!(
            "this breaks the separation of duties '{}': nobody holds both its roles",
            rule.name
        )
    ))
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::fixtures::{Records, role};
    use crate::domains::authorization::granter::HeldByGranter;
    use crate::domains::authorization::group::{
        Group, GroupMembership, GroupMembershipRow, GroupPlace,
    };
    use crate::domains::authorization::group_tree::GroupTree;
    use crate::domains::authorization::role::{RoleAssignment, RoleAssignmentRow};
    use crate::domains::federation::fixtures::switched_on_directory;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{ActorRef, Expiry, UserId};

    fn updater() -> &'static TenantAuthority {
        anyone_holding(&[SHAPES_ROLES])
    }

    /// The tenant: Ann raises payments; nobody may also approve them.
    struct Payments {
        records: Records,
        rules: Vec<SeparationRule<ResolvedTenant>>,
        ann: PrincipalRef,
    }

    fn payments(ann_until: Expiry) -> Payments {
        let raiser = role("raise payments", &[], &["payment:raise"]);
        let approver = role("approve payments", &[], &["payment:approve"]);
        let viewer = role("view payments", &[], &["payment:read"]);
        let rule =
            SeparationRule::declare(label("raise or approve"), &raiser, &approver, updater())
                .unwrap();
        let ann = PrincipalRef::User(UserId::new());
        let given = RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: ann,
            role_id: *raiser.id(),
            assigned_by: ActorRef::System,
            assigned_at: crate::shared::clock::now() - Duration::days(30),
            expires: ann_until,
        })
        .unwrap();
        Payments {
            records: Records {
                roles: vec![raiser, approver, viewer],
                assignments: vec![given],
                ..Records::default()
            },
            rules: vec![rule],
            ann,
        }
    }

    impl Payments {
        fn role(&self, at: usize) -> RoleId {
            *self.records.roles[at].id()
        }
    }

    /// A standing group membership whose inherited roles count for duty separation.
    fn membership(principal: PrincipalRef, group_id: GroupId) -> GroupMembership<ResolvedTenant> {
        GroupMembership::reconstitute(GroupMembershipRow {
            principal,
            group_id,
            joined_at: crate::shared::clock::now(),
            expires: Expiry::Never,
        })
        .unwrap()
    }

    /// Ann's payment-raising role prevents assigning her the conflicting
    /// approval role, while the viewer role remains assignable.
    #[test]
    fn a_role_that_breaks_a_rule_is_not_given() {
        let tenant = payments(Expiry::Never);
        let access = tenant.records.access();
        let duties = DutySeparation {
            rules: &tenant.rules,
            grants: &access.grants,
        };

        let approver = duties.ensure_assignable(tenant.ann, &tenant.role(1));
        let viewer = duties.ensure_assignable(tenant.ann, &tenant.role(2));

        assert!(matches!(approver, Err(DomainError::Conflict(_))));
        assert!(viewer.is_ok());
    }

    /// Ann's raising role ended yesterday. She may now be given the
    /// approving role.
    #[test]
    fn an_ended_role_breaks_no_rule() {
        let yesterday = crate::shared::clock::now() - Duration::days(1);
        let tenant = payments(Expiry::At(yesterday));
        let access = tenant.records.access();
        let duties = DutySeparation {
            rules: &tenant.rules,
            grants: &access.grants,
        };

        assert!(
            duties
                .ensure_assignable(tenant.ann, &tenant.role(1))
                .is_ok()
        );
    }

    /// Ann cannot gain payment approval by joining Approvers or by adding the
    /// approval role to Finance while she holds the conflicting raising role.
    #[test]
    fn a_rule_holds_through_groups_both_ways() {
        let mut tenant = payments(Expiry::Never);
        let mut approvers =
            Group::from_directory(label("Approvers"), &switched_on_directory()).unwrap();
        approvers
            .assign_role(
                &tenant.records.roles[1],
                &HeldByGranter::assumed(SystemPermission::all(), &[]),
            )
            .unwrap();
        let finance = Group::from_directory(label("Finance"), &switched_on_directory()).unwrap();
        let finance_id = *finance.id();
        tenant.records.memberships = vec![membership(tenant.ann, finance_id)];
        tenant.records.groups = vec![approvers, finance];
        let joining = GroupTree::new(&tenant.records.groups)
            .conferred(
                GroupPlace::Under(*tenant.records.groups[0].id()),
                &tenant.records.roles,
            )
            .unwrap();
        let access = tenant.records.access();
        let duties = DutySeparation {
            rules: &tenant.rules,
            grants: &access.grants,
        };

        let joined = duties.ensure_joinable(tenant.ann, &joining);
        let given_to_finance = duties.ensure_group_may_hold(&finance_id, &tenant.role(1));

        assert!(matches!(joined, Err(DomainError::Conflict(_))));
        assert!(matches!(given_to_finance, Err(DomainError::Conflict(_))));
    }

    /// Moving Finance under Approvers is refused because Ann would gain a role
    /// conflicting with payment raising. Moving Finance to the top is allowed.
    #[test]
    fn a_rule_holds_when_a_group_moves() {
        let mut tenant = payments(Expiry::Never);
        let held_by_all = HeldByGranter::assumed(SystemPermission::all(), &[]);
        let mut approvers =
            Group::from_directory(label("Approvers"), &switched_on_directory()).unwrap();
        approvers
            .assign_role(&tenant.records.roles[1], &held_by_all)
            .unwrap();
        let approvers_id = *approvers.id();
        let finance = Group::from_directory(label("Finance"), &switched_on_directory()).unwrap();
        let finance_id = *finance.id();
        tenant.records.memberships = vec![membership(tenant.ann, finance_id)];
        tenant.records.groups = vec![approvers, finance];
        let tree = GroupTree::new(&tenant.records.groups);
        let under_approvers = tree
            .conferred(GroupPlace::Under(approvers_id), &tenant.records.roles)
            .unwrap();
        let access = tenant.records.access();
        let duties = DutySeparation {
            rules: &tenant.rules,
            grants: &access.grants,
        };

        let moved_under = duties.ensure_group_may_move(&finance_id, &under_approvers);
        let moved_up = duties.ensure_group_may_move(&finance_id, &Conferred::at_top());

        assert!(matches!(moved_under, Err(DomainError::Conflict(_))));
        assert!(moved_up.is_ok());
    }

    /// A role viewer cannot add or lift separation rules, and even an authorized
    /// editor cannot separate a role from itself.
    #[test]
    fn a_rule_is_shaped_only_by_someone_who_may_update_roles() {
        let mut tenant = payments(Expiry::Never);
        let sam = anyone_holding(&[SystemPermission::Roles(RoleAction::View)]);
        let roles = &tenant.records.roles;

        let added = SeparationRule::declare(label("again"), &roles[0], &roles[1], sam);
        let itself = SeparationRule::declare(label("self"), &roles[0], &roles[0], updater());
        let lifted = tenant.rules[0].lift(sam);

        assert!(matches!(added, Err(DomainError::Forbidden(_))));
        assert!(matches!(itself, Err(DomainError::Validation(_))));
        assert!(matches!(lifted, Err(DomainError::Forbidden(_))));
    }

    /// A rule is added and later lifted. Each is raised.
    #[test]
    fn adding_and_lifting_a_rule_is_recorded() {
        let mut tenant = payments(Expiry::Never);
        let rule = &mut tenant.rules[0];

        let added = raised_names(rule);
        rule.lift(updater()).unwrap();

        assert_eq!(added, ["authorization.separation_rule_added"]);
        assert_eq!(
            raised_names(rule),
            ["authorization.separation_rule_removed"]
        );
    }

    /// A stored separation rule naming the same role twice is rejected as corrupt.
    #[test]
    fn a_stored_rule_on_one_role_is_refused() {
        let role = RoleId::new();

        let stored = SeparationRule::<ResolvedTenant>::reconstitute(SeparationRuleRow {
            id: SeparationRuleId::new(),
            name: label("broken"),
            first: role,
            second: role,
            created_at: crate::shared::clock::now(),
        });

        assert!(refused_as_corrupt(&stored));
    }
}
