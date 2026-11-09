//! The roles and policies part of a clone: roles, groups and the access
//! policy, without who holds any of them, with the resource types their
//! permissions name and the rules beside them, which `rules` copies.
//!
//! A role or group the target has by the same name takes the source's
//! permissions, roles and place, and keeps its id, so whoever the target
//! gave it to holds the copied version; every other one is added. Groups
//! are written parents first, as each names the one it sits under. The
//! policy's rules name roles and groups by id, so each is put in the
//! target's terms; one naming a role or group the source no longer has
//! keeps the id, which matches no one in the target either.
//!
//! The policy arrives as the target's draft, never live: a policy goes live
//! only through review, and copying one is no exception. A draft the target
//! had open takes the copied rules in its place; one in review is refused,
//! since replacing a version someone is deciding would decide it for them.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_app::listing::SortOrder;
use ianua_app::ports::authorization::{GroupStore as _, PolicyStore as _, RoleStore as _};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::group::{Group, GroupPlace, GroupRow};
use ianua_domain::domains::authorization::policy::condition::PolicyCondition;
use ianua_domain::domains::authorization::policy::review::Submission;
use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::{PolicySet, PolicySetRow};
use ianua_domain::domains::authorization::policy::status::PolicyStatus;
use ianua_domain::domains::authorization::policy::version::{
    PolicyHistory, PolicyVersion, VersionBase,
};
use ianua_domain::domains::authorization::role::{DefaultAssignment, Role, RoleRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, RoleId};
use time::OffsetDateTime;

use crate::postgres::authorization::{PgGroupStore, PgPolicyStore, PgRoleStore};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::tenant::copies::rules::RuleCopy;
use crate::postgres::tenant::copies::{Pair, all_of, whole_part};

/// Copies a tenant's roles, groups and access policy.
pub(crate) struct AccessCopy {
    roles: PgRoleStore,
    groups: PgGroupStore,
    policies: PgPolicyStore,
    rules: RuleCopy,
}

/// What the source's roles and groups are called in the target, and when
/// the copy is made.
struct Renames {
    roles: HashMap<RoleId, RoleId>,
    groups: HashMap<GroupId, GroupId>,
    now: OffsetDateTime,
}

impl AccessCopy {
    /// A copy reading and writing the tenants of `databases`.
    pub(crate) fn new(databases: &Arc<Databases>) -> Self {
        Self {
            roles: PgRoleStore::new(Arc::clone(databases)),
            groups: PgGroupStore::new(Arc::clone(databases)),
            policies: PgPolicyStore::new(Arc::clone(databases)),
            rules: RuleCopy::new(databases),
        }
    }

    /// Gives `pair`'s target the source's resource types, roles, groups,
    /// policy, and the rules beside them.
    pub(crate) async fn copy(&self, pair: &Pair) -> Result<(), DomainError> {
        let now = clock::now();
        self.rules.copy_resource_types(pair, now).await?;
        let roles = self.copy_roles(pair, now).await?;
        let mut renames = Renames {
            roles,
            groups: HashMap::new(),
            now,
        };
        renames.groups = self.copy_groups(pair, &renames).await?;
        self.copy_policy(pair, &renames).await?;
        self.rules.copy_after_roles(pair, &renames.roles, now).await
    }

    /// Every role of `tenant`.
    async fn roles_of(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let page = self
            .roles
            .list_all(tenant, &SortOrder::default(), &whole_part())
            .await?;
        all_of(page, "roles")
    }

    /// Every group of `tenant`.
    async fn groups_of(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
        let page = self
            .groups
            .list_all(tenant, &SortOrder::default(), &whole_part())
            .await?;
        all_of(page, "groups")
    }

    /// Writes the source's roles over the target's, and answers what each
    /// is called there.
    async fn copy_roles(
        &self,
        pair: &Pair,
        now: OffsetDateTime,
    ) -> Result<HashMap<RoleId, RoleId>, DomainError> {
        let source = self.roles_of(&pair.source).await?;
        let target = self.roles_of(&pair.target).await?;
        let held: HashMap<&str, &Role<ResolvedTenant>> = target
            .iter()
            .map(|role| (role.name().as_str(), role))
            .collect();
        let mut renamed = HashMap::with_capacity(source.len());
        for role in &source {
            let copy = role_for_target(role, held.get(role.name().as_str()).copied(), now)?;
            self.roles.save(&pair.target, &copy).await?;
            renamed.insert(*role.id(), *copy.id());
        }
        Ok(renamed)
    }

    /// Writes the source's groups over the target's, parents first, and
    /// answers what each is called there.
    async fn copy_groups(
        &self,
        pair: &Pair,
        renames: &Renames,
    ) -> Result<HashMap<GroupId, GroupId>, DomainError> {
        let source = parents_first(self.groups_of(&pair.source).await?);
        let target = self.groups_of(&pair.target).await?;
        let held: HashMap<&str, &Group<ResolvedTenant>> = target
            .iter()
            .map(|group| (group.name().as_str(), group))
            .collect();
        let mut placed = HashMap::with_capacity(source.len());
        for group in &source {
            let kept = held.get(group.name().as_str()).copied();
            let place = placed_under(group.place(), &placed)?;
            let copy = renames.group(group, kept, place)?;
            self.groups.save(&pair.target, &copy).await?;
            placed.insert(*group.id(), *copy.id());
        }
        Ok(placed)
    }

    /// Writes the source's live policy as the target's draft.
    async fn copy_policy(&self, pair: &Pair, renames: &Renames) -> Result<(), DomainError> {
        let Some(live) = self.policies.find_active(&pair.source).await? else {
            return Ok(());
        };
        let versions = self.policies.find_versions(&pair.target).await?;
        let (version, based_on) = draft_place(&PolicyHistory::of(&versions)?)?;
        let rules = live
            .rules()
            .iter()
            .map(|rule| renames.rule(rule))
            .collect::<Result<Vec<_>, _>>()?;
        let draft = PolicySet::reconstitute(PolicySetRow {
            rules,
            default_action: live.default_action().clone(),
            status: PolicyStatus::Draft,
            version,
            based_on,
            submitted: Submission::NotSubmitted,
        })?;
        self.policies.save(&pair.target, &draft).await
    }
}

impl Renames {
    /// `group` as the target keeps it: under `place`, with the roles in the
    /// target's terms, under the id of `kept` when the target has it.
    fn group(
        &self,
        group: &Group<ResolvedTenant>,
        kept: Option<&Group<ResolvedTenant>>,
        place: GroupPlace,
    ) -> Result<Group<ResolvedTenant>, DomainError> {
        let role_ids = group
            .role_ids()
            .iter()
            .map(|role| {
                self.roles.get(role).copied().ok_or_else(|| {
                    DomainError::infra_msg("a group carries a role the copy did not carry over")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Group::reconstitute(GroupRow {
            id: kept.map_or_else(GroupId::new, |held| *held.id()),
            name: group.name().clone(),
            origin: group.origin(),
            place,
            role_ids,
            created_at: kept.map_or(self.now, Group::created_at),
            updated_at: self.now,
        })
    }

    /// `rule` naming the target's roles and groups.
    fn rule(&self, rule: &PolicyRule) -> Result<PolicyRule, DomainError> {
        let conditions = rule
            .conditions()
            .iter()
            .map(|condition| self.condition(condition))
            .collect();
        Ok(rule.with_conditions(conditions)?)
    }

    /// `condition` naming the target's role or group, where it names one.
    fn condition(&self, condition: &PolicyCondition) -> PolicyCondition {
        match condition {
            PolicyCondition::RoleIs(role) => PolicyCondition::RoleIs(self.role(role)),
            PolicyCondition::RoleIsNot(role) => PolicyCondition::RoleIsNot(self.role(role)),
            PolicyCondition::GroupIs(group) => PolicyCondition::GroupIs(self.group_id(group)),
            PolicyCondition::GroupIsNot(group) => PolicyCondition::GroupIsNot(self.group_id(group)),
            PolicyCondition::PathPrefix(_)
            | PolicyCondition::PathExact(_)
            | PolicyCondition::CountryIn(_)
            | PolicyCondition::CountryNotIn(_)
            | PolicyCondition::DeviceUnknown
            | PolicyCondition::DeviceKnown
            | PolicyCondition::RiskAtLeast(_)
            | PolicyCondition::MethodIn(_)
            | PolicyCondition::SensitiveOperation
            | PolicyCondition::PermissionHeld(_)
            | PolicyCondition::ClaimEquals { .. }
            | PolicyCondition::SourceIpIn(_)
            | PolicyCondition::SourceIpNotIn(_)
            | PolicyCondition::TimeWithin(_)
            | PolicyCondition::HostIn(_) => condition.clone(),
        }
    }

    /// What the source's `role` is called in the target, or the same id
    /// when the source no longer has it.
    fn role(&self, role: &RoleId) -> RoleId {
        self.roles.get(role).copied().unwrap_or(*role)
    }

    /// What the source's `group` is called in the target, or the same id
    /// when the source no longer has it.
    fn group_id(&self, group: &GroupId) -> GroupId {
        self.groups.get(group).copied().unwrap_or(*group)
    }
}

/// `role` as the target keeps it, under the id of `kept` when the target
/// has it.
fn role_for_target(
    role: &Role<ResolvedTenant>,
    kept: Option<&Role<ResolvedTenant>>,
    now: OffsetDateTime,
) -> Result<Role<ResolvedTenant>, DomainError> {
    Role::reconstitute(RoleRow {
        id: kept.map_or_else(RoleId::new, |held| *held.id()),
        name: role.name().clone(),
        system_permissions: role.system_permissions().to_vec(),
        custom_permissions: role.custom_permissions().to_vec(),
        is_default: DefaultAssignment::from(role.is_default()),
        created_at: kept.map_or(now, Role::created_at),
        updated_at: now,
    })
}

/// `place` in the target's terms: under the copy of its parent, which
/// `placed` already holds as parents are written first.
fn placed_under(
    place: &GroupPlace,
    placed: &HashMap<GroupId, GroupId>,
) -> Result<GroupPlace, DomainError> {
    let Some(parent) = place.parent() else {
        return Ok(GroupPlace::TopLevel);
    };
    placed
        .get(parent)
        .map(|copied| GroupPlace::Under(*copied))
        .ok_or_else(|| DomainError::infra_msg("a group sits under one the copy has not placed"))
}

/// `groups` with every parent before the groups under it.
fn parents_first(mut groups: Vec<Group<ResolvedTenant>>) -> Vec<Group<ResolvedTenant>> {
    let parents: HashMap<GroupId, Option<GroupId>> = groups
        .iter()
        .map(|group| (*group.id(), group.place().parent().copied()))
        .collect();
    groups.sort_by_cached_key(|group| depth(&parents, group.id()));
    groups
}

/// How many groups `id` sits under, counting itself. Bounded by the groups
/// there are, so a broken tree cannot loop.
fn depth(parents: &HashMap<GroupId, Option<GroupId>>, id: &GroupId) -> usize {
    std::iter::successors(Some(*id), |at| parents.get(at).copied().flatten())
        .take(parents.len().saturating_add(1))
        .count()
}

/// The version the copied policy takes in the target, and what it started
/// from: the target's open draft, or a new one after its last version.
fn draft_place(history: &PolicyHistory<'_>) -> Result<(PolicyVersion, VersionBase), DomainError> {
    let Some(open) = history.open() else {
        return Ok((history.next_number()?, VersionBase::Blank));
    };
    if open.status() != PolicyStatus::Draft {
        return Err(DomainError::conflict(message!(
            "infra-the-target-tenant-s-next-policy",
            "the target tenant's next policy is in review; decide it before a clone copies one"
        )));
    }
    Ok((open.version(), open.based_on()))
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authorization::{
        ResourceTypeStore as _, RoleAssignmentStore as _, SeparationRuleStore as _,
    };
    use ianua_app::ports::tenant::ClonePartCopier as _;
    use ianua_domain::domains::tenant::clone::{ClonePart, TenantClone};
    use ianua_domain::types::{PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::postgres::authorization::{
        PgResourceTypeStore, PgRoleAssignmentStore, PgSeparationRuleStore,
    };
    use crate::postgres::tenant::copies::tests::{clone_between, copier};
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::{
        assignment, block_admin_rule, group, group_under, human, label, policy_version,
        resource_type, role, separation,
    };

    /// Two tenants of one clone, and the copy's stores over them.
    struct Tenants {
        db: TestDb,
        copy: AccessCopy,
        clone: TenantClone,
        source: ScopedTenant,
        target: ScopedTenant,
    }

    async fn tenants() -> Tenants {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        Tenants {
            copy: AccessCopy::new(&db.databases),
            source: ScopedTenant::for_background(*clone.source()),
            target: ScopedTenant::for_background(*clone.target()),
            clone,
            db,
        }
    }

    impl Tenants {
        async fn copied(&self) {
            copier(&self.db)
                .copy(&self.clone, ClonePart::RolesAndPolicies)
                .await
                .unwrap();
        }

        /// The id of the target's copy of the role `name`.
        async fn copied_role(&self, name: &str) -> RoleId {
            *self
                .copy
                .roles
                .find_by_name(&self.target, &label(name))
                .await
                .unwrap()
                .unwrap()
                .id()
        }

        /// Finds a copied group by the source name preserved in the target.
        async fn copied_group(&self, name: &str) -> Group<ResolvedTenant> {
            self.copy
                .groups
                .find_by_name(&self.target, &label(name))
                .await
                .unwrap()
                .unwrap()
        }
    }

    /// Builds the submitted live policy whose role condition the clone must remap.
    fn live_policy_naming(auditor: RoleId) -> PolicySet {
        let naming = block_admin_rule()
            .with_conditions(vec![PolicyCondition::RoleIs(auditor)])
            .unwrap();
        PolicySet::reconstitute(PolicySetRow {
            rules: vec![naming],
            default_action: policy_version(1, PolicyStatus::Active)
                .default_action()
                .clone(),
            status: PolicyStatus::Active,
            version: PolicyVersion::FIRST,
            based_on: VersionBase::Blank,
            submitted: Submission::By(human(UserId::new(), "pat@acme.example")),
        })
        .unwrap()
    }

    /// The target takes the source's roles and groups, each group under
    /// its copied parent and carrying the copied roles.
    #[tokio::test]
    async fn roles_and_groups_are_copied_in_the_targets_terms() {
        let at = tenants().await;
        let auditor = role("auditor");
        let engineering = group("engineering", vec![*auditor.id()]);
        let backend = group_under("backend", GroupPlace::Under(*engineering.id()));
        at.copy.roles.save(&at.source, &auditor).await.unwrap();
        at.copy.groups.save(&at.source, &engineering).await.unwrap();
        at.copy.groups.save(&at.source, &backend).await.unwrap();

        at.copied().await;

        let role = at.copied_role("auditor").await;
        let parent = at.copied_group("engineering").await;
        let child = at.copied_group("backend").await;
        assert_ne!(&role, auditor.id());
        assert_eq!(parent.role_ids(), &[role]);
        assert_eq!(child.place(), &GroupPlace::Under(*parent.id()));
    }

    /// A copy made twice leaves one of each role and group.
    #[tokio::test]
    async fn copying_twice_leaves_one_copy() {
        let at = tenants().await;
        at.copy
            .roles
            .save(&at.source, &role("auditor"))
            .await
            .unwrap();
        at.copy
            .groups
            .save(&at.source, &group("engineering", Vec::new()))
            .await
            .unwrap();

        at.copied().await;
        at.copied().await;

        assert_eq!(at.copy.roles_of(&at.target).await.unwrap().len(), 1);
        assert_eq!(at.copy.groups_of(&at.target).await.unwrap().len(), 1);
    }

    /// Copying roles leaves the source user's role assignments out of the target.
    #[tokio::test]
    async fn who_holds_a_role_is_not_copied() {
        let at = tenants().await;
        let auditor = role("auditor");
        at.copy.roles.save(&at.source, &auditor).await.unwrap();
        let held = PgRoleAssignmentStore::new(Arc::clone(&at.db.databases));
        let person = PrincipalRef::from(UserId::new());
        held.save(&at.source, &assignment(person, *auditor.id()))
            .await
            .unwrap();

        at.copied().await;

        assert!(
            held.find_by_principal(&at.target, &person)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A source's active policy becomes the target's sole draft, with role
    /// conditions remapped and no active target policy.
    #[tokio::test]
    async fn the_live_policy_arrives_as_a_draft_naming_the_targets_roles() {
        let at = tenants().await;
        let auditor = role("auditor");
        at.copy.roles.save(&at.source, &auditor).await.unwrap();
        let live = live_policy_naming(*auditor.id());
        at.copy.policies.save(&at.source, &live).await.unwrap();

        at.copied().await;

        let copied_role = at
            .copy
            .roles
            .find_by_name(&at.target, &label("auditor"))
            .await
            .unwrap()
            .unwrap();
        let versions = at.copy.policies.find_versions(&at.target).await.unwrap();
        assert!(
            at.copy
                .policies
                .find_active(&at.target)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].status(), PolicyStatus::Draft);
        assert!(matches!(
            versions[0].rules()[0].conditions(),
            [PolicyCondition::RoleIs(named)] if named == copied_role.id()
        ));
    }

    /// Copying access setup preserves the invoices resource type and remaps
    /// the separation rule to the target's payer and approver roles.
    #[tokio::test]
    async fn resource_types_and_separation_arrive_in_the_targets_terms() {
        let at = tenants().await;
        let (payer, approver) = (role("payer"), role("approver"));
        for each in [&payer, &approver] {
            at.copy.roles.save(&at.source, each).await.unwrap();
        }
        let kinds = PgResourceTypeStore::new(Arc::clone(&at.db.databases));
        let separations = PgSeparationRuleStore::new(Arc::clone(&at.db.databases));
        kinds
            .save(&at.source, &resource_type("invoices"))
            .await
            .unwrap();
        separations
            .save(
                &at.source,
                &separation("pay or approve", payer.id(), approver.id()),
            )
            .await
            .unwrap();

        at.copied().await;

        let payer_there = at.copied_role("payer").await;
        let approver_there = at.copied_role("approver").await;
        let copied_kinds = kinds.list_every(&at.target).await.unwrap();
        let separated = separations.list(&at.target).await.unwrap();
        assert_eq!(copied_kinds.len(), 1);
        assert_eq!(copied_kinds[0].key().as_str(), "invoices");
        assert_eq!(separated.len(), 1);
        assert_eq!(separated[0].roles(), (&payer_there, &approver_there));
    }

    /// Copying an active policy into a target with a policy under review
    /// returns a conflict.
    #[tokio::test]
    async fn a_target_policy_in_review_is_refused() {
        let at = tenants().await;
        at.copy
            .policies
            .save(&at.source, &policy_version(1, PolicyStatus::Active))
            .await
            .unwrap();
        at.copy
            .policies
            .save(&at.target, &policy_version(1, PolicyStatus::Review))
            .await
            .unwrap();

        let copied = copier(&at.db)
            .copy(&at.clone, ClonePart::RolesAndPolicies)
            .await;

        assert!(matches!(copied, Err(DomainError::Conflict(_))));
    }
}
