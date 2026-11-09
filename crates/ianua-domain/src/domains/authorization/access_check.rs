//! Whether someone may do an action on a tenant's resource type, or on one
//! object of it, worked out from the tenant's records for its app to ask.
//!
//! The app asks "may Ann `write` project 42?". The answer comes from what
//! Ann holds: an app permission through her roles and groups, widened by
//! the type's ladder, such as `project:admin` bringing `project:write`; or,
//! for one object, a relation on it or on an object it sits under. The
//! answer is allow or deny, with the reason, and anything the records do
//! not show is a deny.

use std::collections::HashSet;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::ladder::reachable;
use crate::domains::authorization::permission::{CustomPermission, PermissionSegment};
use crate::domains::authorization::relationship::{
    ObjectRef, RelationLink, RelationSubject, Relationship,
};
use crate::domains::authorization::resource_type::ResourceType;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{GroupId, PrincipalRef};

/// How many objects up a chain of parents a check walks. A chain longer
/// than this is refused rather than followed: a deep or looping tree would
/// otherwise make one check walk the whole tenant.
pub const MAX_RELATION_DEPTH: usize = 8;

/// The most questions one batch asks.
pub(crate) const MAX_BATCH: usize = 100;

/// What a question is about: a resource type in general, or one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckTarget {
    /// Any object of this resource type, as a role's permission gives.
    AnyOf(PermissionSegment),
    /// This object, through a permission or a relation on it.
    Object(ObjectRef),
}

impl CheckTarget {
    /// The resource type the target is of.
    #[must_use]
    pub fn resource_type(&self) -> &PermissionSegment {
        match self {
            Self::AnyOf(resource_type) => resource_type,
            Self::Object(object) => object.resource_type(),
        }
    }
}

/// One question: may the subject do `action` on `target`?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessQuestion {
    action: PermissionSegment,
    target: CheckTarget,
}

impl AccessQuestion {
    /// May the subject do `action` on `target`?
    #[must_use]
    pub fn new(action: PermissionSegment, target: CheckTarget) -> Self {
        Self { action, target }
    }

    /// The action asked about.
    #[must_use]
    pub fn action(&self) -> &PermissionSegment {
        &self.action
    }

    /// What it is asked about.
    #[must_use]
    pub fn target(&self) -> &CheckTarget {
        &self.target
    }
}

/// Why a question was answered yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedBy {
    /// The subject holds this app permission, which covers the action.
    Permission(CustomPermission),
    /// The subject, or a group of theirs, holds `relation` on `object`: the
    /// object asked about, or one it sits under.
    Relation {
        /// Where the relation is held.
        object: ObjectRef,
        /// The relation held.
        relation: PermissionSegment,
    },
}

/// Why a question was answered no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedBecause {
    /// The tenant declares no such resource type.
    UnknownResourceType,
    /// The resource type declares no such action.
    UndeclaredAction,
    /// Nothing the subject holds gives it.
    NotHeld,
    /// The object sits under a chain of parents longer than
    /// [`MAX_RELATION_DEPTH`].
    TooDeep,
}

impl DeniedBecause {
    /// The stable name an answer and a record carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownResourceType => "unknown_resource_type",
            Self::UndeclaredAction => "undeclared_action",
            Self::NotHeld => "not_held",
            Self::TooDeep => "too_deep",
        }
    }
}

/// The answer to one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    /// Yes, for this reason.
    Allowed(AllowedBy),
    /// No, for this reason.
    Denied(DeniedBecause),
}

impl AccessDecision {
    /// Whether the answer is yes.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }
}

/// What one subject holds, read once for a batch.
struct Holder {
    principal: PrincipalRef,
    permissions: Vec<CustomPermission>,
    groups: Vec<GroupId>,
}

/// A tenant's records an access check reads: who holds what, and the
/// relationships on its app's objects.
#[derive(Debug)]
pub struct AccessRecords<'a, T: TenantScope> {
    /// Roles, groups, the catalogue and break-glass grants.
    pub access: &'a TenantAccess<'a, T>,
    /// The relationships on the app's objects.
    pub relationships: &'a [Relationship<T>],
}

impl<T: TenantScope> AccessRecords<'_, T> {
    /// May `subject` do what `question` asks, at `now`?
    ///
    /// # Errors
    ///
    /// - The cases [`TenantGrants::administrators`] lists, for records that
    ///   name a role or group that is not there.
    ///
    /// [`TenantGrants::administrators`]: crate::domains::authorization::stewardship::TenantGrants::administrators
    pub fn check(
        &self,
        subject: PrincipalRef,
        question: &AccessQuestion,
        now: OffsetDateTime,
    ) -> Result<AccessDecision, DomainError> {
        let holder = self.holder(subject, now)?;
        Ok(self.decide(&holder, question))
    }

    /// May `subject` do what each of `questions` asks, at `now`? The
    /// answers come in the order asked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the batch asks nothing, or more
    ///   than `MAX_BATCH` questions.
    /// - The cases [`check`](Self::check) lists.
    pub fn check_all(
        &self,
        subject: PrincipalRef,
        questions: &[AccessQuestion],
        now: OffsetDateTime,
    ) -> Result<Vec<AccessDecision>, DomainError> {
        ensure_batch(questions)?;
        let holder = self.holder(subject, now)?;
        Ok(questions
            .iter()
            .map(|question| self.decide(&holder, question))
            .collect())
    }

    /// What `principal` holds at `now`: app permissions with what the
    /// ladders confer, an active break-glass grant's for a tenant user, and
    /// the groups they are in.
    fn holder(&self, principal: PrincipalRef, now: OffsetDateTime) -> Result<Holder, DomainError> {
        let held = match principal {
            PrincipalRef::User(user) => self.access.everything_held_by(&user, now)?,
            PrincipalRef::OrgUser(_) | PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => {
                self.access.standing_of(principal)?
            }
        };
        Ok(Holder {
            principal,
            permissions: held.handout().custom.to_vec(),
            groups: self.access.grants.groups_of(principal)?,
        })
    }

    /// The answer to `question` for `holder`.
    fn decide(&self, holder: &Holder, question: &AccessQuestion) -> AccessDecision {
        let resource_type = question.target.resource_type();
        let Some(declared) = self
            .access
            .catalogue
            .iter()
            .find(|entry| entry.key() == resource_type)
        else {
            return AccessDecision::Denied(DeniedBecause::UnknownResourceType);
        };
        let action = question.action.as_str();
        if !declared.declares(action) {
            return AccessDecision::Denied(DeniedBecause::UndeclaredAction);
        }
        let granting = holder
            .permissions
            .iter()
            .find(|held| held.matches(resource_type.as_str(), action));
        if let Some(permission) = granting {
            return AccessDecision::Allowed(AllowedBy::Permission(permission.clone()));
        }
        match &question.target {
            CheckTarget::AnyOf(_) => AccessDecision::Denied(DeniedBecause::NotHeld),
            CheckTarget::Object(object) => self.walk(holder, object, declared, action),
        }
    }

    /// Whether `holder` holds a relation bringing `action` on `object`, or
    /// on an object above it, at most [`MAX_RELATION_DEPTH`] parents up.
    fn walk(
        &self,
        holder: &Holder,
        object: &ObjectRef,
        declared: &ResourceType<T>,
        action: &str,
    ) -> AccessDecision {
        let mut frontier = vec![object];
        let mut seen: HashSet<&ObjectRef> = HashSet::new();
        for _ in 0..=MAX_RELATION_DEPTH {
            let mut parents = Vec::new();
            for current in frontier.into_iter().filter(|current| seen.insert(*current)) {
                for link in self.links_on(current) {
                    match link {
                        RelationLink::Holds { relation, subject }
                            if covers(*subject, holder)
                                && reachable(declared.actions(), relation.as_str())
                                    .contains(&action) =>
                        {
                            return AccessDecision::Allowed(AllowedBy::Relation {
                                object: current.clone(),
                                relation: relation.clone(),
                            });
                        }
                        RelationLink::Holds { .. } => {}
                        RelationLink::Under(parent) => parents.push(parent),
                    }
                }
            }
            if parents.is_empty() {
                return AccessDecision::Denied(DeniedBecause::NotHeld);
            }
            frontier = parents;
        }
        AccessDecision::Denied(DeniedBecause::TooDeep)
    }

    /// What the relationships say about `object`.
    fn links_on<'r>(&'r self, object: &'r ObjectRef) -> impl Iterator<Item = &'r RelationLink> {
        self.relationships
            .iter()
            .filter(move |relationship| relationship.object() == object)
            .map(Relationship::link)
    }
}

/// Refuses a batch before records are loaded when it asks nothing or too
/// many questions. Evaluation applies the same bound again.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] unless there are one through
/// `MAX_BATCH` questions.
pub fn ensure_batch(questions: &[AccessQuestion]) -> Result<(), DomainError> {
    validate_count("checks", questions.len(), 1..=MAX_BATCH)?;
    Ok(())
}

/// Whether `subject` names `holder`, or a group they are in.
fn covers(subject: RelationSubject, holder: &Holder) -> bool {
    match subject {
        RelationSubject::Principal(principal) => principal == holder.principal,
        RelationSubject::Group(group) => holder.groups.contains(&group),
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::fixtures::{
        Records, custom, projects, resource_type, role, segment,
    };
    use crate::domains::authorization::group::{Group, GroupMembership, GroupMembershipRow};
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::authorization::relationship::{
        NewRelationship, ObjectKey, RelationshipRow,
    };
    use crate::domains::authorization::role::{Role, RoleAssignment, RoleAssignmentRow};
    use crate::domains::federation::fixtures::switched_on_directory;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::validation::ValidationError;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::label;
    use crate::types::{
        ActorRef, Expiry, Human, HumanAccount, PersonKey, RelationshipId, TenantId, UserId,
    };

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn object(kind: &str, key: &str) -> ObjectRef {
        ObjectRef::new(segment(kind), ObjectKey::new(key).unwrap())
    }

    fn asking(action: &str, target: CheckTarget) -> AccessQuestion {
        AccessQuestion::new(segment(action), target)
    }

    fn any_project(action: &str) -> AccessQuestion {
        asking(action, CheckTarget::AnyOf(segment("project")))
    }

    fn on(action: &str, kind: &str, key: &str) -> AccessQuestion {
        asking(action, CheckTarget::Object(object(kind, key)))
    }

    /// A relationship stored as `link` on `on`.
    fn stored(on: ObjectRef, link: RelationLink) -> Relationship<ResolvedTenant> {
        Relationship::reconstitute(RelationshipRow {
            id: RelationshipId::new(),
            object: on,
            link,
            created_at: now(),
        })
        .unwrap()
    }

    fn held_by(principal: PrincipalRef, relation: &str) -> RelationLink {
        RelationLink::Holds {
            relation: segment(relation),
            subject: RelationSubject::Principal(principal),
        }
    }

    /// `role` given to `principal` until `expires`.
    fn given(
        principal: PrincipalRef,
        role: &Role<ResolvedTenant>,
        expires: Expiry,
    ) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal,
            role_id: *role.id(),
            assigned_by: ActorRef::System,
            assigned_at: now() - Duration::days(1),
            expires,
        })
        .unwrap()
    }

    /// Records with `project` and `document` declared, and nothing held.
    fn catalogued() -> Records {
        Records {
            catalogue: vec![
                projects(),
                resource_type("document", &[("read", &[]), ("write", &["read"])]),
            ],
            ..Records::default()
        }
    }

    fn decide(
        records: &Records,
        subject: PrincipalRef,
        question: &AccessQuestion,
    ) -> AccessDecision {
        decide_with(records, &[], subject, question)
    }

    fn decide_with(
        records: &Records,
        relationships: &[Relationship<ResolvedTenant>],
        subject: PrincipalRef,
        question: &AccessQuestion,
    ) -> AccessDecision {
        let access = records.access();
        AccessRecords {
            access: &access,
            relationships,
        }
        .check(subject, question, now())
        .unwrap()
    }

    /// Ann's role gives `project:admin`. She may write any project, since
    /// the ladder brings it, and the answer names the permission that did.
    #[test]
    fn a_permission_and_its_ladder_answer_for_any_object_of_the_type() {
        let ann = PrincipalRef::User(UserId::new());
        let admins = role("admins", &[], &["project:admin"]);
        let mut records = catalogued();
        records.assignments = vec![given(ann, &admins, Expiry::Never)];
        records.roles = vec![admins];

        let write = decide(&records, ann, &any_project("write"));
        let on_one = decide(&records, ann, &on("read", "project", "42"));

        assert_eq!(
            write,
            AccessDecision::Allowed(AllowedBy::Permission(custom("project:write")))
        );
        assert!(on_one.is_allowed());
    }

    /// Unknown resource types, undeclared actions including wildcards, and unheld
    /// rights each produce a denial identifying the reason.
    #[test]
    fn anything_the_records_do_not_show_is_denied() {
        let ann = PrincipalRef::User(UserId::new());
        let records = catalogued();

        let unknown = decide(
            &records,
            ann,
            &asking("read", CheckTarget::AnyOf(segment("invoice"))),
        );
        let undeclared = decide(&records, ann, &any_project("delete"));
        let wildcard = decide(&records, ann, &any_project("*"));
        let not_held = decide(&records, ann, &any_project("read"));

        assert_eq!(
            unknown,
            AccessDecision::Denied(DeniedBecause::UnknownResourceType)
        );
        assert_eq!(
            undeclared,
            AccessDecision::Denied(DeniedBecause::UndeclaredAction)
        );
        assert_eq!(
            wildcard,
            AccessDecision::Denied(DeniedBecause::UndeclaredAction)
        );
        assert_eq!(not_held, AccessDecision::Denied(DeniedBecause::NotHeld));
    }

    /// An expired project-admin assignment no longer allows Bob to write projects,
    /// even while the assignment remains in the records.
    #[test]
    fn an_ended_role_answers_nothing() {
        let bob = PrincipalRef::User(UserId::new());
        let admins = role("admins", &[], &["project:admin"]);
        let mut records = catalogued();
        records.assignments = vec![given(bob, &admins, Expiry::At(now() - Duration::hours(1)))];
        records.roles = vec![admins];

        let answer = decide(&records, bob, &any_project("write"));

        assert_eq!(answer, AccessDecision::Denied(DeniedBecause::NotHeld));
    }

    /// Bob is `write` on project 42. He may read and write it, since the
    /// ladder brings reading, but not administer it, and not write project
    /// 43.
    #[test]
    fn a_relation_on_an_object_answers_for_that_object_through_the_ladder() {
        let bob = PrincipalRef::User(UserId::new());
        let records = catalogued();
        let relationships = [stored(object("project", "42"), held_by(bob, "write"))];
        let ask = |asked: &AccessQuestion| decide_with(&records, &relationships, bob, asked);

        assert_eq!(
            ask(&on("read", "project", "42")),
            AccessDecision::Allowed(AllowedBy::Relation {
                object: object("project", "42"),
                relation: segment("write"),
            })
        );
        assert!(!ask(&on("admin", "project", "42")).is_allowed());
        assert!(!ask(&on("write", "project", "43")).is_allowed());
        assert!(!ask(&any_project("write")).is_allowed());
    }

    /// Document 7 sits in project 42, which Bob may `write`. He may write
    /// the document, through the project.
    #[test]
    fn a_relation_on_a_parent_counts_on_what_sits_under_it() {
        let bob = PrincipalRef::User(UserId::new());
        let records = catalogued();
        let relationships = [
            stored(object("project", "42"), held_by(bob, "write")),
            stored(
                object("document", "7"),
                RelationLink::Under(object("project", "42")),
            ),
        ];

        let answer = decide_with(&records, &relationships, bob, &on("write", "document", "7"));

        assert_eq!(
            answer,
            AccessDecision::Allowed(AllowedBy::Relation {
                object: object("project", "42"),
                relation: segment("write"),
            })
        );
    }

    /// Engineering is `read` on project 42 and Carol is in Engineering.
    /// She may read it; Dan, who is not, may not.
    #[test]
    fn a_relation_held_by_a_group_counts_for_its_members() {
        let carol = PrincipalRef::User(UserId::new());
        let dan = PrincipalRef::User(UserId::new());
        let mut records = catalogued();
        records.groups =
            vec![Group::from_directory(label("Engineering"), &switched_on_directory()).unwrap()];
        let engineering = *records.groups[0].id();
        records.memberships = vec![
            GroupMembership::reconstitute(GroupMembershipRow {
                principal: carol,
                group_id: engineering,
                joined_at: now(),
                expires: Expiry::Never,
            })
            .unwrap(),
        ];
        let relationships = [stored(
            object("project", "42"),
            RelationLink::Holds {
                relation: segment("read"),
                subject: RelationSubject::Group(engineering),
            },
        )];
        let question = on("read", "project", "42");

        assert!(decide_with(&records, &relationships, carol, &question).is_allowed());
        assert!(!decide_with(&records, &relationships, dan, &question).is_allowed());
    }

    /// Bob's relation ten parents above a document exceeds the traversal limit
    /// and produces a depth-limit denial.
    #[test]
    fn a_chain_of_parents_past_the_limit_is_denied() {
        let bob = PrincipalRef::User(UserId::new());
        let records = catalogued();
        let mut relationships: Vec<Relationship<ResolvedTenant>> = (0..10)
            .map(|n| {
                stored(
                    object("document", &n.to_string()),
                    RelationLink::Under(object("document", &(n + 1).to_string())),
                )
            })
            .collect();
        relationships.push(stored(object("document", "10"), held_by(bob, "read")));

        let answer = decide_with(&records, &relationships, bob, &on("read", "document", "0"));

        assert_eq!(answer, AccessDecision::Denied(DeniedBecause::TooDeep));
    }

    /// A cycle between two document parents terminates with a denial because Bob
    /// holds no relation on either document.
    #[test]
    fn a_loop_of_parents_is_denied() {
        let bob = PrincipalRef::User(UserId::new());
        let records = catalogued();
        let relationships = [
            stored(
                object("document", "1"),
                RelationLink::Under(object("document", "2")),
            ),
            stored(
                object("document", "2"),
                RelationLink::Under(object("document", "1")),
            ),
        ];

        let answer = decide_with(&records, &relationships, bob, &on("read", "document", "1"));

        assert_eq!(answer, AccessDecision::Denied(DeniedBecause::NotHeld));
    }

    /// The app asks two questions at once and gets two answers in order.
    /// An empty batch, or one of more than a hundred, is refused.
    #[test]
    fn a_batch_answers_each_question_in_order() {
        let ann = PrincipalRef::User(UserId::new());
        let readers = role("readers", &[], &["project:read"]);
        let mut records = catalogued();
        records.assignments = vec![given(ann, &readers, Expiry::Never)];
        records.roles = vec![readers];
        let access = records.access();
        let check = AccessRecords {
            access: &access,
            relationships: &[],
        };

        let answers = check
            .check_all(ann, &[any_project("read"), any_project("write")], now())
            .unwrap();
        let empty = check.check_all(ann, &[], now());
        let too_many = check.check_all(ann, &vec![any_project("read"); MAX_BATCH + 1], now());

        assert!(answers[0].is_allowed());
        assert!(!answers[1].is_allowed());
        for refused in [empty, too_many] {
            assert!(matches!(
                refused,
                Err(DomainError::Validation(ValidationError::Count { .. }))
            ));
        }
    }

    /// Each reason a check denies has a stable name.
    #[test]
    fn each_denial_has_a_stable_name() {
        assert_eq!(DeniedBecause::NotHeld.as_str(), "not_held");
        assert_eq!(DeniedBecause::TooDeep.as_str(), "too_deep");
        assert_eq!(
            DeniedBecause::UnknownResourceType.as_str(),
            "unknown_resource_type"
        );
        assert_eq!(
            DeniedBecause::UndeclaredAction.as_str(),
            "undeclared_action"
        );
    }

    /// A relationship written by the app through the aggregate is one the
    /// check reads: written for Bob, it lets him read project 42.
    #[test]
    fn a_written_relationship_is_read_by_the_check() {
        let bob = PrincipalRef::User(UserId::new());
        let records = catalogued();
        let owner = assumed_authority(
            &Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new("owner@acme.test").unwrap(),
            ),
            TenantId::new(),
            &[SystemPermission::ManageRoles],
            &[],
        );
        let written = Relationship::write(
            NewRelationship {
                object: object("project", "42"),
                link: held_by(bob, "read"),
            },
            &records.catalogue,
            owner,
        )
        .unwrap();

        let answer = decide_with(&records, &[written], bob, &on("read", "project", "42"));

        assert!(answer.is_allowed());
    }
}
