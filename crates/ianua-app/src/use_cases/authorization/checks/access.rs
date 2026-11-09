//! Check access: a tenant's app asks whether someone may do an action on a
//! resource type, or on one object of it, and gets allow or deny with the
//! reason. Every answer is recorded.
//!
//! The answer comes from the tenant's records: the app permissions the
//! subject holds through roles and groups, widened by the type's ladder,
//! and for one object the relations held on it or on an object above it.
//! Anything the records do not show is a deny. An answer that cannot be
//! recorded is not given.

use std::collections::HashSet;
use std::sync::Arc;

use ianua_domain::domains::authorization::access_check::{
    AccessDecision, AccessQuestion, AccessRecords as CheckedRecords, CheckTarget,
    MAX_RELATION_DEPTH, ensure_batch,
};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::relationship::Relationship;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{DecisionRecordId, PrincipalRef};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, DecisionBasis, DecisionRecord, DecisionRecordStore, Holder,
    RelationshipStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::authorization::lookup::held_records;

/// The ports [`AccessUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AccessPorts {
    /// Reads what the subject asked about holds, from their own records.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Reads the relationships on the objects asked about.
    pub relationship_store: Arc<dyn RelationshipStore>,
    /// Keeps a record of every answer.
    pub decision_records: Arc<dyn DecisionRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Whom the app asks about, and what.
pub struct CheckAccessRequest {
    /// The person, agent or app asked about.
    pub subject: PrincipalRef,
    /// The questions, answered in the order asked.
    pub questions: Vec<AccessQuestion>,
}

/// Answers a tenant's app whether someone may do something.
pub struct AccessUseCase {
    ports: AccessPorts,
}

impl AccessUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AccessPorts) -> Self {
        Self { ports }
    }

    /// The relationships on every object `questions` name, and on the
    /// objects above each, as far as a check walks.
    async fn relationships_for(
        &self,
        tenant: &ScopedTenant,
        questions: &[AccessQuestion],
    ) -> Result<Vec<Relationship<ResolvedTenant>>, AppError> {
        let store = self.ports.relationship_store.as_ref();
        let mut seen = HashSet::new();
        let mut objects = Vec::new();
        for question in questions {
            let CheckTarget::Object(object) = question.target() else {
                continue;
            };
            if !seen.insert(object) {
                continue;
            }
            objects.push(object.clone());
        }
        if objects.is_empty() {
            return Ok(Vec::new());
        }
        store
            .find_chains(tenant, &objects, MAX_RELATION_DEPTH)
            .await
            .or_internal()
    }

    /// Records each answer, asked by `authority` about `subject` at `now`.
    async fn record(
        &self,
        tenant: &ScopedTenant,
        authority: &TenantAuthority,
        asked: Asked<'_>,
    ) -> Result<(), AppError> {
        let store = self.ports.decision_records.as_ref();
        let records: Vec<_> = asked
            .questions
            .iter()
            .zip(asked.answers)
            .map(|(question, decision)| DecisionRecord {
                id: DecisionRecordId::new(),
                asked_by: authority.actor(),
                subject: asked.subject,
                basis: DecisionBasis::AppCheck {
                    question: question.clone(),
                    decision: decision.clone(),
                },
                decided_at: asked.at,
            })
            .collect();
        store.record_all(tenant, &records).await.or_internal()
    }
}

/// The questions asked about one subject at one time, with their answers.
struct Asked<'a> {
    /// Whom they were about.
    subject: PrincipalRef,
    /// What was asked.
    questions: &'a [AccessQuestion],
    /// The answers, in the order asked.
    answers: &'a [AccessDecision],
    /// When they were answered.
    at: OffsetDateTime,
}

impl Query for AccessUseCase {
    type Caller = CallerContext;
    type Input = CheckAccessRequest;
    type Output = Result<Vec<AccessDecision>, AppError>;

    /// The answer to each of `request.questions` about `request.subject`,
    /// in the order asked, each recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles: an
    ///   answer tells who holds what.
    /// - `AppError::Domain` when the batch asks nothing, or more than a
    ///   batch may.
    /// - `AppError::Internal` when the records cannot be read, name a role
    ///   or group that is not there, or the answers cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: CheckAccessRequest,
    ) -> Result<Vec<AccessDecision>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        ensure_batch(&request.questions).map_err(AppError::from_domain)?;
        let store = self.ports.access_records.as_ref();
        let records = held_records(store, &tenant, Holder::of(request.subject)).await?;
        let relationships = self.relationships_for(&tenant, &request.questions).await?;
        let at = clock::now();
        let checked = CheckedRecords {
            access: &records.access(*tenant),
            relationships: &relationships,
        };
        let answers = checked
            .check_all(request.subject, &request.questions, at)
            .map_err(AppError::from_domain)?;
        let asked = Asked {
            subject: request.subject,
            questions: &request.questions,
            answers: &answers,
            at,
        };
        self.record(&tenant, &authority, asked).await?;
        Ok(answers)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_check::{AllowedBy, DeniedBecause};
    use ianua_domain::domains::authorization::permission::{CustomPermission, PermissionSegment};
    use ianua_domain::domains::authorization::relationship::{
        ObjectKey, ObjectRef, RelationLink, RelationSubject, RelationshipRow,
    };
    use ianua_domain::types::{RelationshipId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FailingDecisionRecordStore, FakeAccessRecordStore, FakeDecisionRecordStore,
        FakeRelationshipStore, FakeResourceTypeStore, FakeRoleAssignmentStore, FakeRoleStore,
        stored_assignment, stored_role,
    };
    use crate::test_support::{block_on, test_ctx};

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    fn object(kind: &str, key: &str) -> ObjectRef {
        ObjectRef::new(segment(kind), ObjectKey::new(key).unwrap())
    }

    fn may(action: &str, target: CheckTarget) -> AccessQuestion {
        AccessQuestion::new(segment(action), target)
    }

    fn stored(object: ObjectRef, link: RelationLink) -> Relationship<ResolvedTenant> {
        Relationship::reconstitute(RelationshipRow {
            id: RelationshipId::new(),
            object,
            link,
            created_at: clock::now(),
        })
        .unwrap()
    }

    /// A tenant whose app declares `project` and `billing`. Bob holds an
    /// "editor" role carrying `project:write`; Carol writes folder 7, and
    /// project 42 sits in folder 7.
    struct Tenant {
        bob: PrincipalRef,
        carol: PrincipalRef,
        decisions: Arc<FakeDecisionRecordStore>,
        ports: AccessPorts,
    }

    fn tenant() -> Tenant {
        let tenant = test_ctx().tenant_id();
        let bob = PrincipalRef::User(UserId::new());
        let carol = PrincipalRef::User(UserId::new());
        let write = CustomPermission::new("project", "write").unwrap();
        let editor = stored_role("editor", Vec::new(), vec![write]);
        let sources = AccessSources {
            assignments: Arc::new(FakeRoleAssignmentStore::holding(
                tenant,
                [stored_assignment(bob, *editor.id())],
            )),
            roles: Arc::new(FakeRoleStore::holding(tenant, [editor])),
            catalogue: Arc::new(FakeResourceTypeStore::seeded(tenant)),
            ..AccessSources::default()
        };
        let relationships = folder_relations(carol);
        let decisions = Arc::new(FakeDecisionRecordStore::empty());
        Tenant {
            bob,
            carol,
            ports: AccessPorts {
                access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
                relationship_store: Arc::new(FakeRelationshipStore::holding(tenant, relationships)),
                decision_records: decisions.clone(),
                ..AccessPorts::fakes()
            },
            decisions,
        }
    }

    /// Carol writes folder 7, and project 42 inherits that folder's relationships.
    fn folder_relations(carol: PrincipalRef) -> [Relationship<ResolvedTenant>; 2] {
        let folder = object("project", "7");
        [
            write_relation(folder.clone(), carol),
            stored(object("project", "42"), RelationLink::Under(folder)),
        ]
    }

    /// Grants this principal the write relation on the named object.
    fn write_relation(object: ObjectRef, principal: PrincipalRef) -> Relationship<ResolvedTenant> {
        stored(
            object,
            RelationLink::Holds {
                relation: segment("write"),
                subject: RelationSubject::Principal(principal),
            },
        )
    }

    fn check(
        ports: AccessPorts,
        subject: PrincipalRef,
        questions: Vec<AccessQuestion>,
    ) -> Result<Vec<AccessDecision>, AppError> {
        block_on(
            AccessUseCase::new(ports)
                .execute(&test_ctx(), CheckAccessRequest { subject, questions }),
        )
    }

    fn any_project() -> CheckTarget {
        CheckTarget::AnyOf(segment("project"))
    }

    /// Ann's app asks whether Bob may write projects. His "editor" role
    /// says so: allowed, naming the permission, and recorded.
    #[test]
    fn a_permission_held_through_a_role_allows() {
        let tenant = tenant();

        let answers = check(tenant.ports, tenant.bob, vec![may("write", any_project())]).unwrap();

        assert!(matches!(
            &answers[0],
            AccessDecision::Allowed(AllowedBy::Permission(_))
        ));
        assert_eq!(tenant.decisions.recorded(test_ctx().tenant_id()).len(), 1);
    }

    /// Ann's app asks whether Carol may read project 42. She writes folder
    /// 7, which project 42 sits in, and writing brings reading: allowed
    /// through the relation on the folder.
    #[test]
    fn a_relation_on_an_object_above_allows() {
        let tenant = tenant();
        let project_42 = CheckTarget::Object(object("project", "42"));

        let answers = check(tenant.ports, tenant.carol, vec![may("read", project_42)]).unwrap();

        assert!(matches!(
            &answers[0],
            AccessDecision::Allowed(AllowedBy::Relation { .. })
        ));
    }

    /// Ann's app asks about Dan, whom nothing names, and about a type the
    /// tenant never declared. Both are denied, each with its reason, and
    /// both answers are recorded.
    #[test]
    fn whatever_the_records_do_not_show_is_denied() {
        let tenant = tenant();
        let dan = PrincipalRef::User(UserId::new());
        let questions = vec![
            may("write", any_project()),
            may("read", CheckTarget::AnyOf(segment("invoice"))),
        ];

        let answers = check(tenant.ports, dan, questions).unwrap();

        assert_eq!(
            answers,
            [
                AccessDecision::Denied(DeniedBecause::NotHeld),
                AccessDecision::Denied(DeniedBecause::UnknownResourceType),
            ]
        );
        assert_eq!(tenant.decisions.recorded(test_ctx().tenant_id()).len(), 2);
    }

    /// Ann's app sends an empty batch. Nothing was asked, so it is refused.
    #[test]
    fn an_empty_batch_is_refused() {
        let tenant = tenant();

        let result = check(tenant.ports, tenant.bob, Vec::new());

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// An oversized access-check batch is refused before reading object
    /// ancestry or recording any decisions.
    #[test]
    fn an_oversized_batch_reads_no_relationships() {
        let tenant = tenant();
        let relationships = Arc::new(FakeRelationshipStore::empty());
        let ports = AccessPorts {
            relationship_store: relationships.clone(),
            ..tenant.ports
        };
        let questions = vec![may("read", CheckTarget::Object(object("project", "42"))); 101];

        let result = check(ports, tenant.bob, questions);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(relationships.chain_reads().is_empty());
        assert!(tenant.decisions.recorded(test_ctx().tenant_id()).is_empty());
    }

    /// Repeated questions about one object share its ancestry read, while
    /// each answer remains in order and gets its own decision record.
    #[test]
    fn repeated_objects_share_a_read_but_keep_every_answer() {
        let tenant = tenant();
        let project = object("project", "42");
        let relationships = Arc::new(FakeRelationshipStore::holding(
            test_ctx().tenant_id(),
            [stored(
                project.clone(),
                RelationLink::Holds {
                    relation: segment("write"),
                    subject: RelationSubject::Principal(tenant.carol),
                },
            )],
        ));
        let ports = AccessPorts {
            relationship_store: relationships.clone(),
            ..tenant.ports
        };
        let questions = ["read", "write", "admin"]
            .map(|action| may(action, CheckTarget::Object(project.clone())))
            .to_vec();

        let answers = check(ports, tenant.carol, questions).unwrap();

        assert_eq!(
            answers
                .iter()
                .map(AccessDecision::is_allowed)
                .collect::<Vec<_>>(),
            [true, true, false]
        );
        assert_eq!(tenant.decisions.recorded(test_ctx().tenant_id()).len(), 3);
        assert_eq!(relationships.chain_reads(), [project]);
        assert_eq!(tenant.decisions.writes(), 1);
    }

    /// Distinct objects share one ancestry read. Each still receives its
    /// own answer and evidence, including an object with no relationships.
    #[test]
    fn distinct_objects_share_an_ancestry_batch() {
        let tenant = tenant();
        let first = object("project", "first");
        let second = object("project", "second");
        let relationships = Arc::new(FakeRelationshipStore::holding(
            test_ctx().tenant_id(),
            [write_relation(first.clone(), tenant.carol)],
        ));
        let ports = AccessPorts {
            relationship_store: relationships.clone(),
            ..tenant.ports
        };

        let answers = check(
            ports,
            tenant.carol,
            vec![
                may("read", CheckTarget::Object(first)),
                may("read", CheckTarget::Object(second)),
            ],
        )
        .unwrap();

        assert_eq!(
            answers
                .iter()
                .map(AccessDecision::is_allowed)
                .collect::<Vec<_>>(),
            [true, false]
        );
        assert_eq!(tenant.decisions.recorded(test_ctx().tenant_id()).len(), 2);
        assert_eq!(relationships.chain_batches(), 1);
    }

    /// Failure to record Bob's allowed access decision returns an internal
    /// error instead of an answer.
    #[test]
    fn an_answer_that_cannot_be_recorded_is_not_given() {
        let tenant = tenant();
        let ports = AccessPorts {
            decision_records: Arc::new(FailingDecisionRecordStore),
            ..tenant.ports
        };

        let result = check(ports, tenant.bob, vec![may("write", any_project())]);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// A caller without role-viewing rights cannot check Bob's access.
    /// The refusal records no decision.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let tenant = tenant();
        let ports = AccessPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports
        };

        let result = check(ports, tenant.bob, vec![may("write", any_project())]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.decisions.recorded(test_ctx().tenant_id()).is_empty());
    }

    /// A signed-out caller cannot check Bob's access to projects.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let ports = AccessPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports
        };

        let result = check(ports, tenant.bob, vec![may("write", any_project())]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
