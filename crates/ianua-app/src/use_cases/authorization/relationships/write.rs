//! Write relationship: record who holds a relation on one object of the
//! tenant's app, or which object it sits under.
//!
//! The tenant's app writes these as its people share and move things. A
//! relation is one of the object's type's actions, and whoever writes it
//! must be able to hand out everything it brings. Writing the same fact
//! again changes nothing.

use std::sync::Arc;

use ianua_domain::domains::authorization::relationship::{NewRelationship, Relationship};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{RelationshipStore, ResourceTypeStore};
use crate::use_case::Command;
use crate::use_cases::authorization::relationships::lookup::catalogue;

/// The ports [`WriteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct WritePorts {
    /// Saves the relationship.
    pub relationship_store: Arc<dyn RelationshipStore>,
    /// The tenant's resource types, which a relationship must fit.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Writes a relationship on an object of the caller's tenant's app.
pub struct WriteUseCase {
    ports: WritePorts,
}

impl WriteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: WritePorts) -> Self {
        Self { ports }
    }
}

impl Command for WriteUseCase {
    type Caller = CallerContext;
    type Input = NewRelationship;
    type Output = Result<Relationship<ResolvedTenant>, AppError>;

    /// Saves `new` for the caller and records it. The same fact written
    /// before is handed back as it was, with no new record; every check
    /// still runs first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not assign roles, or may
    ///   not hand out what the relation brings.
    /// - `AppError::Domain` when the object's type is not declared, the
    ///   relation is not one of its actions, or an object is put under
    ///   itself.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        new: NewRelationship,
    ) -> Result<Relationship<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let declared = catalogue(self.ports.resource_type_store.as_ref(), &tenant).await?;
        let mut written =
            Relationship::write(new, &declared, &authority).map_err(AppError::from_domain)?;
        let store = self.ports.relationship_store.as_ref();
        let same = store.find_same(&tenant, written.object(), written.link());
        if let Some(existing) = same.await.or_internal()? {
            return Ok(existing);
        }

        store.save(&tenant, &written).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), written.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        CustomPermission, PermissionSegment, RoleAction, SystemPermission,
    };
    use ianua_domain::domains::authorization::relationship::{
        ObjectKey, ObjectRef, RelationLink, RelationSubject,
    };
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRelationshipStore, FakeResourceTypeStore};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    /// Project 42 of the tenant's app.
    fn project_42() -> ObjectRef {
        ObjectRef::new(segment("project"), ObjectKey::new("42").unwrap())
    }

    /// Bob holds `relation` on project 42.
    fn bob_holds(relation: &str) -> NewRelationship {
        NewRelationship {
            object: project_42(),
            link: RelationLink::Holds {
                relation: segment(relation),
                subject: RelationSubject::Principal(PrincipalRef::User(UserId::new())),
            },
        }
    }

    /// A tenant whose app declares `project` with `read` and `write`.
    fn ports_over(store: &Arc<FakeRelationshipStore>) -> WritePorts {
        WritePorts {
            relationship_store: store.clone(),
            resource_type_store: Arc::new(FakeResourceTypeStore::seeded(test_ctx().tenant_id())),
            ..WritePorts::fakes()
        }
    }

    fn write(
        ports: WritePorts,
        sink: &Arc<FakeEventDispatcher>,
        new: NewRelationship,
    ) -> Result<Relationship<ResolvedTenant>, AppError> {
        block_on(WriteUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), new))
    }

    /// Ann's app makes Bob a writer of project 42. It is saved and
    /// recorded.
    #[test]
    fn a_relation_is_written_and_recorded() {
        let store = Arc::new(FakeRelationshipStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        write(ports_over(&store), &sink, bob_holds("write")).unwrap();

        assert_eq!(store.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.relationship_added"]
        );
    }

    /// Ann's app writes the same fact twice. It is kept once and recorded
    /// once.
    #[test]
    fn writing_the_same_fact_again_changes_nothing() {
        let store = Arc::new(FakeRelationshipStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let fact = bob_holds("write");
        write(ports_over(&store), &sink, fact.clone()).unwrap();

        write(ports_over(&store), &sink, fact).unwrap();

        assert_eq!(store.count(), 1);
        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    /// Ann's app names a relation `delete`, which projects do not have. It
    /// is refused and nothing is saved.
    #[test]
    fn a_relation_the_type_does_not_declare_is_refused() {
        let store = Arc::new(FakeRelationshipStore::empty());

        let result = write(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            bob_holds("delete"),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// Sam cannot grant writing on project 42 with only read permission.
    /// No relationship is saved and no grant is recorded.
    #[test]
    fn a_relation_bringing_more_than_the_writer_holds_is_refused() {
        let store = Arc::new(FakeRelationshipStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = WritePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_with_app(
                &[SystemPermission::Roles(RoleAction::Assign)],
                &[CustomPermission::new("project", "read").unwrap()],
            )),
            ..ports_over(&store)
        };

        let result = write(ports, &sink, bob_holds("write"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot write a relationship, leaving the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeRelationshipStore::empty());
        let ports = WritePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = write(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            bob_holds("read"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }
}
