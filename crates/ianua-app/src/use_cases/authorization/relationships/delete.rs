//! Delete relationship: take a relation off an object of the tenant's app,
//! or take an object out from under another.
//!
//! Taking a relation away is held to the rules of giving it: Sam cannot
//! strip Ann of `admin` on project 42 if he could not have given it.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::RelationshipId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{RelationshipStore, ResourceTypeStore};
use crate::use_case::Command;
use crate::use_cases::authorization::relationships::lookup::{catalogue, existing_relationship};

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and removes the relationship.
    pub relationship_store: Arc<dyn RelationshipStore>,
    /// The tenant's resource types, which the relationship is checked
    /// against.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a relationship of the caller's tenant's app.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = RelationshipId;
    type Output = Result<(), AppError>;

    /// Removes relationship `id` for the caller and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the relationship.
    /// - `AppError::NotFound` for a relationship outside the tenant; `Forbidden` when the caller could not grant its access.
    /// - `AppError::Domain` for an undeclared object type; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: RelationshipId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let store = self.ports.relationship_store.as_ref();
        let mut relationship = existing_relationship(store, &tenant, &id).await?;
        let declared = catalogue(self.ports.resource_type_store.as_ref(), &tenant).await?;
        relationship
            .remove(&declared, &authority)
            .map_err(AppError::from_domain)?;

        store.delete(&tenant, &id).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), relationship.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        CustomPermission, PermissionSegment, RoleAction, SystemPermission,
    };
    use ianua_domain::domains::authorization::relationship::{
        NewRelationship, ObjectKey, ObjectRef, RelationLink, RelationSubject, Relationship,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRelationshipStore, FakeResourceTypeStore};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    /// Ann is a writer of project 42, written by someone who could, held
    /// in the tenant's store with the `project` type declared.
    fn ann_writes_project_42() -> (DeletePorts, Arc<FakeRelationshipStore>, RelationshipId) {
        let tenant = test_ctx().tenant_id();
        let catalogue = FakeResourceTypeStore::seeded(tenant);
        let declared = catalogue.of_tenant(tenant);
        let relationship = Relationship::<ResolvedTenant>::write(
            NewRelationship {
                object: ObjectRef::new(segment("project"), ObjectKey::new("42").unwrap()),
                link: RelationLink::Holds {
                    relation: segment("write"),
                    subject: RelationSubject::Principal(PrincipalRef::User(UserId::new())),
                },
            },
            &declared,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();
        let id = *relationship.id();
        let store = Arc::new(FakeRelationshipStore::holding(tenant, [relationship]));
        let ports = DeletePorts {
            relationship_store: store.clone(),
            resource_type_store: Arc::new(catalogue),
            ..DeletePorts::fakes()
        };
        (ports, store, id)
    }

    fn delete(
        ports: DeletePorts,
        sink: &Arc<FakeEventDispatcher>,
        id: RelationshipId,
    ) -> Result<(), AppError> {
        block_on(DeleteUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    /// Ann's app takes away her writing on project 42. It is gone and the
    /// removal is recorded.
    #[test]
    fn a_relationship_is_removed_and_recorded() {
        let (ports, store, id) = ann_writes_project_42();
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(ports, &sink, id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.relationship_removed"]
        );
    }

    /// Ann's app removes a relationship the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_relationship_is_not_found() {
        let (ports, _, _) = ann_writes_project_42();

        let result = delete(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            RelationshipId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Sam's read permission cannot remove Ann's writing permission on
    /// project 42. The relationship stays and no removal is recorded.
    #[test]
    fn a_relation_the_caller_could_not_give_is_not_taken_away() {
        let (ports, store, id) = ann_writes_project_42();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_with_app(
                &[SystemPermission::Roles(RoleAction::Assign)],
                &[CustomPermission::new("project", "read").unwrap()],
            )),
            ..ports
        };

        let result = delete(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot remove a relationship; it stays stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (ports, store, id) = ann_writes_project_42();
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }
}
