//! Delete resource type: remove an entry from the tenant's permission
//! catalogue.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::resource_type::ResourceType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ResourceTypeId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ResourceTypeStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::existing_resource_type;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes from the catalogue.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a resource type of the caller's tenant.
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
    type Input = ResourceTypeId;
    type Output = Result<(), AppError>;

    /// Deletes the resource type `id`, for the caller.
    ///
    /// It is kept while any role still holds a permission naming it: that
    /// permission would be left with nothing defining it, which is the
    /// free-text state the catalogue exists to end.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role-deletion rights, before reading the type.
    /// - `AppError::NotFound` for a type outside the tenant; `Forbidden` for ungrantable ladder permissions.
    /// - `AppError::Conflict` when roles still name the type; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: ResourceTypeId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let store = self.ports.resource_type_store.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Delete))
            .map_err(AppError::from_domain)?;
        let mut resource_type = existing_resource_type(store, &tenant, &id).await?;
        resource_type
            .delete(&authority.standing())
            .map_err(AppError::from_domain)?;
        ensure_unused(store, &tenant, &resource_type).await?;

        store.delete(&tenant, &id).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), resource_type.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Refuses deleting a resource type roles still grant permissions of.
async fn ensure_unused(
    store: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
    resource_type: &ResourceType<ResolvedTenant>,
) -> Result<(), AppError> {
    let key = resource_type.key();
    let in_use = store.count_roles_using(tenant, key).await.or_internal()?;
    if in_use > 0 {
        return Err(AppError::Conflict(message!(
            "authorization-role-s-still-grant-permissions-revoke",
            format!(
                "{in_use} role(s) still grant '{key}' permissions. Revoke them first, so no role \
             is left holding a permission nothing defines."
            )
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        PermissionSegment, RoleAction, SystemPermission,
    };
    use ianua_domain::domains::authorization::resource_type::{ActionDefinition, ResourceTypeRow};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::shared::clock;
    use ianua_domain::types::Label;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    /// `project`, with `read` and a `write` that brings `read`, in `store`.
    fn declare_project(store: &FakeResourceTypeStore) -> ResourceTypeId {
        let now = clock::now();
        let id = ResourceTypeId::new();
        let action = |key: &str, implies: Vec<PermissionSegment>| {
            ActionDefinition::new(segment(key), Label::new("test", key).unwrap(), implies)
        };
        let project = ResourceType::reconstitute(ResourceTypeRow {
            data_class: DataClassLevel::Internal,
            id,
            key: segment("project"),
            display_name: Label::new("test", "Project").unwrap(),
            description: None,
            actions: vec![
                action("read", Vec::new()),
                action("write", vec![segment("read")]),
            ],
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        block_on(store.save(&test_ctx().tenant(), &project)).unwrap();
        id
    }

    fn catalogue(store: FakeResourceTypeStore) -> (Arc<FakeResourceTypeStore>, ResourceTypeId) {
        let id = declare_project(&store);
        (Arc::new(store), id)
    }

    fn delete(
        ports: DeletePorts,
        sink: &Arc<FakeEventDispatcher>,
        id: ResourceTypeId,
    ) -> Result<(), AppError> {
        block_on(DeleteUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn ports_over(store: &Arc<FakeResourceTypeStore>) -> DeletePorts {
        DeletePorts {
            resource_type_store: store.clone(),
            ..DeletePorts::fakes()
        }
    }

    /// Ann deletes `project`, which no role grants. It leaves the catalogue
    /// and the delete is recorded.
    #[test]
    fn a_resource_type_is_deleted_and_recorded() {
        let (store, id) = catalogue(FakeResourceTypeStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(ports_over(&store), &sink, id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.resource_type_deleted"]
        );
    }

    /// Ann deletes `project` while two roles grant its permissions. It is
    /// kept, and she is told to revoke them first.
    #[test]
    fn a_resource_type_roles_still_grant_is_kept() {
        let (store, id) = catalogue(FakeResourceTypeStore::with_roles_using(2));
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = delete(ports_over(&store), &sink, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann deletes a resource type the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_resource_type_is_not_found() {
        let (store, _) = catalogue(FakeResourceTypeStore::empty());

        let result = delete(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            ResourceTypeId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Role deletion permission cannot remove a resource type whose implied
    /// app permissions the caller could not grant. The type stays stored.
    #[test]
    fn a_ladder_conferring_more_than_the_caller_holds_is_kept() {
        let (store, id) = catalogue(FakeResourceTypeStore::empty());
        let sam = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::Delete),
            ])),
            ..ports_over(&store)
        };

        let result = delete(sam, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// Without role deletion permission, the request is forbidden and the
    /// resource type stays in the catalogue.
    #[test]
    fn a_caller_who_may_not_delete_roles_is_refused() {
        let (store, id) = catalogue(FakeResourceTypeStore::empty());
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&store)
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// A signed-out session cannot delete the stored resource type.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = catalogue(FakeResourceTypeStore::empty());
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }
}
