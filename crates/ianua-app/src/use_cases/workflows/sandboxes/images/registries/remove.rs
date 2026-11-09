//! Remove registry: an administrator who may connect accounts takes a
//! registry off the tenant's list. Versions whose image it keeps are not
//! changed, but no longer run: their next run fails as not run until the
//! registry is allowed again.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ImageRegistryId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::ImageRegistryStore;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::workflows::sandboxes::images::registries::lookup::existing_registry;

/// The ports [`RemoveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemovePorts {
    /// Keeps the tenant's registries.
    pub registries: Arc<dyn ImageRegistryStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Drops the registry and keeps its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Removes image registries.
pub struct RemoveUseCase {
    ports: RemovePorts,
}

impl RemoveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemovePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveUseCase {
    type Caller = CallerContext;
    type Input = ImageRegistryId;
    type Output = Result<(), AppError>;

    /// Takes the tenant's registry `id` off its list.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a registry the tenant does not have; `Forbidden` without the right to connect accounts.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: ImageRegistryId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::ConnectAccounts)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut registry = existing_registry(self.ports.registries.as_ref(), &tenant, &id).await?;
        registry.remove(&control).map_err(AppError::from_domain)?;
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .registries
                .delete(&tenant, &id)
                .await
                .map_err(AppError::from_domain)?;
            auditor
                .dispatch_by(&ctx.actor(), registry.take_events(&tenant))
                .await
                .or_internal()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeImageRegistryStore, acme_registry_with_login};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// What removing left and recorded.
    struct Removing {
        registries: Arc<FakeImageRegistryStore>,
        sink: Arc<FakeEventDispatcher>,
        id: ImageRegistryId,
    }

    impl Removing {
        fn new() -> Self {
            let registry =
                acme_registry_with_login(&test_ctx().tenant(), "robot$acme", "s3cret token");
            Self {
                id: *registry.id(),
                registries: Arc::new(FakeImageRegistryStore::holding(&registry)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn remove(&self, holds: &[SystemPermission], id: ImageRegistryId) -> Result<(), AppError> {
            let use_case = RemoveUseCase::new(RemovePorts {
                registries: self.registries.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
                ..RemovePorts::fakes()
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), id))
        }
    }

    fn connecting() -> [SystemPermission; 1] {
        [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)]
    }

    /// Ann removes Acme's registry. It is gone from the list, and the
    /// trail records it.
    #[test]
    fn an_administrator_removes_a_registry() {
        let removing = Removing::new();

        removing.remove(&connecting(), removing.id).unwrap();

        assert!(removing.registries.stored(&removing.id).is_none());
        assert_eq!(
            removing.sink.records.lock().unwrap().as_slice(),
            ["workflows.image_registry_removed"]
        );
    }

    /// A registry the tenant does not have is not found.
    #[test]
    fn an_unknown_registry_is_not_found() {
        let removing = Removing::new();

        let missing = removing.remove(&connecting(), ImageRegistryId::new());

        assert!(matches!(missing, Err(AppError::NotFound(_))));
    }

    /// Someone who may only view workflows cannot remove a registry, and it
    /// stays.
    #[test]
    fn a_viewer_removes_no_registry() {
        let removing = Removing::new();

        let refused = removing.remove(
            &[SystemPermission::Workflows(WorkflowAction::View)],
            removing.id,
        );

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(removing.registries.stored(&removing.id).is_some());
    }
}
