//! List registries: the image registries the tenant allowed, for anyone
//! who may view workflows. No login is ever shown, only how images are
//! pulled.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::registry::ImageRegistry;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::ImageRegistryStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the tenant's registries.
    pub registries: Arc<dyn ImageRegistryStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's allowed registries.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<ImageRegistry<ResolvedTenant>>, AppError>;

    /// Every registry the tenant allowed, by host.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without the right to view workflows; `Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<ImageRegistry<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .registries
            .list(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeImageRegistryStore, acme_registry_with_login};
    use crate::test_support::{block_on, test_ctx};

    fn listing(holds: &[SystemPermission]) -> Result<Vec<ImageRegistry<ResolvedTenant>>, AppError> {
        let registry = acme_registry_with_login(&test_ctx().tenant(), "robot$acme", "s3cret token");
        let use_case = ListUseCase::new(ListPorts {
            registries: Arc::new(FakeImageRegistryStore::holding(&registry)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Someone who may view workflows sees the tenant's registries.
    #[test]
    fn a_viewer_sees_the_registries() {
        let listed = listing(&[SystemPermission::Workflows(WorkflowAction::View)]).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host().as_str(), "registry.acme.example");
    }

    /// Someone with no workflow right sees none.
    #[test]
    fn without_a_workflow_right_none_are_listed() {
        let refused = listing(&[]);

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
    }
}
