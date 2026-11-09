//! List sandboxes: the tenant's sandboxes, ordered and paged, for someone
//! who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::workflows::{SandboxSortField, SandboxStore};
use crate::use_case::Query;

/// Which sandboxes to list, in which order.
pub struct ListRequest {
    /// The order.
    pub sort: SortOrder<SandboxSortField>,
    /// The cursor and size bounds for this code-project listing.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's sandboxes.
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
    type Input = ListRequest;
    type Output = Result<Page<Sandbox<ResolvedTenant>>, AppError>;

    /// One page of the tenant's sandboxes, archived ones among them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<Sandbox<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .sandboxes
            .list(&ctx.tenant(), &request.sort, &request.page)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeSandboxStore, python_sandbox};
    use crate::test_support::{block_on, test_ctx};

    fn listing(holds: &[SystemPermission]) -> Result<Page<Sandbox<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            sandboxes: Arc::new(FakeSandboxStore::holding(&python_sandbox())),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
        });
        let request = ListRequest {
            sort: SortOrder::default(),
            page: PageRequest::default(),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    /// Bob may view workflows and lists the sandboxes. He sees Ann's one.
    /// Sam, holding no workflow right, is refused.
    #[test]
    fn a_viewer_lists_the_sandboxes() {
        let page = listing(&[SystemPermission::Workflows(WorkflowAction::View)]).unwrap();

        assert_eq!(page.items.len(), 1);
        assert!(matches!(listing(&[]), Err(AppError::Forbidden(_))));
    }
}
