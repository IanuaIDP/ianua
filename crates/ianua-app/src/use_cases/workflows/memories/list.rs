//! List memories: every memory of the tenant's, by name, those waiting to
//! be deleted among them, for someone who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::memory::Memory;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::MemoryStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the memories.
    pub memories: Arc<dyn MemoryStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's memories.
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
    type Output = Result<Vec<Memory<ResolvedTenant>>, AppError>;

    /// Every memory of the tenant's, by name.
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
        (): (),
    ) -> Result<Vec<Memory<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let mut memories = self
            .ports
            .memories
            .list(&ctx.tenant())
            .await
            .or_internal()?;
        memories.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(memories)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeMemoryStore, kept_memory};
    use crate::test_support::{block_on, test_ctx};

    fn listing(authorities: FakeTenantAuthorities, memories: Arc<FakeMemoryStore>) -> ListUseCase {
        ListUseCase::new(ListPorts {
            memories,
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Sam may view workflows and sees the support tickets memory.
    #[test]
    fn a_viewer_sees_the_tenant_s_memories() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let _tickets = kept_memory(&memories);
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let listed = block_on(listing(viewer, memories).execute(&test_ctx(), ())).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name().as_str(), "Support tickets");
    }

    /// A caller without workflow view rights is forbidden from listing the
    /// stored support-tickets memory.
    #[test]
    fn someone_without_workflow_rights_lists_nothing() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let _tickets = kept_memory(&memories);

        let listed = block_on(
            listing(FakeTenantAuthorities::holding(&[]), memories).execute(&test_ctx(), ()),
        );

        assert!(matches!(listed, Err(AppError::Forbidden(_))), "{listed:?}");
    }
}
