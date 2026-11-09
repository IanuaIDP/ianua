//! List passes: the passes a run's loops started, newest first, for
//! someone who may view workflows, with the data they are not cleared for
//! withheld.
//!
//! A run's own steps say how far each loop got. Its passes are runs of
//! their own, left out of the lists of runs, so this is where a person
//! finds the steps one item went through.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::execution::ExecutionView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowExecutionId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::workflows::WorkflowExecutionStore;
use crate::use_case::Query;

/// Whose passes to list, and which page of them.
pub struct ListPassesRequest {
    /// The run whose loops started them.
    pub execution_id: WorkflowExecutionId,
    /// The cursor and size bounds for this loop-pass listing.
    pub page: PageRequest,
}

/// The ports [`ListPassesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPassesPorts {
    /// Keeps the executions and their passes.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the passes of a run's loops.
pub struct ListPassesUseCase {
    ports: ListPassesPorts,
}

impl ListPassesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPassesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListPassesUseCase {
    type Caller = CallerContext;
    type Input = ListPassesRequest;
    type Output = Result<Page<ExecutionView<ResolvedTenant>>, AppError>;

    /// One page of the passes `request.execution_id`'s loops started,
    /// newest first, each as the caller may read it: data above their
    /// clearance is withheld. A run without loops has none.
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
        request: ListPassesRequest,
    ) -> Result<Page<ExecutionView<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let viewer = WorkflowControl::new(&authority);
        viewer
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .executions
            .list_passes(&ctx.tenant(), &request.execution_id, &request.page)
            .await
            .map_err(AppError::from_domain)?
            .try_map(|pass| pass.viewed_by(viewer))
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::execution::WorkflowExecution;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeWorkflowExecutionStore, loop_under_way, person};
    use crate::test_support::{block_on, test_ctx};

    fn listing(
        kept: &[WorkflowExecution<ResolvedTenant>],
        execution_id: WorkflowExecutionId,
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<ExecutionView<ResolvedTenant>>, AppError> {
        let use_case = ListPassesUseCase::new(ListPassesPorts {
            executions: Arc::new(FakeWorkflowExecutionStore::holding_all(kept)),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ListPassesRequest {
            execution_id,
            page: PageRequest::default(),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Bob may view workflows and lists the passes of Ann's run, whose loop
    /// started one. He sees that pass, naming her run; another run has
    /// none.
    #[test]
    fn a_viewer_lists_the_passes_of_a_run() {
        let (execution, starts) = loop_under_way(&person("ann@corp.test"), &["a"]);
        let mut kept = vec![execution.clone()];
        kept.extend(starts.into_iter().map(|start| start.execution));

        let page = listing(&kept, *execution.id(), viewer()).unwrap();
        let other = listing(&kept, WorkflowExecutionId::new(), viewer()).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0].pass().map(|of| of.execution),
            Some(*execution.id())
        );
        assert!(other.items.is_empty());
    }

    /// A caller without workflow rights cannot list a run's loop passes.
    #[test]
    fn listing_passes_needs_the_view_right() {
        let (execution, _) = loop_under_way(&person("ann@corp.test"), &["a"]);

        let result = listing(
            std::slice::from_ref(&execution),
            *execution.id(),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
