//! List executions: the runs of a workflow, newest first, for someone who
//! may view workflows, with the data they are not cleared for withheld.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::execution::ExecutionView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::workflows::{RunKind, WorkflowExecutionStore};
use crate::use_case::Query;

/// Whose runs to list, which kind, and which page of them.
pub struct ListRequest {
    /// The workflow, every version of it.
    pub workflow_id: WorkflowId,
    /// Its real runs, or its tests.
    pub kind: RunKind,
    /// The cursor and size bounds for this execution listing.
    pub page: PageRequest,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists a workflow's executions.
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
    type Output = Result<Page<ExecutionView<ResolvedTenant>>, AppError>;

    /// One page of `request.workflow_id`'s executions, newest first, each
    /// as the caller may read it: data above their clearance is withheld.
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
    ) -> Result<Page<ExecutionView<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let viewer = WorkflowControl::new(&authority);
        viewer
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .executions
            .list_for_workflow(
                &ctx.tenant(),
                &request.workflow_id,
                request.kind,
                &request.page,
            )
            .await
            .map_err(AppError::from_domain)?
            .try_map(|execution| execution.viewed_by(viewer))
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::execution::WorkflowExecution;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, awaiting_approval, awaiting_approval_at, person,
    };
    use crate::test_support::{block_on, test_ctx};

    fn kept() -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
        )
    }

    fn list(
        execution: &WorkflowExecution<ResolvedTenant>,
        workflow_id: WorkflowId,
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<ExecutionView<ResolvedTenant>>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ListRequest {
            workflow_id,
            kind: RunKind::Real,
            page: PageRequest::default(),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Bob may view workflows and lists the runs of Ann's report. He sees
    /// its one run; another workflow has none.
    #[test]
    fn a_viewer_lists_a_workflows_runs() {
        let execution = kept();

        let page = list(&execution, *execution.workflow_id(), viewer()).unwrap();
        let other = list(&execution, WorkflowId::new(), viewer()).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id(), execution.id());
        assert!(other.items.is_empty());
    }

    /// Listing a confidential run as a viewer with only internal clearance
    /// withholds its input.
    #[test]
    fn listed_runs_withhold_data_above_the_viewers_clearance() {
        let execution = awaiting_approval_at(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
            DataClassLevel::Confidential,
        );

        let page = list(&execution, *execution.workflow_id(), viewer()).unwrap();

        assert_eq!(page.items[0].input(), None);
    }

    /// A caller without workflow rights cannot list a workflow's runs.
    #[test]
    fn listing_needs_the_view_right() {
        let execution = kept();

        let result = list(
            &execution,
            *execution.workflow_id(),
            FakeTenantAuthorities::holding(&[]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list a workflow's runs.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let execution = kept();

        let result = list(
            &execution,
            *execution.workflow_id(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
