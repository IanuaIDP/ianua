//! List all executions: the runs of every workflow the tenant designed,
//! newest first, for someone who may view workflows, with the data they
//! are not cleared for withheld. Agent flows' runs are read as flows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::execution::ExecutionView;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::workflows::{RunKind, WorkflowExecutionStore};
use crate::use_case::Query;

/// Which kind of runs to list, and which page of them.
pub struct ListAllRequest {
    /// The real runs, or the tests.
    pub kind: RunKind,
    /// The cursor and size bounds for this cross-workflow listing.
    pub page: PageRequest,
}

/// The ports [`ListAllUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListAllPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the runs of every designed workflow.
pub struct ListAllUseCase {
    ports: ListAllPorts,
}

impl ListAllUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListAllPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListAllUseCase {
    type Caller = CallerContext;
    type Input = ListAllRequest;
    type Output = Result<Page<ExecutionView<ResolvedTenant>>, AppError>;

    /// One page of the runs of `request.kind` of every designed workflow,
    /// newest first, each as the caller may read it: data above their
    /// clearance is withheld.
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
        request: ListAllRequest,
    ) -> Result<Page<ExecutionView<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let viewer = WorkflowControl::new(&authority);
        viewer
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .executions
            .list_designed(&ctx.tenant(), request.kind, &request.page)
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
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, awaiting_approval, awaiting_approval_at, flow_by, person,
        started_by,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Runs of two workflows Ann's colleague wrote, and of Ann's agent
    /// flow, which storage knows for a flow.
    fn kept() -> FakeWorkflowExecutionStore {
        let author = person("author@corp.test");
        let ann = person("ann@corp.test");
        let flow = flow_by(&ann);
        let runs = [
            awaiting_approval(&author, &ann, ActionClass::Communicate),
            awaiting_approval(&author, &ann, ActionClass::Write),
            started_by(&ann, &flow),
        ];
        FakeWorkflowExecutionStore::holding_all(&runs).with_flow(*flow.id())
    }

    /// The caller, holding what `authorities` say, lists one page of runs
    /// out of `store`.
    fn list(
        store: FakeWorkflowExecutionStore,
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<ExecutionView<ResolvedTenant>>, AppError> {
        let use_case = ListAllUseCase::new(ListAllPorts {
            executions: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ListAllRequest {
            kind: RunKind::Real,
            page: PageRequest::default(),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    /// Someone who may view workflows.
    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Bob may view workflows and lists every run. He sees the runs of
    /// both workflows; Ann's agent flow's run is left out, as her flow is.
    #[test]
    fn a_viewer_lists_the_runs_of_every_designed_workflow() {
        let page = list(kept(), viewer()).unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(!page.has_next());
    }

    /// The cross-workflow listing withholds a confidential run's input from a
    /// viewer with only internal clearance.
    #[test]
    fn listed_runs_withhold_data_above_the_viewers_clearance() {
        let payroll = awaiting_approval_at(
            &person("author@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Communicate,
            DataClassLevel::Confidential,
        );

        let page = list(FakeWorkflowExecutionStore::holding(&payroll), viewer()).unwrap();

        assert_eq!(page.items[0].input(), None);
    }

    /// A caller without workflow rights cannot list runs across workflows.
    #[test]
    fn listing_needs_the_view_right() {
        let result = list(kept(), FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list runs across workflows.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(kept(), FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
