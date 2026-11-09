//! List flows: the tenant's agent flows, newest first, each with where its
//! run stands, for someone who may view workflows.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest};
use crate::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::workflows::flows::{FlowStanding, RunShown};

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the flows, as workflow versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps their runs.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's agent flows.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }

    /// Enriches only the listed flows with their latest runs in one read,
    /// retaining page order and applying each viewer's clearance.
    async fn standings(
        &self,
        tenant: &ScopedTenant,
        viewer: WorkflowControl<'_>,
        flows: Vec<Workflow<ResolvedTenant>>,
    ) -> Result<Vec<FlowStanding>, AppError> {
        if flows.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = flows.iter().map(|flow| *flow.id()).collect();
        let kept = self
            .ports
            .executions
            .latest_for_workflows(tenant, &ids)
            .await
            .or_internal()?;
        let mut runs: HashMap<_, _> = kept
            .into_iter()
            .map(|run| (*run.workflow_id(), run))
            .collect();
        Ok(flows
            .into_iter()
            .map(|flow| {
                let run = runs
                    .remove(flow.id())
                    .map_or(RunShown::Missing, |run| RunShown::to(viewer, run));
                FlowStanding { flow, run }
            })
            .collect())
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = PageRequest;
    type Output = Result<Page<FlowStanding>, AppError>;

    /// One page of the tenant's agent flows, newest first, each with its
    /// run as the person `ctx` names may read it: data above their
    /// clearance withheld, as reading one flow withholds it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        page: PageRequest,
    ) -> Result<Page<FlowStanding>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let viewer = WorkflowControl::new(&authority);
        viewer
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let Page {
            items: flows,
            next,
            limit,
        } = self
            .ports
            .workflows
            .list_flows(&tenant, &page)
            .await
            .map_err(AppError::from_domain)?;
        let items = self.standings(&tenant, viewer, flows).await?;
        Ok(Page { items, next, limit })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::execution::ExecutionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, draft_by, flow_by, started_by, tidy_step,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Ann's agent flow, and a workflow she designed.
    fn held(flow: &Workflow<ResolvedTenant>) -> FakeWorkflowStore {
        let ann = caller_person();
        FakeWorkflowStore::holding(&[
            flow.clone(),
            draft_by(&ann, vec![tidy_step("tidy")], Vec::new()),
        ])
    }

    /// The caller, holding what `authorities` say, lists the first page of
    /// a tenant holding Ann's flow, whose run `executions` keeps.
    fn list_over(
        executions: FakeWorkflowExecutionStore,
        flow: &Workflow<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<FlowStanding>, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            workflows: Arc::new(held(flow)),
            executions: Arc::new(executions),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), PageRequest::default()))
    }

    /// The caller lists a tenant holding Ann's flow, its run under way.
    fn list(authorities: FakeTenantAuthorities) -> Result<Page<FlowStanding>, AppError> {
        let flow = flow_by(&caller_person());
        let run = started_by(&caller_person(), &flow);
        list_over(
            FakeWorkflowExecutionStore::holding(&run),
            &flow,
            authorities,
        )
    }

    /// Someone who may view workflows.
    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Ann lists the tenant's flows. Her flow is listed; the workflow she
    /// designed is not.
    #[test]
    fn only_agent_flows_are_listed() {
        let page = list(viewer()).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].flow.name().as_str(), "Incident digest");
    }

    /// Ann lists the flows and sees each one's run as it stands, so the
    /// dashboard shows her flow still running without opening it.
    #[test]
    fn a_listed_flow_carries_where_its_run_stands() {
        let page = list(viewer()).unwrap();

        assert!(matches!(
            &page.items[0].run,
            RunShown::Viewed(run) if run.status() == ExecutionStatus::Running
        ));
    }

    /// Three listed flows share one run lookup. Missing runs stay visible,
    /// and each other flow shows its own latest run in the listed order.
    #[test]
    fn listed_flows_share_one_run_lookup() {
        let first = flow_by(&caller_person());
        let second = flow_by(&caller_person());
        let missing = flow_by(&caller_person());
        let runs = [
            started_by(&caller_person(), &first),
            started_by(&caller_person(), &second),
        ];
        let executions = Arc::new(FakeWorkflowExecutionStore::holding_all(&runs));
        let use_case = ListUseCase::new(ListPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(&[
                first,
                second,
                missing.clone(),
            ])),
            executions: executions.clone(),
            tenant_authorities: Arc::new(viewer()),
        });

        let page = block_on(use_case.execute(&test_ctx(), PageRequest::default())).unwrap();

        assert_eq!(page.items.len(), 3);
        for item in &page.items {
            match &item.run {
                RunShown::Viewed(run) => assert_eq!(run.workflow_id(), item.flow.id()),
                RunShown::Missing => assert_eq!(item.flow.id(), missing.id()),
                _ => panic!("the author can view the run"),
            }
        }
        assert_eq!(executions.workflow_reads(), 1);
    }

    /// A flow whose run was never kept, as when its start failed halfway,
    /// is still listed, with no run to show.
    #[test]
    fn a_flow_without_a_run_is_listed_without_one() {
        let flow = flow_by(&caller_person());

        let page = list_over(FakeWorkflowExecutionStore::empty(), &flow, viewer()).unwrap();

        assert!(matches!(page.items[0].run, RunShown::Missing));
    }

    /// A caller without workflow rights cannot list the tenant's flows.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's flows.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
