//! List workflows: the latest version of each of the tenant's workflows,
//! for someone who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::workflows::{WorkflowSortField, WorkflowStore};
use crate::use_case::Query;

/// Which stretch of the tenant's workflows to list, in what order.
pub struct ListWorkflowsRequest {
    /// The order.
    pub sort: SortOrder<WorkflowSortField>,
    /// The stretch.
    pub page: PageRequest,
}

/// The ports [`ListWorkflowsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListWorkflowsPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's workflows.
pub struct ListWorkflowsUseCase {
    ports: ListWorkflowsPorts,
}

impl ListWorkflowsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListWorkflowsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListWorkflowsUseCase {
    type Caller = CallerContext;
    type Input = ListWorkflowsRequest;
    type Output = Result<Page<Workflow<ResolvedTenant>>, AppError>;

    /// One page of the latest version of each workflow, for the person
    /// `ctx` names.
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
        request: ListWorkflowsRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .workflows
            .list_latest(&ctx.tenant(), &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::Label;

    use super::*;
    use crate::listing::{Limit, Sort};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowStore, draft_by, flow_by, managing, published_by, tidy_step,
    };
    use crate::test_support::{block_on, test_ctx};

    /// "Weekly report" with version 1 in service and version 2 drafted, and
    /// "Audit sweep" with one draft.
    fn two_workflows() -> Vec<Workflow<ResolvedTenant>> {
        let ann = caller_person();
        let first = published_by(&ann, draft_by(&ann, vec![tidy_step("tidy")], Vec::new()));
        let second = first.next_draft(&managing(&ann)).unwrap();
        let mut sweep = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        sweep
            .rename(&managing(&ann), Label::new("name", "Audit sweep").unwrap())
            .unwrap();
        vec![first, second, sweep]
    }

    fn list(
        authorities: FakeTenantAuthorities,
        page: PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, AppError> {
        let use_case = ListWorkflowsUseCase::new(ListWorkflowsPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(&two_workflows())),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ListWorkflowsRequest {
            sort: SortOrder::single(Sort::ascending(WorkflowSortField::Name)),
            page,
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Ann lists the tenant's workflows by name. Each appears once, at its
    /// latest version: "Audit sweep" at 1, "Weekly report" at 2.
    #[test]
    fn each_workflow_is_listed_once_at_its_latest_version() {
        let page = list(viewer(), PageRequest::default()).unwrap();

        let listed: Vec<(&str, u32)> = page
            .items
            .iter()
            .map(|workflow| (workflow.name().as_str(), workflow.version()))
            .collect();
        assert_eq!(listed, [("Audit sweep", 1), ("Weekly report", 2)]);
        assert_eq!(page.items.len(), 2);
    }

    /// Ann also made an agent flow. The list of designed workflows leaves
    /// it out, so a one-off run of agents does not crowd it.
    #[test]
    fn agent_flows_are_left_out_of_the_workflows_listed() {
        let mut held = two_workflows();
        held.push(flow_by(&caller_person()));
        let use_case = ListWorkflowsUseCase::new(ListWorkflowsPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(&held)),
            tenant_authorities: Arc::new(viewer()),
        });
        let request = ListWorkflowsRequest {
            sort: SortOrder::single(Sort::ascending(WorkflowSortField::Name)),
            page: PageRequest::default(),
        };

        let page = block_on(use_case.execute(&test_ctx(), request)).unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(
            page.items
                .iter()
                .all(|workflow| workflow.name().as_str() != "Incident digest")
        );
    }

    /// Ann asks for one workflow at a time. She gets the first, and the
    /// page says there are two.
    #[test]
    fn a_page_holds_the_stretch_asked_for() {
        let page = list(viewer(), PageRequest::first(Limit::new(1).unwrap())).unwrap();

        assert_eq!(page.items.len(), 1);
        assert!(page.has_next());
    }

    /// A caller without workflow rights cannot list the tenant's workflows.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]), PageRequest::default());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's workflows.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            PageRequest::default(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
