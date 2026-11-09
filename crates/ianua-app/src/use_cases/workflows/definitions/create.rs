//! Create workflow: a person drafts the first version of a new workflow.
//!
//! Only a person designs a workflow, and only one who may create workflows.
//! The draft runs nothing until it is published.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::workflow::{
    CanvasLayout, CreateWorkflowParams, FailureAlert, RunLimit, Workflow,
};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, Text};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::workflows::WorkflowStore;
use crate::use_case::Command;

/// The first version of a new workflow, as its designer drew it.
pub struct CreateWorkflowRequest {
    /// The label people use to recognize this automation.
    pub name: Label,
    /// What it does, as its designer describes it.
    pub description: Option<Text>,
    /// Its steps and edges.
    pub graph: WorkflowGraph,
    /// Where its steps sit on the canvas.
    pub layout: CanvasLayout,
    /// What starts it.
    pub trigger: Trigger,
    /// How long one execution may run.
    pub run_limit: RunLimit,
    /// Who is told when one of its runs fails.
    pub failure_alert: FailureAlert,
}

/// The ports [`CreateWorkflowUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateWorkflowPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Checks the plan's workflow limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Drafts new workflows.
pub struct CreateWorkflowUseCase {
    ports: CreateWorkflowPorts,
}

impl CreateWorkflowUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreateWorkflowPorts) -> Self {
        Self { ports }
    }
}

impl Command for CreateWorkflowUseCase {
    type Caller = CallerContext;
    type Input = CreateWorkflowRequest;
    type Output = Result<Workflow<ResolvedTenant>, AppError>;

    /// Drafts version 1 of a new workflow, designed by the person `ctx`
    /// names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the plan's workflow limit is reached, or
    ///   the caller may not create workflows.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateWorkflowRequest,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &ctx.tenant(), ResourceKind::Workflows)
            .await
            .map_err(AppError::from_domain)?;
        let params = CreateWorkflowParams {
            name: request.name,
            description: request.description,
            graph: request.graph,
            layout: request.layout,
            trigger: request.trigger,
            run_limit: request.run_limit,
            failure_alert: request.failure_alert,
        };
        let mut workflow = Workflow::create(params, &WorkflowControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .workflows
            .insert(&ctx.tenant(), &workflow)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), workflow.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(workflow)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::WorkflowStatus;
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{FakeWorkflowStore, tidy_step};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The store a create writes to, and what it recorded.
    struct Written {
        workflows: Arc<FakeWorkflowStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Written {
        fn new() -> Self {
            Self {
                workflows: Arc::new(FakeWorkflowStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self, authorities: FakeTenantAuthorities) -> CreateWorkflowPorts {
            CreateWorkflowPorts {
                workflows: self.workflows.clone(),
                tenant_authorities: Arc::new(authorities),
                ..CreateWorkflowPorts::fakes()
            }
        }

        fn create(&self, ports: CreateWorkflowPorts) -> Result<Workflow<ResolvedTenant>, AppError> {
            let use_case = CreateWorkflowUseCase::new(ports);
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), weekly()))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn weekly() -> CreateWorkflowRequest {
        CreateWorkflowRequest {
            name: Label::new("name", "Weekly report").unwrap(),
            description: None,
            graph: WorkflowGraph::new(vec![tidy_step("tidy")], Vec::new()).unwrap(),
            layout: CanvasLayout::default(),
            trigger: Trigger::Manual,
            run_limit: RunLimit::new(Lifetime::seconds(3600).unwrap()).unwrap(),
            failure_alert: FailureAlert::default(),
        }
    }

    fn creator() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Create)])
    }

    /// Ann, who may create workflows, drafts "Weekly report". Version 1 is
    /// kept as a draft she designed, and its creation is recorded.
    #[test]
    fn the_designer_drafts_version_one_and_it_is_recorded() {
        let written = Written::new();

        let workflow = written.create(written.ports(creator())).unwrap();

        let kept = written.workflows.stored(workflow.id(), 1).unwrap();
        assert_eq!(kept.status(), WorkflowStatus::Draft);
        assert!(kept.created_by().is_same_account_as(&caller_person()));
        assert_eq!(written.records(), ["workflows.workflow_created"]);
    }

    /// The tenant's plan allows no more workflows. Ann is refused, nothing
    /// is kept and nothing is recorded.
    #[test]
    fn a_create_past_the_plan_limit_is_refused() {
        let written = Written::new();
        let ports = CreateWorkflowPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..written.ports(creator())
        };

        let result = written.create(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.workflows.count(), 0);
        assert!(written.records().is_empty());
    }

    /// A workflow viewer cannot create a draft; the workflow store remains empty.
    #[test]
    fn a_caller_who_may_not_create_workflows_is_refused() {
        let written = Written::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = written.create(written.ports(sam));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.workflows.count(), 0);
    }

    /// A signed-out session cannot create a draft; the workflow store remains empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let written = Written::new();
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = written.create(written.ports(mallory));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(written.workflows.count(), 0);
    }
}
