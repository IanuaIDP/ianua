//! Start as a test: a person tests the latest version of a workflow, its
//! draft before it is published, on example input.
//!
//! Nothing outside changes. Every step that writes, sends, deletes or is
//! undeclared, every agent run, approval and wait, and code that reaches
//! the network stands in, saying what it would have used; reads, decisions
//! and code that reaches no network run for real. A worker drives what is
//! left, as for any run, and the test is kept apart from real runs in its
//! records and lists.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::workflow::RunnableCode;
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::{ManualStartParams, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{
    SandboxStore, SandboxVersionStore, WorkflowExecutionStore, WorkflowStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::designed_version;
use crate::use_cases::workflows::runnable::Runnable;

/// A person's test of a workflow's latest version.
pub struct StartTestRequest {
    /// The workflow whose latest version, its draft or the one in service,
    /// is tested.
    pub workflow_id: WorkflowId,
    /// The example data it starts with.
    pub input: FlowData,
    /// The most sensitive data in it, as the person declared it.
    pub exposure: DataClassLevel,
}

/// The ports [`StartTestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartTestPorts {
    /// The versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// The sandboxes, for whether a code step's version reaches the
    /// network.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Loads code revisions to check whether the test may execute them.
    pub sandbox_versions: Arc<dyn SandboxVersionStore>,
    /// Hands the test to a worker for its real steps.
    pub wakeups: Wakeups,
    /// Stops what a test gives up, should it end.
    pub run_stops: StopPorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Starts tests of workflows.
pub struct StartTestUseCase {
    ports: StartTestPorts,
}

impl StartTestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartTestPorts) -> Self {
        Self { ports }
    }

    /// The code versions of `graph` that may run in a test, as publishing
    /// is told: those whose sandbox is active and that reach no network.
    async fn runnable(
        &self,
        tenant: &ScopedTenant,
        graph: &WorkflowGraph,
    ) -> Result<Vec<RunnableCode>, AppError> {
        Runnable {
            sandboxes: self.ports.sandboxes.as_ref(),
            versions: self.ports.sandbox_versions.as_ref(),
        }
        .in_graph(tenant, graph)
        .await
    }

    /// Keeps the test just started with what it recorded, and hands its
    /// next steps to a worker.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        execution: &WorkflowExecution<ResolvedTenant>,
        records: Vec<ExecutionRecord>,
    ) -> Result<(), AppError> {
        Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        }
        .keep(tenant, auditor, Kept::Started(execution), records)
        .await
    }
}

impl Command for StartTestUseCase {
    type Caller = CallerContext;
    type Input = StartTestRequest;
    type Output = Result<WorkflowExecution<ResolvedTenant>, AppError>;

    /// Tests the latest version of `request.workflow_id`, acting for the
    /// person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing tenant workflow; `Forbidden` without edit/run rights.
    /// - `AppError::Conflict` for an archived latest version; `Domain` for a step reading one that cannot precede it.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: StartTestRequest,
    ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let workflow = designed_version(
            self.ports.workflows.as_ref(),
            &tenant,
            &request.workflow_id,
            None,
        )
        .await?;
        let runnable = self.runnable(&tenant, workflow.graph()).await?;
        let params = ManualStartParams {
            resources: HeldResources::answered(authority.who().principal(), Vec::new()),
            input: request.input,
            exposure: request.exposure,
        };
        let (execution, records) = WorkflowExecution::start_test(
            &workflow,
            WorkflowControl::new(&authority),
            params,
            &runnable,
        )
        .map_err(AppError::from_domain)?;
        self.keep(&tenant, auditor, &execution, records).await?;
        Ok(execution)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::execution::ExecutionStatus;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, QueuedWakeups, approval_step, draft_by,
        next, person, tidy_step, trigger_data,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn tester() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[
            SystemPermission::Workflows(WorkflowAction::Update),
            SystemPermission::Workflows(WorkflowAction::Run),
        ])
    }

    fn test_of(
        workflows: FakeWorkflowStore,
        authorities: FakeTenantAuthorities,
        workflow_id: WorkflowId,
        sink: &Arc<FakeEventDispatcher>,
    ) -> (
        Result<WorkflowExecution<ResolvedTenant>, AppError>,
        Arc<FakeWorkflowExecutionStore>,
    ) {
        let executions = Arc::new(FakeWorkflowExecutionStore::empty());
        let use_case = StartTestUseCase::new(StartTestPorts {
            workflows: Arc::new(workflows),
            executions: executions.clone(),
            wakeups: QueuedWakeups::none().wakeups(),
            tenant_authorities: Arc::new(authorities),
            ..StartTestPorts::fakes()
        });
        let request = StartTestRequest {
            workflow_id,
            input: trigger_data(),
            exposure: DataClassLevel::Internal,
        };
        let started = block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), request));
        (started, executions)
    }

    /// Ann tests her unpublished draft, which tidies its data and asks for
    /// an approval. The tidying runs, the approval stands in, and the test
    /// is kept, ended, and recorded as a test.
    #[test]
    fn a_draft_is_tested_and_kept_as_a_test() {
        let ann = person("ann@corp.test");
        let draft = draft_by(
            &ann,
            vec![
                tidy_step("tidy"),
                approval_step("check", ActionClass::Write),
            ],
            vec![next("tidy", "check")],
        );
        let sink = Arc::new(FakeEventDispatcher::new());

        let (started, executions) = test_of(
            FakeWorkflowStore::holding(std::slice::from_ref(&draft)),
            tester(),
            *draft.id(),
            &sink,
        );

        let test = started.unwrap();
        let kept = executions.stored(test.id()).unwrap();
        assert!(kept.mode().is_test());
        assert_eq!(
            kept.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
        assert!(
            sink.records
                .lock()
                .unwrap()
                .contains(&"workflows.step_stood_in".to_owned())
        );
    }

    /// Run rights alone do not permit testing a draft; the refusal leaves no
    /// execution saved.
    #[test]
    fn testing_needs_the_right_to_edit() {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());
        let runner_only =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Run)]);

        let (started, executions) = test_of(
            FakeWorkflowStore::holding(std::slice::from_ref(&draft)),
            runner_only,
            *draft.id(),
            &sink,
        );

        assert!(matches!(started, Err(AppError::Forbidden(_))));
        assert!(executions.all().is_empty());
    }
}
