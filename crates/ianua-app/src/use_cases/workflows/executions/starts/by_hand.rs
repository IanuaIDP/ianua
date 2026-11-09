//! Start by hand: a person runs a published workflow, acting for
//! themselves.
//!
//! Who it acts for comes from the caller's proof, never from the request.
//! The steps the domain finishes itself run at once; a worker drives the
//! rest, woken as the start is kept.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::{ManualStartParams, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::lookup::published_designed_version;

/// A person's start of a published workflow.
pub struct StartByHandRequest {
    /// The workflow to run. Its version in service runs.
    pub workflow_id: WorkflowId,
    /// The data it starts with.
    pub input: FlowData,
    /// The most sensitive data in it, as the person declared it.
    pub exposure: DataClassLevel,
}

/// The ports [`StartByHandUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartByHandPorts {
    /// The versions, for the one in service.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Hands the new execution to a worker.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Starts workflows by hand.
pub struct StartByHandUseCase {
    ports: StartByHandPorts,
}

impl StartByHandUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartByHandPorts) -> Self {
        Self { ports }
    }
}

impl Command for StartByHandUseCase {
    type Caller = CallerContext;
    type Input = StartByHandRequest;
    type Output = Result<WorkflowExecution<ResolvedTenant>, AppError>;

    /// Starts the published version of `request.workflow_id`, acting for
    /// the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when no version of the workflow is published,
    ///   or it is an agent flow, which runs once, as it is made.
    /// - `AppError::Forbidden` when the caller may not run workflows.
    /// - `AppError::Domain` when the workflow does not start by hand.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: StartByHandRequest,
    ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let workflow = published_designed_version(
            self.ports.workflows.as_ref(),
            &tenant,
            &request.workflow_id,
        )
        .await?;
        let params = ManualStartParams {
            resources: HeldResources::answered(authority.who().principal(), Vec::new()),
            input: request.input,
            exposure: request.exposure,
        };
        let (execution, records) =
            WorkflowExecution::start_by_hand(&workflow, WorkflowControl::new(&authority), params)
                .map_err(AppError::from_domain)?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        keeping
            .keep(&tenant, auditor, Kept::Started(&execution), records)
            .await?;
        Ok(execution)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::execution::ExecutionStatus;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
    use ianua_domain::domains::workflows::triggers::Trigger;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, QueuedWakeups, approval_workflow, draft_by,
        draft_on, flow_by, person, published_by, tidy_step, trigger_data,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The stores a start writes to, and what it recorded.
    struct Started {
        executions: Arc<FakeWorkflowExecutionStore>,
        wakeups: Arc<QueuedWakeups>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Started {
        fn new() -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                wakeups: Arc::new(QueuedWakeups::none()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn start(
            &self,
            workflows: FakeWorkflowStore,
            authorities: FakeTenantAuthorities,
            workflow_id: WorkflowId,
        ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
            let use_case = StartByHandUseCase::new(StartByHandPorts {
                workflows: Arc::new(workflows),
                executions: self.executions.clone(),
                wakeups: self.wakeups.wakeups(),
                tenant_authorities: Arc::new(authorities),
                ..StartByHandPorts::fakes()
            });
            let request = StartByHandRequest {
                workflow_id,
                input: trigger_data(),
                exposure: DataClassLevel::Internal,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn runner() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Run)])
    }

    /// Ann published a workflow that only tidies its data. Bob runs it by
    /// hand. It acts for Bob, finishes at once, and its start and end are
    /// recorded.
    #[test]
    fn a_start_by_hand_acts_for_the_caller_and_runs_what_it_can() {
        let ann = person("ann@corp.test");
        let workflow = published_by(&ann, draft_by(&ann, vec![tidy_step("tidy")], Vec::new()));
        let started = Started::new();

        let execution = started
            .start(
                FakeWorkflowStore::holding(std::slice::from_ref(&workflow)),
                runner(),
                *workflow.id(),
            )
            .unwrap();

        let kept = started.executions.stored(execution.id()).unwrap();
        assert!(kept.acting_for().is_same_account_as(&caller_person()));
        assert_eq!(
            kept.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
        assert_eq!(
            started.records(),
            [
                "workflows.execution_started",
                "workflows.step_succeeded",
                "workflows.execution_ended"
            ]
        );
    }

    /// Bob starts a workflow whose first step asks for approval. The
    /// execution waits on that step, and a worker is woken at once to ask.
    #[test]
    fn a_start_with_work_left_wakes_a_worker() {
        let ann = person("ann@corp.test");
        let workflow = approval_workflow(&ann, ActionClass::Write);
        let started = Started::new();

        let execution = started
            .start(
                FakeWorkflowStore::holding(std::slice::from_ref(&workflow)),
                runner(),
                *workflow.id(),
            )
            .unwrap();

        assert_eq!(execution.status(), ExecutionStatus::Running);
        assert!(started.wakeups.last_for(execution.id()).is_some());
    }

    /// Bob asks to run a workflow that is still a draft. Nothing published
    /// runs, so it is not found and nothing is kept.
    #[test]
    fn a_workflow_with_no_version_in_service_is_not_found() {
        let ann = person("ann@corp.test");
        let draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let started = Started::new();

        let result = started.start(
            FakeWorkflowStore::holding(std::slice::from_ref(&draft)),
            runner(),
            *draft.id(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(started.executions.all().is_empty());
    }

    /// Ann made an agent flow, which ran as she made it. Bob starts it by
    /// hand as if it were a workflow. It is not found, so a flow keeps its
    /// one run and nothing is kept.
    #[test]
    fn an_agent_flow_is_not_started_again_by_hand() {
        let flow = flow_by(&person("ann@corp.test"));
        let started = Started::new();

        let result = started.start(
            FakeWorkflowStore::holding(std::slice::from_ref(&flow)),
            runner(),
            *flow.id(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(started.executions.all().is_empty());
    }

    /// Bob runs by hand a workflow that starts on a webhook. It is refused
    /// as not what the workflow starts on.
    #[test]
    fn a_workflow_on_another_trigger_does_not_start_by_hand() {
        let ann = person("ann@corp.test");
        let on_webhook = published_by(
            &ann,
            draft_on(&ann, vec![tidy_step("tidy")], Vec::new(), Trigger::Webhook),
        );
        let started = Started::new();

        let result = started.start(
            FakeWorkflowStore::holding(std::slice::from_ref(&on_webhook)),
            runner(),
            *on_webhook.id(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A workflow viewer cannot start a published workflow by hand; no execution
    /// is saved and no audit event is recorded.
    #[test]
    fn a_caller_who_may_not_run_workflows_is_refused() {
        let ann = person("ann@corp.test");
        let workflow = approval_workflow(&ann, ActionClass::Write);
        let started = Started::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = started.start(
            FakeWorkflowStore::holding(std::slice::from_ref(&workflow)),
            sam,
            *workflow.id(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(started.executions.all().is_empty());
        assert!(started.records().is_empty());
    }

    /// A signed-out session cannot start a workflow by hand.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ann = person("ann@corp.test");
        let workflow = approval_workflow(&ann, ActionClass::Write);
        let started = Started::new();
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = started.start(
            FakeWorkflowStore::holding(std::slice::from_ref(&workflow)),
            mallory,
            *workflow.id(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
