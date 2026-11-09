//! Create flow: a person lays out stages of agent runs, and the flow is
//! made, published and started at once, acting for them.
//!
//! A flow counts against the plan's workflows. Making one needs the rights
//! to create and to run workflows, since it runs as it is made.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::node::AgentRunParams;
use ianua_domain::domains::workflows::design::workflow::{FlowDescription, NewFlow, Workflow};
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::{ManualStartParams, WorkflowExecution};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Label;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::workflows::{WorkflowExecutionStore, WorkflowStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};
use crate::use_cases::workflows::flows::FlowStarted;

/// A flow as its maker laid it out, and what its run starts with.
pub struct CreateRequest {
    /// The label people use to recognize this multi-stage flow.
    pub name: Label,
    /// What its maker wrote about it.
    pub description: FlowDescription,
    /// Its stages, in order: the runs of each start together, once every
    /// run of the stage before has answered.
    pub stages: Vec<Vec<AgentRunParams>>,
    /// The data its run starts with.
    pub input: FlowData,
    /// The most sensitive data in it, as the maker declared it.
    pub exposure: DataClassLevel,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the flow, as a workflow version.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps its run.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Hands the run to a worker.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end.
    pub run_stops: StopPorts,
    /// Checks the plan's workflow limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes and starts agent flows.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<FlowStarted, AppError>;

    /// Makes the flow `request` lays out for the person `ctx` names, and
    /// starts its run acting for them. Records `workflows.flow_created` and
    /// the run's start.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the plan's workflow limit is reached, or
    ///   the caller may not both create and run workflows.
    /// - `AppError::Domain` when the stages do not make a flow: a stage
    ///   without runs, a run an agent step does not allow, or too many
    ///   steps.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<FlowStarted, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::Workflows)
            .await
            .map_err(AppError::from_domain)?;
        let (mut started, records) = made_and_started(WorkflowControl::new(&authority), request)
            .map_err(AppError::from_domain)?;
        self.ports
            .workflows
            .insert(&tenant, &started.flow)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), started.flow.take_events(&tenant))
            .await
            .or_internal()?;
        let keeping = Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        };
        keeping
            .keep(&tenant, auditor, Kept::Started(&started.run), records)
            .await?;
        Ok(started)
    }
}

/// The flow `request` lays out, made by `maker`, and its run, started by
/// hand acting for them, with what the start did.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `maker` may not both create and run
///   workflows.
/// - [`DomainError::Validation`] when the stages do not make a flow.
fn made_and_started(
    maker: WorkflowControl<'_>,
    request: CreateRequest,
) -> Result<(FlowStarted, Vec<ExecutionRecord>), DomainError> {
    let CreateRequest {
        name,
        description,
        stages,
        input,
        exposure,
    } = request;
    let graph = WorkflowGraph::staged(stages)?;
    let flow = Workflow::flow(
        &maker,
        NewFlow {
            name,
            description,
            graph,
        },
    )?;
    let params = ManualStartParams {
        resources: HeldResources::answered(maker.by().principal(), Vec::new()),
        input,
        exposure,
    };
    let (run, records) = WorkflowExecution::start_by_hand(&flow, maker, params)?;
    Ok((FlowStarted { flow, run }, records))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::{WorkflowOrigin, WorkflowStatus};
    use ianua_domain::domains::workflows::execution::ExecutionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, QueuedWakeups, trigger_data, two_stages,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The stores a flow is made into, and what it recorded.
    struct Making {
        workflows: Arc<FakeWorkflowStore>,
        executions: Arc<FakeWorkflowExecutionStore>,
        wakeups: Arc<QueuedWakeups>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Making {
        /// Nothing made yet.
        fn new() -> Self {
            Self {
                workflows: Arc::new(FakeWorkflowStore::empty()),
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                wakeups: Arc::new(QueuedWakeups::none()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The ports, with the caller holding what `authorities` say.
        fn ports(&self, authorities: FakeTenantAuthorities) -> CreatePorts {
            CreatePorts {
                workflows: self.workflows.clone(),
                executions: self.executions.clone(),
                wakeups: self.wakeups.wakeups(),
                tenant_authorities: Arc::new(authorities),
                ..CreatePorts::fakes()
            }
        }

        /// The caller makes the flow `stages` lay out, through `ports`.
        fn make(
            &self,
            ports: CreatePorts,
            stages: Vec<Vec<AgentRunParams>>,
        ) -> Result<FlowStarted, AppError> {
            let request = CreateRequest {
                name: Label::new("name", "Incident digest").unwrap(),
                description: FlowDescription::Blank,
                stages,
                input: trigger_data(),
                exposure: DataClassLevel::Internal,
            };
            let use_case = CreateUseCase::new(ports);
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }

        /// Whether nothing was kept.
        fn nothing_kept(&self) -> bool {
            self.workflows.count() == 0 && self.executions.all().is_empty()
        }
    }

    /// Someone who may create and run workflows.
    fn maker() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[
            SystemPermission::Workflows(WorkflowAction::Create),
            SystemPermission::Workflows(WorkflowAction::Run),
        ])
    }

    /// Ann lays out two stages of agents. The flow is kept as one published
    /// version, its run starts acting for her with the first stage ready,
    /// a worker is woken for it, and both are recorded.
    #[test]
    fn a_flow_is_made_published_and_started_for_its_maker() {
        let making = Making::new();

        let started = making.make(making.ports(maker()), two_stages()).unwrap();

        let kept = making.workflows.stored(started.flow.id(), 1).unwrap();
        assert_eq!(kept.status(), WorkflowStatus::Published);
        assert!(matches!(kept.origin(), WorkflowOrigin::Flow(_)));
        let run = making.executions.stored(started.run.id()).unwrap();
        assert_eq!(run.status(), ExecutionStatus::Running);
        assert!(run.acting_for().is_same_account_as(&caller_person()));
        assert_eq!(run.ready().count(), 2);
        assert!(making.wakeups.last_for(run.id()).is_some());
        assert_eq!(
            &making.records()[..2],
            ["workflows.flow_created", "workflows.execution_started"]
        );
    }

    /// The tenant's plan allows no more workflows. Ann's flow is refused,
    /// nothing is kept and nothing is recorded.
    #[test]
    fn a_flow_past_the_plan_limit_is_refused() {
        let making = Making::new();
        let ports = CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..making.ports(maker())
        };

        let result = making.make(ports, two_stages());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(making.nothing_kept());
        assert!(making.records().is_empty());
    }

    /// Ann lays out a stage with no runs. It is refused as no flow, and
    /// nothing is kept.
    #[test]
    fn a_stage_without_runs_is_refused() {
        let making = Making::new();

        let result = making.make(making.ports(maker()), vec![Vec::new()]);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(making.nothing_kept());
    }

    /// Creating a flow also requires workflow run rights. A caller with only
    /// create rights is refused without saving a flow, run or audit event.
    #[test]
    fn a_caller_who_may_not_run_workflows_is_refused() {
        let making = Making::new();
        let bob =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Create)]);

        let result = making.make(making.ports(bob), two_stages());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(making.nothing_kept());
        assert!(making.records().is_empty());
    }

    /// A signed-out session cannot create a flow; neither flow nor run is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let making = Making::new();
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = making.make(making.ports(mallory), two_stages());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(making.nothing_kept());
    }
}
