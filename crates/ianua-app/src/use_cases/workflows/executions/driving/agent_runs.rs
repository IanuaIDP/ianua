//! Starting an agent run step: the run is made from the step, acting for the
//! person the execution acts for, under their delegation to the step's agent
//! when the step grants tools.
//!
//! The run is kept, its drive job queued and the run announced like any
//! other, so the agents' worker drives it, and offers it only the tools
//! that person may still use. When
//! it ends, its result is settled on the step.
//!
//! A code step whose sandbox version holds an agent starts its run the same
//! way, every question asked of the version's rules, the run held to the
//! version's check.
//!
//! The run counts toward the plan's limit on runs in flight. While the
//! tenant holds as many as its plan allows, the step is put off and tried
//! again, so a busy tenant's workflows wait instead of failing. The count
//! is made in the unit of work that keeps the run, so it holds until the
//! run is kept.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::workflows::design::node::{AgentRunStep, NodeKey};
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::step::StepRefusal;
use ianua_domain::domains::workflows::execution::{
    ActingAuthority, AgentRunStart, RunAuthority, RunBacking, WorkflowExecution,
};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore, RunStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::shared::AuditLabelResolver;
use crate::ports::workflows::{ExecutionVersion, SandboxVersionStore};
use crate::services::kept_together::kept_together;
use crate::use_cases::agents::runs::RunDrives;
use crate::use_cases::agents::runs::reading::names::run_names;
use crate::use_cases::workflows::executions::driving::Driving;
use crate::use_cases::workflows::executions::running::keeping::Kept;

/// The ports an agent run step goes through.
#[derive(ianua_macros::Fakes)]
pub struct AgentStepPorts {
    /// The agents agent run steps name.
    pub agents: Arc<dyn AgentStore>,
    /// The delegations a step's run acts under.
    pub delegations: Arc<dyn DelegationStore>,
    /// Keeps the agent runs steps start.
    pub runs: Arc<dyn RunStore>,
    /// Queues the job that drives each run a step starts.
    pub run_drives: RunDrives,
    /// Counts the agent runs in flight against the plan.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Names a run's agent and provider in the record that hands it on.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// The sandbox versions code steps name, read to learn whether one
    /// holds an agent to start.
    pub sandbox_versions: Arc<dyn SandboxVersionStore>,
}

/// Whether the tenant's plan has room for another agent run in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Room {
    /// It has.
    Free,
    /// It holds as many as the plan allows.
    Full,
}

/// What kind of step starts a run.
#[derive(Clone, Copy)]
enum RunOf<'v> {
    /// An agent run step, the run made from the step itself.
    AgentStep,
    /// A code step whose sandbox version holds an agent, the run made from
    /// the version's rules and held to its check.
    Version(&'v SandboxVersion<ResolvedTenant>),
}

/// A run to start: the agent, tools and model provider it asks about, and
/// the kind of step it is made for.
struct RunStart<'s> {
    /// What the run's agent, delegation and person are checked against.
    step: &'s AgentRunStep,
    /// The kind of step it is made for.
    of: RunOf<'s>,
}

impl Driving<'_> {
    /// Starts the ready agent run step `key`, fails it, or puts it off
    /// while the plan has no room, as [`start_run`](Self::start_run) does.
    ///
    /// # Errors
    ///
    /// As [`start_run`](Self::start_run).
    pub(super) async fn start_agent_run(
        &self,
        execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        step: &AgentRunStep,
    ) -> Result<(), AppError> {
        let start = RunStart {
            step,
            of: RunOf::AgentStep,
        };
        self.start_run(execution, read, key, start).await
    }

    /// Starts the ready code step `key`, whose sandbox `version` holds an
    /// agent, as a run of that agent under the version's rules, asking
    /// every question an agent run step asks; or fails it, or puts it off,
    /// as [`start_agent_run`](Self::start_agent_run) does.
    ///
    /// # Errors
    ///
    /// As [`start_agent_run`](Self::start_agent_run).
    pub(super) async fn start_held_agent(
        &self,
        execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let Some(held) = version.held_agent() else {
            return Err(AppError::internal_msg("the sandbox version holds no agent"));
        };
        let start = RunStart {
            step: held.run(),
            of: RunOf::Version(version),
        };
        self.start_run(execution, read, key, start).await
    }

    /// Starts the run `start` makes for the ready step `key`, once its
    /// agent, delegation and person hold and the plan has room; or fails it
    /// with the reason it may not start, or puts it off. The room is counted
    /// in the unit of work that keeps the run, so two steps starting runs at
    /// once, with room for one, are counted one after the other.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the step is not ready, or the plan is gone.
    /// - `AppError::Internal` when a store, the count or the audit fails.
    async fn start_run(
        &self,
        execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        start: RunStart<'_>,
    ) -> Result<(), AppError> {
        let step = start.step;
        let Some(agent) = self.step_agent(step).await? else {
            return self
                .refuse(execution, read, key, StepRefusal::AgentMayNotAct)
                .await;
        };
        let delegation = self.delegation_for(&execution, step).await?;
        let Some(acting) = self
            .acting_for_run(&execution, step, delegation.as_ref())
            .await?
        else {
            return self
                .refuse(execution, read, key, StepRefusal::PersonLacksAuthority)
                .await;
        };
        let authority = delegation
            .as_ref()
            .map_or(RunAuthority::NoDelegation, RunAuthority::Delegation);
        let backing = RunBacking {
            authority: &authority,
            agent: &agent,
            acting: &acting,
        };
        self.start_counted(execution, read, key, |execution| {
            started_run(execution, key, start.of, &backing)
        })
        .await
    }

    /// Starts the ready step `key` of `execution`, read at `read`, through
    /// `start` once the plan has room, and keeps what that came to; puts
    /// the step off while it has none.
    ///
    /// The plan's room is counted in the unit of work that keeps the run,
    /// where the count holds the tenant's runs in flight until the run is
    /// kept.
    async fn start_counted(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        start: impl FnOnce(
            &mut WorkflowExecution<ResolvedTenant>,
        ) -> Result<AgentRunStart<ResolvedTenant>, DomainError>
        + Send,
    ) -> Result<(), AppError> {
        let counted_and_kept = async move {
            if self.room_for_a_run().await? == Room::Full {
                return self.defer(execution, read, key).await;
            }
            let started = start(&mut execution).map_err(AppError::from_domain)?;
            self.keep_start(&execution, read, started).await
        };
        kept_together(self.ports.unit_of_work.as_ref(), counted_and_kept).await
    }

    /// The agent `step` names, or `None` once it is gone.
    async fn step_agent(
        &self,
        step: &AgentRunStep,
    ) -> Result<Option<AgentIdentity<ResolvedTenant>>, AppError> {
        self.ports
            .agent_steps
            .agents
            .find_by_id(self.tenant, step.agent_id())
            .await
            .or_internal()
    }

    /// Whether the tenant's plan has room for another agent run in flight.
    /// A run a workflow starts counts as one a person starts.
    async fn room_for_a_run(&self) -> Result<Room, AppError> {
        let plan = self
            .ports
            .plan_limits
            .for_tenant(self.tenant)
            .await
            .map_err(AppError::from_domain)?;
        let checked = self
            .ports
            .agent_steps
            .limit_enforcer
            .check_tenant_limit(&plan, self.tenant, ResourceKind::ActiveAgentRuns)
            .await;
        match checked {
            Ok(()) => Ok(Room::Free),
            Err(DomainError::Forbidden(_)) => Ok(Room::Full),
            Err(other) => Err(AppError::from_domain(other)),
        }
    }

    /// Puts off the ready agent run step `key` while the plan is full, and
    /// keeps that. The step is tried again when the wake-up comes.
    async fn defer(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
    ) -> Result<(), AppError> {
        let records = execution
            .defer_agent_run(key)
            .map_err(AppError::from_domain)?;
        self.keep(&execution, read, records).await
    }

    /// Keeps what starting an agent run step of `execution`, read at
    /// `read`, came to: the run with the execution waiting on it, or the
    /// step's refusal.
    async fn keep_start(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        started: AgentRunStart<ResolvedTenant>,
    ) -> Result<(), AppError> {
        match started {
            AgentRunStart::Started(mut run, records) => {
                self.keep_with_run(Kept::Changed(execution, read), &mut run, records)
                    .await
            }
            AgentRunStart::Refused(records) => self.keep(execution, read, records).await,
        }
    }

    /// The live delegation the person the execution acts for gave the
    /// step's agent, when the step grants tools. A step that grants none
    /// runs under none.
    async fn delegation_for(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        step: &AgentRunStep,
    ) -> Result<Option<Delegation<ResolvedTenant>>, AppError> {
        if step.tools().is_empty() {
            return Ok(None);
        }
        let person = execution.acting_for().principal();
        let now = clock::now();
        let held = self
            .ports
            .agent_steps
            .delegations
            .list_for_agent(self.tenant, step.agent_id())
            .await
            .or_internal()?;
        Ok(held
            .into_iter()
            .find(|delegation| *delegation.delegator() == person && delegation.is_valid(now)))
    }

    /// What the person the execution acts for holds now, asked about use of
    /// the step's model provider and everything `delegation` grants.
    async fn acting_for_run(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        step: &AgentRunStep,
        delegation: Option<&Delegation<ResolvedTenant>>,
    ) -> Result<Option<ActingAuthority>, AppError> {
        let wanted: Vec<ResourceCapability> =
            std::iter::once(ResourceCapability::use_of_provider(step.provider_id()))
                .chain(
                    delegation
                        .into_iter()
                        .flat_map(|granted| granted.granted().resources().iter().cloned()),
                )
                .collect();
        self.acting_for(execution, &wanted).await
    }

    /// Keeps the new `run`, the job that drives it, the execution waiting
    /// on it, and the record of both together. The record that hands the run on is marked with the
    /// execution's place in its chain, so what it sets off continues it.
    async fn keep_with_run(
        &self,
        execution: Kept<'_>,
        run: &mut AgentRun<ResolvedTenant>,
        records: Vec<ExecutionRecord>,
    ) -> Result<(), AppError> {
        let names = run_names(
            self.ports.agent_steps.audit_label_resolver.as_ref(),
            self.tenant,
            run,
        )
        .await;
        run.announce_start(names);
        let kept = async {
            self.ports
                .agent_steps
                .runs
                .save(self.tenant, run)
                .await
                .or_internal()?;
            self.ports
                .agent_steps
                .run_drives
                .hand_over(self.tenant, run)
                .await?;
            self.keeping()
                .keep(self.tenant, self.auditor, execution, records)
                .await?;
            self.auditor
                .dispatch(&run.take_events(self.tenant))
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), kept).await
    }
}

/// What starting the ready step `key` of `execution`, a step of kind `of`,
/// came to under `backing`.
fn started_run(
    execution: &mut WorkflowExecution<ResolvedTenant>,
    key: &NodeKey,
    of: RunOf<'_>,
    backing: &RunBacking<'_, ResolvedTenant>,
) -> Result<AgentRunStart<ResolvedTenant>, DomainError> {
    match of {
        RunOf::AgentStep => {
            execution.start_agent_run(key, backing.authority, backing.agent, backing.acting)
        }
        RunOf::Version(version) => execution.start_held_agent(key, version, backing),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ports::limits::LimitEnforcer;
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx,
    };
    use crate::use_cases::workflows::executions::DrivePorts;

    /// The room a workflow's run finds when `limits` counts the tenant's
    /// runs in flight.
    fn room_under(limits: Arc<dyn LimitEnforcer>) -> Result<Room, AppError> {
        let ports = DrivePorts {
            agent_steps: AgentStepPorts {
                limit_enforcer: limits,
                ..AgentStepPorts::fakes()
            },
            ..DrivePorts::fakes()
        };
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let tenant = test_ctx().tenant();
        let driving = Driving {
            ports: &ports,
            tenant: &tenant,
            auditor: &auditor,
        };
        block_on(driving.room_for_a_run())
    }

    /// Acme has as many agent runs in flight as its plan allows. A
    /// workflow's run finds no room, which is a reason to wait, not a
    /// fault that fails the drive.
    #[test]
    fn a_plan_at_its_limit_has_no_room_for_a_workflows_run() {
        let room = room_under(Arc::new(RejectingLimitEnforcer));

        assert_eq!(room.unwrap(), Room::Full);
    }

    /// Acme is below its plan's limit. A workflow's run has room.
    #[test]
    fn a_plan_below_its_limit_has_room_for_a_workflows_run() {
        let room = room_under(Arc::new(FakeLimitEnforcer));

        assert_eq!(room.unwrap(), Room::Free);
    }
}
