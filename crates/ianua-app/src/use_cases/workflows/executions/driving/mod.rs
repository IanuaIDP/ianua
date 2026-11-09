//! The worker's moves on one execution, one change at a time, each read
//! afresh and kept with its record.

mod actions;
mod agent_runs;
mod approval;
mod code;
mod company;
mod guardrail;
mod memory;
mod moves;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::workflows::design::also_ask::AlsoAsk;
use ianua_domain::domains::workflows::design::node::{NodeKey, NodeKind};
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::step::StepRefusal;
use ianua_domain::domains::workflows::execution::{ActingAuthority, HoursBegin, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::WorkflowExecutionId;

pub use self::actions::ActionPorts;
pub use self::agent_runs::AgentStepPorts;
pub use self::company::CompanyPorts;
pub use self::guardrail::GuardrailPorts;
pub use self::memory::MemoryPorts;
use self::moves::{Move, next_move};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::ExecutionVersion;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_cases::workflows::executions::DrivePorts;
use crate::use_cases::workflows::executions::running::keeping::{Keeping, Kept};

/// The most changes one wake-up makes before it lets go. Each step changes
/// a few times at most, so this is reached only by a fault, and the next
/// wake-up goes on from where this one stopped.
const MOST_MOVES: usize = 256;

/// One worker driving one execution: its ports, the tenant, and the audit
/// trail it records to.
pub(super) struct Driving<'a> {
    /// Stores, queues and step adapters used to advance this run.
    pub(super) ports: &'a DrivePorts,
    /// The execution's tenant.
    pub(super) tenant: &'a ScopedTenant,
    /// Records what each change did.
    pub(super) auditor: &'a RequestAuditor,
}

/// Takes execution `id` as far as it goes now, one change at a time.
///
/// # Errors
///
/// - `AppError::Domain` or `AppError::Conflict` when the execution refuses
///   a change read as due.
/// - `AppError::Internal` when a store, the catalog or the audit trail
///   fails.
pub(super) async fn drive(driving: &Driving<'_>, id: &WorkflowExecutionId) -> Result<(), AppError> {
    for _ in 0..MOST_MOVES {
        let Some(execution) = driving.current(id).await? else {
            return Ok(());
        };
        let Some(due) = next_move(&execution) else {
            return Ok(());
        };
        let read = ExecutionVersion::of(&execution);
        driving.make(execution, read, due).await?;
    }
    Ok(())
}

impl Driving<'_> {
    /// The execution `id` as stored now.
    async fn current(
        &self,
        id: &WorkflowExecutionId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, AppError> {
        self.ports
            .executions
            .find_by_id(self.tenant, id)
            .await
            .or_internal()
    }

    /// Makes the change `due` on `execution`, read at `read`, and keeps it.
    async fn make(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        due: Move,
    ) -> Result<(), AppError> {
        let records = match due {
            Move::Expire => execution.expire(),
            Move::Lapse(key) => execution.lapse_approval(&key),
            Move::Elapse(key) => execution.elapse(&key),
            Move::Start(key) => return self.start(execution, read, &key).await,
        }
        .map_err(AppError::from_domain)?;
        self.keep(&execution, read, records).await
    }

    /// When the working hours the wait step `key` waits for next begin, as
    /// the calendar reads them, or that a wait for a set time asks nothing.
    fn hours_begin(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        key: &NodeKey,
    ) -> Result<HoursBegin, DomainError> {
        let Some(hours) = execution.hours_awaited(key) else {
            return Ok(HoursBegin::NotAsked);
        };
        let at = self.ports.calendar.next_opening(hours, clock::now())?;
        Ok(HoursBegin::At(at))
    }

    /// Starts the ready step `key` the way its kind starts.
    async fn start(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
    ) -> Result<(), AppError> {
        let Some(kind) = execution.graph().node(key).map(|node| node.kind().clone()) else {
            return Err(AppError::internal_msg("a ready step is not in the graph"));
        };
        let records = match kind {
            NodeKind::Approval(step) => {
                return self.open_approval(execution, read, key, &step).await;
            }
            NodeKind::Wait(_) => self
                .hours_begin(&execution, key)
                .and_then(|begin| execution.begin_wait(key, begin)),
            NodeKind::AgentRun(step) => {
                return self.start_agent_run(execution, read, key, &step).await;
            }
            NodeKind::Action(step) => return self.run_action(execution, read, key, &step).await,
            NodeKind::Loop(_) => return self.begin_loop(execution, read, key).await,
            NodeKind::Code(_) => return self.start_code(execution, read, key).await,
            NodeKind::Guardrail(step) => {
                return self.run_guardrail(execution, read, key, &step).await;
            }
            NodeKind::Condition(_) | NodeKind::Transform(_) => {
                return Err(AppError::internal_msg(
                    "a step the domain settles itself was left ready",
                ));
            }
        }
        .map_err(AppError::from_domain)?;
        self.keep(&execution, read, records).await
    }

    /// Starts the ready loop step `key` of `execution`, read at `read`, and
    /// keeps it with the passes it started. A loop that asks one approval
    /// for every item in a Slack channel too has that question queued in
    /// the same unit of work.
    async fn begin_loop(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
    ) -> Result<(), AppError> {
        let moves = execution.begin_loop(key).map_err(AppError::from_domain)?;
        let asks_in_slack = execution
            .asked_at(key)
            .is_some_and(|approval| *approval.also_ask() != AlsoAsk::Nowhere);
        let kept_and_asked = async {
            self.keeping()
                .keep_loop(
                    self.tenant,
                    self.auditor,
                    Kept::Changed(&execution, read),
                    moves,
                )
                .await?;
            if asks_in_slack {
                self.ports
                    .wakeups
                    .ask_in_slack(self.tenant, execution.id(), key)
                    .await?;
            }
            Ok(())
        };
        kept_together(self.ports.unit_of_work.as_ref(), kept_and_asked).await
    }

    /// Fails the ready step `key` of `execution`, read at `read`, for
    /// `refusal`, and keeps that.
    async fn refuse(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        refusal: StepRefusal,
    ) -> Result<(), AppError> {
        let records = execution
            .refuse(key, refusal)
            .map_err(AppError::from_domain)?;
        self.keep(&execution, read, records).await
    }

    /// What the person `execution` acts for holds now, asked about
    /// `wanted` resources. `None` when their account is gone or may not
    /// act.
    async fn acting_for(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        wanted: &[ResourceCapability],
    ) -> Result<Option<ActingAuthority>, AppError> {
        let Some(person) = self
            .ports
            .accounts_now
            .person(self.tenant, execution.acting_for(), wanted)
            .await?
        else {
            return Ok(None);
        };
        person.authority(|account, access, resources| {
            ActingAuthority::of_acting_for(execution, account, access, resources)
        })
    }

    /// Keeps `execution`, changed from the copy read at `read`, and the
    /// record of `records` together. A person who decided or cancelled
    /// meanwhile is not undone: the change is refused as a conflict, and
    /// the next wake-up reads the execution afresh.
    async fn keep(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        records: Vec<ExecutionRecord>,
    ) -> Result<(), AppError> {
        kept_together(
            self.ports.unit_of_work.as_ref(),
            self.keeping().keep(
                self.tenant,
                self.auditor,
                Kept::Changed(execution, read),
                records,
            ),
        )
        .await
    }

    /// Where a changed execution is kept.
    fn keeping(&self) -> Keeping<'_> {
        Keeping {
            executions: self.ports.executions.as_ref(),
            wakeups: &self.ports.wakeups,
            runs: &self.ports.run_stops,
        }
    }
}
