//! Keeping a changed execution: saving it, recording what happened, stopping
//! the runs and passes it gave up, handing a pass that ended to its loop,
//! and asking for it to be driven again when its next step falls due.

use ianua_domain::domains::workflows::events::execution_events;
use ianua_domain::domains::workflows::execution::record::ExecutionRecord;
use ianua_domain::domains::workflows::execution::step::{Attempt, StepState, Underway};
use ianua_domain::domains::workflows::execution::{
    ExecutionStatus, LoopMoves, PassStart, WorkflowExecution,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{ExecutionVersion, WorkflowExecutionStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::running::Wakeups;

/// Where a changed execution is kept, and what follows from the change.
pub(crate) struct Keeping<'a> {
    /// Keeps the executions.
    pub(crate) executions: &'a dyn WorkflowExecutionStore,
    /// Drives an execution again when its next step falls due.
    pub(crate) wakeups: &'a Wakeups,
    /// Stops the agent runs an execution gave up, settling a paused one at
    /// once.
    pub(crate) runs: &'a StopPorts,
}

/// The execution a keep saves, and how it is written.
#[derive(Clone, Copy)]
pub(crate) enum Kept<'e> {
    /// An execution just started, never stored before.
    Started(&'e WorkflowExecution<ResolvedTenant>),
    /// A stored execution, changed from the copy read at the version: it is
    /// written only while the stored one is still at it, so a change made
    /// meanwhile by the worker or a person is never undone.
    Changed(&'e WorkflowExecution<ResolvedTenant>, ExecutionVersion),
}

impl<'e> Kept<'e> {
    /// The execution kept.
    fn execution(self) -> &'e WorkflowExecution<ResolvedTenant> {
        match self {
            Self::Started(execution) | Self::Changed(execution, _) => execution,
        }
    }
}

impl Keeping<'_> {
    /// Saves the execution `kept` names and records what `records` say
    /// happened to it. Once it ended, every agent run it gave up is ordered
    /// to stop, and one paused for approval is cancelled at once with its
    /// approvals withdrawn, since no worker applies the order until it
    /// resumes. Every pass its loops left running is stopped too, and a
    /// pass that ended is taken in by its loop. While it runs, it is driven
    /// again when its next step falls due.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when a changed execution changed again since
    ///   it was read, or is gone; nothing is recorded.
    /// - `AppError::Internal` when it cannot be saved or recorded, or a stop
    ///   order, a settled run or a wake-up cannot be kept.
    /// - `AppError::Domain` when a paused run's approval cannot be
    ///   withdrawn.
    pub(crate) async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        kept: Kept<'_>,
        records: Vec<ExecutionRecord>,
    ) -> Result<(), AppError> {
        self.save(tenant, kept).await?;
        let execution = kept.execution();
        auditor
            .dispatch(&execution_events(**tenant, execution, records))
            .await
            .or_internal()?;
        self.stop_abandoned_runs(tenant, auditor, execution).await?;
        self.follow_loops(tenant, execution).await?;
        self.wake_when_due(tenant, execution).await
    }

    /// Keeps what a change to a loop step did: each pass it started, saved
    /// as new with its own records, the execution holding the loop, kept as
    /// `kept` names, and a stop for each pass the loop left running when it
    /// failed.
    ///
    /// # Errors
    ///
    /// As [`keep`](Self::keep), for any of the executions kept; a stop that
    /// cannot be queued is `AppError::Internal`.
    pub(crate) async fn keep_loop(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        kept: Kept<'_>,
        moves: LoopMoves<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let LoopMoves {
            records,
            started,
            stop,
        } = moves;
        for PassStart { execution, records } in started {
            self.keep(tenant, auditor, Kept::Started(&execution), records)
                .await?;
        }
        self.keep(tenant, auditor, kept, records).await?;
        for id in &stop {
            self.wakeups.stop_pass(tenant, id).await?;
        }
        Ok(())
    }

    /// Writes the execution `kept` names: a started one as new, a changed
    /// one only over the version it was read at.
    async fn save(&self, tenant: &ScopedTenant, kept: Kept<'_>) -> Result<(), AppError> {
        match kept {
            Kept::Started(execution) => self.executions.save(tenant, execution).await.or_internal(),
            Kept::Changed(execution, read) => self
                .executions
                .save_unchanged_since(tenant, execution, read)
                .await
                .map(|_| ())
                .map_err(AppError::from_domain),
        }
    }

    async fn stop_abandoned_runs(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let stopping = self.runs.stopping();
        for order in execution.abandoned_run_orders() {
            let Some(mut settled) = stopping.stop(tenant, &order).await? else {
                continue;
            };
            let events = self.runs.settled_events(tenant, &mut settled, &order).await;
            auditor.dispatch(&events).await.or_internal()?;
        }
        Ok(())
    }

    /// Once `execution` ended: stops every pass its loops left running, and
    /// when it is itself a pass, has its loop take it in.
    async fn follow_loops(
        &self,
        tenant: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Result<(), AppError> {
        if execution.status() == ExecutionStatus::Running {
            return Ok(());
        }
        for id in execution.abandoned_passes() {
            self.wakeups.stop_pass(tenant, &id).await?;
        }
        if execution.pass().is_some() {
            self.wakeups.pass_ended(tenant, execution.id()).await?;
        }
        Ok(())
    }

    async fn wake_when_due(
        &self,
        tenant: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let Some(at) = next_due(execution) else {
            return Ok(());
        };
        self.wakeups.wake_at(tenant, execution.id(), at).await
    }
}

/// When `execution` next has something to do: a step ready now or due
/// again after a turned-away call or a full plan, a wait that ends, the
/// decision window of an approval step or of a loop's approval of every
/// item closing, or its run limit.
/// `None` once it ended.
pub(crate) fn next_due(execution: &WorkflowExecution<ResolvedTenant>) -> Option<OffsetDateTime> {
    if execution.status() != ExecutionStatus::Running {
        return None;
    }
    let now = clock::now();
    execution
        .steps()
        .filter_map(|(_, state)| due_of(state, now))
        .chain(std::iter::once(execution.deadline()))
        .min()
}

/// When a step in `state` next needs the worker, or `None` while it waits
/// on earlier steps or on work that reports back by itself.
fn due_of(state: &StepState, now: OffsetDateTime) -> Option<OffsetDateTime> {
    match state {
        StepState::Ready {
            attempt: Attempt::First,
            ..
        } => Some(now),
        StepState::Ready {
            attempt:
                Attempt::Again { due, .. } | Attempt::Deferred { due } | Attempt::NextRound { due },
            ..
        } => Some(*due),
        StepState::Running {
            underway: Underway::Timer { until },
            ..
        } => Some(*until),
        StepState::Running {
            underway: underway @ (Underway::Approval(_) | Underway::Loop(_)),
            ..
        } => underway.decision_wait().map(|wait| wait.closes_at),
        StepState::Running { .. }
        | StepState::Waiting
        | StepState::Succeeded { .. }
        | StepState::Failed(_)
        | StepState::Skipped
        | StepState::Stopped
        | StepState::Abandoned { .. } => None,
    }
}
