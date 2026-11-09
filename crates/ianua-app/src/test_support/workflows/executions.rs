//! Workflow executions kept in memory, per tenant, read back the way storage
//! reads them, and the lease and wake-ups a worker drives them by.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::workflows::execution::step::{StepState, Underway};
use ianua_domain::domains::workflows::execution::{
    ExecutionStatus, StoredMode, WorkflowExecution, WorkflowExecutionRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{AgentRunId, CodeRunId, TenantId, WorkflowExecutionId, WorkflowId};
use time::OffsetDateTime;

use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::workflows::{
    ExecutionLease, ExecutionVersion, NewestFirstField, RunKind, WorkflowExecutionStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::scheduling::FakeJobQueue;
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::scheduling::jobs::payload_of;
use crate::use_cases::workflows::executions::running::run_code::CodeJob;
use crate::use_cases::workflows::executions::running::wakeups::DriveJob;
use crate::use_cases::workflows::executions::{DRIVE_WORKFLOW_JOB, RUN_CODE_JOB, Wakeups};

/// `execution` read back from its row, as storage reads it.
fn copy_of(execution: &WorkflowExecution<ResolvedTenant>) -> WorkflowExecution<ResolvedTenant> {
    WorkflowExecution::reconstitute(WorkflowExecutionRow {
        id: *execution.id(),
        workflow_id: *execution.workflow_id(),
        version: execution.version(),
        graph: execution.graph().clone(),
        acting_for: execution.acting_for().clone(),
        authors: execution.authors().clone(),
        failure_alert: execution.failure_alert(),
        mode: StoredMode::from(execution.mode()),
        cause: execution.cause(),
        pass: execution.pass().cloned(),
        chain_depth: execution.chain_depth(),
        input: execution.input().clone(),
        exposure: execution.exposure(),
        steps: execution.steps().map(|(_, state)| state.clone()).collect(),
        status: execution.status(),
        deadline: execution.deadline(),
        created_at: Aggregate::created_at(execution),
        updated_at: Aggregate::updated_at(execution),
    })
    .expect("a kept execution reads back as itself")
}

/// Whether `execution` is a run of `kind`.
fn of_kind(execution: &WorkflowExecution<ResolvedTenant>, kind: RunKind) -> bool {
    execution.mode().is_test() == (kind == RunKind::Tests)
}

/// Whether one of `execution`'s steps waits, or waited, on `run_id`.
fn started(execution: &WorkflowExecution<ResolvedTenant>, run_id: &AgentRunId) -> bool {
    execution.steps().any(|(_, state)| match state {
        StepState::Running { underway, .. } | StepState::Abandoned { underway, .. } => {
            *underway == Underway::AgentRun(*run_id)
        }
        StepState::Waiting
        | StepState::Ready { .. }
        | StepState::Succeeded { .. }
        | StepState::Failed(_)
        | StepState::Skipped
        | StepState::Stopped => false,
    })
}

/// In-memory execution store: executions kept under their tenant, saved in
/// place. It knows which workflows are agent flows only when a test says so,
/// as storage learns it from the workflows it joins.
#[derive(Default)]
pub struct FakeWorkflowExecutionStore {
    executions: Mutex<Vec<(TenantId, WorkflowExecution<ResolvedTenant>)>>,
    flows: Mutex<Vec<WorkflowId>>,
    moves_on: AtomicBool,
    workflow_reads: AtomicUsize,
    purged_before: Mutex<HashMap<TenantId, OffsetDateTime>>,
}

impl TenantScoped for FakeWorkflowExecutionStore {}

impl FakeWorkflowExecutionStore {
    /// The cutoff the last purge of `tenant`'s runs was given, if any.
    ///
    /// # Panics
    ///
    /// When the lock is poisoned.
    #[must_use]
    pub fn purged_before(&self, tenant: TenantId) -> Option<OffsetDateTime> {
        self.purged_before.lock().unwrap().get(&tenant).copied()
    }

    /// How many reads asked for executions belonging to workflows.
    #[must_use]
    pub fn workflow_reads(&self) -> usize {
        self.workflow_reads.load(Ordering::SeqCst)
    }

    /// A store holding no execution.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `execution` in the test tenant.
    #[must_use]
    pub fn holding(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
        Self::holding_all(std::slice::from_ref(execution))
    }

    /// A store holding every one of `executions` in the test tenant.
    #[must_use]
    pub fn holding_all(executions: &[WorkflowExecution<ResolvedTenant>]) -> Self {
        let tenant = test_ctx().tenant_id();
        Self {
            executions: Mutex::new(executions.iter().map(|e| (tenant, copy_of(e))).collect()),
            flows: Mutex::new(Vec::new()),
            moves_on: AtomicBool::new(false),
            workflow_reads: AtomicUsize::new(0),
            purged_before: Mutex::new(HashMap::new()),
        }
    }

    /// Makes every later save over a version refused, as when the worker
    /// keeps a step of the execution between a change's read and its save.
    pub fn moves_on_before_each_save(&self) {
        self.moves_on.store(true, Ordering::SeqCst);
    }

    /// The same store, knowing `workflow_id` is an agent flow.
    #[must_use]
    pub fn with_flow(self, workflow_id: WorkflowId) -> Self {
        self.flows.lock().unwrap().push(workflow_id);
        self
    }

    /// The execution `id`, as the test tenant keeps it now.
    #[must_use]
    pub fn stored(&self, id: &WorkflowExecutionId) -> Option<WorkflowExecution<ResolvedTenant>> {
        self.matching(test_ctx().tenant_id(), |kept| kept.id() == id)
            .into_iter()
            .next()
    }

    /// The passes the test tenant keeps of the loops of execution `id`.
    #[must_use]
    pub fn passes_of(&self, id: &WorkflowExecutionId) -> Vec<WorkflowExecution<ResolvedTenant>> {
        self.matching(test_ctx().tenant_id(), |kept| {
            kept.pass().is_some_and(|of| of.execution == *id)
        })
    }

    /// Every execution kept, in every tenant.
    #[must_use]
    pub fn all(&self) -> Vec<WorkflowExecution<ResolvedTenant>> {
        self.executions
            .lock()
            .unwrap()
            .iter()
            .map(|(_, kept)| copy_of(kept))
            .collect()
    }

    fn matching(
        &self,
        tenant: TenantId,
        wanted: impl Fn(&WorkflowExecution<ResolvedTenant>) -> bool,
    ) -> Vec<WorkflowExecution<ResolvedTenant>> {
        self.executions
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, kept)| *owner == tenant && wanted(kept))
            .map(|(_, kept)| copy_of(kept))
            .collect()
    }
}

#[async_trait]
impl WorkflowExecutionStore for FakeWorkflowExecutionStore {
    async fn latest_for_workflows(
        &self,
        tenant_id: &ScopedTenant,
        workflow_ids: &[WorkflowId],
    ) -> Result<Vec<WorkflowExecution<ResolvedTenant>>, DomainError> {
        self.workflow_reads.fetch_add(1, Ordering::SeqCst);
        let mut found = self.matching(**tenant_id, |kept| {
            kept.pass().is_none() && workflow_ids.contains(kept.workflow_id())
        });
        found.sort_by_key(|run| {
            std::cmp::Reverse((Aggregate::created_at(run), *run.id().as_uuid()))
        });
        let mut seen = HashSet::new();
        found.retain(|run| seen.insert(*run.workflow_id()));
        Ok(found)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |kept| kept.id() == id)
            .into_iter()
            .next())
    }

    async fn find_by_agent_run(
        &self,
        tenant_id: &ScopedTenant,
        run_id: &AgentRunId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |kept| started(kept, run_id))
            .into_iter()
            .next())
    }

    async fn list_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
        kind: RunKind,
        request: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let found = self.matching(**tenant_id, |kept| {
            kept.pass().is_none() && kept.workflow_id() == workflow_id && of_kind(kept, kind)
        });
        self.workflow_reads.fetch_add(1, Ordering::SeqCst);
        page(found, &SortOrder::<NewestFirstField>::default(), request)
    }

    async fn list_passes(
        &self,
        tenant_id: &ScopedTenant,
        execution_id: &WorkflowExecutionId,
        request: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let found = self.matching(**tenant_id, |kept| {
            kept.pass().is_some_and(|of| of.execution == *execution_id)
        });
        page(found, &SortOrder::<NewestFirstField>::default(), request)
    }

    async fn list_designed(
        &self,
        tenant_id: &ScopedTenant,
        kind: RunKind,
        request: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let flows = self.flows.lock().unwrap().clone();
        let found = self.matching(**tenant_id, |kept| {
            kept.pass().is_none() && !flows.contains(kept.workflow_id()) && of_kind(kept, kind)
        });
        page(found, &SortOrder::<NewestFirstField>::default(), request)
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<(), DomainError> {
        self.executions
            .lock()
            .unwrap()
            .retain(|(owner, kept)| owner != &**tenant_id || kept.id() != id);
        Ok(())
    }

    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.purged_before
            .lock()
            .unwrap()
            .insert(**tenant_id, cutoff);
        let mut runs = self.executions.lock().unwrap();
        let before = runs.len();
        runs.retain(|(owner, kept)| {
            owner != &**tenant_id
                || kept.status() == ExecutionStatus::Running
                || Aggregate::updated_at(kept) >= cutoff
        });
        Ok((before - runs.len()) as u64)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut executions = self.executions.lock().unwrap();
        let held = executions
            .iter()
            .position(|(owner, kept)| owner == &**tenant_id && kept.id() == execution.id());
        let entry = (**tenant_id, copy_of(execution));
        match held {
            Some(index) => executions[index] = entry,
            None => executions.push(entry),
        }
        Ok(())
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
    ) -> Result<ExecutionVersion, DomainError> {
        let mut executions = self.executions.lock().unwrap();
        let moved_on = self.moves_on.load(Ordering::SeqCst);
        let held = executions
            .iter()
            .position(|(owner, kept)| {
                owner == &**tenant_id
                    && kept.id() == execution.id()
                    && ExecutionVersion::of(kept) == read
            })
            .filter(|_| !moved_on);
        let Some(index) = held else {
            return Err(DomainError::conflict(
                "the execution changed since it was read, or is gone",
            ));
        };
        executions[index] = (**tenant_id, copy_of(execution));
        Ok(ExecutionVersion::of(execution))
    }
}

impl Fake for Arc<dyn WorkflowExecutionStore> {
    fn fake() -> Self {
        Arc::new(FakeWorkflowExecutionStore::empty())
    }
}

/// A lease every claim wins unless a test holds it for another worker.
#[derive(Default)]
pub struct FakeExecutionLease {
    held: Mutex<Vec<WorkflowExecutionId>>,
    released: Mutex<Vec<WorkflowExecutionId>>,
}

impl FakeExecutionLease {
    /// A lease nobody holds.
    #[must_use]
    pub fn free() -> Self {
        Self::default()
    }

    /// A lease another worker holds on `id`.
    #[must_use]
    pub fn held_elsewhere(id: WorkflowExecutionId) -> Self {
        Self {
            held: Mutex::new(vec![id]),
            released: Mutex::new(Vec::new()),
        }
    }

    /// Whether the claim on `id` was let go.
    #[must_use]
    pub fn was_released(&self, id: &WorkflowExecutionId) -> bool {
        self.released.lock().unwrap().contains(id)
    }
}

#[async_trait]
impl ExecutionLease for FakeExecutionLease {
    async fn try_claim(&self, id: &WorkflowExecutionId) -> Result<bool, DomainError> {
        let mut held = self.held.lock().unwrap();
        if held.contains(id) {
            return Ok(false);
        }
        held.push(*id);
        Ok(true)
    }

    async fn release(&self, id: &WorkflowExecutionId) {
        self.held.lock().unwrap().retain(|held| held != id);
        self.released.lock().unwrap().push(*id);
    }
}

impl Fake for Arc<dyn ExecutionLease> {
    fn fake() -> Self {
        Arc::new(FakeExecutionLease::free())
    }
}

/// Wake-ups queued as drive jobs on an in-memory queue, so a test can read
/// when each execution asked to be driven again.
#[derive(Default)]
pub struct QueuedWakeups {
    queue: Arc<FakeJobQueue>,
}

impl QueuedWakeups {
    /// No wake-up asked for yet.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The wake-ups the use case under test asks for, queued here.
    #[must_use]
    pub fn wakeups(&self) -> Wakeups {
        Wakeups::new(self.queue.clone())
    }

    /// When `id` was last asked to be driven again.
    ///
    /// # Panics
    ///
    /// When a queued drive job does not name an execution.
    #[must_use]
    pub fn last_for(&self, id: &WorkflowExecutionId) -> Option<OffsetDateTime> {
        self.queue
            .jobs_of(DRIVE_WORKFLOW_JOB)
            .iter()
            .rev()
            .find(|job| driven(job).unwrap() == *id)
            .map(ScheduledJob::run_at)
    }

    /// The code runs asked for, in order.
    ///
    /// # Panics
    ///
    /// When a queued code run's job does not name a run.
    #[must_use]
    pub fn code_runs(&self) -> Vec<CodeRunId> {
        self.queue
            .jobs_of(RUN_CODE_JOB)
            .iter()
            .map(|job| payload_of::<CodeJob>(job).unwrap().run_id)
            .collect()
    }
}

impl Fake for Wakeups {
    fn fake() -> Self {
        QueuedWakeups::none().wakeups()
    }
}

/// The execution a drive job drives.
///
/// # Errors
///
/// `AppError::Internal` when the job is not a drive job.
pub fn driven(job: &ScheduledJob) -> Result<WorkflowExecutionId, AppError> {
    payload_of::<DriveJob>(job).map(|payload| payload.execution_id)
}
