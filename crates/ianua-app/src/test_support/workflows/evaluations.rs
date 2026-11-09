//! Stand-ins for evaluations: in-memory stores of sets and evaluations,
//! the queue a look is asked on, and the cases, sets and evaluations the
//! tests build.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{DataPath, FlowData};
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::evaluation::case::{CaseName, CaseParams, EvaluationCase};
use ianua_domain::domains::workflows::evaluation::check::Expectation;
use ianua_domain::domains::workflows::evaluation::run::{
    Evaluation, EvaluationRow, EvaluationState,
};
use ianua_domain::domains::workflows::evaluation::set::{
    EvaluationSet, EvaluationSetRow, PublishGate, SetParams,
};
use ianua_domain::domains::workflows::execution::{ActingAuthority, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{EvaluationId, Human, TenantId, WorkflowId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::workflows::{EvaluationSetStore, EvaluationStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::scheduling::FakeJobQueue;
use crate::test_support::workflows::{managing, trigger_data};
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::scheduling::payload_of;
use crate::use_cases::workflows::evaluations::run::{EVALUATE_JOB, EvaluationJob, Evaluations};

/// `set`, as a store hands it back: rebuilt from its parts.
fn set_copy(set: &EvaluationSet<ResolvedTenant>) -> EvaluationSet<ResolvedTenant> {
    EvaluationSet::reconstitute(EvaluationSetRow {
        workflow_id: *set.workflow_id(),
        cases: set.cases().to_vec(),
        gate: set.gate(),
        edited_by: set.edited_by().clone(),
        created_at: set.created_at(),
        updated_at: set.updated_at(),
    })
    .expect("a kept set reads back as itself")
}

/// `evaluation`, as a store hands it back: rebuilt from its parts.
fn evaluation_copy(evaluation: &Evaluation<ResolvedTenant>) -> Evaluation<ResolvedTenant> {
    Evaluation::reconstitute(EvaluationRow {
        id: *evaluation.id(),
        workflow_id: *evaluation.workflow_id(),
        version: evaluation.version(),
        revision: evaluation.revision(),
        cases: evaluation.cases().to_vec(),
        outcomes: evaluation.outcomes().to_vec(),
        started_by: evaluation.started_by().clone(),
        state: evaluation.state(),
        deadline: evaluation.deadline(),
        created_at: Aggregate::created_at(evaluation),
        updated_at: Aggregate::updated_at(evaluation),
    })
    .expect("a kept evaluation reads back as itself")
}

/// In-memory set store: one set per workflow, kept under its tenant.
#[derive(Default)]
pub struct FakeEvaluationSetStore {
    sets: Mutex<Vec<(TenantId, EvaluationSet<ResolvedTenant>)>>,
}

impl TenantScoped for FakeEvaluationSetStore {}

impl FakeEvaluationSetStore {
    /// A store holding no set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `set` in the test tenant.
    #[must_use]
    pub fn holding(set: &EvaluationSet<ResolvedTenant>) -> Self {
        Self {
            sets: Mutex::new(vec![(test_ctx().tenant_id(), set_copy(set))]),
        }
    }

    /// The set of workflow `id`, as the test tenant keeps it now.
    ///
    /// # Panics
    ///
    /// When the store's lock was poisoned by a test that panicked.
    #[must_use]
    pub fn stored(&self, id: &WorkflowId) -> Option<EvaluationSet<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.sets
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.workflow_id() == id)
            .map(|(_, kept)| set_copy(kept))
    }
}

#[async_trait]
impl EvaluationSetStore for FakeEvaluationSetStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Option<EvaluationSet<ResolvedTenant>>, DomainError> {
        Ok(self
            .sets
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| owner == &**tenant_id && kept.workflow_id() == workflow_id)
            .map(|(_, kept)| set_copy(kept)))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        set: &EvaluationSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut sets = self.sets.lock().unwrap();
        sets.retain(|(owner, kept)| {
            owner != &**tenant_id || kept.workflow_id() != set.workflow_id()
        });
        sets.push((**tenant_id, set_copy(set)));
        Ok(())
    }
}

impl Fake for Arc<dyn EvaluationSetStore> {
    fn fake() -> Self {
        Arc::new(FakeEvaluationSetStore::empty())
    }
}

/// In-memory evaluation store: evaluations kept under their tenant, each
/// written over only as it was read.
#[derive(Default)]
pub struct FakeEvaluationStore {
    evaluations: Mutex<Vec<(TenantId, Evaluation<ResolvedTenant>)>>,
}

impl TenantScoped for FakeEvaluationStore {}

impl FakeEvaluationStore {
    /// A store holding no evaluation.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `evaluation` in the test tenant.
    #[must_use]
    pub fn holding(evaluation: &Evaluation<ResolvedTenant>) -> Self {
        Self {
            evaluations: Mutex::new(vec![(test_ctx().tenant_id(), evaluation_copy(evaluation))]),
        }
    }

    /// The evaluation `id`, as the test tenant keeps it now.
    ///
    /// # Panics
    ///
    /// When the store's lock was poisoned by a test that panicked.
    #[must_use]
    pub fn stored(&self, id: &EvaluationId) -> Option<Evaluation<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.evaluations
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.id() == id)
            .map(|(_, kept)| evaluation_copy(kept))
    }

    /// The tenant's evaluations `wanted` picks, copied.
    fn picked(
        &self,
        tenant_id: &ScopedTenant,
        wanted: impl Fn(&Evaluation<ResolvedTenant>) -> bool,
    ) -> Vec<Evaluation<ResolvedTenant>> {
        self.evaluations
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, kept)| owner == &**tenant_id && wanted(kept))
            .map(|(_, kept)| evaluation_copy(kept))
            .collect()
    }
}

#[async_trait]
impl EvaluationStore for FakeEvaluationStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EvaluationId,
    ) -> Result<Option<Evaluation<ResolvedTenant>>, DomainError> {
        Ok(self.picked(tenant_id, |kept| kept.id() == id).pop())
    }

    async fn latest_of(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
        limit: u32,
    ) -> Result<Vec<Evaluation<ResolvedTenant>>, DomainError> {
        let mut found = self.picked(tenant_id, |kept| kept.workflow_id() == workflow_id);
        found.sort_by_key(|kept| {
            std::cmp::Reverse((Aggregate::created_at(kept), *kept.id().as_uuid()))
        });
        found.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(found)
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.evaluations
            .lock()
            .unwrap()
            .push((**tenant_id, evaluation_copy(evaluation)));
        Ok(())
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
        read_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut evaluations = self.evaluations.lock().unwrap();
        let unchanged = evaluations.iter().position(|(owner, kept)| {
            owner == &**tenant_id
                && kept.id() == evaluation.id()
                && Aggregate::updated_at(kept) == read_at
        });
        let Some(index) = unchanged else {
            return Err(DomainError::conflict(
                "the evaluation changed since it was read",
            ));
        };
        evaluations[index] = (**tenant_id, evaluation_copy(evaluation));
        Ok(())
    }

    async fn overdue(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Evaluation<ResolvedTenant>>, DomainError> {
        let mut found = self.picked(tenant_id, |kept| kept.is_overdue(now));
        found.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(found)
    }

    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let mut evaluations = self.evaluations.lock().unwrap();
        let before = evaluations.len();
        evaluations.retain(|(owner, kept)| {
            owner != &**tenant_id
                || kept.state() == EvaluationState::Running
                || Aggregate::updated_at(kept) >= cutoff
        });
        Ok(u64::try_from(before.saturating_sub(evaluations.len())).unwrap_or(u64::MAX))
    }
}

impl Fake for Arc<dyn EvaluationStore> {
    fn fake() -> Self {
        Arc::new(FakeEvaluationStore::empty())
    }
}

/// The looks a use case queues, held in a fake queue.
#[derive(Default)]
pub struct QueuedLooks {
    queue: Arc<FakeJobQueue>,
}

impl QueuedLooks {
    /// No look queued yet.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The looks the use case under test queues, kept here.
    #[must_use]
    pub fn looks(&self) -> Evaluations {
        Evaluations::new(self.queue.clone())
    }

    /// The evaluations whose looks were queued, in order.
    ///
    /// # Panics
    ///
    /// When a queued job does not name an evaluation.
    #[must_use]
    pub fn queued(&self) -> Vec<EvaluationId> {
        self.queue
            .jobs_of(EVALUATE_JOB)
            .iter()
            .map(|job| payload_of::<EvaluationJob>(job).unwrap().evaluation_id)
            .collect()
    }
}

impl Fake for Evaluations {
    fn fake() -> Self {
        QueuedLooks::none().looks()
    }
}

/// A case on [`trigger_data`] whose check `holds` or not: a
/// [`tidy_step`](crate::test_support::workflows::tidy_step) called `tidy`
/// hands on `seen: true`, and the check expects `seen` to be `expected`.
fn case_expecting_seen(name: &str, expected: bool) -> EvaluationCase {
    EvaluationCase::new(CaseParams {
        name: CaseName::new(name).expect("a test names its case"),
        input: trigger_data(),
        exposure: DataClassLevel::Internal,
        checks: vec![Expectation::Equals {
            at: DataPath::parse("tidy.seen").expect("a path"),
            value: FlowData::bool(expected),
        }],
    })
    .expect("one check is a case")
}

/// A case a draft with a `tidy` step passes.
#[must_use]
pub fn parcel_case(name: &str) -> EvaluationCase {
    case_expecting_seen(name, true)
}

/// A case a draft with a `tidy` step fails: it expects `seen: false`.
#[must_use]
pub fn failing_case(name: &str) -> EvaluationCase {
    case_expecting_seen(name, false)
}

/// The set `by` saved for `workflow`, holding `cases` behind `gate`.
///
/// # Panics
///
/// Panics if the cases break a set's rules.
#[must_use]
pub fn set_for(
    workflow: &Workflow<ResolvedTenant>,
    by: &Human,
    cases: Vec<EvaluationCase>,
    gate: PublishGate,
) -> EvaluationSet<ResolvedTenant> {
    EvaluationSet::create(workflow, &managing(by), SetParams { cases, gate })
        .expect("a test saves a valid set")
}

/// An evaluation of `workflow` against `set` that `by` started now.
///
/// # Panics
///
/// Panics if the set holds no case or is another workflow's.
#[must_use]
pub fn evaluation_of(
    set: &EvaluationSet<ResolvedTenant>,
    workflow: &Workflow<ResolvedTenant>,
    by: &Human,
) -> Evaluation<ResolvedTenant> {
    Evaluation::start(set, workflow, &managing(by)).expect("a test starts a valid evaluation")
}

/// An evaluation of `workflow` that `by` started, each case run as a test
/// for them and taken in, so it ended as the cases came out.
///
/// # Panics
///
/// Panics if a case cannot run, or more cases are given than run at once.
#[must_use]
pub fn passed_evaluation(
    set: &EvaluationSet<ResolvedTenant>,
    workflow: &Workflow<ResolvedTenant>,
    by: &Human,
) -> Evaluation<ResolvedTenant> {
    let mut evaluation = evaluation_of(set, workflow, by);
    let tests = CapabilitySet::new(
        vec![
            SystemPermission::Workflows(WorkflowAction::Update),
            SystemPermission::Workflows(WorkflowAction::Run),
        ],
        Vec::new(),
    );
    let turns: Vec<(usize, EvaluationCase)> = evaluation
        .startable()
        .map(|(place, case)| (place, case.clone()))
        .collect();
    for (place, case) in turns {
        let evaluator = ActingAuthority::assumed(by.clone(), tests.clone());
        let (run, _) = WorkflowExecution::start_case(workflow, evaluator, &case, &[])
            .expect("a test case runs");
        evaluation
            .start_case(place, &run)
            .expect("its place is free");
        evaluation.settle(&run).expect("its run ended");
    }
    evaluation
}
