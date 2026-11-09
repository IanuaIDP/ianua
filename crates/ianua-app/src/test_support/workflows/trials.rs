//! Stand-ins for the trials of sandbox versions: an in-memory store and
//! the queue a started trial's run is asked on.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::sandbox::trial::{SandboxTrial, SandboxTrialRow, TrialState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{SandboxTrialId, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::workflows::SandboxTrialStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::scheduling::FakeJobQueue;
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::scheduling::payload_of;
use crate::use_cases::workflows::sandboxes::trying::run::{
    SandboxTrials, TRY_SANDBOX_JOB, TrialJob,
};

/// `trial`, as a store hands it back: rebuilt from its parts.
fn trial_copy(trial: &SandboxTrial<ResolvedTenant>) -> SandboxTrial<ResolvedTenant> {
    SandboxTrial::reconstitute(SandboxTrialRow {
        id: *trial.id(),
        sandbox_id: *trial.sandbox_id(),
        version_id: *trial.version_id(),
        input: trial.input().clone(),
        state: trial.state().clone(),
        started_by: trial.started_by().clone(),
        created_at: Aggregate::created_at(trial),
        updated_at: Aggregate::updated_at(trial),
    })
    .expect("a kept trial reads back as itself")
}

/// In-memory trial store: trials kept under their tenant, an end written
/// only while a trial runs.
#[derive(Default)]
pub struct FakeSandboxTrialStore {
    trials: Mutex<Vec<(TenantId, SandboxTrial<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSandboxTrialStore {}

impl FakeSandboxTrialStore {
    /// A store holding no trial.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `trial` in the test tenant.
    #[must_use]
    pub fn holding(trial: &SandboxTrial<ResolvedTenant>) -> Self {
        Self {
            trials: Mutex::new(vec![(test_ctx().tenant_id(), trial_copy(trial))]),
        }
    }

    /// The trial `id`, as the test tenant keeps it now.
    ///
    /// # Panics
    ///
    /// When the store's lock was poisoned by a test that panicked.
    #[must_use]
    pub fn stored(&self, id: &SandboxTrialId) -> Option<SandboxTrial<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.trials
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.id() == id)
            .map(|(_, kept)| trial_copy(kept))
    }
}

#[async_trait]
impl SandboxTrialStore for FakeSandboxTrialStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxTrialId,
    ) -> Result<Option<SandboxTrial<ResolvedTenant>>, DomainError> {
        Ok(self
            .trials
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id() == id)
            .map(|(_, kept)| trial_copy(kept)))
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.trials
            .lock()
            .unwrap()
            .push((**tenant_id, trial_copy(trial)));
        Ok(())
    }

    async fn save_end(
        &self,
        tenant_id: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut trials = self.trials.lock().unwrap();
        let running = trials.iter().position(|(owner, kept)| {
            owner == &**tenant_id && kept.id() == trial.id() && kept.state() == &TrialState::Running
        });
        let Some(index) = running else {
            return Err(DomainError::conflict("the trial ended already"));
        };
        trials[index] = (**tenant_id, trial_copy(trial));
        Ok(())
    }

    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let mut trials = self.trials.lock().unwrap();
        let before = trials.len();
        trials.retain(|(owner, kept)| {
            owner != &**tenant_id
                || kept.state() == &TrialState::Running
                || Aggregate::updated_at(kept) >= cutoff
        });
        Ok(u64::try_from(before.saturating_sub(trials.len())).unwrap_or(u64::MAX))
    }
}

impl Fake for Arc<dyn SandboxTrialStore> {
    fn fake() -> Self {
        Arc::new(FakeSandboxTrialStore::empty())
    }
}

/// The trial runs a use case queues, held in a fake queue.
#[derive(Default)]
pub struct QueuedTrials {
    queue: Arc<FakeJobQueue>,
}

impl QueuedTrials {
    /// No run queued yet.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The runs the use case under test queues, kept here.
    #[must_use]
    pub fn runs(&self) -> SandboxTrials {
        SandboxTrials::new(self.queue.clone())
    }

    /// The trials whose runs were queued, in order.
    ///
    /// # Panics
    ///
    /// When a queued job does not name a trial.
    #[must_use]
    pub fn queued(&self) -> Vec<SandboxTrialId> {
        self.queue
            .jobs_of(TRY_SANDBOX_JOB)
            .iter()
            .map(|job| payload_of::<TrialJob>(job).unwrap().trial_id)
            .collect()
    }
}

impl Fake for SandboxTrials {
    fn fake() -> Self {
        QueuedTrials::none().runs()
    }
}
