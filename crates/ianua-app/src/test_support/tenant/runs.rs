//! One fake for the stores of a tenant's step runs, its setup and its
//! teardown: each run kept as its row, one per tenant, and read back
//! through the domain's checks. Like the real store, it saves a new run
//! only once, and a change only over the version it was read at.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::setup::{TenantSetup, TenantSetupRow};
use ianua_domain::domains::tenant::teardown::{TenantTeardown, TenantTeardownRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::{Duration, OffsetDateTime};

use crate::ports::tenant::{SetupVersion, TeardownVersion, TenantSetupStore, TenantTeardownStore};
use crate::test_support::Fake;

/// A run's row as the fake keeps it: whose it is, when it last changed,
/// and the run it reads back as.
pub trait KeptRun: Clone + Send + Sync + 'static {
    /// The run the row reads back as.
    type Run;

    /// The tenant the run is for.
    fn tenant(&self) -> TenantId;

    /// When the run last changed, which is its version.
    fn changed_at(&self) -> OffsetDateTime;

    /// The row, last changed at `at`.
    #[must_use]
    fn changed_on(self, at: OffsetDateTime) -> Self;

    /// The run, through the domain's checks.
    ///
    /// # Errors
    ///
    /// `DomainError::Infrastructure` when the row breaks a rule of the run.
    fn rebuilt(self) -> Result<Self::Run, DomainError>;
}

impl KeptRun for TenantSetupRow {
    type Run = TenantSetup;

    fn tenant(&self) -> TenantId {
        self.tenant_id
    }

    fn changed_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    fn changed_on(self, at: OffsetDateTime) -> Self {
        Self {
            updated_at: at,
            ..self
        }
    }

    fn rebuilt(self) -> Result<TenantSetup, DomainError> {
        TenantSetup::reconstitute(self)
    }
}

impl KeptRun for TenantTeardownRow {
    type Run = TenantTeardown;

    fn tenant(&self) -> TenantId {
        self.tenant_id
    }

    fn changed_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    fn changed_on(self, at: OffsetDateTime) -> Self {
        Self {
            updated_at: at,
            ..self
        }
    }

    fn rebuilt(self) -> Result<TenantTeardown, DomainError> {
        TenantTeardown::reconstitute(self)
    }
}

/// A change another worker saves between a caller's read and its save.
type Meanwhile<R> = Box<dyn FnOnce(R) -> R + Send>;

/// Runs kept in memory, one per tenant.
pub struct FakeRunStore<R> {
    rows: Mutex<Vec<R>>,
    meanwhile: Mutex<Option<Meanwhile<R>>>,
    reads: Mutex<Vec<Vec<TenantId>>>,
}

/// Setups kept in memory.
pub type FakeTenantSetupStore = FakeRunStore<TenantSetupRow>;

/// Teardowns kept in memory.
pub type FakeTenantTeardownStore = FakeRunStore<TenantTeardownRow>;

impl<R: KeptRun> FakeRunStore<R> {
    /// The tenants requested in each store lookup, preserving batches.
    #[must_use]
    pub fn reads(&self) -> Vec<Vec<TenantId>> {
        self.reads.lock().unwrap().clone()
    }

    /// A store holding no run.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
            meanwhile: Mutex::new(None),
            reads: Mutex::new(Vec::new()),
        }
    }

    /// The run kept for `tenant_id`.
    ///
    /// # Panics
    ///
    /// When the kept row no longer reads back, which no test sets up.
    #[must_use]
    pub fn of(&self, tenant_id: &TenantId) -> Option<R::Run> {
        self.found(tenant_id)
            .transpose()
            .expect("a kept run reads back")
    }

    /// Has `change` saved to the kept run just before the next save over a
    /// version, as when a sibling step's job saves the run between the
    /// caller's read and its save. The change moves the version on.
    pub fn changes_before_next_save(&self, change: impl FnOnce(R) -> R + Send + 'static) {
        *self.meanwhile.lock().unwrap() = Some(Box::new(change));
    }

    /// The run kept for `tenant_id`, read back.
    fn found(&self, tenant_id: &TenantId) -> Option<Result<R::Run, DomainError>> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.tenant() == *tenant_id)
            .cloned()
            .map(KeptRun::rebuilt)
    }

    /// Keeps `row` when its tenant has no run kept yet.
    fn added(&self, row: R) -> Result<(), DomainError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|kept| kept.tenant() == row.tenant()) {
            return Err(DomainError::conflict("the tenant's run is kept already"));
        }
        rows.push(row);
        Ok(())
    }

    /// Keeps `row` over the run kept for its tenant while that one is still
    /// at `read`, moving the version on, and answers the version it is
    /// kept at now.
    fn replaced(&self, row: R, read: OffsetDateTime) -> Result<OffsetDateTime, DomainError> {
        let change = self.meanwhile.lock().unwrap().take();
        let mut rows = self.rows.lock().unwrap();
        let Some(kept) = rows.iter_mut().find(|kept| kept.tenant() == row.tenant()) else {
            return Err(DomainError::conflict("the run is gone"));
        };
        if let Some(change) = change {
            *kept = moved_on(kept, change(kept.clone()));
        }
        if kept.changed_at() != read {
            return Err(DomainError::conflict("the run changed since it was read"));
        }
        *kept = moved_on(kept, row);
        Ok(kept.changed_at())
    }
}

/// `row` as it is kept over `kept`: last changed no earlier than just after
/// `kept`, as the real store moves every write's version on.
fn moved_on<R: KeptRun>(kept: &R, row: R) -> R {
    let at = row
        .changed_at()
        .max(kept.changed_at() + Duration::microseconds(1));
    row.changed_on(at)
}

#[async_trait]
impl TenantSetupStore for FakeTenantSetupStore {
    async fn find_many(&self, tenant_ids: &[TenantId]) -> Result<Vec<TenantSetup>, DomainError> {
        self.reads.lock().unwrap().push(tenant_ids.to_vec());
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| tenant_ids.contains(&row.tenant()))
            .cloned()
            .map(KeptRun::rebuilt)
            .collect()
    }

    async fn find(&self, tenant_id: &TenantId) -> Result<Option<TenantSetup>, DomainError> {
        self.reads.lock().unwrap().push(vec![*tenant_id]);
        self.found(tenant_id).transpose()
    }

    async fn save(&self, setup: &TenantSetup) -> Result<(), DomainError> {
        self.added(TenantSetupRow::from(setup))
    }

    async fn save_unchanged_since(
        &self,
        setup: &TenantSetup,
        read: SetupVersion,
    ) -> Result<SetupVersion, DomainError> {
        self.replaced(TenantSetupRow::from(setup), read.changed_at())
            .map(SetupVersion::stored)
    }
}

#[async_trait]
impl TenantTeardownStore for FakeTenantTeardownStore {
    async fn find(&self, tenant_id: &TenantId) -> Result<Option<TenantTeardown>, DomainError> {
        self.found(tenant_id).transpose()
    }

    async fn save(&self, teardown: &TenantTeardown) -> Result<(), DomainError> {
        self.added(TenantTeardownRow::from(teardown))
    }

    async fn save_unchanged_since(
        &self,
        teardown: &TenantTeardown,
        read: TeardownVersion,
    ) -> Result<TeardownVersion, DomainError> {
        self.replaced(TenantTeardownRow::from(teardown), read.changed_at())
            .map(TeardownVersion::stored)
    }
}

impl Fake for Arc<dyn TenantSetupStore> {
    fn fake() -> Self {
        Arc::new(FakeTenantSetupStore::empty())
    }
}

impl Fake for Arc<dyn TenantTeardownStore> {
    fn fake() -> Self {
        Arc::new(FakeTenantTeardownStore::empty())
    }
}
