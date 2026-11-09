//! Fakes for a tenant's setup: the databases made and removed, the progress
//! told, and where its steps are queued. The setups themselves are kept by
//! the fake run store.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::provisioning::infrastructure::IsolationLevel;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};

use crate::ports::provisioning::{SetupProgress, SetupProgressObserver};
use crate::ports::tenant::{
    ProvisionDatabaseRequest, ProvisionedEndpoint, TenantDatabaseProvisioner,
};
use crate::test_support::Fake;
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::tenant::setup::{SETUP_STEP_JOB, SetupSteps};

/// A database provisioner that records each tenant it made a database for
/// or removed one of, and fails the first so many calls of either.
#[derive(Default)]
pub struct FakeTenantDatabaseProvisioner {
    made: Mutex<Vec<(TenantId, IsolationLevel)>>,
    torn_down: Mutex<Vec<TenantId>>,
    failures_left: Mutex<u32>,
}

impl FakeTenantDatabaseProvisioner {
    /// A provisioner that always does what it is asked.
    #[must_use]
    pub fn working() -> Self {
        Self::default()
    }

    /// A provisioner whose first `failures` calls fail.
    #[must_use]
    pub fn failing(failures: u32) -> Self {
        Self {
            failures_left: Mutex::new(failures),
            ..Self::default()
        }
    }

    /// The tenants a database was made for, with their isolation.
    #[must_use]
    pub fn made(&self) -> Vec<(TenantId, IsolationLevel)> {
        self.made.lock().unwrap().clone()
    }

    /// The tenants whose database was removed, in order.
    #[must_use]
    pub fn torn_down(&self) -> Vec<TenantId> {
        self.torn_down.lock().unwrap().clone()
    }

    /// An error while calls are left to fail, as a host that did not answer.
    fn answered(&self) -> Result<(), DomainError> {
        let mut left = self.failures_left.lock().unwrap();
        if *left == 0 {
            return Ok(());
        }
        *left -= 1;
        Err(DomainError::infra_msg("the database host did not answer"))
    }
}

#[async_trait]
impl TenantDatabaseProvisioner for FakeTenantDatabaseProvisioner {
    async fn provision(
        &self,
        tenant_id: &TenantId,
        _organization_id: &OrganizationId,
        request: &ProvisionDatabaseRequest,
    ) -> Result<ProvisionedEndpoint, DomainError> {
        self.answered()?;
        self.made
            .lock()
            .unwrap()
            .push((*tenant_id, request.isolation()));
        Ok(ProvisionedEndpoint::Shared)
    }

    async fn migrate_isolation(
        &self,
        _tenant_id: &TenantId,
        _organization_id: &OrganizationId,
        _from: IsolationLevel,
        _to: &ProvisionDatabaseRequest,
    ) -> Result<ProvisionedEndpoint, DomainError> {
        Ok(ProvisionedEndpoint::Shared)
    }

    async fn teardown(
        &self,
        tenant_id: &TenantId,
        _organization_id: &OrganizationId,
        _isolation: IsolationLevel,
    ) -> Result<(), DomainError> {
        self.answered()?;
        self.torn_down.lock().unwrap().push(*tenant_id);
        Ok(())
    }
}

impl Fake for Arc<dyn TenantDatabaseProvisioner> {
    fn fake() -> Self {
        Arc::new(FakeTenantDatabaseProvisioner::working())
    }
}

/// Setup progress told, kept in order.
#[derive(Default)]
pub struct RecordingSetupProgress {
    told: Mutex<Vec<SetupProgress>>,
}

impl RecordingSetupProgress {
    /// The progress told so far, oldest first.
    #[must_use]
    pub fn told(&self) -> Vec<SetupProgress> {
        self.told.lock().unwrap().clone()
    }
}

#[async_trait]
impl SetupProgressObserver for RecordingSetupProgress {
    async fn on_progress(&self, progress: &SetupProgress) {
        self.told.lock().unwrap().push(progress.clone());
    }
}

impl Fake for Arc<dyn SetupProgressObserver> {
    fn fake() -> Self {
        Arc::new(RecordingSetupProgress::default())
    }
}

/// Setup step jobs queued on `queue`, tried three times each.
#[must_use]
pub fn setup_steps(queue: Arc<FakeJobQueue>) -> SetupSteps {
    SetupSteps::new(
        SETUP_STEP_JOB,
        queue,
        NonZeroU32::new(3).unwrap_or(NonZeroU32::MIN),
    )
}

impl Fake for SetupSteps {
    fn fake() -> Self {
        setup_steps(Arc::new(FakeJobQueue::new()))
    }
}
