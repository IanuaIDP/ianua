//! Fakes for a deleted tenant's teardown: the data and files removed, the audit
//! trails moved, and where its steps are queued. The teardowns themselves
//! are kept by the fake run store.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::audit::AuditTrailMover;
use crate::ports::tenant::{TenantDataPurger, TenantFilePurger};
use crate::test_support::Fake;
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::tenant::teardown::{TEARDOWN_STEP_JOB, TeardownSteps};

/// A purger that records each tenant whose data or files it removed: one
/// stands for either port.
#[derive(Default)]
pub struct FakeTenantPurger {
    purged: Mutex<Vec<TenantId>>,
}

impl FakeTenantPurger {
    /// The tenants whose data or files were removed, in order.
    #[must_use]
    pub fn purged(&self) -> Vec<TenantId> {
        self.purged.lock().unwrap().clone()
    }
}

#[async_trait]
impl TenantDataPurger for FakeTenantPurger {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        self.purged.lock().unwrap().push(*tenant_id);
        Ok(())
    }
}

#[async_trait]
impl TenantFilePurger for FakeTenantPurger {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        self.purged.lock().unwrap().push(*tenant_id);
        Ok(())
    }
}

impl Fake for Arc<dyn TenantDataPurger> {
    fn fake() -> Self {
        Arc::new(FakeTenantPurger::default())
    }
}

impl Fake for Arc<dyn TenantFilePurger> {
    fn fake() -> Self {
        Arc::new(FakeTenantPurger::default())
    }
}

/// A mover that records each tenant whose audit trail it moved.
#[derive(Default)]
pub struct FakeAuditTrailMover {
    moved: Mutex<Vec<TenantId>>,
}

impl FakeAuditTrailMover {
    /// The tenants whose trail was moved, in order.
    #[must_use]
    pub fn moved(&self) -> Vec<TenantId> {
        self.moved.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuditTrailMover for FakeAuditTrailMover {
    async fn move_to_platform(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        self.moved.lock().unwrap().push(*tenant_id);
        Ok(())
    }
}

impl Fake for Arc<dyn AuditTrailMover> {
    fn fake() -> Self {
        Arc::new(FakeAuditTrailMover::default())
    }
}

/// Teardown step jobs queued on `queue`, tried three times each.
#[must_use]
pub fn teardown_steps(queue: Arc<FakeJobQueue>) -> TeardownSteps {
    TeardownSteps::new(
        TEARDOWN_STEP_JOB,
        queue,
        NonZeroU32::new(3).unwrap_or(NonZeroU32::MIN),
    )
}

impl Fake for TeardownSteps {
    fn fake() -> Self {
        teardown_steps(Arc::new(FakeJobQueue::new()))
    }
}
