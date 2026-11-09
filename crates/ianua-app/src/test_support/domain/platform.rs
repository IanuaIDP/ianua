//! Observable platform certificate state for orchestration tests.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::hosts::PlatformCertificate;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateId, TenantId};

use crate::ports::domain::{
    PlatformCertificateOrder, PlatformCertificateStore, PlatformCertificateTarget,
    PlatformZoneSettings,
};
use crate::ports::proxy::{CrossTenantHosts, HostedTenant};
use crate::test_support::Fake;

/// A mutable catalog shared between successive reconciliation rounds.
#[derive(Default)]
pub struct FakeHostedTenants(pub Mutex<Vec<HostedTenant>>);

#[async_trait]
impl CrossTenantHosts for FakeHostedTenants {
    async fn all(&self) -> Result<Vec<HostedTenant>, DomainError> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn find(&self, tenant: &TenantId) -> Result<Option<HostedTenant>, DomainError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|held| &held.tenant_id == tenant)
            .cloned())
    }
}

/// Captures desired addresses and failed attempts without inventing tenant events.
#[derive(Default)]
pub struct FakePlatformCertificates {
    /// Desired roots from the most recent synchronization.
    pub targets: Mutex<Vec<PlatformCertificateTarget>>,
    /// Work offered by the test, consumed at most once per round.
    pub orders: Mutex<Vec<PlatformCertificateOrder>>,
    /// Certificates accepted by storage.
    pub saved: Mutex<Vec<CertificateId>>,
    /// Attempts delayed after issuance failure.
    pub failures: Mutex<Vec<CertificateId>>,
}

#[async_trait]
impl PlatformCertificateStore for FakePlatformCertificates {
    async fn synchronize(
        &self,
        targets: &[PlatformCertificateTarget],
        _zones: Option<&PlatformZoneSettings>,
    ) -> Result<(), DomainError> {
        *self.targets.lock().unwrap() = targets.to_vec();
        Ok(())
    }
    async fn claim_next(
        &self,
        _attempt: CertificateId,
    ) -> Result<Option<PlatformCertificateOrder>, DomainError> {
        Ok(self.orders.lock().unwrap().pop())
    }
    async fn save(&self, certificate: &PlatformCertificate) -> Result<(), DomainError> {
        self.saved.lock().unwrap().push(*certificate.id());
        Ok(())
    }
    async fn record_failure(&self, order: &PlatformCertificateOrder) -> Result<(), DomainError> {
        self.failures.lock().unwrap().push(order.id);
        Ok(())
    }
}

impl Fake for Arc<dyn CrossTenantHosts> {
    /// Starts with no hosted tenants.
    fn fake() -> Self {
        Arc::new(FakeHostedTenants::default())
    }
}

impl Fake for Arc<dyn PlatformCertificateStore> {
    /// Starts with no desired roots or outstanding work.
    fn fake() -> Self {
        Arc::new(FakePlatformCertificates::default())
    }
}
