//! An in-memory board of what the gateway's health checks reported.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ServiceId, TenantId};

use crate::ports::routing::{BackendHealthReader, BackendHealthReports, ServiceHealthReport};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Keeps each tenant's latest report per service. Nothing lapses: a test
/// that wants none still valid holds none.
#[derive(Default)]
pub struct FakeBackendHealth {
    reports: Mutex<Vec<(TenantId, ServiceHealthReport)>>,
}

impl FakeBackendHealth {
    /// A board holding `report` for `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, report: ServiceHealthReport) -> Self {
        Self {
            reports: Mutex::new(vec![(tenant, report)]),
        }
    }
}

#[async_trait]
impl BackendHealthReports for FakeBackendHealth {
    async fn report(
        &self,
        tenant: &ScopedTenant,
        report: &ServiceHealthReport,
        _valid_for: Duration,
    ) -> Result<(), DomainError> {
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        reports.retain(|(kept, old)| *kept != **tenant || old.service_id != report.service_id);
        reports.push((**tenant, report.clone()));
        Ok(())
    }
}

#[async_trait]
impl BackendHealthReader for FakeBackendHealth {
    async fn latest(
        &self,
        tenant: &ScopedTenant,
        service: &ServiceId,
    ) -> Result<Option<ServiceHealthReport>, DomainError> {
        let reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(reports
            .iter()
            .find(|(kept, report)| *kept == **tenant && report.service_id == *service)
            .map(|(_, report)| report.clone()))
    }
}

impl Fake for Arc<dyn BackendHealthReader> {
    fn fake() -> Self {
        Arc::new(FakeBackendHealth::default())
    }
}
