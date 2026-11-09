//! Fakes for the metrics ports: tenant and route-traffic readers that report no traffic and a snapshot writer that keeps what it is handed.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::metrics::{
    MetricSnapshotWriter, RequestMetrics, RouteTraffic, RouteTrafficReader, TenantMetricsReader,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Request figures for a window nobody sent a request in.
#[must_use]
pub fn no_requests() -> RequestMetrics {
    RequestMetrics {
        request_count: 0,
        error_count: 0,
        p95_latency_ms: None,
    }
}

/// Tenant metrics reader for a tenant where nothing has happened yet.
pub struct NoopTenantMetricsReader;

impl TenantScoped for NoopTenantMetricsReader {}

#[async_trait]
impl TenantMetricsReader for NoopTenantMetricsReader {
    async fn login_outcomes(
        &self,
        _: &ScopedTenant,
        _: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, DomainError> {
        Ok(LoginOutcomeCounts::new(0, 0))
    }

    async fn login_outcome_series(
        &self,
        _: &ScopedTenant,
        _: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, DomainError> {
        Ok(Vec::new())
    }

    async fn average_auth_duration_ms(
        &self,
        _: &ScopedTenant,
        _: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, DomainError> {
        Ok(None)
    }

    async fn count_users_as_of(
        &self,
        _: &ScopedTenant,
        _: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn count_active_users(
        &self,
        _: &ScopedTenant,
        _: &MetricsWindow,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn count_active_sessions_as_of(
        &self,
        _: &ScopedTenant,
        _: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn request_metrics(
        &self,
        _: &ScopedTenant,
        _: &MetricsWindow,
    ) -> Result<RequestMetrics, DomainError> {
        Ok(no_requests())
    }

    async fn last_login(&self, _: &ScopedTenant) -> Result<Option<OffsetDateTime>, DomainError> {
        Ok(None)
    }

    async fn count_active_api_keys(&self, _: &ScopedTenant) -> Result<u64, DomainError> {
        Ok(0)
    }
}

#[async_trait]
impl RouteTrafficReader for NoopTenantMetricsReader {
    async fn route_traffic(
        &self,
        _: &ScopedTenant,
        _: &MetricsWindow,
        _: u32,
    ) -> Result<Vec<RouteTraffic>, DomainError> {
        Ok(Vec::new())
    }
}

impl Fake for Arc<dyn TenantMetricsReader> {
    fn fake() -> Self {
        Arc::new(NoopTenantMetricsReader)
    }
}

impl Fake for Arc<dyn RouteTrafficReader> {
    fn fake() -> Self {
        Arc::new(NoopTenantMetricsReader)
    }
}

/// Snapshot writer that answers as a test says.
pub enum FakeSnapshotWriter {
    /// Every run snapshots this many organizations.
    Capturing(u64),
    /// The store cannot be written.
    Failing,
}

#[async_trait]
impl MetricSnapshotWriter for FakeSnapshotWriter {
    async fn capture_all(&self) -> Result<u64, DomainError> {
        match self {
            Self::Capturing(count) => Ok(*count),
            Self::Failing => Err(DomainError::infra_msg("snapshot store unreachable")),
        }
    }
}

impl Fake for Arc<dyn MetricSnapshotWriter> {
    fn fake() -> Self {
        Arc::new(FakeSnapshotWriter::Capturing(0))
    }
}
