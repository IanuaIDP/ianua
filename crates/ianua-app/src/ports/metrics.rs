//! Ports for reading the analytics behind the metrics overviews.
//!
//! [`OrganizationMetricsReader`] is a control-plane port: it aggregates
//! across all of an organization's tenants, so it does not extend
//! [`TenantScoped`]. [`TenantMetricsReader`] and [`RouteTrafficReader`]
//! aggregate within one tenant and take it as a [`ScopedTenant`].
//! Implementations issue scoped
//! aggregate queries; the use cases turn the raw figures into rates,
//! ratios, and trends using the domain's metrics value objects.

use async_trait::async_trait;
use ianua_domain::domains::metrics::{
    LatencyMs, LoginOutcomeCounts, MetricsWindow, TimeSeriesPoint,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, OrganizationId, RouteId, ServiceId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Proxied-request figures for an organization over a single window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestMetrics {
    /// Total requests recorded in the window.
    pub request_count: u64,
    /// Requests whose policy decision blocked them.
    pub error_count: u64,
    /// The 95th-percentile request latency, or `None` when there were no
    /// requests.
    pub p95_latency_ms: Option<LatencyMs>,
}

impl RequestMetrics {
    /// Blocked requests as a percentage of total requests, or `None`
    /// when there were no requests.
    #[must_use]
    pub fn error_rate_percent(&self) -> Option<f64> {
        if self.request_count == 0 {
            return None;
        }

        Some(self.error_count as f64 / self.request_count as f64 * 100.0)
    }
}

/// Traffic through one route over a window.
///
/// A read-model row, not an aggregate: it carries the route's name alongside
/// its id because the only question anyone asks of it is "which routes, and
/// how are they doing", and answering that from ids alone costs a second
/// round trip per row.
///
/// The name is what the route was called when the query ran. A route deleted
/// since still has traffic in the window and still appears, named `None`. Its
/// requests happened, and dropping them would make the totals disagree with
/// the overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTraffic {
    /// The route the requests matched.
    pub route_id: RouteId,
    /// What the route is called now, or `None` if it no longer exists.
    pub route_name: Option<Label>,
    /// The service the route forwards to, when the route still names one.
    pub service_id: Option<ServiceId>,
    /// What that service is called now, or `None` if it no longer exists.
    pub service_name: Option<Label>,
    /// Requests the route served in the window.
    pub request_count: u64,
    /// Requests the pipeline refused before they reached the upstream.
    pub denied_count: u64,
    /// Requests that reached the upstream and came back `5xx`.
    pub server_error_count: u64,
    /// Median request latency, or `None` with no requests.
    pub p50_latency_ms: Option<LatencyMs>,
    /// 95th-percentile request latency, or `None` with no requests.
    pub p95_latency_ms: Option<LatencyMs>,
}

impl RouteTraffic {
    /// Refusals as a percentage of requests, or `None` with no requests.
    #[must_use]
    pub fn denial_rate_percent(&self) -> Option<f64> {
        percent_of(self.denied_count, self.request_count)
    }

    /// Upstream failures as a percentage of requests, or `None` with no
    /// requests.
    ///
    /// Counted separately from refusals: a route the policy is turning away
    /// and a route whose backend is falling over need different people, and
    /// one number cannot say which is happening.
    #[must_use]
    pub fn server_error_rate_percent(&self) -> Option<f64> {
        percent_of(self.server_error_count, self.request_count)
    }
}

/// `part` as a percentage of `whole`, or `None` when nothing was counted.
fn percent_of(part: u64, whole: u64) -> Option<f64> {
    if whole == 0 {
        return None;
    }
    Some(part as f64 / whole as f64 * 100.0)
}

/// Reads organization-wide metrics for the overview page.
#[async_trait]
pub trait OrganizationMetricsReader: Send + Sync {
    /// Counts succeeded and failed logins across the organization
    /// within the window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn login_outcomes(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, DomainError>;

    /// Buckets login outcomes across the window for the success-rate
    /// line chart, using the window's own granularity.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn login_outcome_series(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, DomainError>;

    /// Averages the measured authentication time of successful logins
    /// within the window, or `None` when none were measured.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn average_auth_duration_ms(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, DomainError>;

    /// Counts users that existed as of `at`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_users_as_of(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Counts tenants that existed as of `at`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_tenants_as_of(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Counts sessions that were active as of `at`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_active_sessions_as_of(
        &self,
        organization_id: &OrganizationId,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Aggregates proxied-request figures within the window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn request_metrics(
        &self,
        organization_id: &OrganizationId,
        window: &MetricsWindow,
    ) -> Result<RequestMetrics, DomainError>;

    /// The time of the most recent successful login anywhere in the
    /// organization, or `None` if no one has ever logged in. Not bounded
    /// by the metrics window: it is an absolute "last seen" fact.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn last_login(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OffsetDateTime>, DomainError>;
}

/// Reads single-tenant metrics for the tenant overview page.
#[async_trait]
pub trait TenantMetricsReader: Send + Sync + TenantScoped {
    /// Counts succeeded and failed logins in the tenant within the
    /// window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn login_outcomes(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<LoginOutcomeCounts, DomainError>;

    /// Buckets login outcomes across the window for the activity
    /// line chart, using the window's own granularity.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn login_outcome_series(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Vec<TimeSeriesPoint>, DomainError>;

    /// Averages the measured authentication time of successful logins
    /// within the window, or `None` when none were measured.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn average_auth_duration_ms(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<Option<LatencyMs>, DomainError>;

    /// Counts users that existed as of `at`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_users_as_of(
        &self,
        tenant_id: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Counts distinct users that logged in successfully within the
    /// window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_active_users(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<u64, DomainError>;

    /// Counts sessions that were active as of `at`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_active_sessions_as_of(
        &self,
        tenant_id: &ScopedTenant,
        at: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Aggregates proxied-request figures within the window.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn request_metrics(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
    ) -> Result<RequestMetrics, DomainError>;

    /// The time of the most recent successful login in the tenant, or
    /// `None` if no one has ever logged in. Not bounded by the metrics
    /// window: it is an absolute "last seen" fact.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn last_login(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<OffsetDateTime>, DomainError>;

    /// Counts the tenant's unexpired API keys in `Active` status.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn count_active_api_keys(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError>;
}

/// Reads per-route traffic within one tenant for the route traffic table.
///
/// Kept apart from [`TenantMetricsReader`]: the overview never asks for it,
/// and the route table asks for nothing else.
#[async_trait]
pub trait RouteTrafficReader: Send + Sync + TenantScoped {
    /// Aggregates proxied-request figures per route within the window,
    /// busiest first.
    ///
    /// `limit` bounds the result. Traffic that matched no route is left out
    /// rather than grouped under a null row: it belongs to the tenant, not to
    /// any route, and the overview already counts it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the figures cannot be read.
    async fn route_traffic(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
        limit: u32,
    ) -> Result<Vec<RouteTraffic>, DomainError>;
}

/// Captures point-in-time snapshots of every organization's and
/// tenant's headline counts so the metrics overviews can compute exact
/// trend baselines.
///
/// A background job invokes this on a fixed interval. Counts of mutable
/// resources (users, tenants, active sessions) cannot be reconstructed
/// for a past instant from the live tables, so they are recorded here.
#[async_trait]
pub trait MetricSnapshotWriter: Send + Sync {
    /// Records one snapshot per organization and one per tenant that is
    /// not deleted or archived, and returns the number of organizations
    /// snapshotted.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the underlying write fails.
    async fn capture_all(&self) -> Result<u64, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acme's proxy served 200 requests and 4 failed. Its error rate is 2
    /// percent.
    #[test]
    fn error_rate_is_percentage_of_requests() {
        let metrics = RequestMetrics {
            request_count: 200,
            error_count: 4,
            p95_latency_ms: Some(LatencyMs::new(80)),
        };
        assert_eq!(metrics.error_rate_percent(), Some(2.0));
    }

    /// With no requests there is no error rate at all, rather than a
    /// misleading zero.
    #[test]
    fn error_rate_is_none_without_requests() {
        let metrics = RequestMetrics {
            request_count: 0,
            error_count: 0,
            p95_latency_ms: None,
        };
        assert!(metrics.error_rate_percent().is_none());
    }
}
