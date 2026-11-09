//! One route's traffic in a window, as its query answers it, with the
//! names the route and its service have now.

use ianua_app::ports::metrics::RouteTraffic;
use ianua_domain::domains::metrics::LatencyMs;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, RouteId, ServiceId};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;
use crate::postgres::metrics::tenant::record::count;

const TRAFFIC: Stored = Stored("route traffic");

/// A route's traffic as it is read, its percentiles rounded to the
/// millisecond.
pub(super) struct TrafficRecord {
    pub(super) route_id: Uuid,
    pub(super) route_name: Option<String>,
    pub(super) service_id: Option<Uuid>,
    pub(super) service_name: Option<String>,
    pub(super) requests: i64,
    pub(super) denied: i64,
    pub(super) server_errors: i64,
    pub(super) p50: Option<i32>,
    pub(super) p95: Option<i32>,
}

impl TrafficRecord {
    /// The traffic the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a name no longer passes
    /// its rules.
    pub(super) fn into_traffic(self) -> Result<RouteTraffic, DomainError> {
        Ok(RouteTraffic {
            route_id: RouteId::from_uuid(self.route_id),
            route_name: self.route_name.map(named).transpose()?,
            service_id: self.service_id.map(ServiceId::from_uuid),
            service_name: self.service_name.map(named).transpose()?,
            request_count: count(self.requests),
            denied_count: count(self.denied),
            server_error_count: count(self.server_errors),
            p50_latency_ms: self.p50.map(milliseconds),
            p95_latency_ms: self.p95.map(milliseconds),
        })
    }
}

fn named(name: String) -> Result<Label, DomainError> {
    TRAFFIC.value("name", Label::new("name", name))
}

/// A rounded percentile as a latency; none below zero.
fn milliseconds(value: i32) -> LatencyMs {
    LatencyMs::new(u32::try_from(value).unwrap_or_default())
}
