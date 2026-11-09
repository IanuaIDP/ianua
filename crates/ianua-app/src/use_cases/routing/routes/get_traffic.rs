//! Reads how much traffic each of a tenant's routes carried.
//!
//! The overview says how the tenant's proxy is doing as a whole. This says
//! which route is doing it: the screen someone opens when the overview looks
//! wrong and the next question is "where".

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MetricsAction, SystemPermission};
use ianua_domain::domains::metrics::MetricsWindow;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::metrics::{RouteTraffic, RouteTrafficReader};
use crate::use_case::Query;

/// The largest number of routes one query will return.
///
/// A tenant with a thousand routes has a hundred worth looking at; the rest
/// are the tail, and paging a rollup that is already sorted by volume buys
/// nothing that a longer window would not.
const MAX_ROUTES: u32 = 100;

/// Which stretch of time to read, and how many routes of it.
pub struct GetTrafficRequest {
    /// The stretch of time the figures cover.
    pub window: MetricsWindow,
    /// How many routes to return, busiest first.
    pub limit: u32,
}

/// The ports [`GetTrafficUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetTrafficPorts {
    /// The tenant's per-route traffic figures.
    pub traffic: Arc<dyn RouteTrafficReader>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads per-route traffic figures.
pub struct GetTrafficUseCase {
    ports: GetTrafficPorts,
}

impl GetTrafficUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetTrafficPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetTrafficUseCase {
    type Caller = CallerContext;
    type Input = GetTrafficRequest;
    type Output = Result<Vec<RouteTraffic>, AppError>;

    /// The tenant's routes over the window, busiest first.
    ///
    /// The limit is clamped to `MAX_ROUTES`. A caller asking for none gets
    /// none rather than an error, since an empty page is a fair ask.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the tenant's
    ///   metrics.
    /// - `AppError::Internal` if the figures cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: GetTrafficRequest,
    ) -> Result<Vec<RouteTraffic>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Metrics(MetricsAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .traffic
            .route_traffic(
                &caller.tenant(),
                &request.window,
                request.limit.min(MAX_ROUTES),
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::RouteId;
    use time::Duration;

    use super::*;
    use crate::ports::TenantScoped;
    use crate::tenancy::ScopedTenant;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::routing_label;
    use crate::test_support::{block_on, test_ctx};

    /// Remembers the limit it was asked for, or fails every read.
    #[derive(Default)]
    struct FakeReader {
        asked_for: Mutex<Option<u32>>,
        unreachable: bool,
    }

    impl TenantScoped for FakeReader {}

    #[async_trait]
    impl RouteTrafficReader for FakeReader {
        async fn route_traffic(
            &self,
            _: &ScopedTenant,
            _: &MetricsWindow,
            limit: u32,
        ) -> Result<Vec<RouteTraffic>, DomainError> {
            if self.unreachable {
                return Err(DomainError::infra_msg("metrics store unreachable"));
            }
            *self.asked_for.lock().unwrap() = Some(limit);
            Ok(Vec::new())
        }
    }

    fn window() -> MetricsWindow {
        let end = ianua_domain::shared::clock::now();
        MetricsWindow::new(end - Duration::hours(24), end).unwrap()
    }

    fn read(
        reader: Arc<FakeReader>,
        authorities: FakeTenantAuthorities,
        limit: u32,
    ) -> Result<Vec<RouteTraffic>, AppError> {
        let use_case = GetTrafficUseCase::new(GetTrafficPorts {
            traffic: reader,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(
            &test_ctx(),
            GetTrafficRequest {
                window: window(),
                limit,
            },
        ))
    }

    fn asked_for(limit: u32) -> u32 {
        let reader = Arc::new(FakeReader::default());
        read(
            reader.clone(),
            FakeTenantAuthorities::holding_everything(),
            limit,
        )
        .unwrap();
        reader.asked_for.lock().unwrap().unwrap()
    }

    fn traffic(request_count: u64, denied_count: u64, server_error_count: u64) -> RouteTraffic {
        RouteTraffic {
            route_id: RouteId::new(),
            route_name: Some(routing_label("api")),
            service_id: None,
            service_name: None,
            request_count,
            denied_count,
            server_error_count,
            p50_latency_ms: None,
            p95_latency_ms: None,
        }
    }

    /// Ann asks for the 25 busiest routes. The reader is asked for 25.
    #[test]
    fn a_reasonable_limit_reaches_the_reader_unchanged() {
        assert_eq!(asked_for(25), 25);
    }

    /// Ann asks for ten thousand routes. She gets a page, not a table scan.
    #[test]
    fn an_oversized_limit_is_clamped() {
        assert_eq!(asked_for(10_000), MAX_ROUTES);
    }

    /// Ann asks for no routes. That is a fair ask, passed on, not an error.
    #[test]
    fn a_zero_limit_is_passed_through() {
        assert_eq!(asked_for(0), 0);
    }

    /// A route that carried nothing has no denial or error rate to show.
    #[test]
    fn rates_are_none_without_traffic() {
        let quiet = traffic(0, 0, 0);

        assert!(quiet.denial_rate_percent().is_none());
        assert!(quiet.server_error_rate_percent().is_none());
    }

    /// A route the policy turns away and one whose backend is failing are
    /// different problems, so they are counted apart.
    #[test]
    fn denials_and_upstream_failures_are_separate_rates() {
        let busy = traffic(200, 50, 20);

        assert_eq!(busy.denial_rate_percent(), Some(25.0));
        assert_eq!(busy.server_error_rate_percent(), Some(10.0));
    }

    /// The metrics store cannot be reached. Ann gets an internal error, not
    /// an empty table that would read as no traffic.
    #[test]
    fn a_reader_failure_is_internal() {
        let reader = Arc::new(FakeReader {
            unreachable: true,
            ..FakeReader::default()
        });

        let result = read(reader, FakeTenantAuthorities::holding_everything(), 25);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Reading route traffic without the metrics viewing right is forbidden
    /// and never calls the traffic reader.
    #[test]
    fn a_caller_without_the_metrics_right_is_refused() {
        let reader = Arc::new(FakeReader::default());

        let result = read(reader.clone(), FakeTenantAuthorities::holding(&[]), 25);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(reader.asked_for.lock().unwrap().is_none());
    }

    /// A signed-out session cannot read route traffic.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(
            Arc::new(FakeReader::default()),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            25,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
