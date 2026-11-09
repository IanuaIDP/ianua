//! A tenant's traffic per route in a window, read from its request records
//! in one grouped query, with the names its routes and services have now.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::metrics::{RouteTraffic, RouteTrafficReader};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::metrics::MetricsWindow;
use ianua_domain::shared::errors::DomainError;

use self::record::TrafficRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres reader of a tenant's traffic per route.
pub struct PgRouteTrafficReader {
    databases: Arc<Databases>,
}

impl PgRouteTrafficReader {
    /// A reader of the traffic in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRouteTrafficReader {}

#[async_trait]
impl RouteTrafficReader for PgRouteTrafficReader {
    async fn route_traffic(
        &self,
        tenant_id: &ScopedTenant,
        window: &MetricsWindow,
        limit: u32,
    ) -> Result<Vec<RouteTraffic>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TrafficRecord,
                    "queries/proxy_request_records/per_route.sql",
                    tenant_id.as_uuid(),
                    window.start(),
                    window.end(),
                    i64::from(limit)
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(TrafficRecord::into_traffic)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::proxy::{ProxyAccessLogSink, ProxyRequestRecord};
    use ianua_domain::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, RequestOutcome, RouteMatch,
    };
    use ianua_domain::types::{Label, PipelineId, RouteId, ServiceId, TenantId};

    use super::*;
    use crate::postgres::proxy::PgProxyAccessLogSink;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::proxy::{allowed, request_record, saved_route_on};

    fn on(
        tenant: TenantId,
        route: (RouteId, ServiceId),
        outcome: RequestOutcome,
        ms: u32,
    ) -> ProxyRequestRecord {
        ProxyRequestRecord {
            route: RouteMatch::Matched {
                route_id: route.0,
                service_id: route.1,
            },
            ..request_record(tenant, outcome, ms, 10)
        }
    }

    /// Checks checkout's identity, request outcomes and median latency in the grouped result.
    fn assert_checkout(traffic: &RouteTraffic, route: RouteId, service: ServiceId) {
        assert_eq!(traffic.route_id, route);
        assert_eq!(
            traffic.route_name.as_ref().map(Label::as_str),
            Some("checkout")
        );
        assert_eq!(traffic.service_id, Some(service));
        assert_eq!(traffic.request_count, 3);
        assert_eq!(traffic.denied_count, 1);
        assert_eq!(traffic.server_error_count, 1);
        assert_eq!(
            traffic.p50_latency_ms.map(|latency| latency.millis()),
            Some(20)
        );
    }

    /// Three requests on checkout, one refused and one failing upstream,
    /// and one on a route since deleted: the busiest comes first with its
    /// names and figures, the deleted one nameless, and traffic on no
    /// route is left out.
    #[tokio::test]
    async fn traffic_is_read_per_route_busiest_first() {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let checkout = saved_route_on(&db.databases, &tenant, PipelineId::new(), "checkout").await;
        let gone = (RouteId::new(), ServiceId::new());
        let refused = RequestOutcome::Denied {
            status: 403,
            reason: "no".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Unnamed,
        };
        PgProxyAccessLogSink::new(Arc::clone(&db.databases))
            .write_batch(&[
                on(*tenant, checkout, allowed(200), 10),
                on(*tenant, checkout, refused, 20),
                on(*tenant, checkout, allowed(502), 30),
                on(*tenant, gone, allowed(200), 5),
                request_record(*tenant, allowed(200), 5, 10),
            ])
            .await
            .unwrap();
        let reader = PgRouteTrafficReader::new(Arc::clone(&db.databases));
        let window = MetricsWindow::new(at(0), at(60)).unwrap();

        let traffic = reader.route_traffic(&tenant, &window, 10).await.unwrap();
        let busiest = reader.route_traffic(&tenant, &window, 1).await.unwrap();

        assert_eq!(traffic.len(), 2);
        assert_checkout(&traffic[0], checkout.0, checkout.1);
        assert_eq!(traffic[1].route_name, None);
        assert_eq!(busiest.len(), 1);
    }
}
