//! Rows the proxy store tests build from: pipelines holding the two stages
//! every pipeline has, routes saved on them through the routing stores,
//! log shipping targets, and the records of finished requests.

use std::net::IpAddr;
use std::sync::Arc;

use ianua_app::ports::proxy::ProxyRequestRecord;
use ianua_app::ports::routing::{RouteStore, ServiceStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::streaming::DatadogSite;
use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogFormat, LogShippingTargetRow, LogTargetSettings, LogTargetStatus,
    ShippedRecords, ShippingCredential,
};
use ianua_domain::domains::proxy::observation::{
    ObservedPrincipal, RequestOutcome, RouteMatch, RulingPolicy,
};
use ianua_domain::domains::proxy::pipeline::PipelineRow;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::stages::stage::{MandatoryStage, StageConfig};
use ianua_domain::domains::routing::route::{Route, RouteRow};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    CorrelationId, Label, LogShippingTargetId, PipelineId, RouteId, SealedSecret, ServiceId,
    TenantId, UntrustedText,
};

use crate::postgres::Databases;
use crate::postgres::routing::{PgRouteStore, PgServiceStore};
use crate::test_support::rows::at;
use crate::test_support::rows::routing::{route_row, service_row};

/// A label for a test, such as a pipeline's or a target's name.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn label(name: &str) -> Label {
    Label::new("name", name).expect("a valid name")
}

/// A draft pipeline named `name`, made `seconds` after the fixed moment,
/// holding the Identity and Policy stages alone.
#[must_use]
pub fn pipeline_row(name: &str, seconds: i64) -> PipelineRow {
    PipelineRow {
        id: PipelineId::new(),
        name: label(name),
        status: PipelineStatus::Draft,
        stages: vec![
            StageConfig::locked(MandatoryStage::Identity),
            StageConfig::locked(MandatoryStage::Policy),
        ],
        created_at: at(seconds),
        updated_at: at(seconds),
    }
}

/// A route named `name` of `tenant` on `pipeline`, and the service named
/// after it that it forwards to, both saved through their stores.
///
/// # Panics
///
/// When either cannot be saved, which is a broken test database.
pub async fn saved_route_on(
    databases: &Arc<Databases>,
    tenant: &ScopedTenant,
    pipeline: PipelineId,
    name: &str,
) -> (RouteId, ServiceId) {
    let service: Service<ResolvedTenant> =
        Service::reconstitute(service_row(&format!("{name}-api"))).expect("a valid service");
    PgServiceStore::new(Arc::clone(databases))
        .save(tenant, &service)
        .await
        .expect("the service is saved");
    let route: Route<ResolvedTenant> = Route::reconstitute(RouteRow {
        pipeline_id: pipeline,
        ..route_row(*service.id(), name)
    })
    .expect("a valid route");
    PgRouteStore::new(Arc::clone(databases))
        .save(tenant, &route)
        .await
        .expect("the route is saved");
    (*route.id(), *service.id())
}

/// An active target named `name`, made `seconds` after the fixed moment,
/// shipping every record as JSON lines to Datadog's EU site with a sealed
/// API key.
///
/// # Panics
///
/// Never: the sealed key is a valid literal.
#[must_use]
pub fn target_row(name: &str, seconds: i64) -> LogShippingTargetRow {
    LogShippingTargetRow {
        id: LogShippingTargetId::new(),
        name: label(name),
        settings: LogTargetSettings {
            destination: LogDestination::Datadog(DatadogSite::Eu1),
            credential: ShippingCredential::Sealed(
                SealedSecret::new("v1.ZGF0YWRvZw").expect("a sealed key"),
            ),
            records: ShippedRecords::All,
            format: LogFormat::JsonLines,
        },
        status: LogTargetStatus::Active,
        created_at: at(seconds),
        updated_at: at(seconds),
    }
}

/// The record of an anonymous `GET /orders` of `tenant` that finished
/// `seconds` after the fixed moment, decided as `outcome`, taking
/// `duration_ms`, on no route.
#[must_use]
pub fn request_record(
    tenant: TenantId,
    outcome: RequestOutcome,
    duration_ms: u32,
    seconds: i64,
) -> ProxyRequestRecord {
    ProxyRequestRecord {
        tenant_id: tenant,
        correlation_id: CorrelationId::new(),
        principal: ObservedPrincipal::Anonymous,
        route: RouteMatch::NoRoute,
        ip_address: IpAddr::from([203, 0, 113, 7]),
        method: UntrustedText::record("GET"),
        path: UntrustedText::record("/orders"),
        outcome,
        duration_ms,
        occurred_at: at(seconds),
        classification: Vec::new(),
        policy: RulingPolicy::NoTenantVersion,
        closed: None,
    }
}

/// An allowed request's outcome: the upstream answered `status`.
#[must_use]
pub fn allowed(status: u16) -> RequestOutcome {
    RequestOutcome::Allowed {
        upstream_status: status,
    }
}
