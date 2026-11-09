//! Reading a tenant's gateway as it stands: every service, pipeline, route,
//! stream route, egress policy and consumer it holds, and the connectors
//! services are reached through, which both the export and the import start
//! from.

use futures_util::TryFutureExt;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::domains::routing::egress::EgressPolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::AppError;
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::consumers::ConsumerStore;
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::{
    ConnectorStore, EgressPolicyStore, RouteStore, ServiceStore, StreamRouteStore,
};
use crate::tenancy::ScopedTenant;

/// How many of each resource one read takes.
///
/// Far above any tenant's plan limit, so an export is whole or it is an
/// error. A silently cut configuration is worse than none: applied with a
/// replace, it would delete everything past the cut.
const MAX_RESOURCES: u32 = 10_000;

/// The stores a tenant's gateway is kept in.
#[derive(Clone, Copy)]
pub(crate) struct GatewayStores<'a> {
    /// Keeps the routes.
    pub(crate) routes: &'a dyn RouteStore,
    /// Keeps the services.
    pub(crate) services: &'a dyn ServiceStore,
    /// Keeps the pipelines.
    pub(crate) pipelines: &'a dyn PipelineStore,
    /// Keeps the stream routes.
    pub(crate) stream_routes: &'a dyn StreamRouteStore,
    /// Keeps the egress policies.
    pub(crate) egress_policies: &'a dyn EgressPolicyStore,
    /// Keeps the consumers.
    pub(crate) consumers: &'a dyn ConsumerStore,
    /// Keeps the connectors services are reached through.
    pub(crate) connectors: &'a dyn ConnectorStore,
}

/// A tenant's whole gateway, as the stores hold it.
pub(crate) struct LiveGateway {
    /// Every service.
    pub(crate) services: Vec<Service<ResolvedTenant>>,
    /// Every pipeline.
    pub(crate) pipelines: Vec<Pipeline<ResolvedTenant>>,
    /// Every route.
    pub(crate) routes: Vec<Route<ResolvedTenant>>,
    /// Every stream route.
    pub(crate) stream_routes: Vec<StreamRoute<ResolvedTenant>>,
    /// Every egress policy.
    pub(crate) egress_policies: Vec<EgressPolicy<ResolvedTenant>>,
    /// Every consumer.
    pub(crate) consumers: Vec<Consumer<ResolvedTenant>>,
    /// Every connector, which a document names but never makes.
    pub(crate) connectors: Vec<PrivateConnector<ResolvedTenant>>,
}

/// The HTTP half of a gateway: services, pipelines and routes.
type HttpHalf = (
    Vec<Service<ResolvedTenant>>,
    Vec<Pipeline<ResolvedTenant>>,
    Vec<Route<ResolvedTenant>>,
);

/// The rest of a gateway: stream routes, egress policies, consumers and
/// connectors.
type EdgeHalf = (
    Vec<StreamRoute<ResolvedTenant>>,
    Vec<EgressPolicy<ResolvedTenant>>,
    Vec<Consumer<ResolvedTenant>>,
    Vec<PrivateConnector<ResolvedTenant>>,
);

/// Everything the tenant's gateway holds, read together.
///
/// # Errors
///
/// Returns `AppError::Internal` if any of the reads fails.
pub(crate) async fn live_gateway(
    stores: GatewayStores<'_>,
    tenant: &ScopedTenant,
) -> Result<LiveGateway, AppError> {
    let ((services, pipelines, routes), (stream_routes, egress_policies, consumers, connectors)) =
        futures_util::try_join!(http_half(stores, tenant), edge_half(stores, tenant))?;
    Ok(LiveGateway {
        services,
        pipelines,
        routes,
        stream_routes,
        egress_policies,
        consumers,
        connectors,
    })
}

/// Every service, pipeline and route of the tenant.
async fn http_half(stores: GatewayStores<'_>, tenant: &ScopedTenant) -> Result<HttpHalf, AppError> {
    let everything = &PageRequest::first(Limit::internal(MAX_RESOURCES));
    let (by_service, by_route) = (SortOrder::default(), SortOrder::default());
    let (services, pipelines, routes) = futures_util::try_join!(
        TryFutureExt::map_err(
            stores.services.list_all(tenant, &by_service, everything),
            AppError::internal,
        ),
        TryFutureExt::map_err(stores.pipelines.list(tenant), AppError::internal),
        TryFutureExt::map_err(
            stores.routes.list_all(tenant, None, &by_route, everything),
            AppError::internal,
        ),
    )?;
    Ok((services.items, pipelines, routes.items))
}

/// Every stream route, egress policy, consumer and connector of the tenant.
async fn edge_half(stores: GatewayStores<'_>, tenant: &ScopedTenant) -> Result<EdgeHalf, AppError> {
    let everything = &PageRequest::first(Limit::internal(MAX_RESOURCES));
    let (by_stream, by_consumer) = (SortOrder::default(), SortOrder::default());
    let (stream_routes, egress_policies, consumers, connectors) = futures_util::try_join!(
        TryFutureExt::map_err(
            stores
                .stream_routes
                .list_all(tenant, &by_stream, everything),
            AppError::internal,
        ),
        TryFutureExt::map_err(stores.egress_policies.list(tenant), AppError::internal),
        TryFutureExt::map_err(
            stores.consumers.list_all(tenant, &by_consumer, everything),
            AppError::internal,
        ),
        TryFutureExt::map_err(stores.connectors.list(tenant), AppError::internal),
    )?;
    Ok((
        stream_routes.items,
        egress_policies,
        consumers.items,
        connectors,
    ))
}
