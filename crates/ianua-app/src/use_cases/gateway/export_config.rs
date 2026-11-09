//! Export: write a tenant's gateway down as one document.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{
    ConsumersAction, PipelineAction, RoutingAction, SystemPermission,
};
use ianua_domain::shared::errors::DomainError;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::consumers::ConsumerStore;
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::{
    ConnectorStore, EgressPolicyStore, RouteStore, ServiceStore, StreamRouteStore,
};
use crate::use_case::Query;
use crate::use_cases::gateway::document::GatewayConfig;
use crate::use_cases::gateway::lookup::{GatewayStores, live_gateway};

/// The ports [`ExportConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExportConfigPorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// Keeps the tenant's pipelines.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// Keeps the tenant's consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// Keeps the connectors services are reached through, named in the
    /// document.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Writes a tenant's gateway configuration out.
pub struct ExportConfigUseCase {
    ports: ExportConfigPorts,
}

impl ExportConfigUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ExportConfigPorts) -> Self {
        Self { ports }
    }
}

impl Query for ExportConfigUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<GatewayConfig, AppError>;

    /// The tenant's whole gateway configuration, with no secret in it.
    ///
    /// A route whose service or pipeline has gone missing, or a stream route
    /// naming a consumer that is gone, is left out rather than written down:
    /// it could not be made again from the document, so including it would
    /// make a file that fails on import.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing,
    ///   pipelines and consumers alike.
    /// - `AppError::Internal` if any of the reads fails, or a stored service
    ///   no longer reads back.
    async fn execute(&self, caller: &CallerContext, (): ()) -> Result<GatewayConfig, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        ensure_may_view_gateway(&authority).map_err(AppError::from_domain)?;
        let stores = GatewayStores {
            routes: self.ports.route_store.as_ref(),
            services: self.ports.service_store.as_ref(),
            pipelines: self.ports.pipeline_store.as_ref(),
            stream_routes: self.ports.stream_route_store.as_ref(),
            egress_policies: self.ports.egress_store.as_ref(),
            consumers: self.ports.consumer_store.as_ref(),
            connectors: self.ports.connector_store.as_ref(),
        };
        let live = live_gateway(stores, &caller.tenant()).await?;
        GatewayConfig::of(&live).map_err(AppError::from_domain)
    }
}

/// Refuses unless `authority` may view the tenant's routing, its pipelines
/// and its consumers, the parts a gateway document holds.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when any of the rights is missing.
pub(crate) fn ensure_may_view_gateway(authority: &TenantAuthority) -> Result<(), DomainError> {
    authority.ensure_holds(SystemPermission::Routing(RoutingAction::View))?;
    authority.ensure_holds(SystemPermission::Pipeline(PipelineAction::View))?;
    authority.ensure_holds(SystemPermission::Consumers(ConsumersAction::View))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::pipeline::Pipeline;
    use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
    use ianua_domain::domains::routing::stream::access::{StreamAccess, StreamConsumers};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::ConsumerId;

    use super::*;
    use crate::tenancy::ScopedTenant;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{FakeConsumerStore, consumer_named};
    use crate::test_support::proxy::FakePipelineStore;
    use crate::test_support::routing::{
        FakeEgressPolicyStore, FakeRouteStore, FakeServiceStore, FakeStreamRouteStore, RouteShape,
        egress_policy_for, route_of, routing_admin, routing_label, service_named, tunnel_on,
        unpinned_upstream,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::gateway::document::{
        ConsumerCredentialDeclaration, StreamAccessDeclaration,
    };

    struct Gateway {
        routes: Arc<FakeRouteStore>,
        services: Arc<FakeServiceStore>,
        pipelines: Arc<FakePipelineStore>,
        streams: Arc<FakeStreamRouteStore>,
        egress: Arc<FakeEgressPolicyStore>,
        consumers: Arc<FakeConsumerStore>,
    }

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    fn empty_gateway() -> Gateway {
        Gateway {
            routes: Arc::new(FakeRouteStore::empty()),
            services: Arc::new(FakeServiceStore::empty()),
            pipelines: Arc::new(FakePipelineStore::empty()),
            streams: Arc::new(FakeStreamRouteStore::empty()),
            egress: Arc::new(FakeEgressPolicyStore::default()),
            consumers: Arc::new(FakeConsumerStore::empty()),
        }
    }

    fn edge(gateway: &Gateway) -> Pipeline<ResolvedTenant> {
        let pipeline = Pipeline::with_defaults(routing_label("edge"), &routing_admin()).unwrap();
        block_on(gateway.pipelines.save(&tenant(), &pipeline)).unwrap();
        pipeline
    }

    fn export(
        gateway: &Gateway,
        authorities: FakeTenantAuthorities,
    ) -> Result<GatewayConfig, AppError> {
        let use_case = ExportConfigUseCase::new(ExportConfigPorts {
            route_store: gateway.routes.clone(),
            service_store: gateway.services.clone(),
            pipeline_store: gateway.pipelines.clone(),
            stream_route_store: gateway.streams.clone(),
            egress_store: gateway.egress.clone(),
            consumer_store: gateway.consumers.clone(),
            tenant_authorities: Arc::new(authorities),
            ..ExportConfigPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    fn export_by_admin(gateway: &Gateway) -> GatewayConfig {
        export(gateway, FakeTenantAuthorities::holding_everything()).unwrap()
    }

    /// Acme has no gateway yet. Ann exports an empty document.
    #[test]
    fn an_empty_tenant_exports_an_empty_document() {
        assert_eq!(export_by_admin(&empty_gateway()), GatewayConfig::default());
    }

    /// Acme's projects route runs the edge pipeline to the projects API. The
    /// document names both, not their ids.
    #[test]
    fn a_route_is_exported_naming_its_service_and_pipeline() {
        let gateway = empty_gateway();
        let service = service_named("projects-api", unpinned_upstream("https://backend:8443"));
        block_on(gateway.services.save(&tenant(), &service)).unwrap();
        let route = route_of(
            RouteShape::public("projects", "/v1/projects/*"),
            &service,
            &edge(&gateway),
        );
        block_on(gateway.routes.save(&tenant(), &route)).unwrap();

        let config = export_by_admin(&gateway);

        assert_eq!(config.services.len(), 1);
        assert_eq!(config.pipelines.len(), 1);
        assert_eq!(config.routes[0].service.as_str(), "projects-api");
        assert_eq!(config.routes[0].pipeline.as_str(), "edge");
        assert_eq!(config.routes[0].path_rewrite, PathRewrite::Keep);
    }

    /// A route's service is gone from the store. The route is left out, since
    /// a file naming a service it lacks would fail on import.
    #[test]
    fn a_route_whose_service_is_gone_is_left_out() {
        let gateway = empty_gateway();
        let gone = service_named("gone", unpinned_upstream("https://gone:8443"));
        let route = route_of(RouteShape::public("orphan", "/x"), &gone, &edge(&gateway));
        block_on(gateway.routes.save(&tenant(), &route)).unwrap();

        assert!(export_by_admin(&gateway).routes.is_empty());
    }

    /// Acme has a billing consumer, a tunnel naming it, and an egress policy.
    /// All three are in the document, the tunnel naming the consumer by name
    /// and the consumer's key by its prefix alone.
    #[test]
    fn stream_routes_egress_and_consumers_are_exported() {
        let gateway = empty_gateway();
        let billing = consumer_named("billing", DataClassLevel::Internal);
        let named = StreamConsumers::new(vec![*billing.id()]).unwrap();
        block_on(gateway.consumers.save(&tenant(), &billing)).unwrap();
        block_on(
            gateway
                .streams
                .save(&tenant(), &tunnel_on(15433, StreamAccess::Consumers(named))),
        )
        .unwrap();
        block_on(gateway.egress.save(
            &tenant(),
            &egress_policy_for("spiffe://ianua.test/ns/svc/sa/fetcher"),
        ))
        .unwrap();

        let config = export_by_admin(&gateway);

        assert_eq!(
            config.stream_routes[0].access,
            StreamAccessDeclaration::Consumers(vec![routing_label("billing")])
        );
        assert_eq!(config.egress_policies.len(), 1);
        assert!(matches!(
            config.consumers[0].credential,
            ConsumerCredentialDeclaration::ApiKey { .. }
        ));
    }

    /// A tunnel names a consumer that is gone. It is left out, since a file
    /// naming a consumer it lacks would fail on import.
    #[test]
    fn a_tunnel_naming_a_gone_consumer_is_left_out() {
        let gateway = empty_gateway();
        let named = StreamConsumers::new(vec![ConsumerId::new()]).unwrap();
        block_on(
            gateway
                .streams
                .save(&tenant(), &tunnel_on(15433, StreamAccess::Consumers(named))),
        )
        .unwrap();

        assert!(export_by_admin(&gateway).stream_routes.is_empty());
    }

    /// Routing view rights alone do not let Mallory export pipeline details.
    #[test]
    fn a_caller_without_the_pipeline_view_right_is_refused() {
        let result = export(
            &empty_gateway(),
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Mallory cannot export the gateway without consumer view rights, even
    /// with permission to view routing and pipelines.
    #[test]
    fn a_caller_without_the_consumer_view_right_is_refused() {
        let result = export(
            &empty_gateway(),
            FakeTenantAuthorities::holding(&[
                SystemPermission::Routing(RoutingAction::View),
                SystemPermission::Pipeline(PipelineAction::View),
            ]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller with no gateway view rights is forbidden from exporting it.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = export(&empty_gateway(), FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Exporting with a signed-out session returns an authentication refusal.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = export(
            &empty_gateway(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
