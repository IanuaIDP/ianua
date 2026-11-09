//! Controls the routing context's tests share.

use crate::domains::authorization::permission::{RoutingAction, SystemPermission};
use crate::domains::routing::backend::health_check::HealthCheckPolicy;
use crate::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use crate::domains::routing::control::RoutingControl;
use crate::domains::routing::matching::host::RouteHosts;
use crate::domains::routing::matching::path_rewrite::PathRewrite;
use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::route::{CreateRouteParams, ResponseSharing, Route, RoutePipeline};
use crate::domains::routing::sealed::Sealed;
use crate::domains::routing::service::{CreateServiceParams, Service};
use crate::isolation::scope::ResolvedTenant;
use crate::test_support::authority::anyone_holding;
use crate::test_support::builders::label;
use crate::types::{Audience, HttpUrl, PipelineId, UrlPath};

/// Someone changing routing who holds `system` and no custom permission.
pub(crate) fn holding(system: &[SystemPermission]) -> RoutingControl<'static> {
    RoutingControl::new(anyone_holding(system))
}

/// A routing admin, who may create and change everything in routing.
pub(crate) fn routing_admin() -> RoutingControl<'static> {
    holding(&[SystemPermission::ManageRouting])
}

/// Someone who may change routing but not add to it.
pub(crate) fn routing_editor() -> RoutingControl<'static> {
    holding(&[SystemPermission::Routing(RoutingAction::Update)])
}

/// Someone who may only view routing.
pub(crate) fn routing_viewer() -> RoutingControl<'static> {
    holding(&[SystemPermission::Routing(RoutingAction::View)])
}

/// A pipeline that caches nothing, as a route sees it.
pub(crate) fn plain_pipeline() -> PipelineSeen {
    PipelineSeen(PipelineId::new(), ResponseSharing::PerCaller)
}

/// A pipeline that keeps one cached response for every caller, as a route
/// sees it.
pub(crate) fn shared_cache_pipeline() -> PipelineSeen {
    PipelineSeen(PipelineId::new(), ResponseSharing::Shared)
}

/// A pipeline as a route sees it: its id and whether it shares cached
/// responses. The proxy's own pipeline answers the same questions.
pub(crate) struct PipelineSeen(PipelineId, ResponseSharing);

impl Sealed for PipelineSeen {}

impl RoutePipeline for PipelineSeen {
    fn pipeline_id(&self) -> PipelineId {
        self.0
    }

    fn response_sharing(&self) -> ResponseSharing {
        self.1
    }
}

/// A route on `/projects/*` under `policy`, run by `pipeline` and forwarding
/// to a service that pins its audience.
pub(crate) fn route_on(
    pipeline: &impl RoutePipeline,
    policy: RoutePolicy,
) -> Route<ResolvedTenant> {
    let upstream = Upstream::new(
        HttpUrl::new("https://backend:8080").unwrap(),
        UpstreamTimeout::DEFAULT,
        HostHeader::Rewrite,
    )
    .with_audience(Audience::new("projects").unwrap());
    let service = Service::create(
        CreateServiceParams {
            id: crate::types::ServiceId::new(),
            name: label("projects-api"),
            upstream,
            health_check: HealthCheckPolicy::default(),
        },
        &routing_admin(),
    )
    .unwrap();
    Route::create(
        CreateRouteParams {
            name: label("projects"),
            path_pattern: UrlPath::new("/projects/*").unwrap(),
            methods: Vec::new(),
            policy,
            hosts: RouteHosts::Any,
            path_rewrite: PathRewrite::StripPrefix,
            priority: 100,
        },
        &service,
        pipeline,
        &routing_admin(),
    )
    .unwrap()
}
