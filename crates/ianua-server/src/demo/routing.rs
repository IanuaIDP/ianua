//! What a tenant's proxy answers: a pipeline, the services behind it and a
//! route in front of each, every route asking its caller to be signed in.

use ianua_app::listing::{Limit, PageRequest, SortOrder};
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::routing::{routes, services};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::RouteReach;
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::types::{
    Audience, DeclaredAction, HttpUrl, Label, PipelineId, RouteId, ServiceId, Setting, UrlPath,
};

use crate::demo::DemoError;
use crate::demo::catalog::{self, ServiceSeed};
use crate::demo::seeder::{DemoTenant, Seed, Seeder};

/// The most of one kind a demo tenant holds, which one page of a lookup
/// covers.
const PAGE: Limit = Limit::internal(100);

/// How long a demo service's backend may take to answer, in seconds.
const UPSTREAM_TIMEOUT_SECS: u32 = 30;

/// The tenant's pipeline, found by its name or configured by the owner.
///
/// # Errors
///
/// [`DemoError`] when the pipelines cannot be read or one configured.
pub(super) async fn pipeline(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
) -> Result<Seed<PipelineId>, DemoError> {
    let name = Label::new("name", catalog::PIPELINE)?;
    let pipelines = seeder
        .adapters
        .pipeline_store
        .list(&tenant.scoped())
        .await?;
    if let Some(found) = pipelines.iter().find(|pipeline| pipeline.name() == &name) {
        return Ok(Seed::Found(*found.id()));
    }
    let acting = seeder.in_tenant(tenant).await?;
    let configure = seeder.state.proxy.configure_pipeline.as_ref();
    let id = seeder
        .kept(
            "a pipeline",
            configure.execute(&acting.caller, &acting.auditor, name),
        )
        .await?;
    Ok(Seed::Made(id))
}

/// The pipeline `pipeline` in force on its routes, unless it is already.
///
/// # Errors
///
/// [`DemoError`] when the pipeline cannot be read or activated.
pub(super) async fn in_force(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    pipeline: PipelineId,
) -> Result<Seed<()>, DemoError> {
    let found = seeder
        .adapters
        .pipeline_store
        .find(&tenant.scoped(), &pipeline)
        .await?
        .ok_or(DemoError::Vanished("the pipeline"))?;
    if found.status() == PipelineStatus::Active {
        return Ok(Seed::Found(()));
    }
    let acting = seeder.in_tenant(tenant).await?;
    let activate = seeder.state.proxy.activate_pipeline.as_ref();
    seeder
        .kept(
            "the pipeline in force",
            activate.execute(&acting.caller, &acting.auditor, pipeline),
        )
        .await?;
    Ok(Seed::Made(()))
}

/// The service `seed` names, found by its name or added by the owner.
///
/// # Errors
///
/// [`DemoError`] when the services cannot be read or one added.
pub(super) async fn service(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    seed: &ServiceSeed,
) -> Result<Seed<ServiceId>, DemoError> {
    let name = Label::new("name", seed.name)?;
    let page = PageRequest::first(PAGE);
    let store = seeder.adapters.service_store.as_ref();
    let listed = store
        .list_all(&tenant.scoped(), &SortOrder::default(), &page)
        .await?;
    if let Some(found) = listed.items.iter().find(|service| service.name() == &name) {
        return Ok(Seed::Found(*found.id()));
    }
    let request = service_request(name, seed)?;
    let acting = seeder.in_tenant(tenant).await?;
    let create = seeder.state.routing.create_service.as_ref();
    let id = seeder
        .kept(
            "a service",
            create.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(id))
}

/// Validates the catalogue's upstream and audience before any owner signs in.
fn service_request(name: Label, seed: &ServiceSeed) -> Result<services::CreateRequest, DemoError> {
    Ok(services::CreateRequest {
        name,
        upstream: Upstream::new(
            HttpUrl::new(seed.url)?,
            UpstreamTimeout::seconds(UPSTREAM_TIMEOUT_SECS)?,
            HostHeader::Rewrite,
        )
        .with_audience(Audience::new(seed.audience)?),
        health_check: HealthCheckPolicy::default(),
        tls: Setting::Unset,
    })
}

/// The existing service and pipeline a new demo route connects.
pub(super) struct RoutePlacement {
    /// The service that receives matching requests.
    pub(super) service: ServiceId,
    /// The pipeline enforcing the route's policy.
    pub(super) pipeline: PipelineId,
}

/// The route in front of the service `seed` names, found by its name or
/// added by the owner on the pipeline and service named by `placement`.
///
/// # Errors
///
/// [`DemoError`] when the routes cannot be read or one added.
pub(super) async fn route(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    seed: &ServiceSeed,
    placement: &RoutePlacement,
) -> Result<Seed<RouteId>, DemoError> {
    let name = Label::new("name", seed.route)?;
    let page = PageRequest::first(PAGE);
    let store = seeder.adapters.route_store.as_ref();
    let listed = store
        .list_all(&tenant.scoped(), None, &SortOrder::default(), &page)
        .await?;
    if let Some(found) = listed.items.iter().find(|route| route.name() == &name) {
        return Ok(Seed::Found(*found.id()));
    }
    let request = route_request(name, seed, placement)?;
    let acting = seeder.in_tenant(tenant).await?;
    let create = seeder.state.routing.create_route.as_ref();
    let id = seeder
        .kept(
            "a route",
            create.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(id))
}

/// Builds an authenticated route over the catalogue path and existing backend.
fn route_request(
    name: Label,
    seed: &ServiceSeed,
    placement: &RoutePlacement,
) -> Result<routes::CreateRequest, DemoError> {
    Ok(routes::CreateRequest {
        name,
        path_pattern: UrlPath::new(seed.path)?,
        methods: Vec::new(),
        service_id: placement.service,
        policy: RoutePolicy::Authenticated,
        path_rewrite: PathRewrite::Keep,
        priority: seed.priority,
        hosts: RouteHosts::Any,
        pipeline_id: placement.pipeline,
        data_class: DataClassLevel::Internal,
        action_class: DeclaredAction::Undeclared,
        reach: RouteReach::Fixed,
        parameter_rules: Vec::new(),
        conditions: RouteConditions::default(),
    })
}
