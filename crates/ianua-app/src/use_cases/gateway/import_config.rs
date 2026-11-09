//! Import: apply a configuration document to a tenant's gateway.
//!
//! Two things make this safe enough to run from CI. It refuses the whole
//! document if a route names a service or pipeline that would not exist
//! after the apply, rather than applying the half that resolves; and it can
//! work out the plan without touching anything, so the change is readable
//! before it is real. Every resource is then written through the same domain
//! steps and checks as changing it by hand.

use std::sync::Arc;

use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::import::{GatewayImport, ImportedChanges};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::shared::validation::distinct::first_repeat;
use ianua_domain::types::Setting;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::consumers::ConsumerStore;
use crate::ports::data_classification::ClassificationStore;
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::limits::LimitEnforcer;
use crate::ports::proxy::PipelineStore;
use crate::ports::routing::{
    ConnectorStore, EgressPolicyStore, RouteStore, ServiceStore, StreamRouteStore,
};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::SiteRules;
use crate::services::hosts::PlatformAddresses;
use crate::services::issuers::TenantIssuers;
use crate::services::kept_together::kept_together;
use crate::services::routing::reachability::{
    reject_private_stream_backends, reject_private_upstream,
};
use crate::services::routing::rule_sets::ensure_reads_own_rules;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::gateway::apply::consumers::write_consumer;
use crate::use_cases::gateway::apply::deletes::{delete_resource, ensure_routes_deletable};
use crate::use_cases::gateway::apply::egress::write_egress_policy;
use crate::use_cases::gateway::apply::pipelines::write_pipeline;
use crate::use_cases::gateway::apply::routes::write_route;
use crate::use_cases::gateway::apply::services::write_service;
use crate::use_cases::gateway::apply::sign_in::settle_app_sign_in;
use crate::use_cases::gateway::apply::state::{
    Applier, Apply, invalid, missing_reference, missing_sign_in_owner,
};
use crate::use_cases::gateway::apply::stream_routes::write_stream_route;
use crate::use_cases::gateway::diff::{ChangeKind, ConfigDiff, ImportMode, ResourceKind, diff};
use crate::use_cases::gateway::document::{GatewayConfig, StreamAccessDeclaration};
use crate::use_cases::gateway::export_config::ensure_may_view_gateway;
use crate::use_cases::gateway::lookup::{GatewayStores, LiveGateway, live_gateway};
use crate::use_cases::gateway::normalize::normalized;

/// Whether the caller wants the change or only the plan.
///
/// The two are not degrees of the same thing: one writes to the gateway and
/// one does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplyPlan {
    /// Work out the plan and change nothing.
    #[default]
    DryRun,
    /// Work out the plan and carry it out.
    Apply,
}

/// A configuration document and what to do with it.
pub struct ImportConfigRequest {
    /// The desired configuration.
    pub config: GatewayConfig,
    /// Whether resources the document omits are removed.
    pub mode: ImportMode,
    /// Whether to write, or only to plan.
    pub plan: ApplyPlan,
}

/// The ports [`ImportConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ImportConfigPorts {
    /// The gateway's records an import reads and writes.
    pub records: RecordPorts,
    /// What an import is checked against before anything is written.
    pub checks: ImportCheckPorts,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the writes and their record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// The gateway's records an import reads and writes.
#[derive(ianua_macros::Fakes)]
pub struct RecordPorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// Keeps the tenant's pipelines.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// Keeps the tenant's classification rules, which a declared stage
    /// reading rules must name.
    pub classification_store: Arc<dyn ClassificationStore>,
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// Keeps the tenant's consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// Keeps the connectors a service may be reached through. A document
    /// names them and never makes one.
    pub connector_store: Arc<dyn ConnectorStore>,
}

/// What an import is checked against before anything is written.
#[derive(ianua_macros::Fakes)]
pub struct ImportCheckPorts {
    /// The tenant's registered domains, which route and sign-in hosts must
    /// be.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// The tenant's permission catalogue, which a route's required custom
    /// permission must be declared in.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// Which hosts are on the same site, as a service's own cookie must be
    /// with the sign-in it accepts.
    pub site_rules: Arc<dyn SiteRules>,
    /// Internal networks an upstream may target besides public addresses.
    pub upstream_networks: UpstreamNetworks,
    /// The tenant's own token issuer, which no consumer may trust.
    pub issuers: TenantIssuers,
    /// The plan's ceiling on every resource the document creates.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

/// Applies a configuration document.
pub struct ImportConfigUseCase {
    ports: ImportConfigPorts,
    platform: Option<Arc<PlatformAddresses>>,
}

impl ImportConfigUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ImportConfigPorts) -> Self {
        ImportConfigUseCase {
            ports,
            platform: None,
        }
    }

    /// Checks imported host restrictions against live platform ownership too.
    #[must_use]
    pub fn with_platform_addresses(mut self, platform: Arc<PlatformAddresses>) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Records the applied plan inside the same unit of work as its writes.
    async fn record_import(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        mode: ImportMode,
        plan: &ConfigDiff,
    ) -> Result<(), AppError> {
        let mut import = GatewayImport::<ResolvedTenant>::applied(mode, imported_changes(plan));
        auditor
            .dispatch_by(&caller.actor(), import.take_events(&caller.tenant()))
            .await
            .or_internal()
    }
}

impl Command for ImportConfigUseCase {
    type Caller = CallerContext;
    type Input = ImportConfigRequest;
    type Output = Result<ConfigDiff, AppError>;

    /// Plans, and unless this is a dry run, applies the document, recording
    /// `routing.gateway_config_imported`.
    ///
    /// The writes and the record are one unit, kept or dropped together. The
    /// document rewrites route policies, which decide who reaches what, so a
    /// change the audit trail cannot show is never kept, and a write that
    /// fails leaves no record of a change that did not happen. A dry run, or
    /// a document that changes nothing, writes nothing and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing gateway-view/change rights or a create exceeding the plan.
    /// - `AppError::NotFound` for a connector outside the tenant; `Domain` for duplicate resources, broken references, forbidden upstreams or missing credential secrets.
    /// - `AppError::Domain` also covers foreign classification rules, deletion of active routes, and every rule a manual resource change must keep.
    /// - `AppError::Conflict` for taken names/ports/sign-in hosts or deletion of a pipeline/service still in use.
    /// - `AppError::Internal` on read, write or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ImportConfigRequest,
    ) -> Result<ConfigDiff, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        ensure_may_view_gateway(&authority).map_err(AppError::from_domain)?;
        let desired = normalized(&request.config);
        ensure_document_sound(&self.ports, &desired, request.mode)?;
        ensure_stages_read_own_rules(&self.ports, &caller.tenant(), &desired).await?;
        let live = live_gateway(stores_of(&self.ports), &caller.tenant()).await?;
        let plan = diff(&desired, &current_config(&live)?, request.mode);
        if request.plan == ApplyPlan::DryRun || plan.is_empty() {
            return Ok(plan);
        }
        let applier = Applier {
            platform: self.platform.as_deref(),
            ports: &self.ports,
            caller,
            by: RoutingControl::new(&authority),
            consumers: ConsumerControl::new(&authority),
        };
        let mut apply = Apply::starting(applier, &desired, live);
        ensure_routes_deletable(&apply, &plan)?;
        kept_together(self.ports.unit_of_work.as_ref(), async {
            carry_out(&mut apply, &plan).await?;
            self.record_import(caller, auditor, request.mode, &plan)
                .await
        })
        .await?;
        Ok(plan)
    }
}

/// Refuses a document the apply could not carry out as written: one naming
/// a resource twice, naming things that would not exist, or dialling an
/// internal address the operator does not allow.
///
/// # Errors
///
/// `AppError::Domain` when any of those checks refuses the document.
fn ensure_document_sound(
    ports: &ImportConfigPorts,
    desired: &GatewayConfig,
    mode: ImportMode,
) -> Result<(), AppError> {
    ensure_named_once(desired)?;
    ensure_references_resolve(desired, mode)?;
    ensure_destinations_public(ports, desired)
}

/// Refuses a document declaring a stage that reads classification rules
/// that are not `tenant`'s own, which could hide nothing.
///
/// # Errors
///
/// - `AppError::Domain` when a declared stage reads another tenant's
///   rules, or reads rules and the tenant has classified nothing.
/// - `AppError::Internal` on storage failure.
async fn ensure_stages_read_own_rules(
    ports: &ImportConfigPorts,
    tenant: &ScopedTenant,
    desired: &GatewayConfig,
) -> Result<(), AppError> {
    let kinds = desired
        .pipelines
        .iter()
        .flat_map(|pipeline| &pipeline.stages)
        .map(|stage| &stage.kind);
    ensure_reads_own_rules(ports.records.classification_store.as_ref(), tenant, kinds).await
}

/// Refuses a [`ImportMode::Replace`] document whose routes, stream routes,
/// or services accepting another's sign-in, name things that would not
/// exist.
///
/// Checked before anything is written, and against the document rather than
/// the database: in that mode a route may name a service the document
/// introduces, and may not name one the document is about to delete. A
/// [`ImportMode::Merge`] document passes here, since what it names may
/// already be live; the apply refuses a missing one as it writes.
fn ensure_references_resolve(config: &GatewayConfig, mode: ImportMode) -> Result<(), AppError> {
    if mode != ImportMode::Replace {
        return Ok(());
    }
    ensure_sign_in_owners_declared(config)?;
    ensure_route_targets_declared(config)?;
    ensure_stream_consumers_declared(config)
}

/// Refuses a service accepting the sign-in of one the document lacks.
fn ensure_sign_in_owners_declared(config: &GatewayConfig) -> Result<(), AppError> {
    for service in &config.services {
        let Setting::Set(accepted) = &service.accepts_app_sign_in else {
            continue;
        };
        if !config.services.iter().any(|s| s.name == accepted.owner) {
            return Err(missing_sign_in_owner(&service.name, &accepted.owner));
        }
    }
    Ok(())
}

/// Refuses a route naming a service or pipeline the document lacks.
fn ensure_route_targets_declared(config: &GatewayConfig) -> Result<(), AppError> {
    for route in &config.routes {
        if !config.services.iter().any(|s| s.name == route.service) {
            return Err(missing_reference(&route.name, "service", &route.service));
        }
        if !config.pipelines.iter().any(|p| p.name == route.pipeline) {
            return Err(missing_reference(&route.name, "pipeline", &route.pipeline));
        }
    }
    Ok(())
}

/// Refuses a stream route naming a consumer the document lacks.
fn ensure_stream_consumers_declared(config: &GatewayConfig) -> Result<(), AppError> {
    for route in &config.stream_routes {
        let StreamAccessDeclaration::Consumers(names) = &route.access else {
            continue;
        };
        let missing = names
            .iter()
            .find(|name| !config.consumers.iter().any(|c| &c.name == *name));
        if let Some(name) = missing {
            return Err(missing_reference(&route.name, "consumer", name));
        }
    }
    Ok(())
}

/// Refuses a document naming one resource twice, which the apply could not
/// tell apart.
fn ensure_named_once(config: &GatewayConfig) -> Result<(), AppError> {
    let repeated = first_repeat(config.services.iter().map(|s| &s.name))
        .or_else(|| first_repeat(config.pipelines.iter().map(|p| &p.name)))
        .or_else(|| first_repeat(config.routes.iter().map(|r| &r.name)))
        .or_else(|| first_repeat(config.stream_routes.iter().map(|r| &r.name)))
        .or_else(|| first_repeat(config.egress_policies.iter().map(|p| &p.name)))
        .or_else(|| first_repeat(config.consumers.iter().map(|c| &c.name)));
    if let Some(name) = repeated {
        return Err(invalid(format!("'{name}' is declared twice")));
    }
    let Some(service) = first_repeat(config.egress_policies.iter().map(|p| &p.service)) else {
        return Ok(());
    };
    Err(invalid(format!(
        "{service} has two egress policies; a service has one"
    )))
}

/// Refuses a document naming a directly dialled upstream or a stream
/// backend on an internal address the operator does not allow. Upstreams
/// reached through a connector are judged by its scope as they are written.
fn ensure_destinations_public(
    ports: &ImportConfigPorts,
    desired: &GatewayConfig,
) -> Result<(), AppError> {
    let networks = &ports.checks.upstream_networks;
    desired
        .services
        .iter()
        .filter(|service| service.connector.is_unset())
        .try_for_each(|service| reject_private_upstream(&service.upstream, networks))
        .and_then(|()| {
            desired
                .stream_routes
                .iter()
                .try_for_each(|route| reject_private_stream_backends(&route.backends, networks))
        })
        .map_err(AppError::from_domain)
}

/// The stores the tenant's gateway is kept in.
fn stores_of(ports: &ImportConfigPorts) -> GatewayStores<'_> {
    GatewayStores {
        routes: ports.records.route_store.as_ref(),
        services: ports.records.service_store.as_ref(),
        pipelines: ports.records.pipeline_store.as_ref(),
        stream_routes: ports.records.stream_route_store.as_ref(),
        egress_policies: ports.records.egress_store.as_ref(),
        consumers: ports.records.consumer_store.as_ref(),
        connectors: ports.records.connector_store.as_ref(),
    }
}

/// The live gateway as a document, in the form the diff compares.
///
/// # Errors
///
/// `AppError::Internal` when a stored service no longer reads back.
fn current_config(live: &LiveGateway) -> Result<GatewayConfig, AppError> {
    let config = GatewayConfig::of(live).map_err(AppError::from_domain)?;
    Ok(normalized(&config))
}

/// Carries out `plan` in the order it is written, then settles app sign-in
/// once the routes it is checked against are in place.
async fn carry_out(apply: &mut Apply<'_>, plan: &ConfigDiff) -> Result<(), AppError> {
    for change in plan.effective() {
        let name = &change.name;
        match (change.kind, change.resource) {
            (ChangeKind::Delete, _) => delete_resource(apply, change).await?,
            (_, ResourceKind::Service) => write_service(apply, name).await?,
            (_, ResourceKind::Pipeline) => write_pipeline(apply, name).await?,
            (_, ResourceKind::Route) => write_route(apply, name).await?,
            (_, ResourceKind::Consumer) => write_consumer(apply, name).await?,
            (_, ResourceKind::StreamRoute) => write_stream_route(apply, name).await?,
            (_, ResourceKind::EgressPolicy) => write_egress_policy(apply, name).await?,
        }
    }
    settle_app_sign_in(apply, plan).await
}

/// How many resources `plan` creates, changes and removes.
fn imported_changes(plan: &ConfigDiff) -> ImportedChanges {
    let count = |kind: ChangeKind| plan.changes.iter().filter(|c| c.kind == kind).count();
    ImportedChanges {
        created: count(ChangeKind::Create),
        updated: count(ChangeKind::Update),
        deleted: count(ChangeKind::Delete),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ianua_domain::domains::authorization::permission::{
        PipelineAction, RoutingAction, SystemPermission,
    };
    use ianua_domain::domains::consumers::consumer::ConsumerStatus;
    use ianua_domain::domains::consumers::quota::ConsumerQuota;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::pipeline::Pipeline;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::{
        RateLimitConfig, RateLimitKey, StageConfig, StageKind, StageRemoval,
    };
    use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
    use ianua_domain::domains::routing::egress::ServiceIdentity;
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::matching::parameter::RouteReach;
    use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
    use ianua_domain::domains::routing::matching::request_match::{
        MatchSubject, RequestCondition, RouteConditions, ValueMatch,
    };
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::domains::routing::service::Service;
    use ianua_domain::domains::routing::sign_in::accepted::SignInDelivery;
    use ianua_domain::domains::routing::sign_in::app::{
        AppSignIn, AppSignInParams, SignedOutBrowsers,
    };
    use ianua_domain::domains::routing::stream::access::{StreamAccess, StreamConsumers};
    use ianua_domain::domains::routing::stream::{
        ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamTimeouts,
    };
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{
        CertificatePem, DeclaredAction, DomainName, Expiry, FederatedSubject, HeaderName,
        HeaderValue, HttpsUrl, Issuer, KeyPrefix, Seconds, UrlPath,
    };

    use super::*;
    use crate::listing::{Limit, PageRequest, SortOrder};
    use crate::ports::runtime::Settlement;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::consumers::FakeConsumerStore;
    use crate::test_support::proxy::FakePipelineStore;
    use crate::test_support::routing::{
        FakeEgressPolicyStore, FakeRouteStore, FakeServiceStore, FakeStreamRouteStore, github,
        pinned_upstream, routing_label, unpinned_upstream, verified_domains,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx,
    };
    use crate::use_cases::gateway::document::{
        AcceptedSignInDeclaration, ConsumerCredentialDeclaration, ConsumerDeclaration,
        EgressPolicyDeclaration, PipelineDeclaration, RouteDeclaration, ServiceDeclaration,
        StageDeclaration, StageSwitch, StreamRouteDeclaration,
    };

    const SHOP_HOST: &str = "shop.example.com";

    struct Fixture {
        routes: Arc<FakeRouteStore>,
        services: Arc<FakeServiceStore>,
        pipelines: Arc<FakePipelineStore>,
        streams: Arc<FakeStreamRouteStore>,
        egress: Arc<FakeEgressPolicyStore>,
        consumers: Arc<FakeConsumerStore>,
        audit: Arc<FakeEventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
        use_case: ImportConfigUseCase,
    }

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    /// Admits the verified shop host and declared resources on public networks.
    fn checked_import(records: RecordPorts, unit: Arc<RecordingUnitOfWork>) -> ImportConfigPorts {
        ImportConfigPorts {
            records,
            unit_of_work: unit,
            checks: ImportCheckPorts {
                domain_store: verified_domains(&tenant(), &[SHOP_HOST]),
                resource_type_store: Arc::new(FakeResourceTypeStore::seeded(
                    test_ctx().tenant_id(),
                )),
                upstream_networks: UpstreamNetworks::public_only(),
                ..ImportCheckPorts::fakes()
            },
            ..ImportConfigPorts::fakes()
        }
    }

    /// Applies imports through observable stores with the requested port overrides.
    fn fixture_with(ports: impl FnOnce(ImportConfigPorts) -> ImportConfigPorts) -> Fixture {
        let routes = Arc::new(FakeRouteStore::empty());
        let services = Arc::new(FakeServiceStore::empty());
        let pipelines = Arc::new(FakePipelineStore::empty());
        let streams = Arc::new(FakeStreamRouteStore::empty());
        let egress = Arc::new(FakeEgressPolicyStore::default());
        let consumers = Arc::new(FakeConsumerStore::empty());
        let unit = Arc::new(RecordingUnitOfWork::default());
        Fixture {
            use_case: ImportConfigUseCase::new(ports(checked_import(
                RecordPorts {
                    route_store: routes.clone(),
                    service_store: services.clone(),
                    pipeline_store: pipelines.clone(),
                    stream_route_store: streams.clone(),
                    egress_store: egress.clone(),
                    consumer_store: consumers.clone(),
                    ..RecordPorts::fakes()
                },
                unit.clone(),
            ))),
            routes,
            services,
            pipelines,
            streams,
            egress,
            consumers,
            audit: Arc::new(FakeEventDispatcher::new()),
            unit,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(|ports| ports)
    }

    fn holding(authorities: FakeTenantAuthorities) -> Fixture {
        fixture_with(|ports| ImportConfigPorts {
            tenant_authorities: Arc::new(authorities),
            ..ports
        })
    }

    fn service(name: &str, url: &str) -> ServiceDeclaration {
        ServiceDeclaration {
            name: routing_label(name),
            upstream: unpinned_upstream(url),
            client_certificate: Setting::Unset,
            connector: Setting::Unset,
            health_check: HealthCheckPolicy::Disabled,
            app_sign_in: Setting::Unset,
            accepts_app_sign_in: Setting::Unset,
            status: RouteStatus::Active,
        }
    }

    fn pipeline(name: &str) -> PipelineDeclaration {
        PipelineDeclaration {
            name: routing_label(name),
            stages: Vec::new(),
            status: PipelineStatus::Draft,
        }
    }

    fn route(name: &str, service: &str, pipeline: &str) -> RouteDeclaration {
        RouteDeclaration {
            name: routing_label(name),
            path_pattern: UrlPath::new(format!("/{name}/*")).unwrap(),
            methods: Vec::new(),
            service: routing_label(service),
            pipeline: routing_label(pipeline),
            policy: RoutePolicy::Public,
            path_rewrite: PathRewrite::Keep,
            priority: 100,
            hosts: RouteHosts::Any,
            conditions: RouteConditions::default(),
            data_class: DataClassLevel::Internal,
            action_class: DeclaredAction::Undeclared,
            reach: RouteReach::Fixed,
            parameter_rules: Vec::new(),
            status: RouteStatus::Active,
        }
    }

    fn whole_gateway() -> GatewayConfig {
        GatewayConfig {
            services: vec![service("api", "https://api.example.com:8443")],
            pipelines: vec![pipeline("edge")],
            routes: vec![route("public", "api", "edge")],
            ..GatewayConfig::default()
        }
    }

    fn import(
        f: &Fixture,
        config: GatewayConfig,
        mode: ImportMode,
        plan: ApplyPlan,
    ) -> Result<ConfigDiff, AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            ImportConfigRequest { config, mode, plan },
        ))
    }

    fn merge(f: &Fixture, config: GatewayConfig) -> Result<ConfigDiff, AppError> {
        import(f, config, ImportMode::Merge, ApplyPlan::Apply)
    }

    fn stored_pipelines(f: &Fixture) -> Vec<Pipeline<ResolvedTenant>> {
        block_on(f.pipelines.list(&tenant())).unwrap()
    }

    fn stored_service(f: &Fixture, name: &str) -> Service<ResolvedTenant> {
        let all = block_on(f.services.list_all(
            &tenant(),
            &SortOrder::default(),
            &PageRequest::first(Limit::internal(100)),
        ))
        .unwrap();
        all.items
            .into_iter()
            .find(|service| service.name().as_str() == name)
            .unwrap()
    }

    fn shop_sign_in(host: &str) -> AppSignIn {
        AppSignIn::new(AppSignInParams {
            hosts: vec![DomainName::new(host).unwrap()],
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap()
    }

    /// A shop signing people in on its own host, and an API on the same host
    /// accepting the shop's sign-in.
    fn signing_in_gateway(host: &str) -> GatewayConfig {
        let shop = ServiceDeclaration {
            upstream: pinned_upstream("https://shop.example.com:8443", "shop"),
            app_sign_in: Setting::Set(shop_sign_in(host)),
            ..service("shop", "https://shop.example.com:8443")
        };
        let api = ServiceDeclaration {
            upstream: pinned_upstream("https://api.example.com:8443", "shop-api"),
            accepts_app_sign_in: Setting::Set(AcceptedSignInDeclaration {
                owner: routing_label("shop"),
                delivery: SignInDelivery::SameHost,
            }),
            ..service("shop-api", "https://api.example.com:8443")
        };
        GatewayConfig {
            services: vec![api, shop],
            pipelines: vec![pipeline("edge")],
            routes: vec![
                route("shop-pages", "shop", "edge"),
                route("shop-api", "shop-api", "edge"),
            ],
            ..GatewayConfig::default()
        }
    }

    fn jwt_consumer(name: &str) -> ConsumerDeclaration {
        ConsumerDeclaration {
            name: routing_label(name),
            credential: ConsumerCredentialDeclaration::JwtBearer {
                issuer: Issuer::new("https://auth.partner.example").unwrap(),
                subject: FederatedSubject::new(name).unwrap(),
                jwks_uri: HttpsUrl::new("https://auth.partner.example/jwks.json").unwrap(),
            },
            credential_expiry: Expiry::Never,
            quota: ConsumerQuota::Unlimited,
            clearance: DataClassLevel::Internal,
            status: ConsumerStatus::Active,
        }
    }

    fn tunnel_for(consumer: &str) -> StreamRouteDeclaration {
        StreamRouteDeclaration {
            name: routing_label("billing-db"),
            protocol: StreamProtocol::Tcp,
            listen_port: ListenPort::new(15433).unwrap(),
            sni: RouteHosts::Any,
            policy: StreamPolicy::Tunnel,
            access: StreamAccessDeclaration::Consumers(vec![routing_label(consumer)]),
            backends: vec![StreamBackend::new("db.example.com", 5432, 1).unwrap()],
            timeouts: StreamTimeouts::default(),
            status: RouteStatus::Active,
        }
    }

    fn fetcher_egress(name: &str) -> EgressPolicyDeclaration {
        EgressPolicyDeclaration {
            name: routing_label(name),
            service: ServiceIdentity::new("spiffe://ianua.test/ns/svc/sa/fetcher").unwrap(),
            destinations: vec![github()],
            max_data_class: DataClassLevel::Internal,
        }
    }

    /// A billing consumer, a tunnel letting only it in, and an egress
    /// policy.
    fn edge_gateway() -> GatewayConfig {
        GatewayConfig {
            consumers: vec![jwt_consumer("billing")],
            stream_routes: vec![tunnel_for("billing")],
            egress_policies: vec![fetcher_egress("fetcher")],
            ..GatewayConfig::default()
        }
    }

    /// Ann applies a gateway with a consumer, a tunnel naming it and an
    /// egress policy. All three are made, the tunnel letting in the consumer
    /// it names, and a second apply changes nothing.
    #[test]
    fn stream_routes_egress_and_consumers_are_applied() {
        let f = fixture();

        merge(&f, edge_gateway()).unwrap();

        let consumer = f.consumers.consumers.lock().unwrap()[0].1.clone();
        let streams = block_on(f.streams.list_all(
            &tenant(),
            &SortOrder::default(),
            &PageRequest::first(Limit::internal(10)),
        ))
        .unwrap()
        .items;
        assert_eq!(
            streams[0].access(),
            &StreamAccess::Consumers(StreamConsumers::new(vec![*consumer.id()]).unwrap())
        );
        assert_eq!(block_on(f.egress.list(&tenant())).unwrap().len(), 1);
        assert!(merge(&f, edge_gateway()).unwrap().is_empty());
    }

    /// Ann replaces the gateway with a tunnel naming a consumer the document
    /// lacks. It is refused before anything is written.
    #[test]
    fn a_tunnel_naming_a_consumer_the_document_lacks_is_refused() {
        let f = fixture();
        let config = GatewayConfig {
            stream_routes: vec![tunnel_for("nobody")],
            ..GatewayConfig::default()
        };

        let result = import(&f, config, ImportMode::Replace, ApplyPlan::Apply);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.streams.count(), 0);
    }

    /// Importing a new API-key consumer is refused because the document holds
    /// no key; the import's unit of work is rolled back.
    #[test]
    fn a_new_api_key_consumer_is_refused() {
        let f = fixture();
        let config = GatewayConfig {
            consumers: vec![ConsumerDeclaration {
                credential: ConsumerCredentialDeclaration::ApiKey {
                    prefix: KeyPrefix::new("sk_live_abc").unwrap(),
                },
                ..jwt_consumer("billing")
            }],
            ..GatewayConfig::default()
        };

        let result = merge(&f, config);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.unit.settlements(), [Settlement::Rollback]);
    }

    /// Replacing an existing consumer's token issuer through an import is
    /// refused; credentials must be rotated through their own operation.
    #[test]
    fn changing_a_consumers_credential_is_refused() {
        let f = fixture();
        merge(&f, edge_gateway()).unwrap();
        let mut config = edge_gateway();
        config.consumers[0].credential = ConsumerCredentialDeclaration::JwtBearer {
            issuer: Issuer::new("https://mallory.example").unwrap(),
            subject: FederatedSubject::new("billing").unwrap(),
            jwks_uri: HttpsUrl::new("https://mallory.example/jwks.json").unwrap(),
        };

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
    }

    /// A dry run refuses two egress policies for the same service even when
    /// their names differ.
    #[test]
    fn two_egress_policies_for_one_service_are_refused() {
        let f = fixture();
        let config = GatewayConfig {
            egress_policies: vec![fetcher_egress("fetcher"), fetcher_egress("fetcher-two")],
            ..GatewayConfig::default()
        };

        let result = import(&f, config, ImportMode::Merge, ApplyPlan::DryRun);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A stream backend targeting the metadata address is refused, leaving
    /// the tenant with no stored stream routes.
    #[test]
    fn a_private_stream_backend_is_refused() {
        let f = fixture();
        let mut tunnel = tunnel_for("billing");
        tunnel.backends = vec![StreamBackend::new("169.254.169.254", 80, 1).unwrap()];
        let config = GatewayConfig {
            stream_routes: vec![tunnel],
            ..edge_gateway()
        };

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
        assert_eq!(f.streams.count(), 0);
    }

    /// An imported service naming an unknown connector is refused without
    /// saving a service.
    #[test]
    fn a_service_through_an_unknown_connector_is_refused() {
        let f = fixture();
        let mut config = whole_gateway();
        config.services[0].connector = Setting::Set(routing_label("office"));

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
        assert_eq!(f.services.count(), 0);
    }

    /// Importing a client certificate without a stored sealed key is refused,
    /// leaving the service store empty.
    #[test]
    fn a_client_certificate_without_a_key_on_record_is_refused() {
        let f = fixture();
        let mut config = whole_gateway();
        config.services[0].client_certificate = Setting::Set(
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
                .unwrap(),
        );

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
        assert_eq!(f.services.count(), 0);
    }

    /// Ann's route pins the green deployment by header and declares its
    /// data class. Both arrive, and the second apply changes nothing.
    #[test]
    fn route_conditions_and_declarations_are_applied() {
        let f = fixture();
        let mut config = whole_gateway();
        config.routes[0].conditions = RouteConditions::new(vec![RequestCondition::new(
            MatchSubject::Header(HeaderName::new("x-deployment").unwrap()),
            ValueMatch::Exact(HeaderValue::new("green").unwrap()),
        )])
        .unwrap();
        config.routes[0].data_class = DataClassLevel::Confidential;

        merge(&f, config.clone()).unwrap();

        let first = PageRequest::first(Limit::internal(10));
        let routes = block_on(
            f.routes
                .list_all(&tenant(), None, &SortOrder::default(), &first),
        )
        .unwrap()
        .items;
        assert_eq!(routes[0].conditions(), &config.routes[0].conditions);
        assert_eq!(routes[0].data_class(), DataClassLevel::Confidential);
        assert!(merge(&f, config).unwrap().is_empty());
    }

    /// Acme's plan holds no more consumers. A document adding one is
    /// refused.
    #[test]
    fn a_consumer_past_the_plan_is_refused() {
        let f = fixture_with(|ports| ImportConfigPorts {
            checks: ImportCheckPorts {
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                ..ports.checks
            },
            ..ports
        });

        assert!(matches!(
            merge(&f, edge_gateway()),
            Err(AppError::Forbidden(_))
        ));
        assert_eq!(f.consumers.count(), 0);
    }

    fn rate_limit(switch: StageSwitch, position: u16) -> StageDeclaration {
        StageDeclaration {
            kind: StageKind::RateLimit(RateLimitConfig {
                max_requests: 100,
                window_seconds: Seconds::new(60),
                key_by: RateLimitKey::UserId,
            }),
            position,
            switch,
            removal: StageRemoval::Allowed,
        }
    }

    /// Ann asks for a dry run. She sees the three resources that would be
    /// made, and nothing is written or recorded.
    #[test]
    fn a_dry_run_reports_the_plan_and_writes_nothing() {
        let f = fixture();

        let plan = import(&f, whole_gateway(), ImportMode::Merge, ApplyPlan::DryRun).unwrap();

        assert_eq!(plan.effective_count(), 3);
        assert_eq!(f.services.count(), 0);
        assert_eq!(f.routes.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann applies the document. The import is recorded once.
    #[test]
    fn applying_a_document_is_recorded() {
        let f = fixture();

        merge(&f, whole_gateway()).unwrap();

        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.gateway_config_imported"]
        );
    }

    /// Ann applies the same document a second time. It changes nothing, so
    /// nothing more is recorded.
    #[test]
    fn a_document_that_changes_nothing_records_nothing() {
        let f = fixture();
        merge(&f, whole_gateway()).unwrap();

        merge(&f, whole_gateway()).unwrap();

        assert_eq!(f.audit.records.lock().unwrap().len(), 1);
    }

    /// Ann applies a gateway where the shop signs people in and the shop API
    /// accepts it. Both are set as the document says.
    #[test]
    fn importing_sets_app_sign_in_and_who_accepts_it() {
        let f = fixture();

        merge(&f, signing_in_gateway(SHOP_HOST)).unwrap();

        let shop = stored_service(&f, "shop");
        let api = stored_service(&f, "shop-api");
        assert_eq!(shop.app_sign_in(), Some(&shop_sign_in(SHOP_HOST)));
        assert_eq!(api.accepts_app_sign_in_of(), Some(shop.id()));
    }

    /// Ann's document signs people in on a host Acme never proved. It is
    /// refused, as setting it by hand would be.
    #[test]
    fn importing_sign_in_on_a_host_the_tenant_has_not_verified_is_refused() {
        let f = fixture();

        let result = merge(&f, signing_in_gateway("unverified.example.com"));

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// Ann replaces the gateway with one where the shop API accepts the
    /// shop's sign-in but the shop is missing. It is refused before anything
    /// is written.
    #[test]
    fn a_service_accepting_the_sign_in_of_one_the_document_lacks_is_refused() {
        let f = fixture();
        let mut config = signing_in_gateway(SHOP_HOST);
        config.services.retain(|s| s.name.as_str() == "shop-api");
        config.routes.retain(|r| r.service.as_str() == "shop-api");

        let result = import(&f, config, ImportMode::Replace, ApplyPlan::DryRun);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// Ann applies the shop gateway, then a version without any sign-in. A
    /// document states the whole service, so sign-in is turned off.
    #[test]
    fn importing_a_service_without_sign_in_turns_it_off() {
        let f = fixture();
        merge(&f, signing_in_gateway(SHOP_HOST)).unwrap();
        let mut config = signing_in_gateway(SHOP_HOST);
        for service in &mut config.services {
            service.app_sign_in = Setting::Unset;
            service.accepts_app_sign_in = Setting::Unset;
        }

        merge(&f, config).unwrap();

        assert!(stored_service(&f, "shop").app_sign_in().is_none());
        assert!(
            stored_service(&f, "shop-api")
                .accepts_app_sign_in_of()
                .is_none()
        );
    }

    /// Ann applies a document to an empty gateway. Every resource it names
    /// is made.
    #[test]
    fn applying_creates_every_resource_the_document_names() {
        let f = fixture();

        let plan = merge(&f, whole_gateway()).unwrap();

        assert!(plan.changes.iter().all(|c| c.kind == ChangeKind::Create));
        assert_eq!(f.services.count(), 1);
        assert_eq!(f.routes.count(), 1);
        assert_eq!(stored_pipelines(&f).len(), 1);
    }

    /// Ann applies the same document twice. The second time does nothing.
    #[test]
    fn applying_the_same_document_twice_changes_nothing_the_second_time() {
        let f = fixture();
        merge(&f, whole_gateway()).unwrap();

        let second = merge(&f, whole_gateway()).unwrap();

        assert!(second.is_empty(), "{second:?}");
        assert_eq!(f.services.count(), 1);
        assert_eq!(f.routes.count(), 1);
    }

    /// Ann points the API elsewhere in the document and applies it. The one
    /// service is updated in place.
    #[test]
    fn applying_a_changed_document_updates_in_place() {
        let f = fixture();
        merge(&f, whole_gateway()).unwrap();
        let mut changed = whole_gateway();
        changed.services[0] = service("api", "https://api-v2.example.com:8443");

        let plan = merge(&f, changed).unwrap();

        assert_eq!(plan.effective_count(), 1);
        assert_eq!(plan.effective()[0].kind, ChangeKind::Update);
        assert_eq!(f.services.count(), 1);
    }

    /// Ann merges an empty document. The route it does not mention keeps
    /// serving.
    #[test]
    fn merge_leaves_a_route_the_document_omits_serving() {
        let f = fixture();
        merge(&f, whole_gateway()).unwrap();

        merge(&f, GatewayConfig::default()).unwrap();

        assert_eq!(f.routes.count(), 1);
    }

    /// Ann disables the route, then replaces the gateway with an empty
    /// document. Everything the document omits is removed.
    #[test]
    fn replace_removes_what_the_document_omits() {
        let f = fixture();
        let mut off = whole_gateway();
        off.routes[0].status = RouteStatus::Disabled;
        merge(&f, off).unwrap();

        import(
            &f,
            GatewayConfig::default(),
            ImportMode::Replace,
            ApplyPlan::Apply,
        )
        .unwrap();

        assert_eq!(f.routes.count(), 0);
        assert_eq!(f.services.count(), 0);
        assert!(stored_pipelines(&f).is_empty());
    }

    /// Ann replaces the gateway with an empty document while the route still
    /// takes traffic. A live route is never deleted in one slip, so the whole
    /// document is refused and nothing is removed or recorded.
    #[test]
    fn replace_refuses_to_delete_an_active_route() {
        let f = fixture();
        merge(&f, whole_gateway()).unwrap();

        let result = import(
            &f,
            GatewayConfig::default(),
            ImportMode::Replace,
            ApplyPlan::Apply,
        );

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
        assert_eq!(f.routes.count(), 1);
        assert_eq!(f.services.count(), 1);
        assert_eq!(f.audit.records.lock().unwrap().len(), 1);
    }

    /// Ann replaces the gateway with a route naming a service the document
    /// lacks. Applying the half that resolves would leave the route pointing
    /// nowhere, so nothing is written.
    #[test]
    fn a_route_naming_a_service_the_document_does_not_define_is_refused() {
        let f = fixture();
        let config = GatewayConfig {
            services: Vec::new(),
            pipelines: vec![pipeline("edge")],
            routes: vec![route("public", "missing", "edge")],
            ..GatewayConfig::default()
        };

        let result = import(&f, config, ImportMode::Replace, ApplyPlan::Apply);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(stored_pipelines(&f).is_empty());
    }

    /// Ann merges a document whose route names a service that exists nowhere.
    /// The service is written before the route is refused, so the whole
    /// apply is dropped as one unit and no import is recorded.
    #[test]
    fn a_write_that_fails_drops_the_apply_and_records_nothing() {
        let f = fixture();
        let config = GatewayConfig {
            services: vec![service("api", "https://api.example.com:8443")],
            pipelines: vec![pipeline("edge")],
            routes: vec![route("public", "missing", "edge")],
            ..GatewayConfig::default()
        };

        let result = merge(&f, config);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.unit.settlements(), [Settlement::Rollback]);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann applies the document. Its writes and its record are kept together
    /// as one unit.
    #[test]
    fn an_apply_is_kept_as_one_unit() {
        let f = fixture();

        merge(&f, whole_gateway()).unwrap();

        assert_eq!(f.unit.settlements(), [Settlement::Commit]);
    }

    /// Ann replaces the gateway with a document whose route names what it
    /// defines. It is applied.
    #[test]
    fn a_replace_whose_routes_name_what_it_defines_is_applied() {
        let f = fixture();

        import(&f, whole_gateway(), ImportMode::Replace, ApplyPlan::Apply).unwrap();

        assert_eq!(f.routes.count(), 1);
        assert_eq!(f.services.count(), 1);
    }

    /// Ann replaces the gateway with a route naming a pipeline the document
    /// lacks. It is refused.
    #[test]
    fn a_route_naming_a_pipeline_the_document_does_not_define_is_refused() {
        let f = fixture();
        let config = GatewayConfig {
            services: vec![service("api", "https://api.example.com:8443")],
            pipelines: Vec::new(),
            routes: vec![route("public", "api", "missing")],
            ..GatewayConfig::default()
        };

        let result = import(&f, config, ImportMode::Replace, ApplyPlan::Apply);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// An import cannot point a service at a loopback address.
    #[test]
    fn a_private_upstream_is_refused() {
        let f = fixture();
        let config = GatewayConfig {
            services: vec![service("api", "http://127.0.0.1:8080")],
            ..GatewayConfig::default()
        };

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
    }

    /// Importing an authenticated route is refused when its service pins no
    /// token audience.
    #[test]
    fn a_signed_in_route_without_a_pinned_audience_is_refused() {
        let f = fixture();
        let mut config = whole_gateway();
        config.routes[0].policy = RoutePolicy::Authenticated;

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
    }

    /// Ann's document restricts the route to a host Acme never proved. It is
    /// refused, as creating the route by hand would be.
    #[test]
    fn a_route_on_an_unverified_host_is_refused() {
        let f = fixture();
        let mut config = whole_gateway();
        config.routes[0].hosts =
            RouteHosts::only(vec![DomainName::new("app.example.com").unwrap()]).unwrap();

        assert!(matches!(merge(&f, config), Err(AppError::Domain(_))));
    }

    /// Acme's plan holds no more services or routes. Ann's document is
    /// refused.
    #[test]
    fn a_document_that_would_exceed_the_plan_is_refused() {
        let f = fixture_with(|ports| ImportConfigPorts {
            checks: ImportCheckPorts {
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                ..ports.checks
            },
            ..ports
        });

        assert!(matches!(
            merge(&f, whole_gateway()),
            Err(AppError::Forbidden(_))
        ));
    }

    /// Acme's plan holds no more resources. A dry run still shows Ann the
    /// plan, which is how she finds out she is over the limit.
    #[test]
    fn a_dry_run_does_not_consult_the_plan_limit() {
        let f = fixture_with(|ports| ImportConfigPorts {
            checks: ImportCheckPorts {
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                ..ports.checks
            },
            ..ports
        });

        let plan = import(&f, whole_gateway(), ImportMode::Merge, ApplyPlan::DryRun).unwrap();

        assert_eq!(plan.effective_count(), 3);
    }

    /// Ann's document names no stage. The imported pipeline still runs
    /// Identity and Policy, so it cannot skip who calls or what they may do.
    #[test]
    fn an_imported_pipeline_keeps_its_mandatory_stages() {
        let f = fixture();

        merge(&f, whole_gateway()).unwrap();

        let stored = stored_pipelines(&f);
        let kinds: Vec<_> = stored[0]
            .stages()
            .iter()
            .map(|s| s.kind().clone())
            .collect();
        assert!(kinds.contains(&StageKind::Identity));
        assert!(kinds.contains(&StageKind::Policy));
    }

    /// Ann's document has one rate limit on and one off. They arrive as
    /// declared, since flipping either would change what runs on traffic.
    #[test]
    fn an_imported_stage_keeps_the_switch_the_document_gave_it() {
        let f = fixture();
        let mut config = whole_gateway();
        config.pipelines[0].stages = vec![
            rate_limit(StageSwitch::On, 300),
            rate_limit(StageSwitch::Off, 400),
        ];

        merge(&f, config).unwrap();

        let stored = stored_pipelines(&f);
        let switches: Vec<bool> = stored[0]
            .stages_in_order()
            .into_iter()
            .filter(|s| matches!(s.kind(), StageKind::RateLimit(_)))
            .map(StageConfig::enabled)
            .collect();
        assert_eq!(switches, [true, false]);
    }

    /// Ann applies a document with rate limits at 300 and 400 twice. The
    /// pipeline places them itself, and the second apply still sees no
    /// change.
    #[test]
    fn a_pipeline_with_stages_applies_as_no_change_the_second_time() {
        let f = fixture();
        let mut config = whole_gateway();
        config.pipelines[0].stages = vec![rate_limit(StageSwitch::On, 300)];
        merge(&f, config.clone()).unwrap();

        let second = merge(&f, config).unwrap();

        assert!(second.is_empty(), "{second:?}");
    }

    /// Routing and pipeline view rights do not permit applying a document;
    /// the refusal leaves the service store empty.
    #[test]
    fn a_caller_who_may_only_view_is_refused_on_apply() {
        let f = holding(FakeTenantAuthorities::holding(&[
            SystemPermission::Routing(RoutingAction::View),
            SystemPermission::Pipeline(PipelineAction::View),
        ]));

        let result = merge(&f, whole_gateway());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.services.count(), 0);
    }

    /// A caller with no gateway view rights cannot obtain even a dry-run plan.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let f = holding(FakeTenantAuthorities::holding(&[]));

        let result = import(&f, whole_gateway(), ImportMode::Merge, ApplyPlan::DryRun);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Importing with a signed-out session returns an authentication refusal.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = merge(&f, whole_gateway());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
