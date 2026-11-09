//! The HTTP half of a gateway document: services, the routes in front of
//! them, and the pipelines those routes run.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::stages::stage::{StageConfig, StageKind, StageRemoval};
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::connector::scope::UpstreamReach;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::sign_in::accepted::SignInDelivery;
use ianua_domain::domains::routing::sign_in::app::AppSignIn;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificatePem, DeclaredAction, HttpMethod, Label, Setting, UrlPath};

use crate::use_cases::gateway::document::Names;

/// A backend, as declared.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceDeclaration {
    /// Unique within the tenant; the key this document is applied by.
    pub name: Label,
    /// Where requests go, and how they are addressed, retried, balanced and
    /// spoken to over TLS. Dialled directly and holding no client key: the
    /// connector and the client certificate are declared beside it.
    pub upstream: Upstream,
    /// The client certificate presented to the upstream, by its public
    /// chain. Its private key stays sealed in the store; a document only
    /// keeps the one already on record.
    pub client_certificate: Setting<CertificatePem>,
    /// The tenant's connector the upstream is reached through, by name.
    pub connector: Setting<Label>,
    /// How its backends are probed.
    pub health_check: HealthCheckPolicy,
    /// Sign-in on the hosts it is served on.
    pub app_sign_in: Setting<AppSignIn>,
    /// Whose app sign-in it accepts instead, and how it reaches it.
    pub accepts_app_sign_in: Setting<AcceptedSignInDeclaration>,
    /// Whether it is accepting traffic.
    pub status: RouteStatus,
}

/// Another service's app sign-in accepted, as declared: naming the owner
/// rather than pointing at its id.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptedSignInDeclaration {
    /// The service whose sign-in is accepted, by name.
    pub owner: Label,
    /// How the sign-in reaches the accepting service.
    pub delivery: SignInDelivery,
}

/// A route, as declared: naming its service and pipeline rather than
/// pointing at their ids.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDeclaration {
    /// Unique within the tenant; the key this document is applied by.
    pub name: Label,
    /// The path this route claims.
    pub path_pattern: UrlPath,
    /// The methods it answers. Empty means all of them.
    pub methods: Vec<HttpMethod>,
    /// The service it forwards to, by name.
    pub service: Label,
    /// The pipeline it runs, by name.
    pub pipeline: Label,
    /// Who may reach it.
    pub policy: RoutePolicy,
    /// What path the upstream sees.
    pub path_rewrite: PathRewrite,
    /// Lower is evaluated first where two routes claim one path.
    pub priority: u16,
    /// Which of the tenant's domains it answers on.
    pub hosts: RouteHosts,
    /// The headers and cookies a request must carry for it to match.
    pub conditions: RouteConditions,
    /// The most sensitive data it serves or accepts.
    pub data_class: DataClassLevel,
    /// What kind of action it takes, as declared.
    pub action_class: DeclaredAction,
    /// Whether its service goes only where it was built to, or where it is
    /// told.
    pub reach: RouteReach,
    /// Which hosts its URL parameters may name.
    pub parameter_rules: Vec<ParameterRule>,
    /// Whether it is serving.
    pub status: RouteStatus,
}

/// A pipeline, as declared.
#[derive(Debug, Clone, PartialEq)]
pub struct PipelineDeclaration {
    /// Unique within the tenant; the key this document is applied by.
    pub name: Label,
    /// Its stages, in the order given.
    pub stages: Vec<StageDeclaration>,
    /// Whether it is live.
    pub status: PipelineStatus,
}

/// One stage of a declared pipeline.
///
/// The stage id is left out on purpose. It names a stage within one
/// pipeline in one database, which is what a portable document must not
/// carry: two gateways configured from the same file would otherwise differ
/// in every stage.
#[derive(Debug, Clone, PartialEq)]
pub struct StageDeclaration {
    /// What the stage does, with its configuration.
    pub kind: StageKind,
    /// Evaluation order. Lower runs first.
    pub position: u16,
    /// Whether it runs.
    pub switch: StageSwitch,
    /// Whether the tenant may remove it.
    pub removal: StageRemoval,
}

/// Whether a declared stage runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageSwitch {
    /// The stage runs.
    On,
    /// The stage is kept but skipped.
    Off,
}

impl ServiceDeclaration {
    /// Describes a live service, naming the service whose sign-in it
    /// accepts and the connector it is reached through from `names`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when its upstream names a connector
    ///   the tenant does not hold, which deleting a connector never allows.
    pub(crate) fn of(
        service: &Service<ResolvedTenant>,
        names: &Names,
    ) -> Result<Self, DomainError> {
        let accepts = service.accepted_sign_in().and_then(|accepted| {
            names
                .services
                .get(accepted.owner())
                .map(|owner| AcceptedSignInDeclaration {
                    owner: owner.clone(),
                    delivery: accepted.delivery().clone(),
                })
        });
        let upstream = service.upstream();
        Ok(Self {
            name: service.name().clone(),
            upstream: upstream.portable(),
            client_certificate: Setting::from_stored(
                upstream
                    .tls()
                    .and_then(|tls| tls.client_certificate())
                    .map(|certificate| certificate.certificate().clone()),
            ),
            connector: connector_name(upstream.reach(), names)?,
            health_check: service.health_check().clone(),
            app_sign_in: Setting::from_stored(service.app_sign_in().cloned()),
            accepts_app_sign_in: Setting::from_stored(accepts),
            status: service.status(),
        })
    }
}

/// The name of the connector `reach` goes through, if any.
fn connector_name(reach: UpstreamReach, names: &Names) -> Result<Setting<Label>, DomainError> {
    let UpstreamReach::Connector(connector) = reach else {
        return Ok(Setting::Unset);
    };
    names
        .connectors
        .get(&connector)
        .cloned()
        .map(Setting::Set)
        .ok_or_else(|| {
            DomainError::corrupt_row("service", "reached through a connector the tenant lacks")
        })
}

impl RouteDeclaration {
    /// Describes a live route, turning its service and pipeline ids back
    /// into the names the document speaks in.
    ///
    /// `None` when either name is missing. A route pointing at a service
    /// that is gone cannot be written down in a form that would make it
    /// again, and writing it down anyway would make a document that fails on
    /// import.
    #[must_use]
    pub(crate) fn of(route: &Route<ResolvedTenant>, names: &Names) -> Option<Self> {
        Some(Self {
            name: route.name().clone(),
            path_pattern: route.path_pattern().clone(),
            methods: route.methods().to_vec(),
            service: names.services.get(route.service_id())?.clone(),
            pipeline: names.pipelines.get(route.pipeline_id())?.clone(),
            policy: route.policy().clone(),
            path_rewrite: route.path_rewrite().clone(),
            priority: route.priority(),
            hosts: route.hosts().clone(),
            conditions: route.conditions().clone(),
            data_class: route.data_class(),
            action_class: route.declared_action_class(),
            reach: route.reach(),
            parameter_rules: route.parameter_rules().to_vec(),
            status: route.status(),
        })
    }
}

impl PipelineDeclaration {
    /// Describes a live pipeline, in its own stage order.
    #[must_use]
    pub fn of(pipeline: &Pipeline<ResolvedTenant>) -> Self {
        Self {
            name: pipeline.name().clone(),
            stages: pipeline
                .stages_in_order()
                .into_iter()
                .map(StageDeclaration::of)
                .collect(),
            status: pipeline.status(),
        }
    }
}

impl StageDeclaration {
    /// Describes a live stage, without its id.
    #[must_use]
    pub fn of(stage: &StageConfig) -> Self {
        Self {
            kind: stage.kind().clone(),
            position: stage.position(),
            switch: switch_of(stage),
            removal: removal_of(stage),
        }
    }
}

/// Whether `stage` runs.
fn switch_of(stage: &StageConfig) -> StageSwitch {
    if stage.enabled() {
        return StageSwitch::On;
    }
    StageSwitch::Off
}

/// Whether the tenant may remove `stage`.
fn removal_of(stage: &StageConfig) -> StageRemoval {
    if stage.mandatory() {
        return StageRemoval::Locked;
    }
    StageRemoval::Allowed
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::proxy::stages::stage::MandatoryStage;
    use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
    use ianua_domain::types::ConnectorId;

    use super::*;
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        RouteShape, pinned_upstream, route_of, routing_admin, routing_label, service_named,
        unpinned_upstream,
    };

    fn projects_api() -> Service<ResolvedTenant> {
        service_named(
            "projects-api",
            unpinned_upstream("https://backend.internal:8443"),
        )
    }

    /// The same live service, described twice, gives equal declarations. So
    /// the diff can tell "same" from "different" by comparing.
    #[test]
    fn describing_a_service_twice_gives_equal_declarations() {
        let service = projects_api();
        let names = Names::default();

        assert_eq!(
            ServiceDeclaration::of(&service, &names).unwrap(),
            ServiceDeclaration::of(&service, &names).unwrap()
        );
    }

    /// Ann points the service somewhere else. Its declaration differs from
    /// the one before.
    #[test]
    fn a_changed_upstream_makes_the_declaration_differ() {
        let mut service = projects_api();
        let names = Names::default();
        let before = ServiceDeclaration::of(&service, &names).unwrap();

        service
            .replace_upstream(
                unpinned_upstream("https://elsewhere.internal:8443"),
                &[],
                &routing_admin(),
            )
            .unwrap();

        assert_ne!(before, ServiceDeclaration::of(&service, &names).unwrap());
    }

    /// The shop API accepts the shop's sign-in. Its declaration names the
    /// shop rather than pointing at its id.
    #[test]
    fn a_service_accepting_anothers_sign_in_names_it() {
        let shop = projects_api();
        let mut api = service_named("shop-api", pinned_upstream("https://api:8443", "api"));
        api.accept_app_sign_in_of(
            Setting::Set(AcceptedSignIn::new(*shop.id(), SignInDelivery::SameHost)),
            &routing_admin(),
        )
        .unwrap();
        let names = Names {
            services: HashMap::from([(*shop.id(), routing_label("shop"))]),
            ..Names::default()
        };

        let declared = ServiceDeclaration::of(&api, &names).unwrap();

        assert_eq!(
            declared.accepts_app_sign_in,
            Setting::Set(AcceptedSignInDeclaration {
                owner: routing_label("shop"),
                delivery: SignInDelivery::SameHost,
            })
        );
    }

    /// The payroll service is reached through the office connector. Its
    /// declaration names the connector, so a second environment with its own
    /// office connector applies it as is.
    #[test]
    fn a_service_through_a_connector_names_it() {
        let office = ConnectorId::new();
        let service = service_named(
            "payroll",
            unpinned_upstream("https://payroll.corp:8443").through_connector(office),
        );
        let names = Names {
            connectors: HashMap::from([(office, routing_label("office"))]),
            ..Names::default()
        };

        let declared = ServiceDeclaration::of(&service, &names).unwrap();

        assert_eq!(declared.connector, Setting::Set(routing_label("office")));
        assert_eq!(
            declared.upstream,
            unpinned_upstream("https://payroll.corp:8443")
        );
    }

    /// A service reached through a connector the tenant no longer holds is
    /// a broken record. It is reported, not written down without the
    /// connector, which would dial the private address directly.
    #[test]
    fn a_service_through_a_missing_connector_is_refused() {
        let service = service_named(
            "payroll",
            unpinned_upstream("https://payroll.corp:8443").through_connector(ConnectorId::new()),
        );

        let result = ServiceDeclaration::of(&service, &Names::default());

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A route whose service or pipeline is gone cannot be written in a form
    /// that would make it again, so it has no declaration.
    #[test]
    fn a_route_whose_service_is_missing_cannot_be_declared() {
        let service = projects_api();
        let pipeline = test_pipeline();
        let route = route_of(RouteShape::public("orphan", "/x"), &service, &pipeline);
        let services = HashMap::from([(*service.id(), routing_label("api"))]);
        let pipelines = HashMap::from([(*pipeline.id(), routing_label("edge"))]);
        let only_pipeline = Names {
            pipelines: pipelines.clone(),
            ..Names::default()
        };
        let only_service = Names {
            services: services.clone(),
            ..Names::default()
        };
        let both = Names {
            services,
            pipelines,
            ..Names::default()
        };

        assert!(RouteDeclaration::of(&route, &only_pipeline).is_none());
        assert!(RouteDeclaration::of(&route, &only_service).is_none());
        assert!(RouteDeclaration::of(&route, &both).is_some());
    }

    /// Two Identity stages differ only in their ids. Their declarations are
    /// equal, so two gateways made from one file do not differ in every
    /// stage.
    #[test]
    fn a_stage_declaration_carries_no_id() {
        let one = StageConfig::locked(MandatoryStage::Identity);
        let another = StageConfig::locked(MandatoryStage::Identity);

        assert_ne!(one.id(), another.id());
        assert_eq!(StageDeclaration::of(&one), StageDeclaration::of(&another));
    }
}
