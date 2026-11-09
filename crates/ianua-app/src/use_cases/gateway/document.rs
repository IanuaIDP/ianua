//! A tenant's gateway configuration, as one declarative document.
//!
//! Everything here is keyed by name, never by id. A configuration checked
//! into a repository and applied to staging and then to production describes
//! the same gateway in both, and ids are not the same in both. Names are
//! unique per tenant, so they are the natural key. The one exception is an
//! egress policy, which is kept once per service and so is keyed by the
//! service it is for.
//!
//! These are declarations, not aggregates: what the tenant asked for, with no
//! identity and no timestamps. Each can be worked out from the aggregate it
//! describes, which is how the diff decides whether anything changed: build
//! the declaration the live resource would produce, and compare.
//!
//! Nothing secret is written down: no sealed client key, no API key hash.
//! A document only refers to secrets already on record.

mod edge;
mod http;

use std::collections::HashMap;

pub use edge::*;
pub use http::*;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectorId, ConsumerId, Label, PipelineId, ServiceId};

use crate::use_cases::gateway::lookup::LiveGateway;

/// A tenant's gateway as one document.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayConfig {
    /// The backends routes forward to.
    pub services: Vec<ServiceDeclaration>,
    /// The pipelines routes run.
    pub pipelines: Vec<PipelineDeclaration>,
    /// The routes themselves, naming a service and a pipeline.
    pub routes: Vec<RouteDeclaration>,
    /// The ports listened on below HTTP.
    pub stream_routes: Vec<StreamRouteDeclaration>,
    /// Where services agents can reach may send traffic.
    pub egress_policies: Vec<EgressPolicyDeclaration>,
    /// The non-human callers let in.
    pub consumers: Vec<ConsumerDeclaration>,
}

/// The names a document speaks in instead of the ids records hold.
#[derive(Debug, Default)]
pub(crate) struct Names {
    /// Every service's name.
    pub(crate) services: HashMap<ServiceId, Label>,
    /// Every pipeline's name.
    pub(crate) pipelines: HashMap<PipelineId, Label>,
    /// Every consumer's name.
    pub(crate) consumers: HashMap<ConsumerId, Label>,
    /// Every connector's name.
    pub(crate) connectors: HashMap<ConnectorId, Label>,
}

impl Names {
    /// The names of everything `live` holds.
    fn of(live: &LiveGateway) -> Self {
        Self {
            services: live
                .services
                .iter()
                .map(|service| (*service.id(), service.name().clone()))
                .collect(),
            pipelines: live
                .pipelines
                .iter()
                .map(|pipeline| (*pipeline.id(), pipeline.name().clone()))
                .collect(),
            consumers: live
                .consumers
                .iter()
                .map(|consumer| (*consumer.id(), consumer.name().clone()))
                .collect(),
            connectors: live
                .connectors
                .iter()
                .map(|connector| (*connector.id(), connector.name().clone()))
                .collect(),
        }
    }
}

impl GatewayConfig {
    /// Describes a live gateway, naming everything by name rather than id.
    ///
    /// A route whose service or pipeline has gone missing, or a stream
    /// route naming a consumer that is gone, is left out rather than written
    /// down: it could not be made again from the document, so including it
    /// would make a file that fails on import.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a service's upstream no longer
    ///   reads back, or is reached through a connector the tenant lacks.
    pub(crate) fn of(live: &LiveGateway) -> Result<Self, DomainError> {
        let names = Names::of(live);
        Ok(Self {
            services: live
                .services
                .iter()
                .map(|service| ServiceDeclaration::of(service, &names))
                .collect::<Result<_, _>>()?,
            pipelines: live.pipelines.iter().map(PipelineDeclaration::of).collect(),
            routes: live
                .routes
                .iter()
                .filter_map(|route| RouteDeclaration::of(route, &names))
                .collect(),
            stream_routes: live
                .stream_routes
                .iter()
                .filter_map(|route| StreamRouteDeclaration::of(route, &names.consumers))
                .collect(),
            egress_policies: live
                .egress_policies
                .iter()
                .map(EgressPolicyDeclaration::of)
                .collect(),
            consumers: live.consumers.iter().map(ConsumerDeclaration::of).collect(),
        })
    }
}
