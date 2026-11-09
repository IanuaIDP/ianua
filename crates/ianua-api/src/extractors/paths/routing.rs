//! The route, service, stream route, egress policy or connector a tenant
//! request names.

use ianua_domain::types::{ConnectorId, EgressPolicyId, RouteId, ServiceId, StreamRouteId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../routes/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct RoutePath {
    id: Uuid,
}

impl RoutePath {
    /// The route named.
    #[must_use]
    pub(crate) fn route(&self) -> RouteId {
        RouteId::from_uuid(self.id)
    }
}

/// `.../services/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct ServicePath {
    id: Uuid,
}

impl ServicePath {
    /// The service named.
    #[must_use]
    pub(crate) fn service(&self) -> ServiceId {
        ServiceId::from_uuid(self.id)
    }
}

/// `.../stream-routes/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct StreamRoutePath {
    id: Uuid,
}

impl StreamRoutePath {
    /// The stream route named.
    #[must_use]
    pub(crate) fn stream_route(&self) -> StreamRouteId {
        StreamRouteId::from_uuid(self.id)
    }
}

/// `.../egress-policies/{id}`.
#[derive(Deserialize)]
pub(crate) struct EgressPolicyPath {
    id: Uuid,
}

impl EgressPolicyPath {
    /// The egress policy named.
    #[must_use]
    pub(crate) fn policy(&self) -> EgressPolicyId {
        EgressPolicyId::from_uuid(self.id)
    }
}

/// `.../connectors/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct ConnectorPath {
    id: Uuid,
}

impl ConnectorPath {
    /// The connector named.
    #[must_use]
    pub(crate) fn connector(&self) -> ConnectorId {
        ConnectorId::from_uuid(self.id)
    }
}
