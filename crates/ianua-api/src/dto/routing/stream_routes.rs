//! Stream route bodies: the ports a tenant listens on below HTTP.

use ianua_app::use_cases::routing::stream_routes::{CreateRequest, UpdateRequest};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::stream::access::StreamAccess;
use ianua_domain::domains::routing::stream::{
    ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamRoute, StreamTimeouts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{DomainName, Label, Seconds, StreamRouteId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::routing::routes::host_names;
use crate::error::ApiError;

/// The weight a backend gets when the client names none: an even split.
const DEFAULT_WEIGHT: u32 = 1;

/// A backend on the wire.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct StreamBackendBody {
    /// Host to dial: a DNS name or an IP literal.
    pub host: String,
    /// Port to dial.
    pub port: u16,
    /// Relative traffic weight. Defaults to an even split.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// The weight a backend gets when the body names none.
fn default_weight() -> u32 {
    DEFAULT_WEIGHT
}

impl TryFrom<StreamBackendBody> for StreamBackend {
    type Error = ApiError;

    fn try_from(body: StreamBackendBody) -> Result<Self, Self::Error> {
        Self::new(body.host, body.port, body.weight).map_err(ApiError::validation)
    }
}

impl From<&StreamBackend> for StreamBackendBody {
    fn from(backend: &StreamBackend) -> Self {
        Self {
            host: backend.host().as_str().to_owned(),
            port: backend.port(),
            weight: backend.weight(),
        }
    }
}

/// Reads backends, refusing the first one that is not valid.
fn backends(bodies: Vec<StreamBackendBody>) -> Result<Vec<StreamBackend>, ApiError> {
    bodies.into_iter().map(StreamBackend::try_from).collect()
}

/// Timeouts on the wire. Both fields are optional and default to the
/// platform's.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(default)]
pub(crate) struct StreamTimeoutsBody {
    /// Seconds the proxy waits to reach a backend.
    pub connect_secs: u32,
    /// Seconds a spliced stream may carry nothing before it is closed.
    pub idle_secs: u32,
}

impl Default for StreamTimeoutsBody {
    fn default() -> Self {
        Self::from(StreamTimeouts::default())
    }
}

impl From<StreamTimeouts> for StreamTimeoutsBody {
    fn from(timeouts: StreamTimeouts) -> Self {
        Self {
            connect_secs: timeouts.connect_secs().get(),
            idle_secs: timeouts.idle_secs().get(),
        }
    }
}

impl TryFrom<StreamTimeoutsBody> for StreamTimeouts {
    type Error = ApiError;

    fn try_from(body: StreamTimeoutsBody) -> Result<Self, Self::Error> {
        Self::new(
            Seconds::new(body.connect_secs),
            Seconds::new(body.idle_secs),
        )
        .map_err(ApiError::validation)
    }
}

/// Which handshakes a route answers, on the wire.
///
/// Tagged rather than a nullable list so that "answer everything" is a thing a
/// caller says, not a thing it omits: the difference matters on an update,
/// where an omitted field means "leave it alone".
#[derive(Deserialize, Serialize, Default, utoipa::ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(crate) enum StreamSniBody {
    /// Every handshake arriving on the port.
    #[default]
    Any,
    /// Only handshakes asking for one of these names.
    Only {
        /// The server names, at least one.
        names: Vec<String>,
    },
}

impl TryFrom<StreamSniBody> for RouteHosts {
    type Error = ApiError;

    /// Refuses a name that is not a domain name, or an empty list: a route
    /// restricted to nothing could never be reached.
    fn try_from(body: StreamSniBody) -> Result<Self, Self::Error> {
        let StreamSniBody::Only { names } = body else {
            return Ok(Self::Any);
        };
        let names = names
            .into_iter()
            .map(DomainName::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::validation)?;
        Self::only(names).map_err(ApiError::validation)
    }
}

impl From<&RouteHosts> for StreamSniBody {
    fn from(sni: &RouteHosts) -> Self {
        match sni {
            RouteHosts::Any => Self::Any,
            RouteHosts::Only(_) => Self::Only {
                names: host_names(sni),
            },
        }
    }
}

/// Request body for opening a port.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateStreamRouteBody {
    /// Name, unique within the tenant.
    pub name: String,
    /// How the proxy speaks on the port: `tcp`, `tls_terminate`,
    /// `tls_passthrough` or `udp`.
    #[schema(schema_with = crate::dto::schemas::stream_protocol)]
    pub protocol: StreamProtocol,
    /// The port to listen on. Must be 1024 or above.
    pub listen_port: u16,
    /// Which handshakes to answer. Defaults to every one on the port.
    #[serde(default)]
    pub sni: StreamSniBody,
    /// What is checked on the wire: `public`, `mutual_tls` (requires
    /// `tls_terminate`) or `tunnel` (the signed-in tunnel client, over
    /// `tcp`).
    #[schema(schema_with = crate::dto::schemas::stream_policy)]
    pub policy: StreamPolicy,
    /// Who by name may pass: `"any_holder"` (whoever the policy lets
    /// through), `{"people": <route policy>}` for people signed in through
    /// the tunnel, or `{"consumers": [<id>, ...]}`. Omit for `any_holder`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub access: Option<StreamAccess>,
    /// Where accepted streams go. At least one.
    pub backends: Vec<StreamBackendBody>,
    /// How long a stream may take to start, and stay silent.
    #[serde(default)]
    pub timeouts: StreamTimeoutsBody,
}

impl TryFrom<CreateStreamRouteBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateStreamRouteBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            protocol: body.protocol,
            listen_port: ListenPort::new(body.listen_port).map_err(ApiError::validation)?,
            sni: body.sni.try_into()?,
            policy: body.policy,
            access: body.access.unwrap_or(StreamAccess::AnyHolder),
            backends: backends(body.backends)?,
            timeouts: body.timeouts.try_into()?,
        })
    }
}

/// Request body for changing a stream route.
///
/// The protocol and the port are absent on purpose: changing either is a
/// different socket on a different listener, which is a new route rather than
/// an edit to this one.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateStreamRouteBody {
    /// New name.
    pub name: Option<String>,
    /// New server-name restriction. Send `{"mode":"any"}` to clear one.
    pub sni: Option<StreamSniBody>,
    /// New policy.
    #[schema(schema_with = crate::dto::schemas::stream_policy)]
    pub policy: Option<StreamPolicy>,
    /// Who by name may pass from now on. Changed together with `policy`,
    /// and judged with it.
    #[schema(value_type = Option<Object>)]
    pub access: Option<StreamAccess>,
    /// New backends.
    pub backends: Option<Vec<StreamBackendBody>>,
    /// New timeouts.
    pub timeouts: Option<StreamTimeoutsBody>,
}

impl UpdateStreamRouteBody {
    /// The change this body asks of `route`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for an invalid name, server name,
    /// backend or timeout.
    pub(crate) fn into_request(self, route: StreamRouteId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            stream_route_id: route,
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            sni: self.sni.map(RouteHosts::try_from).transpose()?,
            policy: self.policy,
            access: self.access,
            backends: self.backends.map(backends).transpose()?,
            timeouts: self.timeouts.map(StreamTimeouts::try_from).transpose()?,
        })
    }
}

/// The listener, upstreams and access rules configured for transport traffic.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StreamRouteResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The label administrators use to distinguish this transport listener.
    pub name: String,
    /// How the proxy speaks on the port.
    #[schema(schema_with = crate::dto::schemas::stream_protocol)]
    pub protocol: StreamProtocol,
    /// The inbound socket number on which the proxy accepts transport connections.
    pub listen_port: u16,
    /// Which handshakes it answers.
    pub sni: StreamSniBody,
    /// What is checked on the wire.
    #[schema(schema_with = crate::dto::schemas::stream_policy)]
    pub policy: StreamPolicy,
    /// Who by name may pass.
    #[schema(value_type = Object)]
    pub access: StreamAccess,
    /// Where accepted streams go.
    pub backends: Vec<StreamBackendBody>,
    /// How long a stream may take to start, and stay silent.
    pub timeouts: StreamTimeoutsBody,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::route_status)]
    pub status: RouteStatus,
    /// `open` when the tenant's workflows may reach it as the person a run
    /// acts for, with the login kept for them, `closed` otherwise. The
    /// login itself is never shown.
    #[schema(value_type = String, example = "closed")]
    pub workflow_use: &'static str,
    /// When the route was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<StreamRoute<ResolvedTenant>> for StreamRouteResponse {
    fn from(r: StreamRoute<ResolvedTenant>) -> Self {
        Self {
            id: *r.id().as_uuid(),
            name: r.name().as_str().to_owned(),
            protocol: r.protocol(),
            listen_port: r.listen_port().get(),
            sni: StreamSniBody::from(r.sni()),
            policy: r.policy(),
            access: r.access().clone(),
            backends: r.backends().iter().map(StreamBackendBody::from).collect(),
            timeouts: r.timeouts().into(),
            status: r.status(),
            workflow_use: r.workflow_use().as_str(),
            created_at: r.created_at(),
            updated_at: r.updated_at(),
        }
    }
}

/// The id of a newly opened port.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateStreamRouteResponse {
    /// The new stream route.
    pub id: Uuid,
}

impl From<StreamRouteId> for CreateStreamRouteResponse {
    fn from(id: StreamRouteId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream route body with this protocol and policy, one backend and no
    /// timeouts.
    fn stream_body(protocol: &str, policy: &str) -> String {
        format!(
            r#"{{"name":"pg","protocol":"{protocol}","listen_port":15432,
               "policy":"{policy}","backends":[{{"host":"db.example.com","port":5432}}]}}"#
        )
    }

    /// A backend sent without a weight gets the even weight of one.
    #[test]
    fn a_stream_backend_defaults_to_an_even_weight() {
        let body: CreateStreamRouteBody =
            serde_json::from_str(&stream_body("tcp", "public")).expect("a stream route");

        assert_eq!(body.backends[0].weight, 1);
    }

    /// A route sent without timeouts gets the default ones.
    #[test]
    fn timeouts_default_when_absent() {
        let body: CreateStreamRouteBody =
            serde_json::from_str(&stream_body("tcp", "public")).expect("a stream route");

        assert_eq!(
            StreamTimeouts::try_from(body.timeouts).ok(),
            Some(StreamTimeouts::default())
        );
    }

    /// An empty list of server names would make the port unreachable, so it
    /// is refused rather than read as "answer nothing".
    #[test]
    fn an_empty_server_name_list_is_refused() {
        let body = StreamSniBody::Only { names: Vec::new() };

        assert!(RouteHosts::try_from(body).is_err());
    }

    /// A route limited to `db.acme.com` accepts that name, and reads back
    /// as the same one-name list.
    #[test]
    fn a_named_server_name_restricts_and_reads_back() {
        let body = StreamSniBody::Only {
            names: vec!["db.acme.com".to_owned()],
        };

        let Ok(sni) = RouteHosts::try_from(body) else {
            panic!("a named server name is a restriction");
        };

        assert!(sni.accepts("db.acme.com"));
        assert!(matches!(
            StreamSniBody::from(&sni),
            StreamSniBody::Only { names } if names == ["db.acme.com"]
        ));
    }
}
