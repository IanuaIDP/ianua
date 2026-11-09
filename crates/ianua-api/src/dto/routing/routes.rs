//! Route bodies: a route as it is created, changed and read, and the
//! traffic each route served.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::metrics::RouteTraffic;
use ianua_app::ports::routing::RouteSortField;
use ianua_app::use_cases::routing::routes::{
    AttackChange, ChangeConditionsRequest, CreateRequest, GetTrafficRequest, ListRequest,
    OpenableApp, Opening, RouteFilter, SetAttackModeRequest, UpdateRequest,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::metrics::MetricsWindow;
use ianua_domain::domains::proxy::access::decision::Challenge;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use ianua_domain::domains::routing::matching::path_rewrite::{PathRewrite, PathTemplate};
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::{AttackLength, AttackMode, Route};
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    ActionClass, DeclaredAction, DomainName, HttpMethod, Label, PipelineId, RouteId, ServiceId,
    UrlPath,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::metrics::MetricsWindowResponse;
use crate::error::ApiError;

/// The priority a route gets when the client names none.
const DEFAULT_PRIORITY: u16 = 100;

/// How many routes a traffic rollup returns when the client names no limit.
const DEFAULT_TRAFFIC_LIMIT: u32 = 20;

/// Request body for creating a route.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateRouteBody {
    /// Route name, unique within the tenant.
    pub name: String,
    /// The path it claims, such as `/api/v1/projects/*`.
    pub path_pattern: String,
    /// The methods it answers, such as `Get`. Empty means all of them.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::http_method_list)]
    pub methods: Vec<HttpMethod>,
    /// The service whose upstream this route forwards to.
    pub service_id: Uuid,
    /// What a caller must prove to be let through: `Public`,
    /// `Authenticated`, or an object naming the permissions or scopes
    /// required.
    #[schema(value_type = Object)]
    pub policy: RoutePolicy,
    /// What path the upstream sees. Defaults to the path as it arrived.
    #[serde(default)]
    pub path_rewrite: PathRewriteBody,
    /// Higher wins where two routes claim one path. Defaults to 100.
    #[serde(default = "default_priority")]
    pub priority: u16,
    /// Restrict the route to these of the tenant's domains. Omit, or send
    /// an empty list, to leave it reachable on all of them.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Which pipeline runs on this route.
    ///
    /// Required. A route whose security posture is decided somewhere other
    /// than the route is one nobody can read off the route.
    pub pipeline_id: Uuid,
    /// The most sensitive data this route serves or accepts. An agent that
    /// has touched data of some class may reach only routes cleared at least
    /// that high. Omit for `Internal`.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: Option<DataClassLevel>,
    /// What kind of action this route takes, such as `Financial` for a
    /// payments path. An agent's intent must permit it. Omit to judge each
    /// request by its method and path; a `DELETE` is never judged lower than
    /// `Delete`.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::action_class)]
    pub action_class: Option<ActionClass>,
    /// `open_ended` for a service that fetches whatever URL or host it is
    /// given: it is judged as communicating, and an agent may call it only
    /// within `parameter_rules` or with a person's approval for each call.
    /// Omit for `fixed`.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::route_reach)]
    pub reach: RouteReach,
    /// The parameters that carry a URL or host name, and the hosts each may
    /// name. An agent request naming any other host, encoding one oddly, or
    /// carrying an address in a field no rule covers is refused.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub parameter_rules: Vec<ParameterRule>,
    /// Header and cookie conditions a request must all meet for the route
    /// to match it, for a blue/green switch or a canary pinned by a cookie.
    /// Omit for none.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub conditions: RouteConditions,
}

/// The priority a route gets when the caller does not name one.
fn default_priority() -> u16 {
    DEFAULT_PRIORITY
}

impl TryFrom<CreateRouteBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateRouteBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            path_pattern: UrlPath::new(body.path_pattern).map_err(ApiError::validation)?,
            methods: body.methods,
            service_id: ServiceId::from_uuid(body.service_id),
            policy: body.policy,
            path_rewrite: body.path_rewrite.try_into()?,
            priority: body.priority,
            hosts: route_hosts(&body.hosts)?,
            pipeline_id: PipelineId::from_uuid(body.pipeline_id),
            data_class: body.data_class.unwrap_or(DataClassLevel::Internal),
            action_class: DeclaredAction::from_stored(body.action_class),
            reach: body.reach,
            parameter_rules: body.parameter_rules,
            conditions: body.conditions,
        })
    }
}

/// Request body for replacing a route's header and cookie conditions.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RouteConditionsBody {
    /// The conditions a request must all meet, at most 16, each header or
    /// cookie named once, such as
    /// `{"subject": {"header": "x-canary"}, "value": {"exact": "on"}}`.
    /// Send an empty list to match every request again.
    #[schema(value_type = Vec<Object>)]
    pub conditions: RouteConditions,
}

impl RouteConditionsBody {
    /// The change this body asks of `route`.
    #[must_use]
    pub(crate) fn into_request(self, route: RouteId) -> ChangeConditionsRequest {
        ChangeConditionsRequest {
            route_id: route,
            conditions: self.conditions,
        }
    }
}

/// Request body for changing a route. Every field is optional; an omitted
/// one is left as it is.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateRouteBody {
    /// A new name.
    pub name: Option<String>,
    /// A new path pattern.
    pub path_pattern: Option<String>,
    /// New methods to answer.
    #[schema(value_type = Option<Vec<String>>)]
    pub methods: Option<Vec<HttpMethod>>,
    /// Point the route at another service.
    pub service_id: Option<Uuid>,
    /// A new policy.
    #[schema(value_type = Option<Object>)]
    pub policy: Option<RoutePolicy>,
    /// A new priority.
    pub priority: Option<u16>,
    /// Change what path the upstream sees.
    pub path_rewrite: Option<PathRewriteBody>,
    /// Restrict the route to these of the tenant's domains. Send an empty
    /// list to lift an existing restriction; omit to leave it as it is.
    pub hosts: Option<Vec<String>>,
    /// Move the route onto another of the tenant's pipelines. This is the
    /// zero-downtime path: build the replacement, move routes across one at
    /// a time, retire the old one.
    pub pipeline_id: Option<Uuid>,
    /// Change the most sensitive data this route serves or accepts.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: Option<DataClassLevel>,
    /// Declare what kind of action this route takes.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::action_class)]
    pub action_class: Option<ActionClass>,
    /// Change the service's reach.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::route_reach)]
    pub reach: Option<RouteReach>,
    /// Replace the parameter rules. Send an empty list to remove them.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub parameter_rules: Option<Vec<ParameterRule>>,
}

impl UpdateRouteBody {
    /// The change this body asks of `route`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for an invalid name, path pattern,
    /// path template or host.
    pub(crate) fn into_request(self, route: RouteId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            route_id: route,
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            path_pattern: self
                .path_pattern
                .map(UrlPath::new)
                .transpose()
                .map_err(ApiError::validation)?,
            methods: self.methods,
            service_id: self.service_id.map(ServiceId::from_uuid),
            policy: self.policy,
            priority: self.priority,
            path_rewrite: self.path_rewrite.map(PathRewrite::try_from).transpose()?,
            hosts: self.hosts.as_deref().map(route_hosts).transpose()?,
            pipeline_id: self.pipeline_id.map(PipelineId::from_uuid),
            data_class: self.data_class,
            action_class: self.action_class.map(DeclaredAction::Declared),
            reach: self.reach,
            parameter_rules: self.parameter_rules,
        })
    }
}

/// Wire form of the rule turning the requested path into the forwarded one.
///
/// Tagged by `mode` rather than mirroring the domain enum's shape: a field
/// that is sometimes a string and sometimes an object is awkward to type on
/// the client, and the template needs validating on the way in either way.
#[derive(Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(crate) enum PathRewriteBody {
    /// Forward the path exactly as it arrived.
    #[default]
    Keep,
    /// Forward only what the pattern's trailing `/*` caught: every segment
    /// before it is dropped, `{name}` ones too, and a pattern without `/*`
    /// forwards `/`. Keep a captured segment with a template instead.
    StripPrefix,
    /// Build the forwarded path from the parameters the pattern captured.
    Template {
        /// Literal text plus `{name}` placeholders, e.g. `/internal/user/{id}`.
        template: String,
    },
}

impl TryFrom<PathRewriteBody> for PathRewrite {
    type Error = ApiError;

    fn try_from(body: PathRewriteBody) -> Result<Self, Self::Error> {
        match body {
            PathRewriteBody::Keep => Ok(Self::Keep),
            PathRewriteBody::StripPrefix => Ok(Self::StripPrefix),
            PathRewriteBody::Template { template } => PathTemplate::new(template)
                .map(Self::Template)
                .map_err(ApiError::validation),
        }
    }
}

impl From<&PathRewrite> for PathRewriteBody {
    fn from(rewrite: &PathRewrite) -> Self {
        match rewrite {
            PathRewrite::Keep => Self::Keep,
            PathRewrite::StripPrefix => Self::StripPrefix,
            PathRewrite::Template(template) => Self::Template {
                template: template.as_str().to_owned(),
            },
        }
    }
}

/// Reads a host restriction from the wire.
///
/// An empty list means "no restriction" rather than "restricted to nothing":
/// a route reachable from nowhere could never be requested, and a client
/// clearing the field naturally sends `[]`.
///
/// # Errors
///
/// Returns [`ApiError::validation`] if a value is not a valid domain name.
pub(crate) fn route_hosts(hosts: &[String]) -> Result<RouteHosts, ApiError> {
    if hosts.is_empty() {
        return Ok(RouteHosts::Any);
    }
    let domains = hosts
        .iter()
        .map(|raw| DomainName::new(raw.as_str()).map_err(ApiError::validation))
        .collect::<Result<Vec<_>, _>>()?;
    RouteHosts::only(domains).map_err(ApiError::validation)
}

/// A host restriction on the wire: the names, or an empty list for none.
pub(crate) fn host_names(hosts: &RouteHosts) -> Vec<String> {
    hosts
        .as_stored()
        .map(|domains| domains.iter().map(|d| d.as_str().to_owned()).collect())
        .unwrap_or_default()
}

/// Query parameters for filtering a route listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RouteFilterParams {
    /// Filter by lifecycle status (`Active` or `Disabled`). Omit to return
    /// routes of every status.
    #[param(value_type = Option<String>)]
    pub status: Option<RouteStatus>,
}

impl RouteFilterParams {
    /// The listing asked for: these routes, in `sort` order, the page
    /// `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        &self,
        sort: SortOrder<RouteSortField>,
        pagination: PageRequest,
    ) -> ListRequest {
        ListRequest {
            filter: self.filter(),
            sort,
            page: pagination,
        }
    }

    /// Which routes the listing includes.
    fn filter(&self) -> RouteFilter {
        self.status.map_or(RouteFilter::All, RouteFilter::InStatus)
    }
}

/// The path claim, upstream service and access rules configured for HTTP traffic.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RouteResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Route name.
    pub name: String,
    /// The path it claims.
    pub path_pattern: String,
    /// The methods it answers. Empty means all of them.
    #[schema(schema_with = crate::dto::schemas::http_method_list)]
    pub methods: Vec<HttpMethod>,
    /// The service whose upstream this route forwards to.
    pub service_id: Uuid,
    /// What a caller must prove to be let through.
    #[schema(value_type = Object)]
    pub policy: RoutePolicy,
    /// What path the upstream sees.
    pub path_rewrite: PathRewriteBody,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::route_status)]
    pub status: RouteStatus,
    /// Higher wins where two routes claim one path.
    pub priority: u16,
    /// The domains this route answers on. Empty means every domain the
    /// tenant has.
    pub hosts: Vec<String>,
    /// The pipeline this route runs. Every route has one.
    pub pipeline_id: Uuid,
    /// The most sensitive data this route serves or accepts.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
    /// The kind of action requests to this route are judged as: what was
    /// declared, or `Communicate` for an open-ended route.
    #[schema(schema_with = crate::dto::schemas::action_class)]
    pub action_class: Option<ActionClass>,
    /// Whether the service goes only where it was built to, or where it is
    /// told.
    #[schema(schema_with = crate::dto::schemas::route_reach)]
    pub reach: RouteReach,
    /// The parameters that carry a URL or host name, and the hosts each may
    /// name.
    #[schema(value_type = Vec<Object>)]
    pub parameter_rules: Vec<ParameterRule>,
    /// The header and cookie conditions a request must all meet. Empty
    /// matches every request.
    #[schema(value_type = Vec<Object>)]
    pub conditions: RouteConditions,
    /// `open` when the tenant's workflows may call it as the person a run
    /// acts for, `closed` otherwise.
    #[schema(value_type = String, example = "closed")]
    pub workflow_use: &'static str,
    /// Until when the route is in attack mode, every request to it checked
    /// harder before its pipeline; left out when it is not.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub attack_mode_until: Option<OffsetDateTime>,
    /// When the route was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Route<ResolvedTenant>> for RouteResponse {
    fn from(r: Route<ResolvedTenant>) -> Self {
        Self {
            id: *r.id().as_uuid(),
            name: r.name().as_str().to_owned(),
            path_pattern: r.path_pattern().as_str().to_owned(),
            methods: r.methods().to_vec(),
            service_id: *r.service_id().as_uuid(),
            policy: r.policy().clone(),
            path_rewrite: PathRewriteBody::from(r.path_rewrite()),
            status: r.status(),
            priority: r.priority(),
            hosts: host_names(r.hosts()),
            pipeline_id: *r.pipeline_id().as_uuid(),
            data_class: r.data_class(),
            action_class: r.action_class().stored(),
            reach: r.reach(),
            parameter_rules: r.parameter_rules().to_vec(),
            conditions: r.conditions().clone(),
            workflow_use: r.workflow_use().as_str(),
            attack_mode_until: attack_mode_until(r.attack_mode()),
            created_at: r.created_at(),
            updated_at: r.updated_at(),
        }
    }
}

/// When attack mode ends, while it is in force.
fn attack_mode_until(mode: AttackMode) -> Option<OffsetDateTime> {
    match mode {
        AttackMode::Off => None,
        AttackMode::Until(until) => Some(until),
    }
}

/// How long to put a route in attack mode.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct StartAttackModeBody {
    /// For how many minutes, from 5 to 1440 (a day). It ends on its own.
    pub minutes: u32,
}

impl StartAttackModeBody {
    /// Starting attack mode on the route `route_id` for this long.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the minutes are outside 5 to 1440.
    pub(crate) fn request(&self, route_id: RouteId) -> Result<SetAttackModeRequest, ApiError> {
        Ok(SetAttackModeRequest {
            route_id,
            change: AttackChange::Start(
                AttackLength::minutes(self.minutes).map_err(ApiError::validation)?,
            ),
        })
    }
}

/// Where a route's attack mode stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AttackModeResponse {
    /// Until when it is in force; left out once it is off.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub until: Option<OffsetDateTime>,
}

impl From<AttackMode> for AttackModeResponse {
    fn from(mode: AttackMode) -> Self {
        Self {
            until: attack_mode_until(mode),
        }
    }
}

/// The id of a newly created route.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateRouteResponse {
    /// The new route.
    pub id: Uuid,
}

impl From<RouteId> for CreateRouteResponse {
    fn from(id: RouteId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// How many routes a traffic rollup returns.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RouteTrafficParams {
    /// Routes to return, busiest first. Defaults to 20; the use case clamps
    /// it.
    #[serde(default = "default_traffic_limit")]
    pub limit: u32,
}

/// How many routes a traffic rollup returns when the caller does not say.
fn default_traffic_limit() -> u32 {
    DEFAULT_TRAFFIC_LIMIT
}

impl RouteTrafficParams {
    /// The rollup asked for, over `window`.
    #[must_use]
    pub(crate) fn request(&self, window: MetricsWindow) -> GetTrafficRequest {
        GetTrafficRequest {
            window,
            limit: self.limit,
        }
    }
}

/// Traffic through one route over the requested window.
///
/// Flat rather than trended, unlike the overview figures: this is a table of
/// routes read at a glance to find the one behaving differently, and a trend
/// arrow per cell answers a question nobody asks of a list.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RouteTrafficResponse {
    /// The route the requests matched.
    pub route_id: Uuid,
    /// What the route is called, or `null` if it has since been deleted.
    pub route_name: Option<String>,
    /// The service the route forwards to.
    pub service_id: Option<Uuid>,
    /// What that service is called, or `null` if it has since been deleted.
    pub service_name: Option<String>,
    /// Requests served in the window.
    pub request_count: u64,
    /// Requests the pipeline refused.
    pub denied_count: u64,
    /// Requests that reached the upstream and came back `5xx`.
    pub server_error_count: u64,
    /// Refusals as a percentage of requests, or `null` with no requests.
    pub denial_rate: Option<f64>,
    /// Upstream failures as a percentage of requests, or `null` with no
    /// requests.
    pub server_error_rate: Option<f64>,
    /// Median latency in milliseconds.
    pub p50_latency_ms: Option<u32>,
    /// 95th-percentile latency in milliseconds.
    pub p95_latency_ms: Option<u32>,
}

impl From<RouteTraffic> for RouteTrafficResponse {
    fn from(traffic: RouteTraffic) -> Self {
        Self {
            denial_rate: traffic.denial_rate_percent(),
            server_error_rate: traffic.server_error_rate_percent(),
            route_id: *traffic.route_id.as_uuid(),
            route_name: traffic.route_name.map(|name| name.as_str().to_owned()),
            service_id: traffic.service_id.map(|id| *id.as_uuid()),
            service_name: traffic.service_name.map(|name| name.as_str().to_owned()),
            request_count: traffic.request_count,
            denied_count: traffic.denied_count,
            server_error_count: traffic.server_error_count,
            p50_latency_ms: traffic.p50_latency_ms.map(|latency| latency.millis()),
            p95_latency_ms: traffic.p95_latency_ms.map(|latency| latency.millis()),
        }
    }
}

/// The tenant's routes, busiest first, over one window.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RouteTrafficListResponse {
    /// The window the figures were computed over.
    pub window: MetricsWindowResponse,
    /// One row per route that served traffic in the window.
    pub items: Vec<RouteTrafficResponse>,
}

impl RouteTrafficListResponse {
    /// The rows `traffic` holds, over `window`.
    #[must_use]
    pub(crate) fn over(window: MetricsWindow, traffic: Vec<RouteTraffic>) -> Self {
        Self {
            window: window.into(),
            items: traffic
                .into_iter()
                .map(RouteTrafficResponse::from)
                .collect(),
        }
    }
}

/// One app on the caller's start page.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OpenableAppResponse {
    /// The route the app is served through.
    pub route_id: Uuid,
    /// The app's name, as its route is named.
    pub name: String,
    /// The path the app opens at, to put after one of its addresses.
    pub path: String,
    /// The company's addresses the app answers on; empty for every one.
    pub hosts: Vec<String>,
    /// `now` when it opens at once, `step_up` when the person signs in more
    /// strongly first, `key_proof` when their client proves its key first.
    pub opens: &'static str,
}

impl From<OpenableApp> for OpenableAppResponse {
    fn from(app: OpenableApp) -> Self {
        let opens = match app.opens {
            Opening::Now => "now",
            Opening::AfterMore(Challenge::StepUp(_)) => "step_up",
            Opening::AfterMore(Challenge::DpopProof) => "key_proof",
        };
        Self {
            route_id: *app.route_id.as_uuid(),
            name: app.name.as_str().to_owned(),
            path: app.path.to_wire(),
            hosts: host_names(&app.hosts),
            opens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty list is a client clearing the field, which is what asking for
    /// no restriction looks like on the wire. Reading it as "restricted to
    /// nothing" would make the route unreachable; reading a real list as "no
    /// restriction" would open an admin route onto every domain the tenant
    /// owns.
    #[test]
    fn an_empty_host_list_is_no_restriction_and_a_named_one_restricts() {
        assert_eq!(route_hosts(&[]).ok(), Some(RouteHosts::Any));

        let Ok(restricted) = route_hosts(&["admin.acme.com".to_owned()]) else {
            panic!("a named host is a restriction, not an error");
        };
        assert!(!restricted.is_any());
        assert!(restricted.accepts("admin.acme.com"));
        assert!(!restricted.accepts("app.acme.com"));
    }

    /// A host that is not a domain name is refused at the boundary rather
    /// than stored and matched against forever.
    #[test]
    fn a_host_that_is_not_a_domain_name_is_refused() {
        assert!(route_hosts(&["not a host".to_owned()]).is_err());
    }

    /// The defaults are what a route gets when the client says nothing, and
    /// they are read back to the operator as the route's settings. A
    /// priority of zero or one would reorder every route created without an
    /// explicit one.
    #[test]
    fn the_wire_defaults_are_the_ones_documented() {
        assert_eq!(default_priority(), 100);
        assert_eq!(default_traffic_limit(), 20);
    }

    /// A route that names no data class is cleared for `Internal`, and one
    /// that declares no action class is judged by each request.
    #[test]
    fn an_omitted_data_class_and_action_class_take_their_defaults() {
        let body: CreateRouteBody = serde_json::from_value(serde_json::json!({
            "name": "orders",
            "path_pattern": "/orders",
            "service_id": Uuid::now_v7(),
            "policy": "Public",
            "pipeline_id": Uuid::now_v7(),
        }))
        .unwrap();

        let Ok(request) = CreateRequest::try_from(body) else {
            panic!("a minimal route is a route");
        };

        assert_eq!(request.data_class, DataClassLevel::Internal);
        assert_eq!(request.action_class, DeclaredAction::Undeclared);
        assert_eq!(request.priority, 100);
    }
}
