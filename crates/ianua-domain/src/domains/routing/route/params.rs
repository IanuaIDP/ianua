//! What a route is made from: the settings of a new one, and a stored one.

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::matching::host::RouteHosts;
use crate::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use crate::domains::routing::matching::path_rewrite::PathRewrite;
use crate::domains::routing::matching::request_match::RouteConditions;
use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::route::{AttackMode, WorkflowUse};
use crate::domains::routing::route_status::RouteStatus;
use crate::types::{DeclaredAction, HttpMethod, Label, PipelineId, RouteId, ServiceId, UrlPath};

/// What a new route is created with.
pub struct CreateRouteParams {
    /// Route name shown in the routing dashboard.
    pub name: Label,
    /// Path pattern to match, such as `/api/v1/projects` or
    /// `/api/v1/projects/*`.
    pub path_pattern: UrlPath,
    /// HTTP methods this route matches. Empty means every method.
    pub methods: Vec<HttpMethod>,
    /// What a caller must prove to be let through.
    pub policy: RoutePolicy,
    /// Which of the tenant's domains this route answers on. The default,
    /// [`RouteHosts::Any`], is every one of them.
    pub hosts: RouteHosts,
    /// What path the upstream sees.
    pub path_rewrite: PathRewrite,
    /// Lower numbers are evaluated first. Among routes with the same
    /// priority, the most specific path pattern is evaluated first.
    pub priority: u16,
}

/// A [`Route`](crate::domains::routing::route::Route) as storage holds it,
/// read back through
/// [`Route::reconstitute`](crate::domains::routing::route::Route::reconstitute).
pub struct RouteRow {
    /// The route's id.
    pub id: RouteId,
    /// Route name shown in the routing dashboard.
    pub name: Label,
    /// Path pattern this route matches.
    pub path_pattern: UrlPath,
    /// HTTP methods this route matches. Empty means every method.
    pub methods: Vec<HttpMethod>,
    /// The service whose upstream this route forwards to.
    pub service_id: ServiceId,
    /// What a caller must prove to be let through.
    pub policy: RoutePolicy,
    /// Which of the tenant's domains this route answers on.
    pub hosts: RouteHosts,
    /// The header and cookie conditions a request must meet.
    pub conditions: RouteConditions,
    /// Which pipeline runs on this route.
    pub pipeline_id: PipelineId,
    /// What path the upstream sees.
    pub path_rewrite: PathRewrite,
    /// Whether the route is accepting traffic.
    pub status: RouteStatus,
    /// Evaluation priority. Lower numbers are evaluated first.
    pub priority: u16,
    /// The most sensitive data this route serves or accepts.
    pub data_class: DataClassLevel,
    /// The action class as the operator declared it.
    pub action_class: DeclaredAction,
    /// Whether the service goes only where it was built to, or where it is told.
    pub reach: RouteReach,
    /// Which hosts the route's URL parameters may name.
    pub parameter_rules: Vec<ParameterRule>,
    /// Whether workflows may call the route.
    pub workflow_use: WorkflowUse,
    /// Whether the route is in attack mode, and until when.
    pub attack_mode: AttackMode,
    /// When the route was created.
    pub created_at: OffsetDateTime,
    /// When the route was last modified.
    pub updated_at: OffsetDateTime,
}
