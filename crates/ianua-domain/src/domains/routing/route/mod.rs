//! Routes: which requests reach which service, under which policy.

mod attack;
mod conditions;
mod declarations;
mod params;
mod pipeline;
mod resolution;
mod rules;
mod workflows;

use std::marker::PhantomData;

pub use attack::{
    ATTACK_REQUESTS_PER_WINDOW, ATTACK_WINDOW_SECONDS, AttackLength, AttackMode,
    LONGEST_ATTACK_MINUTES, SHORTEST_ATTACK_MINUTES,
};
pub use params::*;
pub use pipeline::*;
pub use resolution::*;
use time::OffsetDateTime;
pub use workflows::WorkflowUse;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::backend::upstream::Upstream;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{
    RouteActivated, RouteCreated, RouteDeleted, RouteDisabled, RouteUpdated,
};
use crate::domains::routing::matching::host::RouteHosts;
use crate::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use crate::domains::routing::matching::path_rewrite::PathRewrite;
use crate::domains::routing::matching::request_match::RouteConditions;
use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::route::rules::{
    ensure_audience_pinned, ensure_cache_private, ensure_matchable, ensure_row_consistent,
};
use crate::domains::routing::route_status::RouteStatus;
use crate::domains::routing::service::Service;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::types::event_type::RoutingEvent;
use crate::types::{
    CanonicalPath, DeclaredAction, HttpMethod, Label, PipelineId, RouteId, ServiceId, UrlPath,
};

/// A route in a tenant that sends requests matching a path pattern to a
/// service.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// The proxy handles a request in this order:
/// 1. It resolves the tenant from the request's domain or slug.
/// 2. It matches the path and method against the tenant's routes.
/// 3. It checks the route's [`RoutePolicy`].
/// 4. It forwards to the service's upstream if allowed, and refuses
///    otherwise.
///
/// A route names a [`Service`] instead of holding an upstream of its own. So
/// many routes share one backend, with one address, one health state and one
/// pool.
///
/// Every change needs the routing right, held by a person signed in to the
/// tenant, so an agent never makes one. Without this rule, Sam's agent marks
/// the route to the payroll records as public data, relabels a delete as a
/// read, and its own checks then let it through.
#[derive(Debug)]
pub struct Route<T: TenantScope> {
    id: RouteId,
    name: Label,
    path_pattern: UrlPath,
    methods: Vec<HttpMethod>,
    service_id: ServiceId,
    policy: RoutePolicy,
    hosts: RouteHosts,
    conditions: RouteConditions,
    pipeline_id: PipelineId,
    path_rewrite: PathRewrite,
    status: RouteStatus,
    priority: u16,
    data_class: DataClassLevel,
    action_class: DeclaredAction,
    reach: RouteReach,
    parameter_rules: Vec<ParameterRule>,
    workflow_use: WorkflowUse,
    attack_mode: AttackMode,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Route<T> {
    /// Creates a new active route forwarding to `service` through
    /// `pipeline`, on behalf of `by`. Raises `routing.route_created`.
    ///
    /// The pipeline is always named, never defaulted. So anyone reading the
    /// route sees what runs on it. A changed default would also change every
    /// route that never named one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create routing.
    /// - [`DomainError::Validation`] if the path pattern holds a `%` escape.
    /// - [`DomainError::Validation`] if the path rewrite names a parameter
    ///   the path pattern does not capture.
    /// - [`DomainError::Validation`] if the route needs sign-in and `service`
    ///   pins no audience.
    /// - [`DomainError::Validation`] if the route needs sign-in and
    ///   `pipeline` shares cached responses between callers.
    pub fn create(
        params: CreateRouteParams,
        service: &Service<T>,
        pipeline: &impl RoutePipeline,
        by: &RoutingControl<'_>,
    ) -> Result<Self, DomainError> {
        Self::ensure_creatable(&params, service, pipeline, by)?;
        let now = crate::shared::clock::now();
        Ok(Self {
            id: RouteId::new(),
            name: params.name,
            path_pattern: params.path_pattern,
            methods: params.methods,
            service_id: *service.id(),
            policy: params.policy,
            hosts: params.hosts,
            conditions: RouteConditions::default(),
            pipeline_id: pipeline.pipeline_id(),
            path_rewrite: params.path_rewrite,
            status: RouteStatus::Active,
            priority: params.priority,
            data_class: DataClassLevel::Internal,
            action_class: DeclaredAction::Undeclared,
            reach: RouteReach::Fixed,
            parameter_rules: Vec::new(),
            workflow_use: WorkflowUse::Closed,
            attack_mode: AttackMode::Off,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        }
        .created())
    }

    /// Checks authority, matching and caller isolation before constructing a route.
    fn ensure_creatable(
        params: &CreateRouteParams,
        service: &Service<T>,
        pipeline: &impl RoutePipeline,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Create)?;
        ensure_matchable(&params.path_pattern)?;
        params.path_rewrite.validate_against(&params.path_pattern)?;
        ensure_audience_pinned(&params.policy, service.upstream())?;
        ensure_cache_private(&params.policy, pipeline)
    }

    /// This new route, having raised its creation.
    fn created(mut self) -> Self {
        self.raised.raise(RouteCreated {
            route_id: self.id,
            name: self.name.clone(),
            path_pattern: self.path_pattern.clone(),
            occurred_at: self.created_at,
        });
        self
    }

    /// Refuses `upstream` for this route's service when the route could not
    /// work with it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the route needs sign-in and
    ///   `upstream` pins no audience.
    pub(super) fn ensure_served_by(&self, upstream: &Upstream) -> Result<(), DomainError> {
        ensure_audience_pinned(&self.policy, upstream)
    }

    /// Refuses `pipeline`'s stages for this route when the route could not
    /// keep callers apart with them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the route needs sign-in and
    ///   `pipeline` shares cached responses between callers.
    pub(crate) fn ensure_runs_on(&self, pipeline: &impl RoutePipeline) -> Result<(), DomainError> {
        ensure_cache_private(&self.policy, pipeline)
    }

    /// Rebuilds a route from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has a path pattern that
    ///   matches nothing.
    /// - [`DomainError::Infrastructure`] when its rewrite names a parameter
    ///   the pattern does not capture.
    /// - [`DomainError::Infrastructure`] when it rules on a parameter twice.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: RouteRow) -> Result<Self, DomainError> {
        ensure_row_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            path_pattern: row.path_pattern,
            methods: row.methods,
            service_id: row.service_id,
            policy: row.policy,
            hosts: row.hosts,
            conditions: row.conditions,
            pipeline_id: row.pipeline_id,
            path_rewrite: row.path_rewrite,
            status: row.status,
            priority: row.priority,
            data_class: row.data_class,
            action_class: row.action_class,
            reach: row.reach,
            parameter_rules: row.parameter_rules,
            workflow_use: row.workflow_use,
            attack_mode: row.attack_mode,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The route's id.
    #[must_use]
    pub fn id(&self) -> &RouteId {
        &self.id
    }

    /// Route name shown in the routing dashboard.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Path pattern this route matches, such as `/api/v1/*`.
    #[must_use]
    pub fn path_pattern(&self) -> &UrlPath {
        &self.path_pattern
    }

    /// HTTP methods this route matches.
    #[must_use]
    pub fn methods(&self) -> &[HttpMethod] {
        &self.methods
    }

    /// The service whose upstream this route forwards to.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// What a caller must prove to be let through this route.
    #[must_use]
    pub fn policy(&self) -> &RoutePolicy {
        &self.policy
    }

    /// What path the upstream sees.
    #[must_use]
    pub fn path_rewrite(&self) -> &PathRewrite {
        &self.path_rewrite
    }

    /// Whether this route is accepting traffic.
    #[must_use]
    pub fn status(&self) -> RouteStatus {
        self.status
    }

    /// Which of the tenant's domains this route answers on.
    #[must_use]
    pub fn hosts(&self) -> &RouteHosts {
        &self.hosts
    }

    /// Restricts the domains this route answers on, or lifts the restriction.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn change_hosts(
        &mut self,
        hosts: RouteHosts,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.hosts = hosts;
        self.record_update();
        Ok(())
    }

    /// Which pipeline runs on this route.
    #[must_use]
    pub fn pipeline_id(&self) -> &PipelineId {
        &self.pipeline_id
    }

    /// Moves the route onto `pipeline`.
    ///
    /// It is one write, so the route is never between pipelines. That lets a
    /// pipeline be replaced without the outage that editing it in place
    /// causes.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] when the route needs sign-in and
    ///   `pipeline` shares cached responses between callers.
    pub fn move_to_pipeline(
        &mut self,
        pipeline: &impl RoutePipeline,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        ensure_cache_private(&self.policy, pipeline)?;
        self.pipeline_id = pipeline.pipeline_id();
        self.record_update();
        Ok(())
    }

    /// Evaluation priority. Lower numbers are evaluated first.
    #[must_use]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// When this route was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this route was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether this route is active and accepting traffic.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RouteStatus::Active
    }

    /// Whether this route matches `method`. An empty method list, or one
    /// holding [`HttpMethod::Any`], matches every method.
    #[must_use]
    pub fn matches_method(&self, method: HttpMethod) -> bool {
        self.methods.is_empty()
            || self.methods.contains(&HttpMethod::Any)
            || self.methods.contains(&method)
    }

    /// Whether this route's path pattern fits a request path. See
    /// [`crate::domains::routing::matching::path_match`] for the pattern
    /// language.
    #[must_use]
    pub fn matches_path(&self, path: &CanonicalPath) -> bool {
        crate::domains::routing::matching::path_match::captures(self.path_pattern.as_str(), path)
            .is_some()
    }

    /// The path a person opens this app at from a start page: its pattern
    /// up to a trailing `/*`, when the route is active, takes `GET`, and the
    /// path names no `{part}` a person would have to fill in.
    #[must_use]
    pub fn landing(&self) -> Option<CanonicalPath> {
        if !self.is_active() || !self.matches_method(HttpMethod::Get) {
            return None;
        }
        let pattern = self.path_pattern.as_str();
        let prefix = pattern.strip_suffix("/*").unwrap_or(pattern);
        if prefix.contains('{') {
            return None;
        }
        let path = if prefix.is_empty() { "/" } else { prefix };
        CanonicalPath::new(path)
            .ok()
            .filter(|path| self.matches_path(path))
    }

    /// How specific this route's path pattern is.
    #[must_use]
    pub fn specificity(&self) -> crate::domains::routing::matching::path_match::Specificity {
        crate::domains::routing::matching::path_match::Specificity::of(self.path_pattern.as_str())
    }

    /// Enables the route. Raises `routing.route_activated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] if already active.
    pub fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(RouteStatus::Active)?;
        self.touch();
        self.raised.raise(RouteActivated {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Disables the route. Requests it would have taken go to the next route
    /// that fits, or get 404 when none does. Raises `routing.route_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] if already disabled.
    pub fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(RouteStatus::Disabled)?;
        self.touch();
        self.raised.raise(RouteDisabled {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Refuses to delete this route unless `by` may delete routing and the
    /// route is disabled.
    ///
    /// A route is disabled first, so the traffic it took already goes to the
    /// next route that fits by the time it is gone. A live route is never
    /// deleted in one slip.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    /// - [`DomainError::InvalidTransition`] while the route is active.
    pub fn ensure_deletable(&self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Delete)?;
        if self.is_active() {
            return Err(DomainError::invalid_transition(message!(
                "routing-a-route-is-disabled-before-it",
                "a route is disabled before it is deleted"
            )));
        }
        Ok(())
    }

    /// Deletes this route once `by` may delete routing and the route is
    /// disabled, as [`ensure_deletable`](Self::ensure_deletable) checks.
    /// Raises `routing.route_deleted`, taken once the route is removed from
    /// storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    /// - [`DomainError::InvalidTransition`] while the route is active.
    pub fn delete(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        self.ensure_deletable(by)?;
        self.raised.raise(RouteDeleted {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Points the route at another service.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] when the route needs sign-in and
    ///   `service` pins no audience.
    pub fn move_to_service(
        &mut self,
        service: &Service<T>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        ensure_audience_pinned(&self.policy, service.upstream())?;
        self.service_id = *service.id();
        self.record_update();
        Ok(())
    }

    /// Replaces the route's policy, judged against `service`, the one this
    /// route forwards to, and `pipeline`, the one it runs.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Conflict`] when `service` or `pipeline` is not this
    ///   route's.
    /// - [`DomainError::Validation`] when the policy needs sign-in and the
    ///   service pins no audience.
    /// - [`DomainError::Validation`] when the policy needs sign-in and the
    ///   pipeline shares cached responses between callers.
    pub fn change_policy(
        &mut self,
        policy: RoutePolicy,
        service: &Service<T>,
        pipeline: &impl RoutePipeline,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        if *service.id() != self.service_id {
            return Err(DomainError::conflict(message!(
                "routing-a-route-s-policy-is-judged",
                "a route's policy is judged against the service it forwards to"
            )));
        }
        if pipeline.pipeline_id() != self.pipeline_id {
            return Err(DomainError::conflict(message!(
                "routing-a-route-s-policy-is-judged-2",
                "a route's policy is judged against the pipeline it runs"
            )));
        }
        ensure_audience_pinned(&policy, service.upstream())?;
        ensure_cache_private(&policy, pipeline)?;
        self.policy = policy;
        self.record_update();
        Ok(())
    }

    /// Changes which paths the route matches and what path the upstream
    /// sees. Both change together, since the rewrite may only name what the
    /// pattern captures.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] if `pattern` holds a percent-escape.
    /// - [`DomainError::Validation`] if `rewrite` names a parameter `pattern`
    ///   does not capture.
    pub fn change_path(
        &mut self,
        pattern: UrlPath,
        rewrite: PathRewrite,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        ensure_matchable(&pattern)?;
        rewrite.validate_against(&pattern)?;
        self.path_pattern = pattern;
        self.path_rewrite = rewrite;
        self.record_update();
        Ok(())
    }

    /// Replaces the matched HTTP methods.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn change_methods(
        &mut self,
        methods: Vec<HttpMethod>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.methods = methods;
        self.record_update();
        Ok(())
    }

    /// Changes the evaluation priority.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn change_priority(
        &mut self,
        priority: u16,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.priority = priority;
        self.record_update();
        Ok(())
    }

    /// Updates the route name.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn rename(&mut self, name: Label, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.name = name;
        self.record_update();
        Ok(())
    }

    /// Sets `updated_at` to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// Marks a change to how the route matches, forwards or is declared,
    /// raising `routing.route_updated` with the route as it now is. Several
    /// changes before a save are one update. A route not yet saved since it
    /// was created raises nothing more: what it is declared with before
    /// its first save is part of its creation.
    fn record_update(&mut self) {
        self.touch();
        if self.raised.holds(RoutingEvent::RouteCreated.into()) {
            return;
        }
        self.raised.raise_latest(RouteUpdated {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
    }
}

impl<T: TenantScope> Raises for Route<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// A route is a tenant-scoped aggregate root. It decides how incoming
/// requests are matched and forwarded to services.
impl<T: TenantScope> Aggregate for Route<T> {
    /// A [`RouteId`].
    type Id = RouteId;

    /// The route's id within the tenant.
    fn id(&self) -> &Self::Id {
        &self.id
    }

    /// When this route was created.
    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this route was last modified.
    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::backend::upstream::HostHeader;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{ActionClass, Fact};

    fn matches(route: &Route<ResolvedTenant>, path: &str) -> bool {
        route.matches_path(&CanonicalPath::new(path).unwrap())
    }

    fn resolve<'a>(
        routes: &'a [Route<ResolvedTenant>],
        method: HttpMethod,
        path: &str,
    ) -> Option<&'a Route<ResolvedTenant>> {
        let path = CanonicalPath::new(path).unwrap();
        let request = RouteRequest {
            method,
            path: &path,
            host: Fact::Unknown,
            values: Fact::Unknown,
        };
        resolve_route(routes, &request, |_| true)
    }
    use crate::domains::routing::backend::upstream::UpstreamTimeout;
    use crate::domains::routing::fixtures::{
        plain_pipeline, routing_admin, routing_editor, routing_viewer, shared_cache_pipeline,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::HttpUrl;

    /// A route with the shape most tests need: wildcard path, two methods,
    /// authenticated.
    fn test_route() -> Route<ResolvedTenant> {
        route_matching(
            "/api/v1/projects/*",
            vec![HttpMethod::Get, HttpMethod::Post],
            100,
        )
    }

    /// `/api/v1/projects/*` on `/api/v1/projects/7/tasks` keeps what it
    /// captured beside the path it forwards, the path `forwarding_path`
    /// gives; a path it does not fit gives neither.
    #[test]
    fn forwarding_keeps_the_captures_beside_the_forwarded_path() {
        let route = test_route();
        let path = CanonicalPath::new("/api/v1/projects/7/tasks").unwrap();

        let forwarding = route.forwarding(&path).unwrap();

        assert_eq!(
            forwarding
                .captures()
                .get(crate::domains::routing::matching::path_match::REST),
            Some("7/tasks")
        );
        assert_eq!(
            Some(forwarding.path().clone()),
            route.forwarding_path(&path)
        );
        assert!(
            route
                .forwarding(&CanonicalPath::new("/other").unwrap())
                .is_none()
        );
    }

    fn service_with(upstream: Upstream) -> Service<ResolvedTenant> {
        Service::create(
            crate::domains::routing::service::CreateServiceParams {
                id: crate::types::ServiceId::new(),
                name: label("projects-api"),
                upstream,
                health_check:
                    crate::domains::routing::backend::health_check::HealthCheckPolicy::default(),
            },
            &routing_admin(),
        )
        .unwrap()
    }

    fn pinned_service() -> Service<ResolvedTenant> {
        service_with(upstream_pinning(Some("client-123")))
    }

    fn params(pattern: &str, methods: Vec<HttpMethod>, priority: u16) -> CreateRouteParams {
        CreateRouteParams {
            hosts: RouteHosts::Any,
            name: label("Projects API"),
            path_pattern: UrlPath::new(pattern).unwrap(),
            methods,
            policy: RoutePolicy::Authenticated,
            path_rewrite: PathRewrite::StripPrefix,
            priority,
        }
    }

    fn route_matching(
        pattern: &str,
        methods: Vec<HttpMethod>,
        priority: u16,
    ) -> Route<ResolvedTenant> {
        Route::create(
            params(pattern, methods, priority),
            &pinned_service(),
            &plain_pipeline(),
            &routing_admin(),
        )
        .unwrap()
    }

    /// Pat's start page opens the projects app at `/api/v1/projects`, and
    /// an app on `/*` at `/`. One on `/users/{id}` names a part Pat would
    /// have to fill in, one that takes only `POST` cannot be opened, and a
    /// disabled one is not offered.
    #[test]
    fn an_app_opens_at_its_fixed_path() {
        let landing = |route: &Route<ResolvedTenant>| route.landing().map(|path| path.to_wire());
        let mut disabled = test_route();
        disabled.disable(&routing_admin()).unwrap();

        assert_eq!(landing(&test_route()).as_deref(), Some("/api/v1/projects"));
        assert_eq!(
            landing(&route_matching("/*", vec![], 1)).as_deref(),
            Some("/")
        );
        assert_eq!(landing(&route_matching("/users/{id}", vec![], 1)), None);
        assert_eq!(
            landing(&route_matching("/hooks", vec![HttpMethod::Post], 1)),
            None
        );
        assert_eq!(landing(&disabled), None);
    }

    fn named(name: &str, pattern: &str, priority: u16) -> Route<ResolvedTenant> {
        let mut route = route_matching(pattern, vec![HttpMethod::Get], priority);
        route.rename(label(name), &routing_admin()).unwrap();
        route
    }

    /// A tenant creates "Projects API" on `/api/v1/projects/*` at priority
    /// 100, stripping the prefix. The route starts active and keeps each of
    /// those settings.
    #[test]
    fn create_produces_active_route() {
        let route = test_route();

        assert!(route.is_active());
        assert_eq!(route.name().as_str(), "Projects API");
        assert_eq!(route.path_pattern().as_str(), "/api/v1/projects/*");
        assert_eq!(route.priority(), 100);
        assert_eq!(*route.path_rewrite(), PathRewrite::StripPrefix);
    }

    /// A route for GET and POST matches those two methods and not DELETE.
    #[test]
    fn matches_specified_methods() {
        let route = test_route();

        assert!(route.matches_method(HttpMethod::Get));
        assert!(route.matches_method(HttpMethod::Post));
        assert!(!route.matches_method(HttpMethod::Delete));
    }

    /// `/api/v1/projects/*` matches `/api/v1/projects` and paths under it. It
    /// does not match `/api/v1/projects-other` or `/api/v1/other`.
    #[test]
    fn wildcard_pattern_matches_prefix_and_nested_paths() {
        let route = test_route();

        assert!(matches(&route, "/api/v1/projects"));
        assert!(matches(&route, "/api/v1/projects/123"));
        assert!(!matches(&route, "/api/v1/projects-other"));
        assert!(!matches(&route, "/api/v1/other"));
    }

    /// A route on `/health` matches that path. It does not match
    /// `/health/live` or `/healthy`.
    #[test]
    fn exact_pattern_matches_only_that_path() {
        let route = route_matching("/health", vec![HttpMethod::Get], 0);

        assert!(matches(&route, "/health"));
        assert!(!matches(&route, "/health/live"));
        assert!(!matches(&route, "/healthy"));
    }

    /// Two routes on `/api/*` have priority 100 and 10. A request to
    /// `/api/support` takes the one at 10.
    #[test]
    fn resolve_route_picks_the_lowest_priority_match() {
        let routes = vec![named("high", "/api/*", 100), named("low", "/api/*", 10)];

        let resolved = resolve(&routes, HttpMethod::Get, "/api/support").unwrap();

        assert_eq!(resolved.name().as_str(), "low");
    }

    /// `/api/*` and `/api/users` share priority 100. A request to
    /// `/api/users` takes the exact route.
    #[test]
    fn on_equal_priority_the_more_specific_pattern_takes_the_request() {
        let routes = vec![
            named("all", "/api/*", 100),
            named("users", "/api/users", 100),
        ];

        let resolved = resolve(&routes, HttpMethod::Get, "/api/users").unwrap();

        assert_eq!(resolved.name().as_str(), "users");
    }

    /// `/api/users` takes only GET, and `/api/*` takes any method. A POST to
    /// `/api/users` goes to `/api/*`.
    #[test]
    fn a_route_that_refuses_the_method_leaves_the_request_to_the_next() {
        let mut all = route_matching("/api/*", vec![HttpMethod::Any], 100);
        all.rename(label("all"), &routing_admin()).unwrap();
        let routes = vec![named("users", "/api/users", 100), all];

        let resolved = resolve(&routes, HttpMethod::Post, "/api/users").unwrap();

        assert_eq!(resolved.name().as_str(), "all");
    }

    /// `/api/users` has priority 100 and `/api/*` has 50. A request to
    /// `/api/users` takes `/api/*`, since priority comes before specificity.
    #[test]
    fn a_lower_priority_number_wins_over_a_more_specific_pattern() {
        let routes = vec![
            named("users", "/api/users", 100),
            named("all", "/api/*", 50),
        ];

        let resolved = resolve(&routes, HttpMethod::Get, "/api/users").unwrap();

        assert_eq!(resolved.name().as_str(), "all");
    }

    /// With `/admin/*` ahead of the broad `/*` route, `/ADMIN/users`
    /// resolves to the admin route despite the different letter case.
    #[test]
    fn a_differently_cased_path_takes_the_route_its_literals_name() {
        let routes = vec![named("admin", "/admin/*", 10), named("all", "/*", 100)];

        let resolved = resolve(&routes, HttpMethod::Get, "/ADMIN/users").unwrap();

        assert_eq!(resolved.name().as_str(), "admin");
    }

    /// The only route for `/api/v1/projects` is disabled. A request there
    /// matches no route.
    #[test]
    fn resolve_route_ignores_disabled_routes() {
        let mut route = test_route();
        route.disable(&routing_admin()).unwrap();
        let routes = vec![route];

        assert!(resolve(&routes, HttpMethod::Get, "/api/v1/projects").is_none());
    }

    /// Fay may delete routing. She disables the projects route and deletes
    /// it. It is allowed.
    #[test]
    fn a_disabled_route_may_be_deleted() {
        let mut route = test_route();
        route.disable(&routing_admin()).unwrap();

        assert!(route.ensure_deletable(&routing_admin()).is_ok());
    }

    /// An editor lacks deletion authority even when an admin has disabled
    /// the route.
    #[test]
    fn deleting_a_route_needs_the_delete_right() {
        let mut route = test_route();
        route.disable(&routing_admin()).unwrap();

        let deleted = route.ensure_deletable(&routing_editor());

        assert!(matches!(deleted, Err(DomainError::Forbidden(_))));
    }

    /// A route still taking traffic is deleted. It is refused until it is
    /// disabled.
    #[test]
    fn a_live_route_is_not_deleted() {
        let route = test_route();

        let deleted = route.ensure_deletable(&routing_admin());

        assert!(matches!(deleted, Err(DomainError::InvalidTransition(_))));
    }

    /// A request to `/unrelated` fits no route. Nothing is resolved, so the
    /// caller denies it.
    #[test]
    fn resolve_route_returns_none_when_nothing_matches() {
        let routes = vec![test_route()];

        assert!(resolve(&routes, HttpMethod::Get, "/unrelated").is_none());
    }

    /// One `/api/*` route is bound to `admin.acme.com`, and another answers
    /// everywhere. The app host and an unknown host get the second, and the
    /// admin host gets the first.
    #[test]
    fn a_route_bound_to_another_host_is_not_the_one() {
        let mut admin_only = route_matching("/api/*", vec![HttpMethod::Get], 1);
        admin_only
            .change_hosts(
                RouteHosts::only(vec![
                    crate::types::DomainName::new("admin.acme.com").unwrap(),
                ])
                .unwrap(),
                &routing_admin(),
            )
            .unwrap();
        let everywhere = route_matching("/api/*", vec![HttpMethod::Get], 100);
        let (admin_id, everywhere_id) = (*admin_only.id(), *everywhere.id());
        let routes = vec![admin_only, everywhere];
        let path = CanonicalPath::new("/api/users").unwrap();
        let on = |host| RouteRequest {
            method: HttpMethod::Get,
            path: &path,
            host,
            values: Fact::Unknown,
        };

        let on_app = resolve_route(&routes, &on(Fact::Known("app.acme.com")), |_| true).unwrap();
        let on_admin =
            resolve_route(&routes, &on(Fact::Known("admin.acme.com")), |_| true).unwrap();
        let unknown = resolve_route(&routes, &on(Fact::Unknown), |_| true).unwrap();

        assert_eq!(*on_app.id(), everywhere_id);
        assert_eq!(*on_admin.id(), admin_id);
        assert_eq!(*unknown.id(), everywhere_id);
    }

    /// A run pass names the admin-only `/api/*` route. Named so, it takes
    /// a `GET /api/users` whatever host was sent, but still not a `POST`
    /// or another path.
    #[test]
    fn a_named_route_takes_its_method_and_path_on_any_host() {
        let mut admin_only = route_matching("/api/*", vec![HttpMethod::Get], 1);
        admin_only
            .change_hosts(
                RouteHosts::only(vec![
                    crate::types::DomainName::new("admin.acme.com").unwrap(),
                ])
                .unwrap(),
                &routing_admin(),
            )
            .unwrap();
        let (users, other) = (
            CanonicalPath::new("/api/users").unwrap(),
            CanonicalPath::new("/billing").unwrap(),
        );
        let sent = |method, path| RouteRequest {
            method,
            path,
            host: Fact::Unknown,
            values: Fact::Unknown,
        };

        assert!(admin_only.takes_once_named(&sent(HttpMethod::Get, &users)));
        assert!(!admin_only.takes(&sent(HttpMethod::Get, &users)));
        assert!(!admin_only.takes_once_named(&sent(HttpMethod::Post, &users)));
        assert!(!admin_only.takes_once_named(&sent(HttpMethod::Get, &other)));
    }

    /// An admin changes a route's pattern to `/caf%C3%A9/*`. It is refused,
    /// since requests are matched decoded and this pattern would match
    /// nothing.
    #[test]
    fn a_pattern_with_an_escape_is_refused() {
        let mut route = test_route();

        let result = route.change_path(
            UrlPath::new("/caf%C3%A9/*").unwrap(),
            PathRewrite::default(),
            &routing_admin(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The first `/api/*` route's service is stopped. The request goes to
    /// the fallback route, as the gateway would send it.
    #[test]
    fn a_route_whose_service_is_not_serving_is_passed_over() {
        let first = route_matching("/api/*", vec![HttpMethod::Get], 1);
        let fallback = route_matching("/api/*", vec![HttpMethod::Get], 100);
        let (stopped, fallback_id) = (*first.service_id(), *fallback.id());
        let routes = vec![first, fallback];
        let path = CanonicalPath::new("/api/users").unwrap();
        let request = RouteRequest {
            method: HttpMethod::Get,
            path: &path,
            host: Fact::Unknown,
            values: Fact::Unknown,
        };

        let resolved = resolve_route(&routes, &request, |service| *service != stopped).unwrap();

        assert_eq!(*resolved.id(), fallback_id);
    }

    /// A route with no methods listed matches GET and DELETE alike.
    #[test]
    fn empty_methods_matches_all() {
        let route = route_matching("/*", vec![], 999);

        assert!(route.matches_method(HttpMethod::Get));
        assert!(route.matches_method(HttpMethod::Delete));
    }

    /// A route listing the `Any` method matches GET, POST and DELETE.
    #[test]
    fn any_method_matches_all() {
        let route = route_matching("/health", vec![HttpMethod::Any], 0);

        assert!(route.matches_method(HttpMethod::Get));
        assert!(route.matches_method(HttpMethod::Post));
        assert!(route.matches_method(HttpMethod::Delete));
    }

    /// An admin disables a route and then turns it back on. Each change
    /// shows in whether it is active.
    #[test]
    fn disable_and_reenable() {
        let mut route = test_route();

        route.disable(&routing_admin()).unwrap();
        assert!(!route.is_active());

        route.activate(&routing_admin()).unwrap();
        assert!(route.is_active());
    }

    /// An admin makes a signed-in route public, judged against its own
    /// service. The route's policy is then public.
    #[test]
    fn a_changed_policy_takes_effect() {
        let (service, pipeline) = (pinned_service(), plain_pipeline());
        let mut route = Route::create(
            params("/api/*", Vec::new(), 1),
            &service,
            &pipeline,
            &routing_admin(),
        )
        .unwrap();

        route
            .change_policy(RoutePolicy::Public, &service, &pipeline, &routing_admin())
            .unwrap();

        assert!(route.policy().is_public());
    }

    /// Checking a policy change against another service is refused as a
    /// conflict, even when that service pins an audience.
    #[test]
    fn a_policy_judged_against_another_service_is_refused() {
        let mut route = test_route();

        let result = route.change_policy(
            RoutePolicy::Authenticated,
            &pinned_service(),
            &plain_pipeline(),
            &routing_admin(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// A public route on a shared cache cannot be made authenticated by
    /// supplying another pipeline. The conflict leaves its policy public.
    #[test]
    fn a_policy_judged_against_another_pipeline_is_refused() {
        let service = pinned_service();
        let mut public = Route::create(
            CreateRouteParams {
                policy: RoutePolicy::Public,
                ..params("/api/*", Vec::new(), 1)
            },
            &service,
            &shared_cache_pipeline(),
            &routing_admin(),
        )
        .unwrap();

        let result = public.change_policy(
            RoutePolicy::Authenticated,
            &service,
            &plain_pipeline(),
            &routing_admin(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(public.policy().is_public());
    }

    /// A public route's service pins no audience. Making the route need
    /// sign-in is refused, and it stays public.
    #[test]
    fn a_route_can_require_sign_in_only_on_a_service_that_pins_an_audience() {
        let (service, pipeline) = (service_with(upstream_pinning(None)), plain_pipeline());
        let mut public = Route::create(
            CreateRouteParams {
                policy: RoutePolicy::Public,
                ..params("/api/*", Vec::new(), 1)
            },
            &service,
            &pipeline,
            &routing_admin(),
        )
        .unwrap();

        let result = public.change_policy(
            RoutePolicy::Authenticated,
            &service,
            &pipeline,
            &routing_admin(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(public.policy().is_public());
    }

    /// A shared cache pipeline refuses authenticated route creation,
    /// moving an authenticated route onto it, and requiring sign-in on a
    /// public route. The refused changes retain the original pipeline and
    /// public policy.
    #[test]
    fn a_signed_in_route_cannot_run_on_a_pipeline_sharing_cached_responses() {
        let (service, shared) = (pinned_service(), shared_cache_pipeline());
        let anyone = CreateRouteParams {
            policy: RoutePolicy::Public,
            ..params("/payslips/*", Vec::new(), 1)
        };
        let mut public = Route::create(anyone, &service, &shared, &routing_admin()).unwrap();
        let mut signed_in = test_route();
        let before = *signed_in.pipeline_id();

        let created = Route::create(
            params("/payslips/*", Vec::new(), 1),
            &service,
            &shared,
            &routing_admin(),
        );
        let moved = signed_in.move_to_pipeline(&shared, &routing_admin());
        let tightened = public.change_policy(
            RoutePolicy::Authenticated,
            &service,
            &shared,
            &routing_admin(),
        );

        assert!(matches!(created, Err(DomainError::Validation(_))));
        assert!(matches!(moved, Err(DomainError::Validation(_))));
        assert!(matches!(tightened, Err(DomainError::Validation(_))));
        assert_eq!(*signed_in.pipeline_id(), before);
        assert!(public.policy().is_public());
    }

    /// An admin moves a route to `/users/{id}` with the rewrite
    /// `/internal/user/{id}`. The route holds both.
    #[test]
    fn change_path_changes_the_pattern_and_the_rewrite_together() {
        let mut route = test_route();

        route
            .change_path(
                UrlPath::new("/users/{id}").unwrap(),
                template("/internal/user/{id}"),
                &routing_admin(),
            )
            .unwrap();

        assert_eq!(route.path_pattern().as_str(), "/users/{id}");
        assert_eq!(*route.path_rewrite(), template("/internal/user/{id}"));
    }

    fn template(text: &str) -> PathRewrite {
        PathRewrite::Template(
            crate::domains::routing::matching::path_rewrite::PathTemplate::new(text).unwrap(),
        )
    }

    /// An admin moves a route to `/users` with the rewrite `/internal/{id}`.
    /// It is refused, since nothing would fill `{id}`, and the old rewrite
    /// stays.
    #[test]
    fn a_rewrite_naming_an_uncaptured_parameter_is_refused() {
        let mut route = test_route();

        let result = route.change_path(
            UrlPath::new("/users").unwrap(),
            template("/internal/{id}"),
            &routing_admin(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(*route.path_rewrite(), PathRewrite::StripPrefix);
    }

    /// A tenant creates a route on `/users` with the rewrite
    /// `/internal/{id}`. It is refused.
    #[test]
    fn a_route_cannot_be_created_with_a_rewrite_its_pattern_does_not_fit() {
        let result = Route::<ResolvedTenant>::create(
            CreateRouteParams {
                path_rewrite: template("/internal/{id}"),
                ..params("/users", vec![HttpMethod::Get], 100)
            },
            &pinned_service(),
            &plain_pipeline(),
            &routing_admin(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An admin points a route at a replacement service. The route then
    /// names that service, so a backend can be swapped in one write.
    #[test]
    fn moving_a_route_to_another_service_repoints_it() {
        let mut route = test_route();
        let replacement = pinned_service();

        route
            .move_to_service(&replacement, &routing_admin())
            .unwrap();

        assert_eq!(route.service_id(), replacement.id());
    }

    /// An admin renames a route to "Updated Name". The name shows and the
    /// update time does not move backwards.
    #[test]
    fn mutations_update_timestamp() {
        let mut route = test_route();
        let before = route.updated_at();

        route
            .rename(label("Updated Name"), &routing_admin())
            .unwrap();

        assert!(route.updated_at() >= before);
        assert_eq!(route.name().as_str(), "Updated Name");
    }

    fn upstream_pinning(audience: Option<&str>) -> Upstream {
        let upstream = Upstream::new(
            HttpUrl::new("https://backend:8080").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        match audience {
            Some(a) => upstream.with_audience(crate::types::Audience::new(a).unwrap()),
            None => upstream,
        }
    }

    /// A service without a pinned audience cannot receive an authenticated
    /// route through creation or a move. The refused move does not attach
    /// the route to that service.
    #[test]
    fn an_authenticated_route_needs_a_service_that_pins_an_audience() {
        let unpinned = service_with(upstream_pinning(None));

        let created = Route::create(
            params("/api/*", Vec::new(), 1),
            &unpinned,
            &plain_pipeline(),
            &routing_admin(),
        );
        let mut route = test_route();
        let moved = route.move_to_service(&unpinned, &routing_admin());

        assert!(matches!(created, Err(DomainError::Validation(_))));
        assert!(matches!(moved, Err(DomainError::Validation(_))));
        assert_ne!(route.service_id(), unpinned.id());
    }

    /// A tenant creates a public route on a service with no audience. It is
    /// accepted, since a public route reads no tokens.
    #[test]
    fn a_public_route_needs_no_audience() {
        let result = Route::create(
            CreateRouteParams {
                policy: RoutePolicy::Public,
                ..params("/api/*", Vec::new(), 1)
            },
            &service_with(upstream_pinning(None)),
            &plain_pipeline(),
            &routing_admin(),
        );

        assert!(result.is_ok());
    }

    /// A tenant puts its public price list behind a pipeline that keeps one
    /// cached answer for everyone. It is accepted, since nobody signs in to
    /// read it.
    #[test]
    fn a_public_route_may_run_on_a_pipeline_sharing_cached_responses() {
        let result = Route::create(
            CreateRouteParams {
                policy: RoutePolicy::Public,
                ..params("/prices/*", Vec::new(), 1)
            },
            &pinned_service(),
            &shared_cache_pipeline(),
            &routing_admin(),
        );

        assert!(result.is_ok());
    }

    /// A route is created on a given pipeline. It has a real id, its
    /// aggregate id is the same one, and it names that pipeline.
    #[test]
    fn a_route_carries_its_own_id_and_the_pipeline_it_runs() {
        let pipeline = plain_pipeline();
        let route = Route::<ResolvedTenant>::create(
            params("/api/v1/projects/*", vec![HttpMethod::Get], 100),
            &pinned_service(),
            &pipeline,
            &routing_admin(),
        )
        .unwrap();

        assert!(!route.id().as_uuid().is_nil());
        assert_eq!(*route.pipeline_id(), pipeline.pipeline_id());
        assert_eq!(
            Aggregate::id(&route),
            route.id(),
            "the aggregate identity is the route's own id"
        );
    }

    /// A route made for GET and POST reports those two and refuses DELETE.
    /// An empty list would mean every method.
    #[test]
    fn a_route_reports_the_methods_it_was_created_with() {
        let route = test_route();

        assert_eq!(
            route.methods(),
            &[HttpMethod::Get, HttpMethod::Post],
            "an empty list would be read as matching every method"
        );
        assert!(!route.matches_method(HttpMethod::Delete));
    }

    /// An admin binds a route to `admin.acme.com`. It then accepts that host
    /// and refuses `app.acme.com`, so the admin route stays off the public
    /// domain.
    #[test]
    fn restricting_a_routes_hosts_takes_effect() {
        let mut route = test_route();
        assert!(route.hosts().is_any());

        route
            .change_hosts(
                RouteHosts::only(vec![
                    crate::types::DomainName::new("admin.acme.com").unwrap(),
                ])
                .unwrap(),
                &routing_admin(),
            )
            .unwrap();

        assert!(!route.hosts().is_any());
        assert!(route.hosts().accepts("admin.acme.com"));
        assert!(!route.hosts().accepts("app.acme.com"));
    }

    /// An admin moves a route to a new pipeline. The route then names the
    /// new one, so traffic leaves the old filters.
    #[test]
    fn moving_a_route_points_it_at_the_new_pipeline() {
        let mut route = test_route();
        let original = *route.pipeline_id();
        let replacement = plain_pipeline();

        route
            .move_to_pipeline(&replacement, &routing_admin())
            .unwrap();

        assert_eq!(*route.pipeline_id(), replacement.pipeline_id());
        assert_ne!(*route.pipeline_id(), original);
    }

    /// An admin moves a route to `/api/v2/reports`, DELETE only, priority 5.
    /// It then matches the new path and method and not the old ones.
    #[test]
    fn editing_what_a_route_matches_changes_what_it_matches() {
        let mut route = test_route();

        route
            .change_path(
                UrlPath::new("/api/v2/reports").unwrap(),
                PathRewrite::StripPrefix,
                &routing_admin(),
            )
            .unwrap();
        route
            .change_methods(vec![HttpMethod::Delete], &routing_admin())
            .unwrap();
        route.change_priority(5, &routing_admin()).unwrap();

        assert!(matches(&route, "/api/v2/reports"));
        assert!(!matches(&route, "/api/v1/projects/42"));
        assert!(route.matches_method(HttpMethod::Delete));
        assert!(!route.matches_method(HttpMethod::Get));
        assert_eq!(route.priority(), 5);
    }

    /// An admin changes a route's priority five minutes after creating it.
    /// Its update time moves to then and its creation time stays, so caches
    /// see the change.
    #[test]
    fn editing_a_route_bumps_the_timestamp_readers_watch() {
        let mut route = test_route();
        let created = route.updated_at();
        let later = created + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        route.change_priority(7, &routing_admin()).unwrap();

        assert_eq!(route.updated_at(), later);
        assert_eq!(
            route.created_at(),
            created,
            "an edit does not rewrite when the route was created"
        );
    }

    mod reach {
        use super::*;
        use crate::domains::routing::matching::parameter::{
            ParameterLocation, ParameterRule, RouteReach,
        };
        use crate::types::DomainName;

        fn rule(name: &str) -> ParameterRule {
            ParameterRule::new(
                name,
                ParameterLocation::Query,
                vec![DomainName::new("docs.example.com").unwrap()],
            )
            .unwrap()
        }

        /// An admin adds rules for `url` and `URL`. A binder reads both as
        /// `url`, so the pair is refused instead of storing a rule never
        /// applied.
        #[test]
        fn a_parameter_ruled_on_twice_in_two_spellings_is_refused() {
            let mut route = test_route();

            let result =
                route.replace_parameter_rules(vec![rule("url"), rule("URL")], &routing_admin());

            assert!(matches!(result, Err(DomainError::Validation(_))));
        }

        /// An open-ended route counts as communicating, even when declared a
        /// read. Declared financial, it stays financial, and the stored
        /// declaration stays as written.
        #[test]
        fn an_open_ended_route_communicates_unless_declared_riskier() {
            let mut route = test_route();
            let read = DeclaredAction::Declared(ActionClass::Read);
            let communicate = DeclaredAction::Declared(ActionClass::Communicate);
            let financial = DeclaredAction::Declared(ActionClass::Financial);
            route
                .declare_reach(RouteReach::OpenEnded, &routing_admin())
                .unwrap();
            assert_eq!(route.action_class(), communicate);

            route.declare_action_class(read, &routing_admin()).unwrap();
            assert_eq!(route.action_class(), communicate);
            assert_eq!(route.declared_action_class(), read);

            route
                .declare_action_class(financial, &routing_admin())
                .unwrap();
            assert_eq!(route.action_class(), financial);
        }

        /// A fixed route needs no approval. Once open-ended, every agent call
        /// needs one, until a parameter rule for `url` is added.
        #[test]
        fn an_open_ended_route_without_rules_needs_approval_for_agents() {
            let mut route = test_route();
            assert!(!route.needs_approval_for_agents());

            route
                .declare_reach(RouteReach::OpenEnded, &routing_admin())
                .unwrap();
            assert!(route.needs_approval_for_agents());

            route
                .replace_parameter_rules(vec![rule("url")], &routing_admin())
                .unwrap();
            assert!(!route.needs_approval_for_agents());
        }

        /// An admin adds two rules for `url` in the query. It is refused.
        #[test]
        fn a_parameter_is_ruled_on_once() {
            let mut route = test_route();

            assert!(
                route
                    .replace_parameter_rules(vec![rule("url"), rule("url")], &routing_admin())
                    .is_err()
            );
        }

        /// A viewer cannot declare open-ended reach or replace parameter
        /// rules. The route retains fixed reach and no parameter rules.
        #[test]
        fn a_viewer_cannot_widen_where_a_route_reaches() {
            let mut route = test_route();

            let reach = route.declare_reach(RouteReach::OpenEnded, &routing_viewer());
            let rules = route.replace_parameter_rules(vec![rule("url")], &routing_viewer());

            assert!(matches!(reach, Err(DomainError::Forbidden(_))));
            assert!(matches!(rules, Err(DomainError::Forbidden(_))));
            assert_eq!(route.reach(), RouteReach::Fixed);
            assert!(route.parameter_rules().is_empty());
        }
    }

    /// A viewer cannot change restricted data to public or declared deletes
    /// to reads. Both refusals preserve the admin's declarations.
    #[test]
    fn a_viewer_cannot_lower_what_a_route_declares() {
        let mut route = test_route();
        route
            .declare_data_class(DataClassLevel::Restricted, &routing_admin())
            .unwrap();
        route
            .declare_action_class(
                DeclaredAction::Declared(ActionClass::Delete),
                &routing_admin(),
            )
            .unwrap();

        let class = route.declare_data_class(DataClassLevel::Public, &routing_viewer());
        let action = route.declare_action_class(
            DeclaredAction::Declared(ActionClass::Read),
            &routing_viewer(),
        );

        assert!(matches!(class, Err(DomainError::Forbidden(_))));
        assert!(matches!(action, Err(DomainError::Forbidden(_))));
        assert_eq!(route.data_class(), DataClassLevel::Restricted);
        assert_eq!(
            route.declared_action_class(),
            DeclaredAction::Declared(ActionClass::Delete)
        );
    }

    /// A viewer cannot make a route public, move it to another pipeline,
    /// or change its hosts. Its policy remains nonpublic and its pipeline
    /// remains the original one.
    #[test]
    fn a_viewer_cannot_open_up_a_route() {
        let (service, pipeline) = (pinned_service(), plain_pipeline());
        let mut route = Route::create(
            params("/api/*", Vec::new(), 1),
            &service,
            &pipeline,
            &routing_admin(),
        )
        .unwrap();

        let policy =
            route.change_policy(RoutePolicy::Public, &service, &pipeline, &routing_viewer());
        let moved = route.move_to_pipeline(&plain_pipeline(), &routing_viewer());
        let hosts = route.change_hosts(RouteHosts::Any, &routing_viewer());

        assert!(matches!(policy, Err(DomainError::Forbidden(_))));
        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert!(matches!(hosts, Err(DomainError::Forbidden(_))));
        assert!(!route.policy().is_public());
        assert_eq!(*route.pipeline_id(), pipeline.pipeline_id());
    }

    /// A viewer cannot disable a route or change its priority. It stays
    /// active at priority 100.
    #[test]
    fn a_viewer_cannot_switch_off_or_reorder_a_route() {
        let mut route = test_route();

        let disabled = route.disable(&routing_viewer());
        let priority = route.change_priority(0, &routing_viewer());

        assert!(matches!(disabled, Err(DomainError::Forbidden(_))));
        assert!(matches!(priority, Err(DomainError::Forbidden(_))));
        assert!(route.is_active());
        assert_eq!(route.priority(), 100);
    }

    /// A viewer cannot move a disabled route, change its path or methods,
    /// rename it, or activate it. The route retains its service and path
    /// and stays disabled.
    #[test]
    fn a_viewer_cannot_repoint_or_rematch_a_route() {
        let mut route = test_route();
        route.disable(&routing_admin()).unwrap();
        let service = *route.service_id();

        let moved = route.move_to_service(&pinned_service(), &routing_viewer());
        let path = route.change_path(
            UrlPath::new("/*").unwrap(),
            PathRewrite::StripPrefix,
            &routing_viewer(),
        );
        let methods = route.change_methods(vec![HttpMethod::Any], &routing_viewer());
        let renamed = route.rename(label("Everything"), &routing_viewer());
        let activated = route.activate(&routing_viewer());

        for result in [moved, path, methods, renamed, activated] {
            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(*route.service_id(), service);
        assert_eq!(route.path_pattern().as_str(), "/api/v1/projects/*");
        assert!(!route.is_active());
    }

    /// An editor cannot create a route matching every path at priority zero
    /// without the create right.
    #[test]
    fn creating_a_route_needs_the_create_right() {
        let created = Route::<ResolvedTenant>::create(
            params("/*", Vec::new(), 0),
            &pinned_service(),
            &plain_pipeline(),
            &routing_editor(),
        );

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
    }

    /// A stored route rewrites to `/v2/{missing}`, which its pattern never
    /// captures. Reading it back is refused as a corrupt row.
    #[test]
    fn a_stored_route_rewriting_to_a_parameter_it_does_not_capture_is_refused() {
        let route = test_route();
        let row = RouteRow {
            id: route.id,
            name: route.name.clone(),
            path_pattern: route.path_pattern.clone(),
            methods: route.methods.clone(),
            service_id: route.service_id,
            policy: route.policy.clone(),
            hosts: route.hosts.clone(),
            conditions: route.conditions.clone(),
            pipeline_id: route.pipeline_id,
            path_rewrite: template("/v2/{missing}"),
            status: route.status,
            priority: route.priority,
            data_class: route.data_class,
            action_class: route.action_class,
            reach: route.reach,
            parameter_rules: route.parameter_rules.clone(),
            workflow_use: route.workflow_use,
            attack_mode: route.attack_mode,
            created_at: route.created_at,
            updated_at: route.updated_at,
        };

        assert!(refused_as_corrupt(&Route::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// A route as it was saved, its creation taken out.
    fn saved_route() -> Route<ResolvedTenant> {
        let mut route = test_route();
        raised_names(&mut route);
        route
    }

    fn stored(route: &Route<ResolvedTenant>) -> RouteRow {
        RouteRow {
            id: route.id,
            name: route.name.clone(),
            path_pattern: route.path_pattern.clone(),
            methods: route.methods.clone(),
            service_id: route.service_id,
            policy: route.policy.clone(),
            hosts: route.hosts.clone(),
            conditions: route.conditions.clone(),
            pipeline_id: route.pipeline_id,
            path_rewrite: route.path_rewrite.clone(),
            status: route.status,
            priority: route.priority,
            data_class: route.data_class,
            action_class: route.action_class,
            reach: route.reach,
            parameter_rules: route.parameter_rules.clone(),
            workflow_use: route.workflow_use,
            attack_mode: route.attack_mode,
            created_at: route.created_at,
            updated_at: route.updated_at,
        }
    }

    /// Ann opens the projects route to workflows: it is open, the change is
    /// raised, and opening it again is refused. Closing it raises its own
    /// event and leaves it closed.
    #[test]
    fn a_route_is_opened_and_closed_to_workflows() {
        let mut route = saved_route();
        assert_eq!(route.workflow_use(), WorkflowUse::Closed);

        route.open_to_workflows(&routing_editor()).unwrap();
        let opened = raised_names(&mut route);
        let again = route.open_to_workflows(&routing_editor());
        route.close_to_workflows(&routing_editor()).unwrap();

        assert_eq!(opened, ["routing.route_opened_to_workflows"]);
        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert_eq!(route.workflow_use(), WorkflowUse::Closed);
        assert_eq!(
            raised_names(&mut route),
            ["routing.route_closed_to_workflows"]
        );
    }

    /// Ann puts the Orders route in attack mode for an hour: it is in force
    /// now and not after the hour, and the start is raised with when it
    /// ends. Ending it raises its own event, and ending it again is refused.
    #[test]
    fn attack_mode_holds_for_its_length_and_ends_early_on_request() {
        let mut route = saved_route();
        let start = crate::shared::clock::now();

        route
            .start_attack_mode(&routing_editor(), AttackLength::minutes(60).unwrap())
            .unwrap();
        let started = raised_names(&mut route);

        let mode = route.attack_mode();
        assert!(mode.in_force_at(start + time::Duration::minutes(59)));
        assert!(!mode.in_force_at(start + time::Duration::minutes(61)));
        assert_eq!(started, ["routing.route_attack_mode_started"]);
        route.end_attack_mode(&routing_editor()).unwrap();
        assert_eq!(route.attack_mode(), AttackMode::Off);
        assert_eq!(
            raised_names(&mut route),
            ["routing.route_attack_mode_ended"]
        );
        assert!(matches!(
            route.end_attack_mode(&routing_editor()),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A viewer cannot start attack mode, leaving it off. Attack lengths of
    /// one minute and one week are also refused.
    #[test]
    fn attack_mode_needs_the_right_and_a_bounded_length() {
        let mut route = saved_route();

        let by_viewer =
            route.start_attack_mode(&routing_viewer(), AttackLength::minutes(60).unwrap());

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert_eq!(route.attack_mode(), AttackMode::Off);
        assert!(AttackLength::minutes(1).is_err());
        assert!(AttackLength::minutes(7 * 1_440).is_err());
    }

    /// A viewer cannot open a route to workflows, and it stays closed.
    #[test]
    fn a_viewer_opens_no_route_to_workflows() {
        let mut route = saved_route();

        let refused = route.open_to_workflows(&routing_viewer());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(route.workflow_use(), WorkflowUse::Closed);
    }

    /// Ann creates "Projects API" on `/api/v1/projects/*`. The creation is
    /// raised with the path it claims.
    #[test]
    fn creating_raises_routing_route_created() {
        let mut route = test_route();

        let events = raised(&mut route);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "routing.route_created");
        assert_eq!(
            events[0].payload().value("path_pattern"),
            Some(&FieldValue::Text("/api/v1/projects/*".to_owned()))
        );
    }

    /// Ann creates a route and declares it restricted before it is first
    /// saved. That is how it was made, so only the creation is raised.
    #[test]
    fn declaring_a_new_route_before_its_first_save_raises_only_the_creation() {
        let mut route = test_route();

        route
            .declare_data_class(DataClassLevel::Restricted, &routing_admin())
            .unwrap();

        assert_eq!(raised_names(&mut route), ["routing.route_created"]);
    }

    /// "Projects API" is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn a_route_read_back_from_storage_has_raised_nothing() {
        let row = stored(&test_route());

        let mut route = Route::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut route).is_empty());
    }

    /// Ann renames a saved route, changes its methods and raises its
    /// priority in one edit. One update is raised, naming the route by its
    /// new name.
    #[test]
    fn several_edits_before_a_save_raise_one_update_as_the_route_ends() {
        let mut route = saved_route();

        route.rename(label("Projects"), &routing_admin()).unwrap();
        route
            .change_methods(vec![HttpMethod::Get], &routing_admin())
            .unwrap();
        route.change_priority(10, &routing_admin()).unwrap();

        let events = raised(&mut route);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "routing.route_updated");
        assert!(matches!(
            events[0].payload().value("route"),
            Some(FieldValue::Reference(reference)) if reference.label() == "Projects"
        ));
    }

    /// Ann disables a saved route and turns it back on. Each move is raised,
    /// in order.
    #[test]
    fn disabling_and_activating_raise_routing_route_disabled_and_activated() {
        let mut route = saved_route();

        route.disable(&routing_admin()).unwrap();
        route.activate(&routing_admin()).unwrap();

        assert_eq!(
            raised_names(&mut route),
            ["routing.route_disabled", "routing.route_activated"]
        );
    }

    /// Ann deletes a disabled route. The deletion is raised.
    #[test]
    fn deleting_raises_routing_route_deleted() {
        let mut route = saved_route();
        route.disable(&routing_admin()).unwrap();
        raised_names(&mut route);

        route.delete(&routing_admin()).unwrap();

        assert_eq!(raised_names(&mut route), ["routing.route_deleted"]);
    }

    /// A viewer's rename and an admin's deletion of an active route are
    /// both refused without raising events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut route = saved_route();

        let renamed = route.rename(label("Everything"), &routing_viewer());
        let deleted = route.delete(&routing_admin());

        assert!(renamed.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut route).is_empty());
    }
}
