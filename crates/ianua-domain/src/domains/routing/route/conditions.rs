//! The header and cookie conditions a route matches on, beside its host,
//! method and path.

use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::matching::request_match::{RequestValues, RouteConditions};
use crate::domains::routing::route::Route;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;

impl<T: TenantScope> Route<T> {
    /// The header and cookie conditions a request must meet. None by
    /// default, so every request on the route's path matches.
    #[must_use]
    pub fn conditions(&self) -> &RouteConditions {
        &self.conditions
    }

    /// Whether `request` meets every header and cookie condition. The
    /// gateway asks this after host, method and path fit.
    #[must_use]
    pub fn matches_values(&self, request: &(impl RequestValues + ?Sized)) -> bool {
        self.conditions.hold_for(request)
    }

    /// Replaces header/cookie conditions that narrow requests selected by this route.
    /// Nonmatching requests try the next route under its own policy.
    /// Raises `routing.route_updated` once for all changes before saving.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without routing-update authority.
    pub fn change_conditions(
        &mut self,
        conditions: RouteConditions,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.conditions = conditions;
        self.record_update();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::routing::backend::health_check::HealthCheckPolicy;
    use crate::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
    use crate::domains::routing::fixtures::{plain_pipeline, routing_admin, routing_viewer};
    use crate::domains::routing::matching::host::RouteHosts;
    use crate::domains::routing::matching::path_rewrite::PathRewrite;
    use crate::domains::routing::matching::request_match::{
        MatchSubject, RequestCondition, RequestValues, RouteConditions, ValueMatch,
    };
    use crate::domains::routing::policy::RoutePolicy;
    use crate::domains::routing::route::{CreateRouteParams, Route, RouteRequest, resolve_route};
    use crate::domains::routing::service::{CreateServiceParams, Service};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::errors::DomainError;
    use crate::test_support::builders::label;
    use crate::types::{
        CanonicalPath, CookieName, Fact, HeaderName, HeaderValue, HttpMethod, HttpUrl, UrlPath,
    };

    struct Green;

    impl RequestValues for Green {
        fn header(&self, name: &HeaderName) -> Fact<&str> {
            if name.as_str() == "x-deployment" {
                return Fact::Known("green");
            }
            Fact::Unknown
        }

        fn cookie(&self, _name: &CookieName) -> Fact<&str> {
            Fact::Unknown
        }
    }

    fn green_only() -> RouteConditions {
        RouteConditions::new(vec![RequestCondition::new(
            MatchSubject::Header(HeaderName::new("x-deployment").unwrap()),
            ValueMatch::Exact(HeaderValue::new("green").unwrap()),
        )])
        .unwrap()
    }

    fn route() -> Route<ResolvedTenant> {
        let service = Service::create(
            CreateServiceParams {
                id: crate::types::ServiceId::new(),
                name: label("orders"),
                upstream: Upstream::new(
                    HttpUrl::new("http://orders:8080").unwrap(),
                    UpstreamTimeout::DEFAULT,
                    HostHeader::Rewrite,
                ),
                health_check: HealthCheckPolicy::default(),
            },
            &routing_admin(),
        )
        .unwrap();
        Route::create(
            CreateRouteParams {
                name: label("orders green"),
                path_pattern: UrlPath::new("/orders/*").unwrap(),
                methods: Vec::new(),
                policy: RoutePolicy::Public,
                hosts: RouteHosts::Any,
                path_rewrite: PathRewrite::Keep,
                priority: 10,
            },
            &service,
            &plain_pipeline(),
            &routing_admin(),
        )
        .unwrap()
    }

    /// Ann gives the green route the condition `x-deployment: green`. A
    /// request carrying it matches the route.
    #[test]
    fn a_route_matches_a_request_meeting_its_conditions() {
        let mut route = route();

        route
            .change_conditions(green_only(), &routing_admin())
            .unwrap();

        assert!(route.matches_values(&Green));
        assert_eq!(route.conditions(), &green_only());
    }

    /// A viewer cannot clear the route's header condition. The green-only
    /// condition remains in place.
    #[test]
    fn a_viewer_cannot_change_a_routes_conditions() {
        let mut route = route();
        route
            .change_conditions(green_only(), &routing_admin())
            .unwrap();

        let result = route.change_conditions(RouteConditions::default(), &routing_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(route.conditions(), &green_only());
    }

    /// A route with a header condition is never picked when the request's
    /// headers are not known, so its policy never stands in for the one
    /// the gateway would apply.
    #[test]
    fn a_conditional_route_is_not_resolved_without_the_request_values() {
        let mut route = route();
        route
            .change_conditions(green_only(), &routing_admin())
            .unwrap();
        let path = CanonicalPath::new("/orders/7").unwrap();
        let request = RouteRequest {
            method: HttpMethod::Get,
            path: &path,
            host: Fact::Unknown,
            values: Fact::Unknown,
        };

        assert!(resolve_route(std::slice::from_ref(&route), &request, |_| true).is_none());
    }

    struct Plain;

    impl RequestValues for Plain {
        fn header(&self, _name: &HeaderName) -> Fact<&str> {
            Fact::Unknown
        }

        fn cookie(&self, _name: &CookieName) -> Fact<&str> {
            Fact::Unknown
        }
    }

    /// Blue/green: the green route comes first and takes only requests
    /// carrying `x-deployment: green`; the rest fall to the route behind it.
    #[test]
    fn a_conditional_route_takes_only_the_requests_meeting_its_conditions() {
        let mut green = route();
        green
            .change_conditions(green_only(), &routing_admin())
            .unwrap();
        let mut blue = route();
        blue.change_priority(20, &routing_admin()).unwrap();
        let (green_id, blue_id) = (*green.id(), *blue.id());
        let routes = vec![green, blue];
        let path = CanonicalPath::new("/orders/7").unwrap();
        let carrying = |values: &'static dyn RequestValues| RouteRequest {
            method: HttpMethod::Get,
            path: &path,
            host: Fact::Known("shop.acme.com"),
            values: Fact::Known(values),
        };

        let with = resolve_route(&routes, &carrying(&Green), |_| true).unwrap();
        let without = resolve_route(&routes, &carrying(&Plain), |_| true).unwrap();

        assert_eq!(*with.id(), green_id);
        assert_eq!(*without.id(), blue_id);
    }
}
