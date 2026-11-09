//! Moving a route to another service or pipeline and changing its policy,
//! in an order the route's rules allow at every step. Editing a route and
//! importing a gateway document both move routes this way.

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

/// A service a route forwards to and the pipeline it runs.
#[derive(Clone, Copy)]
pub(crate) struct RouteTargets<'a> {
    /// The backend receiving requests matched by the route.
    pub(crate) service: &'a Service<ResolvedTenant>,
    /// The processing stages applied before forwarding a matched request.
    pub(crate) pipeline: &'a Pipeline<ResolvedTenant>,
}

/// Where a route forwards and runs now, and where it is to from now on.
#[derive(Clone, Copy)]
pub(crate) struct Retarget<'a> {
    /// What the route forwards to and runs now.
    pub(crate) current: RouteTargets<'a>,
    /// What it is to forward to and run.
    pub(crate) next: RouteTargets<'a>,
}

/// Moves `route` to `retarget.next` and, when given, sets `policy`, on
/// behalf of `by`.
///
/// A policy that needs sign-in is judged against where the route goes, so
/// the route moves first. A public policy needs nothing of the service or
/// pipeline, so it is set first, and a signed-in route may then move onto a
/// service that pins no audience.
///
/// # Errors
///
/// Returns the route's own refusal: `by` may not update routing, or a step
/// would leave a signed-in route on a service that pins no audience or a
/// pipeline that shares cached responses.
pub(crate) fn retarget(
    route: &mut Route<ResolvedTenant>,
    policy: Option<RoutePolicy>,
    retarget: Retarget<'_>,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    let Retarget { current, next } = retarget;
    match policy {
        None => move_to(route, next, by),
        Some(policy) if policy.requires_auth() => {
            move_to(route, next, by)?;
            route.change_policy(policy, next.service, next.pipeline, by)
        }
        Some(policy) => {
            route.change_policy(policy, current.service, current.pipeline, by)?;
            move_to(route, next, by)
        }
    }
}

/// Points `route` at `targets`, where it does not already point.
fn move_to(
    route: &mut Route<ResolvedTenant>,
    targets: RouteTargets<'_>,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if route.service_id() != targets.service.id() {
        route.move_to_service(targets.service, by)?;
    }
    if route.pipeline_id() == targets.pipeline.id() {
        return Ok(());
    }
    route.move_to_pipeline(targets.pipeline, by)
}
