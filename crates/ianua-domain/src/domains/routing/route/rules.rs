//! The checks a route's settings pass before it keeps them.

use crate::domains::routing::backend::upstream::Upstream;
use crate::domains::routing::matching::parameter::{ParameterLocation, ParameterRule};
use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::route::pipeline::{ResponseSharing, RoutePipeline};
use crate::domains::routing::route::{AttackMode, RouteRow};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::web::parameter_key::ParameterKey;
use crate::types::UrlPath;

/// Refuses two rules on the same parameter in the same place, in any
/// spelling a server reads as one name.
pub(super) fn ensure_ruled_once(rules: &[ParameterRule]) -> Result<(), DomainError> {
    let keys: Vec<(ParameterKey, ParameterLocation)> = rules
        .iter()
        .map(|rule| (ParameterKey::written(rule.name().as_str()), rule.location()))
        .collect();
    if first_repeat(&keys).is_some() {
        return Err(DomainError::invalid(message!(
            "routing-a-parameter-is-ruled-on-twice",
            "a parameter is ruled on twice"
        )));
    }
    Ok(())
}

/// Refuses a route that needs sign-in on an upstream that pins no expected
/// JWT audience.
///
/// Without one, a JWT made for any of the tenant's OAuth clients is accepted
/// on the route. Ann's tenant has a billing client and a reports client.
/// Without this check, a token Sam got for reports opens the billing routes.
///
/// The audience lives on the service. So this check runs wherever a route
/// and its service meet: creating a route, changing its policy or service,
/// and replacing the service's upstream.
pub(super) fn ensure_audience_pinned(
    policy: &RoutePolicy,
    upstream: &Upstream,
) -> Result<(), DomainError> {
    if !policy.is_public() && upstream.expected_audience().is_none() {
        return Err(DomainError::invalid(message!(
            "routing-a-route-requiring-authentication-must-be",
            "a route requiring authentication must be served by a service that pins an \
             expected JWT audience"
        )));
    }
    Ok(())
}

/// Refuses a route that needs sign-in on a pipeline that keeps one cached
/// response for every caller.
///
/// Ann reads her payslip through a signed-in route. The shared cache keeps
/// the answer, and Sam asking for the same path a moment later is served
/// Ann's payslip without the upstream being asked.
///
/// The cache lives on the pipeline. So this check runs wherever a route and
/// its pipeline meet: creating a route, changing its policy or pipeline, and
/// turning the pipeline on.
pub(super) fn ensure_cache_private(
    policy: &RoutePolicy,
    pipeline: &impl RoutePipeline,
) -> Result<(), DomainError> {
    if policy.requires_auth() && pipeline.response_sharing() == ResponseSharing::Shared {
        return Err(DomainError::invalid(message!(
            "routing-a-route-requiring-authentication-cannot-run",
            "a route requiring authentication cannot run on a pipeline that shares cached \
             responses between callers"
        )));
    }
    Ok(())
}

/// Refuses a pattern that could never match a request.
///
/// Requests are matched in their canonical spelling, decoded once. So a
/// pattern written with a `%` escape, such as `/caf%C3%A9/*`, never matches
/// anything. The route would protect nothing, and a broader route would take
/// the request instead.
pub(super) fn ensure_matchable(pattern: &UrlPath) -> Result<(), DomainError> {
    if pattern.as_str().contains('%') {
        return Err(DomainError::invalid(message!(
            "routing-a-route-pattern-is-written-as",
            "a route pattern is written as paths are matched, decoded, without '%' escapes"
        )));
    }
    Ok(())
}

/// Refuses a stored route row that breaks a rule a route keeps.
pub(super) fn ensure_row_consistent(row: &RouteRow) -> Result<(), DomainError> {
    RowCheck::of("route")
        .holds(
            ensure_matchable(&row.path_pattern).is_ok(),
            "a path pattern that matches nothing",
        )
        .holds(
            row.path_rewrite.validate_against(&row.path_pattern).is_ok(),
            "a rewrite naming a parameter the pattern does not capture",
        )
        .holds(
            ensure_ruled_once(&row.parameter_rules).is_ok(),
            "a parameter ruled on twice",
        )
        .holds(
            !matches!(row.attack_mode, AttackMode::Until(until) if until <= row.created_at),
            "attack mode ending before the route was created",
        )
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was created",
        )
        .finish()
}
