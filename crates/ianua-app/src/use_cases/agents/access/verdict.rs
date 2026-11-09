//! A dry run's answer for a request: the gateway's decision under each live
//! delegation's token, and the one that speaks for them all, with why.

use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::proxy::access::decide;
use ianua_domain::domains::proxy::access::decision::{AccessDecision, DenyCode, Outcome};
use ianua_domain::domains::proxy::access::question::{
    AccessQuestion, Asked, Circumstances, Lookup, Records, RouteTerms,
};
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::use_cases::agents::access::authorize::AgentAuthorizeOutcome;
use crate::use_cases::agents::access::token::Token;

/// The decision for `asked` through `route` under each of `tokens`, with
/// what the facts of a dry run cannot know read as unknown.
pub(in crate::use_cases::agents::access) fn decisions_through(
    route: &Route<ResolvedTenant>,
    tokens: &[Token],
    own: &Records,
    asked: &Asked,
    policy: &Lookup<PolicySet>,
) -> Vec<AccessDecision> {
    let around = Circumstances::unknown();
    tokens
        .iter()
        .map(|token| {
            decide(&AccessQuestion {
                route: Lookup::Found(RouteTerms::of(route)),
                asker: token.asker(own),
                asked,
                circumstances: &around,
                local_times: &[],
                tenant_policy: policy.as_ref(),
            })
        })
        .collect()
}

/// The decision across every token's: allowed when one passes, otherwise
/// denied with the closest miss as the reason.
pub(in crate::use_cases::agents::access) fn delegations_outcome(
    route: &Route<ResolvedTenant>,
    decisions: &[AccessDecision],
) -> AgentAuthorizeOutcome {
    let route_name = route.name().as_str();
    let closest = decisions
        .iter()
        .map(AccessDecision::outcome)
        .min_by_key(|outcome| distance(*outcome));
    match closest {
        Some(Outcome::Permit) => AgentAuthorizeOutcome::allow(format!(
            "route {route_name:?} is satisfied by an active delegation's authority, \
             intent, and resource scope",
        )),
        Some(Outcome::Deny(code)) => {
            AgentAuthorizeOutcome::deny(refusal(route_name, route.policy(), code))
        }
        Some(Outcome::Challenge(_)) => AgentAuthorizeOutcome::deny(format!(
            "route {route_name:?}: the tenant's policy asks for more than an agent can show",
        )),
        None => AgentAuthorizeOutcome::deny(format!(
            "route {route_name:?}: no active delegation grants the required authority"
        )),
    }
}

/// Which outcome speaks for the tokens when they differ: a pass wins, then
/// a miss on intent, then one on resource scope, then anything else.
fn distance(outcome: Outcome) -> u8 {
    match outcome {
        Outcome::Permit => 0,
        Outcome::Deny(DenyCode::OutsideIntent) => 1,
        Outcome::Deny(DenyCode::OutsideResourceScope) => 2,
        Outcome::Deny(_) | Outcome::Challenge(_) => 3,
    }
}

/// Why the closest token was refused on the route named `route_name`.
fn refusal(route_name: &str, policy: &RoutePolicy, code: DenyCode) -> String {
    match (code, policy) {
        (DenyCode::OutsideIntent, _) => format!(
            "route {route_name:?}: a delegation grants the required authority, but its \
             bound intent excludes this action",
        ),
        (DenyCode::OutsideResourceScope, _) => format!(
            "route {route_name:?}: a delegation grants the required authority, but its \
             resource scope excludes this path",
        ),
        (DenyCode::PermissionMissing, RoutePolicy::RequireCustomPermission(_)) => format!(
            "route {route_name:?} requires a custom permission no active delegation carries",
        ),
        (DenyCode::ScopeMissing, _) => format!(
            "route {route_name:?} requires an OAuth scope; agent delegations don't carry \
             those, so this can't be satisfied by an agent",
        ),
        (code, _) => format!(
            "route {route_name:?}: no active delegation carries the request ({})",
            code.as_str()
        ),
    }
}
