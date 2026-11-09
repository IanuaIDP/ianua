//! Whether a rule's conditions hold for a request, reading an unknown fact the way the rule says.
//!
//! Every condition on a fact that may be unknown answers
//! `Verdict::Unknown` for it, never a plain failure. So a deny or a
//! step-up rule still matches, and an allow rule does not.

use std::net::IpAddr;

use crate::domains::authentication::risk_engine::step_up::{Familiarity, Sensitivity};
use crate::domains::authorization::permission::CustomPermission;
use crate::domains::authorization::policy::action::UnknownFact;
use crate::domains::authorization::policy::claims::{Claim, ClaimName, ClaimValue};
use crate::domains::authorization::policy::condition::{PolicyCondition, RiskThreshold};
use crate::domains::authorization::policy::simulator::RequestFacts;
use crate::domains::authorization::policy::time_window::{TimeWindow, ZonedTime};
use crate::types::{
    CanonicalPath, CidrRange, CountryCode, Fact, GroupId, HostName, HttpMethod, PathPrefix, RoleId,
};

/// The conditions that fail for `facts`, each described in words. Empty when
/// all hold.
///
/// A condition on an unknown fact counts as failing only when `unknown` says
/// so.
pub(super) fn check_conditions(
    conditions: &[PolicyCondition],
    facts: &RequestFacts<'_>,
    unknown: UnknownFact,
) -> Vec<String> {
    conditions
        .iter()
        .filter_map(|condition| match check_one(condition, facts) {
            Verdict::Holds => None,
            Verdict::Fails(reason) => Some(reason),
            Verdict::Unknown(reason) => (unknown == UnknownFact::DoesNotMatch).then_some(reason),
        })
        .collect()
}

/// What a single condition says about a request.
enum Verdict {
    /// The condition holds.
    Holds,
    /// The condition does not hold, and why.
    Fails(String),
    /// The fact the condition is about is not known, and which one.
    Unknown(String),
}

/// Checks a single condition.
fn check_one(condition: &PolicyCondition, facts: &RequestFacts<'_>) -> Verdict {
    match condition {
        PolicyCondition::PathPrefix(prefix) => check_path_prefix(facts.path, prefix),
        PolicyCondition::PathExact(expected) => check_path_exact(facts.path, expected),
        PolicyCondition::RoleIs(role) => check_role(facts.roles, role, Expected::Yes),
        PolicyCondition::RoleIsNot(role) => check_role(facts.roles, role, Expected::No),
        PolicyCondition::CountryIn(list) => check_country(facts.country, list, Listing::Listed),
        PolicyCondition::CountryNotIn(list) => {
            check_country(facts.country, list, Listing::Unlisted)
        }
        PolicyCondition::DeviceUnknown => check_is(facts.device, &Familiarity::New, "device trust"),
        PolicyCondition::DeviceKnown => check_is(facts.device, &Familiarity::Known, "device trust"),
        PolicyCondition::RiskAtLeast(threshold) => check_risk(facts.risk, *threshold),
        PolicyCondition::MethodIn(methods) => check_method(facts.method, methods),
        PolicyCondition::SensitiveOperation => check_sensitive(facts.sensitive_operation),
        PolicyCondition::GroupIs(group) => check_group(facts.groups, group, Expected::Yes),
        PolicyCondition::GroupIsNot(group) => check_group(facts.groups, group, Expected::No),
        PolicyCondition::PermissionHeld(held) => check_permission(facts.permissions, held),
        PolicyCondition::ClaimEquals { name, value } => check_claim(facts.claims, name, value),
        PolicyCondition::SourceIpIn(ranges) => {
            check_source(facts.source_ip, ranges, Listing::Listed)
        }
        PolicyCondition::SourceIpNotIn(ranges) => {
            check_source(facts.source_ip, ranges, Listing::Unlisted)
        }
        PolicyCondition::TimeWithin(window) => check_time(facts.local_times, window),
        PolicyCondition::HostIn(hosts) => check_host(facts.host, hosts),
    }
}

/// Whether the request path is `prefix` or under it, on a `/` boundary.
///
/// An unknown path cannot be judged. Ann denies `/admin`. Without this, a
/// request with no known path fails the deny's condition and the allow
/// default lets it in.
fn check_path_prefix(path: Fact<&CanonicalPath>, prefix: &PathPrefix) -> Verdict {
    let Fact::Known(path) = path else {
        return Verdict::Unknown("request path not known".to_owned());
    };
    if prefix.covers(path) {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("path '{path}' is not under '{prefix}'"))
}

/// Whether the request path is exactly `expected`. An unknown path cannot
/// be judged.
fn check_path_exact(path: Fact<&CanonicalPath>, expected: &CanonicalPath) -> Verdict {
    let Fact::Known(path) = path else {
        return Verdict::Unknown("request path not known".to_owned());
    };
    if path == expected {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("path '{path}' != '{expected}'"))
}

/// Whether the request method is one of `methods`. An unknown method cannot
/// be judged.
fn check_method(method: Fact<&str>, methods: &[HttpMethod]) -> Verdict {
    let Fact::Known(method) = method else {
        return Verdict::Unknown("request method not known".to_owned());
    };
    let asked = HttpMethod::parse(&method.to_ascii_uppercase());
    let listed = methods
        .iter()
        .any(|m| *m == HttpMethod::Any || Some(*m) == asked);
    if listed {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("method '{method}' not in allowed list"))
}

/// Whether holding `role` is what the condition expects.
fn check_role(roles: &[RoleId], role: &RoleId, expected: Expected) -> Verdict {
    let held = roles.contains(role);
    match (expected, held) {
        (Expected::Yes, false) => Verdict::Fails(format!("user does not have role '{role}'")),
        (Expected::No, true) => Verdict::Fails(format!("user has role '{role}' (excluded)")),
        (Expected::Yes, true) | (Expected::No, false) => Verdict::Holds,
    }
}

/// Whether being in `group`, or a group under it, is what the condition
/// expects. Unknown groups cannot be judged.
fn check_group(groups: Fact<&[GroupId]>, group: &GroupId, expected: Expected) -> Verdict {
    let Fact::Known(groups) = groups else {
        return Verdict::Unknown("groups not known".to_owned());
    };
    match (expected, groups.contains(group)) {
        (Expected::Yes, false) => Verdict::Fails(format!("user is not in group '{group}'")),
        (Expected::No, true) => Verdict::Fails(format!("user is in group '{group}' (excluded)")),
        (Expected::Yes, true) | (Expected::No, false) => Verdict::Holds,
    }
}

/// Whether the caller holds `wanted`, itself or through a wildcard.
fn check_permission(held: Fact<&[CustomPermission]>, wanted: &CustomPermission) -> Verdict {
    let Fact::Known(held) = held else {
        return Verdict::Unknown("permissions not known".to_owned());
    };
    let covered = held
        .iter()
        .any(|own| own.matches(wanted.resource().as_str(), wanted.action().as_str()));
    if covered {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("user does not hold '{wanted}'"))
}

/// Whether the caller carries `name` with exactly `value`. A known list
/// without the claim fails; an unknown list cannot be judged.
fn check_claim(claims: Fact<&[Claim]>, name: &ClaimName, value: &ClaimValue) -> Verdict {
    let Fact::Known(claims) = claims else {
        return Verdict::Unknown("attributes and claims not known".to_owned());
    };
    let carried = claims
        .iter()
        .any(|claim| claim.name() == name && claim.value() == value);
    if carried {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("'{name}' is not '{value}'"))
}

/// Whether the request's address is in or out of `ranges`, as `listing`
/// asks.
fn check_source(source: Fact<IpAddr>, ranges: &[CidrRange], listing: Listing) -> Verdict {
    let Fact::Known(address) = source else {
        return Verdict::Unknown("source address not known".to_owned());
    };
    let inside = ranges.iter().any(|range| range.contains_addr(address));
    if inside == (listing == Listing::Listed) {
        return Verdict::Holds;
    }
    let side = match listing {
        Listing::Listed => "in none of the ranges",
        Listing::Unlisted => "in an excluded range",
    };
    Verdict::Fails(format!("address {address} is {side}"))
}

/// Whether the request arrived inside `window`, read in its zone. A zone
/// the caller gave no time for cannot be judged.
fn check_time(local_times: &[ZonedTime], window: &TimeWindow) -> Verdict {
    let Some(local) = local_times.iter().find(|time| time.zone() == window.zone()) else {
        return Verdict::Unknown(format!("time in {} not known", window.zone()));
    };
    if window.holds(local.time()) {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("{} is outside {window}", local.time()))
}

/// Whether the request is for one of `hosts`, without regard to case.
fn check_host(host: Fact<&HostName>, hosts: &[HostName]) -> Verdict {
    let Fact::Known(host) = host else {
        return Verdict::Unknown("request host not known".to_owned());
    };
    let listed = hosts
        .iter()
        .any(|listed| listed.as_str().eq_ignore_ascii_case(host.as_str()));
    if listed {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("host '{host}' not in the list"))
}

/// Whether the request's risk reaches `threshold`.
fn check_risk(risk: Fact<RiskThreshold>, threshold: RiskThreshold) -> Verdict {
    let Fact::Known(risk) = risk else {
        return Verdict::Unknown("risk not known".to_owned());
    };
    if risk >= threshold {
        return Verdict::Holds;
    }
    Verdict::Fails(format!("risk {risk:?} below threshold {threshold:?}"))
}

/// Whether a list condition wants the fact in the list or out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listing {
    /// The fact must be listed.
    Listed,
    /// The fact must not be listed.
    Unlisted,
}

/// The value a yes-or-no condition holds for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// It holds when the fact is true.
    Yes,
    /// It holds when the fact is false.
    No,
}

/// Whether the request's country is in or out of `countries`, as `listing`
/// asks.
fn check_country(
    country: Fact<&CountryCode>,
    countries: &[CountryCode],
    listing: Listing,
) -> Verdict {
    let Fact::Known(country) = country else {
        return Verdict::Unknown("country not known".to_owned());
    };
    if countries.contains(country) == (listing == Listing::Listed) {
        return Verdict::Holds;
    }
    let side = match listing {
        Listing::Listed => "not in the allowed list",
        Listing::Unlisted => "in the blocked list",
    };
    Verdict::Fails(format!("country '{}' is {side}", country.as_str()))
}

/// A condition on one fact. It holds when the fact is `wanted`, and cannot
/// be judged when the fact is unknown.
fn check_is<T: PartialEq + std::fmt::Debug>(fact: Fact<T>, wanted: &T, name: &str) -> Verdict {
    match fact {
        Fact::Unknown => Verdict::Unknown(format!("{name} not known")),
        Fact::Known(value) if &value == wanted => Verdict::Holds,
        Fact::Known(value) => Verdict::Fails(format!("{name} is {value:?}, expected {wanted:?}")),
    }
}

/// Whether the request is a sensitive operation.
fn check_sensitive(fact: Fact<Sensitivity>) -> Verdict {
    check_is(fact, &Sensitivity::Sensitive, "sensitive operation")
}
