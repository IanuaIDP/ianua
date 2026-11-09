//! Matching a route on a request's headers and cookies.
//!
//! Two routes on one path can send a request to two backends by what it
//! carries: a blue/green switch on a header, or a canary pinned by a cookie
//! the app sets for its testers. Every condition on a route must hold for
//! the route to match.
//!
//! A value is matched exactly or by its start, never by a pattern. A pattern
//! a tenant writes runs on every request, and one written badly can take
//! seconds on a long header.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CookieName, Fact, HeaderName, HeaderValue};

/// Where a condition reads its value from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MatchSubject {
    /// A request header, by name, whatever its case.
    Header(HeaderName),
    /// A cookie the request carries, by name.
    Cookie(CookieName),
}

/// What a condition asks of the value it reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ValueMatch {
    /// It is sent, with any value.
    Present,
    /// It is not sent.
    Absent,
    /// It is sent with exactly this value.
    Exact(HeaderValue),
    /// It is sent with a value starting with this.
    Prefix(HeaderValue),
}

impl ValueMatch {
    /// Whether `value`, as the request carries it, meets this.
    fn holds(&self, value: Fact<&str>) -> bool {
        match (self, value) {
            (Self::Present, Fact::Known(_)) | (Self::Absent, Fact::Unknown) => true,
            (Self::Exact(wanted), Fact::Known(sent)) => sent == wanted.as_str(),
            (Self::Prefix(wanted), Fact::Known(sent)) => sent.starts_with(wanted.as_str()),
            (Self::Present | Self::Exact(_) | Self::Prefix(_), Fact::Unknown)
            | (Self::Absent, Fact::Known(_)) => false,
        }
    }
}

/// One condition a request must meet for a route to match it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequestCondition {
    subject: MatchSubject,
    value: ValueMatch,
}

impl RequestCondition {
    /// The condition that `subject` meets `value`.
    #[must_use]
    pub fn new(subject: MatchSubject, value: ValueMatch) -> Self {
        Self { subject, value }
    }

    /// Where the value is read from.
    #[must_use]
    pub fn subject(&self) -> &MatchSubject {
        &self.subject
    }

    /// What is asked of it.
    #[must_use]
    pub fn value(&self) -> &ValueMatch {
        &self.value
    }
}

/// The values of a live request a route's conditions read. `Sync`, so a
/// request holding them can be matched inside a future sent across threads.
pub trait RequestValues: Sync {
    /// The value of header `name`, when the request sends it. A header sent
    /// more than once reads as its first value.
    fn header(&self, name: &HeaderName) -> Fact<&str>;

    /// The value of cookie `name`, when the request carries it.
    fn cookie(&self, name: &CookieName) -> Fact<&str>;
}

/// The header and cookie conditions on a route, all of which must hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<RequestCondition>", into = "Vec<RequestCondition>")
)]
pub struct RouteConditions(Vec<RequestCondition>);

impl RouteConditions {
    /// The most conditions one route holds.
    pub const MAX: usize = 16;

    /// A checked set of conditions. An empty set matches every request.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when there are more than 16.
    /// - [`DomainError::Validation`] when one subject is read twice. Two
    ///   conditions on one header either repeat each other or can never both
    ///   hold, and a route that can never match hides behind its neighbours.
    pub fn new(conditions: Vec<RequestCondition>) -> Result<Self, DomainError> {
        validate_count("conditions", conditions.len(), 0..=Self::MAX)?;
        if first_repeat(conditions.iter().map(RequestCondition::subject)).is_some() {
            return Err(DomainError::invalid(message!(
                "routing-a-header-or-cookie-is-matched",
                "a header or cookie is matched by one condition"
            )));
        }
        Ok(Self(conditions))
    }

    /// The conditions.
    #[must_use]
    pub fn as_slice(&self) -> &[RequestCondition] {
        &self.0
    }

    /// Whether there are none, so every request matches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `request` meets every condition.
    #[must_use]
    pub fn hold_for(&self, request: &(impl RequestValues + ?Sized)) -> bool {
        self.0.iter().all(|condition| {
            let value = match &condition.subject {
                MatchSubject::Header(name) => request.header(name),
                MatchSubject::Cookie(name) => request.cookie(name),
            };
            condition.value.holds(value)
        })
    }
}

#[cfg(feature = "serde")]
impl TryFrom<Vec<RequestCondition>> for RouteConditions {
    type Error = DomainError;

    fn try_from(conditions: Vec<RequestCondition>) -> Result<Self, Self::Error> {
        Self::new(conditions)
    }
}

#[cfg(feature = "serde")]
impl From<RouteConditions> for Vec<RequestCondition> {
    fn from(conditions: RouteConditions) -> Self {
        conditions.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sent {
        headers: Vec<(&'static str, &'static str)>,
        cookies: Vec<(&'static str, &'static str)>,
    }

    impl RequestValues for Sent {
        fn header(&self, name: &HeaderName) -> Fact<&str> {
            self.headers
                .iter()
                .find(|(sent, _)| sent.eq_ignore_ascii_case(name.as_str()))
                .map_or(Fact::Unknown, |(_, value)| Fact::Known(*value))
        }

        fn cookie(&self, name: &CookieName) -> Fact<&str> {
            self.cookies
                .iter()
                .find(|(sent, _)| *sent == name.as_str())
                .map_or(Fact::Unknown, |(_, value)| Fact::Known(*value))
        }
    }

    fn header(name: &str) -> MatchSubject {
        MatchSubject::Header(HeaderName::new(name).unwrap())
    }

    fn cookie(name: &str) -> MatchSubject {
        MatchSubject::Cookie(CookieName::new(name).unwrap())
    }

    fn value(text: &str) -> HeaderValue {
        HeaderValue::new(text).unwrap()
    }

    fn conditions(list: Vec<RequestCondition>) -> RouteConditions {
        RouteConditions::new(list).unwrap()
    }

    /// The green route asks for `x-deployment: green`. Ann's request with
    /// `X-Deployment: green` matches; Bob's with `blue`, and one without the
    /// header, do not.
    #[test]
    fn an_exact_header_value_picks_the_route() {
        let green = conditions(vec![RequestCondition::new(
            header("x-deployment"),
            ValueMatch::Exact(value("green")),
        )]);
        let sent = |deployment| Sent {
            headers: vec![("X-Deployment", deployment)],
            cookies: Vec::new(),
        };

        assert!(green.hold_for(&sent("green")));
        assert!(!green.hold_for(&sent("blue")));
        assert!(!green.hold_for(&Sent {
            headers: Vec::new(),
            cookies: Vec::new(),
        }));
    }

    /// The canary route asks for a `canary` cookie starting with `beta-`.
    /// Ann's `beta-7` matches, Bob's `stable` does not.
    #[test]
    fn a_cookie_prefix_pins_a_canary() {
        let canary = conditions(vec![RequestCondition::new(
            cookie("canary"),
            ValueMatch::Prefix(value("beta-")),
        )]);
        let sent = |pin| Sent {
            headers: Vec::new(),
            cookies: vec![("canary", pin)],
        };

        assert!(canary.hold_for(&sent("beta-7")));
        assert!(!canary.hold_for(&sent("stable")));
    }

    /// A route for requests without a `x-internal` header matches one
    /// without it and not one with it.
    #[test]
    fn an_absent_condition_matches_only_without_the_header() {
        let outside = conditions(vec![RequestCondition::new(
            header("x-internal"),
            ValueMatch::Absent,
        )]);

        assert!(outside.hold_for(&Sent {
            headers: Vec::new(),
            cookies: Vec::new(),
        }));
        assert!(!outside.hold_for(&Sent {
            headers: vec![("x-internal", "1")],
            cookies: Vec::new(),
        }));
    }

    /// Every condition must hold: a request with the header but without the
    /// cookie does not match.
    #[test]
    fn every_condition_must_hold() {
        let both = conditions(vec![
            RequestCondition::new(header("x-deployment"), ValueMatch::Present),
            RequestCondition::new(cookie("canary"), ValueMatch::Present),
        ]);

        assert!(!both.hold_for(&Sent {
            headers: vec![("x-deployment", "green")],
            cookies: Vec::new(),
        }));
    }

    /// Two conditions on `x-deployment`, or seventeen conditions, are
    /// refused.
    #[test]
    fn a_subject_is_matched_once_and_conditions_are_bounded() {
        let twice = RouteConditions::new(vec![
            RequestCondition::new(header("x-deployment"), ValueMatch::Present),
            RequestCondition::new(header("x-deployment"), ValueMatch::Absent),
        ]);
        let many = RouteConditions::new(
            (0..17)
                .map(|n| RequestCondition::new(header(&format!("x-{n}")), ValueMatch::Present))
                .collect(),
        );

        assert!(twice.is_err());
        assert!(many.is_err());
    }
}
