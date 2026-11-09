//! What a GraphQL request costs, and whether it may be cached.
//!
//! Every other route the proxy handles says what it wants in its method and
//! path. GraphQL says it in the body. One `POST /graphql` may read a single
//! field or walk a graph until the backend is overloaded. To a gateway
//! counting requests, those look the same.
//!
//! So the two controls that work everywhere else do not work here. A rate
//! limit counts a trivial query the same as a huge one. A response cache
//! keyed on the URL would give every query the first one's answer.
//!
//! This module holds the rules. Parsing belongs to an adapter.

use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;

/// The most a deployment may allow a query to nest.
///
/// Well past anything a person writes by hand, and far short of the depths a
/// cyclic schema reaches when someone is looking for one.
pub const MAX_ALLOWED_DEPTH: u32 = 64;

/// The most a deployment may allow a query to cost.
pub const MAX_ALLOWED_COMPLEXITY: u32 = 1_000_000;

/// What a GraphQL document asks the backend to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum OperationKind {
    /// Reads. The only kind that may be cached.
    Query,
    /// Writes.
    Mutation,
    /// A stream the client holds open.
    Subscription,
}

impl OperationKind {
    /// Whether an answer to this may be served again.
    ///
    /// Only a query. Caching a mutation would replay somebody's write as
    /// though it had happened, and a subscription has no single answer to
    /// keep.
    #[must_use]
    pub fn is_cacheable(&self) -> bool {
        matches!(self, Self::Query)
    }
}

/// One GraphQL request, reduced to what a gateway can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlOperation {
    /// What it asks the backend to do.
    pub kind: OperationKind,
    /// The operation's name, when the document gives one.
    pub name: Option<String>,
    /// How far the deepest selection nests.
    pub depth: u32,
    /// What it costs, by [`GraphQlLimits`]' reckoning.
    pub complexity: u32,
    /// A stable identifier for this query and these variables.
    ///
    /// A response cache relies on it. Two requests with the same fingerprint
    /// ask the same question, and no other pair does.
    pub fingerprint: String,
}

/// What a tenant allows through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "GraphQlLimitsWire"))]
pub struct GraphQlLimits {
    /// How far a query may nest.
    ///
    /// The cheapest defence there is. A schema with a cycle in it, such as a
    /// user with posts with an author with posts, lets a short query ask for
    /// exponentially many rows. Depth bounds that.
    max_depth: u32,
    /// What a query may cost.
    ///
    /// Depth alone does not catch a flat query asking for ten thousand
    /// fields, which costs the backend just as much.
    max_complexity: u32,
    /// How many rate-limit units a complexity point is worth.
    ///
    /// Zero counts every GraphQL request as one, whatever it asks for. A
    /// deployment starts there before it knows its own numbers.
    cost_per_complexity: u32,
}

/// Limits as they arrive, before [`GraphQlLimits::new`] has checked them.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct GraphQlLimitsWire {
    max_depth: u32,
    max_complexity: u32,
    cost_per_complexity: u32,
}

#[cfg(feature = "serde")]
impl TryFrom<GraphQlLimitsWire> for GraphQlLimits {
    type Error = ValidationError;

    /// Limits read from a stored pipeline or an API body are held to the same
    /// ranges as ones built in code.
    fn try_from(wire: GraphQlLimitsWire) -> Result<Self, Self::Error> {
        Self::new(
            wire.max_depth,
            wire.max_complexity,
            wire.cost_per_complexity,
        )
    }
}

impl GraphQlLimits {
    /// How far a query may nest.
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// What a query may cost.
    #[must_use]
    pub fn max_complexity(&self) -> u32 {
        self.max_complexity
    }

    /// How many rate-limit units a complexity point is worth.
    #[must_use]
    pub fn cost_per_complexity(&self) -> u32 {
        self.cost_per_complexity
    }

    /// Creates limits.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the depth or complexity limit is zero. A depth
    ///   of zero admits nothing.
    /// - [`ValidationError`] if any limit is beyond what the platform allows:
    ///   [`MAX_ALLOWED_DEPTH`], [`MAX_ALLOWED_COMPLEXITY`], or 1,000 units per
    ///   complexity point. A depth of a million admits everything.
    pub fn new(
        max_depth: u32,
        max_complexity: u32,
        cost_per_complexity: u32,
    ) -> Result<Self, ValidationError> {
        validate_range("max_depth", max_depth, 1..=MAX_ALLOWED_DEPTH)?;
        validate_range("max_complexity", max_complexity, 1..=MAX_ALLOWED_COMPLEXITY)?;
        validate_range("cost_per_complexity", cost_per_complexity, 0..=1_000)?;

        Ok(Self {
            max_depth,
            max_complexity,
            cost_per_complexity,
        })
    }

    /// What this operation should count as against a rate limit.
    ///
    /// Always at least one. A query that costs nothing is still a request,
    /// and a limit that cheap queries never use up is not a limit.
    #[must_use]
    pub fn cost_of(&self, operation: &GraphQlOperation) -> u32 {
        operation
            .complexity
            .saturating_mul(self.cost_per_complexity)
            .max(1)
    }

    /// Whether this operation may be forwarded.
    #[must_use]
    pub fn verdict_on(&self, operation: &GraphQlOperation) -> GraphQlVerdict {
        if operation.depth > self.max_depth {
            return GraphQlVerdict::TooDeep {
                depth: operation.depth,
                allowed: self.max_depth,
            };
        }
        if operation.complexity > self.max_complexity {
            return GraphQlVerdict::TooComplex {
                complexity: operation.complexity,
                allowed: self.max_complexity,
            };
        }
        GraphQlVerdict::Allowed
    }
}

impl Default for GraphQlLimits {
    /// Limits a deployment can start from.
    ///
    /// Chosen to pass anything a person writes and refuse the shapes that only
    /// appear when somebody is probing. That means more than fifteen levels
    /// of nesting, or a query costing more than a thousand.
    fn default() -> Self {
        Self {
            max_depth: 15,
            max_complexity: 1_000,
            cost_per_complexity: 0,
        }
    }
}

/// Whether a GraphQL request may go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphQlVerdict {
    /// Within the tenant's limits.
    Allowed,
    /// Nests further than the tenant allows.
    TooDeep {
        /// How far it nests.
        depth: u32,
        /// How far it may.
        allowed: u32,
    },
    /// Costs more than the tenant allows.
    TooComplex {
        /// What it costs.
        complexity: u32,
        /// What it may.
        allowed: u32,
    },
}

impl GraphQlVerdict {
    /// Whether the request may be forwarded.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Why it was refused, in words for the client.
    ///
    /// Names the limit and what was asked, because a developer who has hit a
    /// depth limit needs to know which one and by how much. It says nothing
    /// about the schema, which is the part worth not telling a stranger.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Allowed => None,
            Self::TooDeep { depth, allowed } => Some(format!(
                "query nests {depth} levels, the limit is {allowed}"
            )),
            Self::TooComplex {
                complexity,
                allowed,
            } => Some(format!("query costs {complexity}, the limit is {allowed}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(kind: OperationKind, depth: u32, complexity: u32) -> GraphQlOperation {
        GraphQlOperation {
            kind,
            name: Some("GetUser".to_owned()),
            depth,
            complexity,
            fingerprint: "abc123".to_owned(),
        }
    }

    fn query(depth: u32, complexity: u32) -> GraphQlOperation {
        operation(OperationKind::Query, depth, complexity)
    }

    /// A query five levels deep that costs 20 is well inside the default
    /// limits of 15 and 1,000, so it goes on.
    #[test]
    fn a_query_within_the_limits_is_allowed() {
        let limits = GraphQlLimits::default();

        assert!(limits.verdict_on(&query(5, 20)).is_allowed());
    }

    /// A query with a reported depth of 50 is refused under the default
    /// depth limit of 15, and the reason names both numbers.
    #[test]
    fn a_query_nesting_past_the_limit_is_refused() {
        let limits = GraphQlLimits::default();

        let verdict = limits.verdict_on(&query(50, 20));

        assert!(!verdict.is_allowed());
        assert_eq!(
            verdict.reason(),
            Some("query nests 50 levels, the limit is 15".to_owned())
        );
    }

    /// A query two levels deep with a reported cost of 50,000 is refused
    /// under the default limits, with its cost included in the reason.
    #[test]
    fn a_shallow_but_enormous_query_is_refused() {
        let limits = GraphQlLimits::default();

        let verdict = limits.verdict_on(&query(2, 50_000));

        assert!(!verdict.is_allowed());
        assert!(
            verdict.reason().is_some_and(|r| r.contains("costs 50000")),
            "the reason names what was asked"
        );
    }

    /// A query that is both too deep and too costly is refused as too deep.
    /// Depth points the developer at one place in the query, so it is the
    /// more useful answer.
    #[test]
    fn a_query_breaking_both_limits_is_told_about_its_depth() {
        let limits = GraphQlLimits::default();

        assert!(matches!(
            limits.verdict_on(&query(50, 50_000)),
            GraphQlVerdict::TooDeep { .. }
        ));
    }

    /// Queries are marked cacheable; mutations and subscriptions are not.
    #[test]
    fn only_a_query_may_be_cached() {
        assert!(OperationKind::Query.is_cacheable());
        assert!(!OperationKind::Mutation.is_cacheable());
        assert!(!OperationKind::Subscription.is_cacheable());
    }

    /// A query with zero complexity still costs one rate-limit unit.
    #[test]
    fn every_operation_costs_at_least_one() {
        let limits = GraphQlLimits::new(15, 1_000, 2).expect("valid limits");

        assert_eq!(limits.cost_of(&query(1, 0)), 1);
    }

    /// A tenant sets three units per complexity point. A query of complexity
    /// 10 counts as 30 against the rate limit.
    #[test]
    fn cost_follows_complexity_when_a_tenant_asks_it_to() {
        let limits = GraphQlLimits::new(15, 1_000, 3).expect("valid limits");

        assert_eq!(limits.cost_of(&query(3, 10)), 30);
    }

    /// With zero units per point, a query of complexity 500 counts as one.
    /// A deployment starts there before it knows its own numbers.
    #[test]
    fn a_zero_multiplier_counts_every_request_as_one() {
        let limits = GraphQlLimits::new(15, 1_000, 0).expect("valid limits");

        assert_eq!(limits.cost_of(&query(3, 500)), 1);
    }

    /// Multiplying `u32::MAX` complexity by 1,000 units per point saturates
    /// the calculated cost at `u32::MAX`.
    #[test]
    fn an_enormous_cost_saturates_rather_than_wrapping() {
        let limits = GraphQlLimits::new(15, 1_000, 1_000).expect("valid limits");

        assert_eq!(limits.cost_of(&query(3, u32::MAX)), u32::MAX);
    }

    /// A tenant sets a depth or cost limit of zero, or one past the platform
    /// maximum. Each is refused. Zero would admit nothing, and past the
    /// maximum would admit anything.
    #[test]
    fn limits_outside_what_the_platform_allows_are_refused() {
        assert!(GraphQlLimits::new(0, 1_000, 0).is_err());
        assert!(GraphQlLimits::new(MAX_ALLOWED_DEPTH + 1, 1_000, 0).is_err());
        assert!(GraphQlLimits::new(15, 0, 0).is_err());
        assert!(GraphQlLimits::new(15, MAX_ALLOWED_COMPLEXITY + 1, 0).is_err());
    }

    /// A depth refusal omits the operation name `GetUser` and the word
    /// `field` from its reason.
    #[test]
    fn a_refusal_says_nothing_about_the_schema() {
        let limits = GraphQlLimits::default();

        let reason = limits
            .verdict_on(&query(50, 20))
            .reason()
            .expect("a reason");

        assert!(!reason.contains("GetUser"));
        assert!(!reason.to_lowercase().contains("field"));
    }

    /// With limits of depth 10 and cost 100, a query at exactly 10 and 100
    /// goes on. One step past either is refused, so the limit written is the
    /// limit applied.
    #[test]
    fn an_operation_exactly_at_a_limit_is_allowed() {
        let limits = GraphQlLimits::new(10, 100, 1).unwrap();

        assert!(limits.verdict_on(&query(10, 100)).is_allowed());
        assert!(matches!(
            limits.verdict_on(&query(11, 100)),
            GraphQlVerdict::TooDeep { .. }
        ));
        assert!(matches!(
            limits.verdict_on(&query(10, 101)),
            GraphQlVerdict::TooComplex { .. }
        ));
    }
}
