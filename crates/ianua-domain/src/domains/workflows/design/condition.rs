//! The tests a condition step makes on the data it receives, to choose which
//! way the workflow goes on.
//!
//! A condition only compares values found by path. Nothing in it runs code.
//! It decides a branch from data an earlier step produced, and a model may
//! have shaped that data from what it read. So a condition must not be able
//! to do more than compare.

use crate::domains::workflows::data::{DataPath, FlowData, FlowValue};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;

/// The most clauses one condition may hold.
pub(crate) const MAX_CLAUSES: usize = 32;

/// What a clause asks of the value at its path.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Test {
    /// There is a value there, even null.
    Exists,
    /// There is no value there, or it is null, empty text, an empty list or
    /// an empty map.
    IsEmpty,
    /// The value is this one.
    Equals(FlowData),
    /// The value is not this one, or there is none.
    NotEquals(FlowData),
    /// The value is text containing this, or a list holding this text.
    Contains(String),
    /// The value is a number greater than this.
    GreaterThan(f64),
    /// The value is a number less than this.
    LessThan(f64),
}

impl Test {
    /// Whether `found` passes this test. `None` means nothing is there.
    fn passes(&self, found: Option<&FlowData>) -> bool {
        match self {
            Self::Exists => found.is_some(),
            Self::IsEmpty => found.is_none_or(FlowData::is_empty),
            Self::Equals(expected) => found == Some(expected),
            Self::NotEquals(expected) => found != Some(expected),
            Self::Contains(needle) => found.is_some_and(|value| contains(value, needle)),
            Self::GreaterThan(bound) => number_of(found).is_some_and(|value| value > *bound),
            Self::LessThan(bound) => number_of(found).is_some_and(|value| value < *bound),
        }
    }
}

fn contains(value: &FlowData, needle: &str) -> bool {
    match value.value() {
        FlowValue::Text(text) => text.contains(needle),
        FlowValue::List(items) => items
            .iter()
            .any(|item| item.value() == FlowValue::Text(needle)),
        FlowValue::Null | FlowValue::Bool(_) | FlowValue::Number(_) | FlowValue::Map(_) => false,
    }
}

fn number_of(found: Option<&FlowData>) -> Option<f64> {
    let FlowValue::Number(value) = found?.value() else {
        return None;
    };
    Some(value)
}

/// One test, on the value at one path.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "crate::domains::workflows::stored::ClauseWire")
)]
pub struct Clause {
    path: DataPath,
    test: Test,
}

impl Clause {
    /// Tests the value at `path`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a numeric bound is not finite.
    pub fn new(path: DataPath, test: Test) -> Result<Self, DomainError> {
        if let Test::GreaterThan(bound) | Test::LessThan(bound) = test
            && !bound.is_finite()
        {
            return Err(DomainError::invalid(message!(
                "workflows-a-condition-s-bound-must-be",
                "a condition's bound must be finite"
            )));
        }
        Ok(Self { path, test })
    }

    /// Where the value is looked for.
    #[must_use]
    pub fn path(&self) -> &DataPath {
        &self.path
    }

    /// What is asked of it.
    #[must_use]
    pub fn test(&self) -> &Test {
        &self.test
    }

    fn holds_for(&self, input: &FlowData) -> bool {
        self.test.passes(input.at(&self.path))
    }
}

/// Whether every clause must hold, or any one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Matching {
    /// Every clause holds.
    All,
    /// At least one clause holds.
    Any,
}

/// The rule a condition step decides its branch by.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "crate::domains::workflows::stored::ConditionRuleWire")
)]
pub struct ConditionRule {
    matching: Matching,
    clauses: Vec<Clause>,
}

impl ConditionRule {
    /// A rule of `clauses`, combined as `matching` says.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when there is no clause.
    /// - [`DomainError::Validation`] when there are more than
    ///   `MAX_CLAUSES`.
    pub fn new(matching: Matching, clauses: Vec<Clause>) -> Result<Self, DomainError> {
        validate_count("condition_clauses", clauses.len(), 1..=MAX_CLAUSES)?;
        Ok(Self { matching, clauses })
    }

    /// How the clauses combine.
    #[must_use]
    pub fn matching(&self) -> Matching {
        self.matching
    }

    /// The comparisons combined by the rule's matching strategy.
    #[must_use]
    pub fn clauses(&self) -> &[Clause] {
        &self.clauses
    }

    /// Whether the rule holds for `input`.
    #[must_use]
    pub fn holds_for(&self, input: &FlowData) -> bool {
        match self.matching {
            Matching::All => self.clauses.iter().all(|clause| clause.holds_for(input)),
            Matching::Any => self.clauses.iter().any(|clause| clause.holds_for(input)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::FieldName;

    fn order(total: f64, status: &str) -> FlowData {
        FlowData::map(vec![
            (
                FieldName::new("total").unwrap(),
                FlowData::number(total).unwrap(),
            ),
            (
                FieldName::new("status").unwrap(),
                FlowData::text(status).unwrap(),
            ),
        ])
        .unwrap()
    }

    fn clause(path: &str, test: Test) -> Clause {
        Clause::new(DataPath::parse(path).unwrap(), test).unwrap()
    }

    /// A rule asks for a total over 100 and a status of `paid`. A paid
    /// order of 150 passes. An open order of 150 and a paid one of 50 fail.
    #[test]
    fn every_clause_must_hold_when_all_are_asked_for() {
        let rule = ConditionRule::new(
            Matching::All,
            vec![
                clause("total", Test::GreaterThan(100.0)),
                clause("status", Test::Equals(FlowData::text("paid").unwrap())),
            ],
        )
        .unwrap();

        assert!(rule.holds_for(&order(150.0, "paid")));
        assert!(!rule.holds_for(&order(150.0, "open")));
        assert!(!rule.holds_for(&order(50.0, "paid")));
    }

    /// A rule asks for a total under 10 or a status containing `refund`.
    /// An order of 5 passes, and so does one marked `partial refund`. A
    /// paid order of 500 fails.
    #[test]
    fn one_clause_is_enough_when_any_is_asked_for() {
        let rule = ConditionRule::new(
            Matching::Any,
            vec![
                clause("total", Test::LessThan(10.0)),
                clause("status", Test::Contains("refund".to_owned())),
            ],
        )
        .unwrap();

        assert!(rule.holds_for(&order(5.0, "paid")));
        assert!(rule.holds_for(&order(500.0, "partial refund")));
        assert!(!rule.holds_for(&order(500.0, "paid")));
    }

    /// "Status above 0" fails, since the status is text. "Amount below 1"
    /// fails, since the order has no amount. A branch is never taken on a
    /// guess.
    #[test]
    fn a_missing_or_non_numeric_value_fails_a_comparison() {
        let rule = ConditionRule::new(
            Matching::All,
            vec![clause("status", Test::GreaterThan(0.0))],
        )
        .unwrap();
        let missing =
            ConditionRule::new(Matching::All, vec![clause("amount", Test::LessThan(1.0))]).unwrap();

        assert!(!rule.holds_for(&order(1.0, "paid")));
        assert!(!missing.holds_for(&order(1.0, "paid")));
    }

    /// An order has no `note`. "Note is empty" passes and "note exists"
    /// fails.
    #[test]
    fn a_missing_value_is_empty_and_does_not_exist() {
        let empty = ConditionRule::new(Matching::All, vec![clause("note", Test::IsEmpty)]).unwrap();
        let exists = ConditionRule::new(Matching::All, vec![clause("note", Test::Exists)]).unwrap();

        assert!(empty.holds_for(&order(1.0, "paid")));
        assert!(!exists.holds_for(&order(1.0, "paid")));
    }

    /// A rule with no clause is refused. So is "total above NaN", which no
    /// value could ever pass or fail sensibly.
    #[test]
    fn a_rule_with_no_clause_or_an_unbounded_comparison_is_refused() {
        assert!(ConditionRule::new(Matching::All, Vec::new()).is_err());
        assert!(
            Clause::new(
                DataPath::parse("total").unwrap(),
                Test::GreaterThan(f64::NAN)
            )
            .is_err()
        );
    }
}
