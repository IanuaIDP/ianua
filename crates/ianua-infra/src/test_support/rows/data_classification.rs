//! Rows of the data classification context.

use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSetRow, RedactionStrategy,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::types::{ClassificationRuleSetId, FieldPath};

use crate::test_support::rows::at;

/// A rule masking the field at `path`, classified at `level`.
///
/// # Panics
///
/// When `path` is not a valid field path, which is a mistake in the test.
#[must_use]
pub fn rule(path: &str, level: DataClassLevel) -> ClassificationRule {
    ClassificationRule::new(
        FieldPath::new(path).expect("a valid field path"),
        level,
        RedactionStrategy::Mask,
    )
}

/// A rule set holding `rules` in their order, made at the fixed moment.
#[must_use]
pub fn rule_set_row(rules: Vec<ClassificationRule>) -> ClassificationRuleSetRow {
    ClassificationRuleSetRow {
        id: ClassificationRuleSetId::new(),
        rules,
        created_at: at(0),
        updated_at: at(0),
    }
}
