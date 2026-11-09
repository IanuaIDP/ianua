//! The comparisons a filter may make against an attribute.

use crate::domains::identity::attribute::value_type::ValueType;

/// How many values an operator compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandArity {
    /// The operator asks whether a value is set, and takes no value itself.
    None,
    /// The operator compares against a single value.
    One,
    /// The operator compares against a list of values.
    Many,
}

/// A comparison a filter makes against a custom attribute.
///
/// The set is closed. A query adapter matches the operator and turns each
/// variant into a fixed clause. So the shape of a filter comes from the
/// variant, never from text a caller sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AttributeOperator {
    /// Equal to the given value.
    Is,
    /// Not equal to the given value.
    IsNot,
    /// Contains the given text, ignoring case.
    Contains,
    /// Equal to any of the given values.
    IsOneOf,
    /// Greater than the given value.
    GreaterThan,
    /// Greater than or equal to the given value.
    GreaterThanOrEqual,
    /// Less than the given value.
    LessThan,
    /// Less than or equal to the given value.
    LessThanOrEqual,
    /// The list holds at least one of the given values.
    HasAny,
    /// The list holds all of the given values.
    HasAll,
    /// A value has been set, whatever it is.
    IsPresent,
    /// No value has been set.
    IsAbsent,
}

impl AttributeOperator {
    /// Every operator, so a client can offer the ones that apply without its
    /// own copy of the list.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Is,
            Self::IsNot,
            Self::Contains,
            Self::IsOneOf,
            Self::GreaterThan,
            Self::GreaterThanOrEqual,
            Self::LessThan,
            Self::LessThanOrEqual,
            Self::HasAny,
            Self::HasAll,
            Self::IsPresent,
            Self::IsAbsent,
        ]
    }

    /// The name a caller writes this comparison as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Is => "is",
            Self::IsNot => "is_not",
            Self::Contains => "contains",
            Self::IsOneOf => "is_one_of",
            Self::GreaterThan => "greater_than",
            Self::GreaterThanOrEqual => "greater_than_or_equal",
            Self::LessThan => "less_than",
            Self::LessThanOrEqual => "less_than_or_equal",
            Self::HasAny => "has_any",
            Self::HasAll => "has_all",
            Self::IsPresent => "is_present",
            Self::IsAbsent => "is_absent",
        }
    }

    /// Reads a comparison a caller named.
    ///
    /// It gives `None` for anything outside the set, which is a bad request.
    /// A near miss is not guessed at, since that would run a comparison
    /// nobody asked for.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|op| op.as_str() == value)
    }

    /// How many values this operator compares against.
    #[must_use]
    pub fn arity(self) -> OperandArity {
        match self {
            Self::IsPresent | Self::IsAbsent => OperandArity::None,
            Self::IsOneOf | Self::HasAny | Self::HasAll => OperandArity::Many,
            Self::Is
            | Self::IsNot
            | Self::Contains
            | Self::GreaterThan
            | Self::GreaterThanOrEqual
            | Self::LessThan
            | Self::LessThanOrEqual => OperandArity::One,
        }
    }

    /// Whether this operator asks if a value is set, not what it is.
    #[must_use]
    pub fn tests_existence(self) -> bool {
        matches!(self, Self::IsPresent | Self::IsAbsent)
    }

    /// Whether `value_type` can be compared this way.
    ///
    /// Greater-than and less-than apply to text as well as numbers, because
    /// dates are stored as text. "Hired before 2020" is a text comparison. It
    /// gives the right answer because only one date spelling is stored.
    #[must_use]
    pub fn applies_to(self, value_type: ValueType) -> bool {
        if self.tests_existence() {
            return true;
        }

        match value_type {
            ValueType::Text => matches!(
                self,
                Self::Is
                    | Self::IsNot
                    | Self::Contains
                    | Self::IsOneOf
                    | Self::GreaterThan
                    | Self::GreaterThanOrEqual
                    | Self::LessThan
                    | Self::LessThanOrEqual
            ),
            ValueType::Integer | ValueType::Number => matches!(
                self,
                Self::Is
                    | Self::IsNot
                    | Self::IsOneOf
                    | Self::GreaterThan
                    | Self::GreaterThanOrEqual
                    | Self::LessThan
                    | Self::LessThanOrEqual
            ),
            ValueType::Boolean => matches!(self, Self::Is | Self::IsNot),
            ValueType::TextArray => matches!(self, Self::HasAny | Self::HasAll),
        }
    }

    /// Every operator `value_type` can be compared with.
    #[must_use]
    pub fn applicable_to(value_type: ValueType) -> Vec<Self> {
        Self::all()
            .iter()
            .copied()
            .filter(|op| op.applies_to(value_type))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPES: [ValueType; 5] = [
        ValueType::Text,
        ValueType::Integer,
        ValueType::Number,
        ValueType::Boolean,
        ValueType::TextArray,
    ];

    /// "Is present" and "is absent" apply to every value type. Whether
    /// anything was stored makes sense to ask of any attribute.
    #[test]
    fn presence_applies_to_every_type() {
        for value_type in TYPES {
            assert!(AttributeOperator::IsPresent.applies_to(value_type));
            assert!(AttributeOperator::IsAbsent.applies_to(value_type));
        }
    }

    /// Greater-than and less-than are refused on lists and on yes/no values,
    /// which have no order. They apply to whole and decimal numbers.
    #[test]
    fn ordering_comparisons_are_refused_where_there_is_no_order() {
        for op in [
            AttributeOperator::GreaterThan,
            AttributeOperator::GreaterThanOrEqual,
            AttributeOperator::LessThan,
            AttributeOperator::LessThanOrEqual,
        ] {
            assert!(!op.applies_to(ValueType::TextArray), "{op:?} on a list");
            assert!(!op.applies_to(ValueType::Boolean), "{op:?} on a boolean");
            assert!(op.applies_to(ValueType::Integer));
            assert!(op.applies_to(ValueType::Number));
        }
    }

    /// Less-than and greater-or-equal apply to text. Dates are stored as
    /// text, so "hired before 2020" is a text comparison.
    #[test]
    fn text_can_be_ordered_because_dates_are_text() {
        assert!(AttributeOperator::LessThan.applies_to(ValueType::Text));
        assert!(AttributeOperator::GreaterThanOrEqual.applies_to(ValueType::Text));
    }

    /// "Contains" applies to text. It is refused on numbers, yes/no values
    /// and lists.
    #[test]
    fn contains_is_a_text_comparison_only() {
        assert!(AttributeOperator::Contains.applies_to(ValueType::Text));

        for value_type in [
            ValueType::Integer,
            ValueType::Number,
            ValueType::Boolean,
            ValueType::TextArray,
        ] {
            assert!(
                !AttributeOperator::Contains.applies_to(value_type),
                "contains on {value_type:?}"
            );
        }
    }

    /// "Has any" and "has all" apply to lists. They are refused on text,
    /// numbers and yes/no values.
    #[test]
    fn the_list_tests_apply_to_lists_only() {
        for op in [AttributeOperator::HasAny, AttributeOperator::HasAll] {
            assert!(op.applies_to(ValueType::TextArray));

            for value_type in [
                ValueType::Text,
                ValueType::Integer,
                ValueType::Number,
                ValueType::Boolean,
            ] {
                assert!(!op.applies_to(value_type), "{op:?} on {value_type:?}");
            }
        }
    }

    /// "Is", "is not" and "is one of" are refused on a list. Matching a whole
    /// tag set is rarely what someone means. "Has any" is.
    #[test]
    fn a_list_is_not_compared_for_equality() {
        assert!(!AttributeOperator::Is.applies_to(ValueType::TextArray));
        assert!(!AttributeOperator::IsNot.applies_to(ValueType::TextArray));
        assert!(!AttributeOperator::IsOneOf.applies_to(ValueType::TextArray));
    }

    /// A yes/no value offers exactly four operators: is, is not, is present
    /// and is absent.
    #[test]
    fn a_boolean_is_only_compared_for_equality() {
        let applicable = AttributeOperator::applicable_to(ValueType::Boolean);

        assert!(applicable.contains(&AttributeOperator::Is));
        assert!(applicable.contains(&AttributeOperator::IsNot));
        assert!(applicable.contains(&AttributeOperator::IsPresent));
        assert!(applicable.contains(&AttributeOperator::IsAbsent));
        assert_eq!(applicable.len(), 4);
    }

    /// Presence tests take no value, "is" and "less than" take one, and "is
    /// one of" and the list tests take several.
    #[test]
    fn arity_matches_what_each_operator_compares_against() {
        assert_eq!(AttributeOperator::IsPresent.arity(), OperandArity::None);
        assert_eq!(AttributeOperator::IsAbsent.arity(), OperandArity::None);

        assert_eq!(AttributeOperator::Is.arity(), OperandArity::One);
        assert_eq!(AttributeOperator::Contains.arity(), OperandArity::One);
        assert_eq!(AttributeOperator::LessThan.arity(), OperandArity::One);

        assert_eq!(AttributeOperator::IsOneOf.arity(), OperandArity::Many);
        assert_eq!(AttributeOperator::HasAny.arity(), OperandArity::Many);
        assert_eq!(AttributeOperator::HasAll.arity(), OperandArity::Many);
    }

    /// For every operator, taking no value and being a presence test go
    /// together. The query builder relies on both answers matching.
    #[test]
    fn the_operators_taking_no_value_are_the_existence_tests() {
        for op in AttributeOperator::all() {
            assert_eq!(
                op.arity() == OperandArity::None,
                op.tests_existence(),
                "{op:?} disagrees about whether it takes a value"
            );
        }
    }

    /// Every operator's name reads back as that operator, and no two share a
    /// name. Otherwise a caller would get a comparison they did not ask for.
    #[test]
    fn every_operator_has_its_own_name_and_reads_back() {
        let mut names = Vec::new();

        for op in AttributeOperator::all() {
            assert_eq!(AttributeOperator::parse(op.as_str()), Some(*op));
            names.push(op.as_str());
        }

        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "two operators share a name");
    }

    /// "equals", "=", "IS", "is " and "gt" are not operator names. Each is
    /// refused, not read as the closest match.
    #[test]
    fn a_near_miss_is_refused_rather_than_guessed_at() {
        for unknown in ["", "equals", "=", "IS", "is ", "greaterthan", "gt"] {
            assert!(
                AttributeOperator::parse(unknown).is_none(),
                "{unknown:?} was read as a comparison"
            );
        }
    }

    /// Every value type offers more than the two presence tests, so each can
    /// be filtered by what it holds.
    #[test]
    fn every_type_can_be_filtered_somehow() {
        for value_type in TYPES {
            let applicable = AttributeOperator::applicable_to(value_type);
            assert!(
                applicable.len() > 2,
                "{value_type:?} can only be tested for presence"
            );
        }
    }
}
