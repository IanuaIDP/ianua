//! How an attribute's values are stored.
//!
//! It is separate from [`AttributeKind`](crate::domains::identity::attribute::AttributeKind), which is
//! what an administrator picks. Money, a percentage and a rating out of five
//! are filled in with three different controls. All three are stored as a
//! number. The kind is what the administrator sees. The value type is the
//! storage.

use crate::domains::identity::metadata_value::MetadataValue;

/// The stored type of an attribute value.
///
/// The set is closed. A query adapter maps each variant to the one place its
/// values are stored. So where a filter or sort reads is picked by this type,
/// never by anything the caller sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ValueType {
    /// Any text.
    Text,
    /// A whole number.
    Integer,
    /// A number with a fractional part.
    Number,
    /// True or false.
    Boolean,
    /// A list of strings, held as a JSON array.
    TextArray,
}

impl ValueType {
    /// The name stored in the `value_type` column.
    ///
    /// It matches what the column's CHECK constraint allows and what stored
    /// rows hold.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "string",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::TextArray => "string_array",
        }
    }

    /// Whether `value` is of this type.
    ///
    /// A whole number passes for [`Number`](ValueType::Number) as well as
    /// [`Integer`](ValueType::Integer). A salary of exactly 45000 is a valid
    /// decimal. Refusing it would make every round figure an error.
    #[must_use]
    pub fn accepts(self, value: &MetadataValue) -> bool {
        match self {
            Self::Text => value.is_string(),
            Self::Integer => value.is_i64(),
            Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(),
            Self::TextArray => value.as_string_array().is_some(),
        }
    }

    /// Reads a value of this type from text.
    ///
    /// A query string carries everything as text. Which text is valid
    /// depends on the type it is compared with. So the type decides here,
    /// and a caller does not guess from how the text looks.
    ///
    /// It gives `None` when the text is not a value of this type. That is a
    /// bad request, and nothing is converted. Reading `maybe` as `false`, or
    /// `12abc` as `12`, would answer a question nobody asked.
    #[must_use]
    pub fn parse_value(self, text: &str) -> Option<MetadataValue> {
        match self {
            Self::Text | Self::TextArray => Some(MetadataValue::String(text.to_owned())),
            Self::Integer => text.parse().ok().map(MetadataValue::Integer),
            Self::Number => text
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite())
                .map(MetadataValue::Number),
            Self::Boolean => match text {
                "true" => Some(MetadataValue::Bool(true)),
                "false" => Some(MetadataValue::Bool(false)),
                _ => None,
            },
        }
    }

    /// Whether values of this type can be sorted.
    ///
    /// A list cannot. Of two tag sets, neither is greater, so a user list
    /// cannot be sorted by one.
    #[must_use]
    pub fn is_orderable(self) -> bool {
        !matches!(self, Self::TextArray)
    }

    /// A name for people to read, for error messages.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "a whole number",
            Self::Number => "a number",
            Self::Boolean => "true or false",
            Self::TextArray => "a list of text",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ValueType; 5] = [
        ValueType::Text,
        ValueType::Integer,
        ValueType::Number,
        ValueType::Boolean,
        ValueType::TextArray,
    ];

    /// The types are stored as "string", "integer", "number", "boolean" and
    /// "string_array". The CHECK constraint and stored rows use these, so a
    /// changed name would leave stored values unreadable.
    #[test]
    fn the_stored_discriminants_are_the_ones_the_column_permits() {
        assert_eq!(ValueType::Text.as_str(), "string");
        assert_eq!(ValueType::Integer.as_str(), "integer");
        assert_eq!(ValueType::Number.as_str(), "number");
        assert_eq!(ValueType::Boolean.as_str(), "boolean");
        assert_eq!(ValueType::TextArray.as_str(), "string_array");
    }

    /// Text accepts "hello" but not 42. A whole number refuses 1.5 and text.
    /// Yes/no and lists each refuse plain text.
    #[test]
    fn each_type_accepts_its_own_values_and_no_others() {
        let text = MetadataValue::from("hello");
        let integer = MetadataValue::from(42_i64);
        let decimal = MetadataValue::Number(1.5);
        let boolean = MetadataValue::from(true);
        let list = MetadataValue::from(vec!["a".to_owned()]);

        assert!(ValueType::Text.accepts(&text));
        assert!(!ValueType::Text.accepts(&integer));

        assert!(ValueType::Integer.accepts(&integer));
        assert!(!ValueType::Integer.accepts(&decimal));
        assert!(!ValueType::Integer.accepts(&text));

        assert!(ValueType::Boolean.accepts(&boolean));
        assert!(!ValueType::Boolean.accepts(&text));

        assert!(ValueType::TextArray.accepts(&list));
        assert!(!ValueType::TextArray.accepts(&text));
    }

    /// A decimal attribute accepts both 45000 and 45000.5. Refusing the
    /// whole number would make every round salary an error.
    #[test]
    fn a_whole_number_satisfies_a_decimal_attribute() {
        assert!(ValueType::Number.accepts(&MetadataValue::from(45_000_i64)));
        assert!(ValueType::Number.accepts(&MetadataValue::Number(45_000.5)));
    }

    /// A null is refused by all five types, so it never passes the type
    /// check as a value.
    #[test]
    fn nothing_accepts_a_null() {
        for value_type in ALL {
            assert!(
                !value_type.accepts(&MetadataValue::Null),
                "{value_type:?} accepted a null"
            );
        }
    }

    /// From a query string, "sales" reads as text, "-42" as a whole number,
    /// "1.5" as a decimal and "true" as yes.
    #[test]
    fn a_value_is_read_from_the_text_a_query_string_carries() {
        assert_eq!(
            ValueType::Text.parse_value("sales"),
            Some(MetadataValue::String("sales".to_owned()))
        );
        assert_eq!(
            ValueType::Integer.parse_value("42"),
            Some(MetadataValue::Integer(42))
        );
        assert_eq!(
            ValueType::Integer.parse_value("-42"),
            Some(MetadataValue::Integer(-42))
        );
        assert_eq!(
            ValueType::Number.parse_value("1.5"),
            Some(MetadataValue::Number(1.5))
        );
        assert_eq!(
            ValueType::Boolean.parse_value("true"),
            Some(MetadataValue::Bool(true))
        );
    }

    /// A filter on a list reads "red" as plain text. A list is compared item
    /// by item, so each operand is one text value.
    #[test]
    fn a_list_reads_its_operands_as_text() {
        assert_eq!(
            ValueType::TextArray.parse_value("red"),
            Some(MetadataValue::String("red".to_owned()))
        );
    }

    /// "12abc", " 42" and "0x10" are not whole numbers. "yes" and "TRUE" are
    /// not yes/no values, and "inf" and "NaN" are not decimals. Each is
    /// refused, not converted.
    #[test]
    fn text_that_is_not_a_value_of_the_type_is_refused_rather_than_coerced() {
        for text in ["", "12abc", "1.5", "0x10", " 42", "42 ", "+-1"] {
            assert!(
                ValueType::Integer.parse_value(text).is_none(),
                "{text:?} was read as a whole number"
            );
        }

        for text in ["yes", "no", "1", "0", "TRUE", "True", ""] {
            assert!(
                ValueType::Boolean.parse_value(text).is_none(),
                "{text:?} was read as a boolean"
            );
        }

        for text in ["", "inf", "NaN", "abc"] {
            assert!(
                ValueType::Number.parse_value(text).is_none(),
                "{text:?} was read as a number"
            );
        }
    }

    /// A list of text cannot be sorted on. Every other type can.
    #[test]
    fn a_list_has_no_order_and_everything_else_does() {
        assert!(!ValueType::TextArray.is_orderable());

        for value_type in ALL.iter().filter(|t| **t != ValueType::TextArray) {
            assert!(value_type.is_orderable(), "{value_type:?} should order");
        }
    }
}
