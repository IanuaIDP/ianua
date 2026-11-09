//! The domain's own metadata value.
//!
//! The domain uses it in place of `serde_json::Value`, so metadata does not
//! depend on a serialization library. The infra layer converts to and from
//! `serde_json::Value` at the boundary.

use std::fmt;

/// A typed metadata value the domain can carry without `serde_json`.
///
/// It covers the part of JSON that user and app metadata use: strings,
/// integers, floats, booleans and string arrays.
#[derive(Debug, Clone, PartialEq)]
pub enum MetadataValue {
    /// A string value.
    String(std::string::String),
    /// An integer value.
    Integer(i64),
    /// A floating-point value.
    Number(f64),
    /// A boolean value.
    Bool(bool),
    /// An array of strings, such as tags or roles.
    StringArray(Vec<std::string::String>),
    /// No value.
    Null,
}

impl MetadataValue {
    /// The value as a string slice, if it is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        let Self::String(s) = self else {
            return None;
        };
        Some(s)
    }

    /// The value as an `i64`, if it is an integer.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        let Self::Integer(n) = self else {
            return None;
        };
        Some(*n)
    }

    /// The value as an `f64`, if it is an integer or a float.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Integer(n) => Some(*n as f64),
            Self::String(_) | Self::Bool(_) | Self::StringArray(_) | Self::Null => None,
        }
    }

    /// The value as a bool, if it is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        let Self::Bool(b) = self else {
            return None;
        };
        Some(*b)
    }

    /// The value as a slice of strings, if it is a string array.
    #[must_use]
    pub fn as_string_array(&self) -> Option<&[std::string::String]> {
        let Self::StringArray(v) = self else {
            return None;
        };
        Some(v)
    }

    /// Whether this is a string.
    #[must_use]
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Whether this is an integer.
    #[must_use]
    pub fn is_i64(&self) -> bool {
        matches!(self, Self::Integer(_))
    }

    /// Whether this is a number (integer or float).
    #[must_use]
    pub fn is_number(&self) -> bool {
        matches!(self, Self::Integer(_) | Self::Number(_))
    }

    /// Whether this is a boolean.
    #[must_use]
    pub fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }

    /// Whether this is null.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::StringArray(v) => write!(f, "{v:?}"),
            Self::Null => write!(f, "null"),
        }
    }
}

impl From<&str> for MetadataValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for MetadataValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i64> for MetadataValue {
    fn from(n: i64) -> Self {
        Self::Integer(n)
    }
}

impl From<f64> for MetadataValue {
    fn from(n: f64) -> Self {
        Self::Number(n)
    }
}

impl From<bool> for MetadataValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<Vec<String>> for MetadataValue {
    fn from(v: Vec<String>) -> Self {
        Self::StringArray(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "hello" reads back as that text and is not taken for an integer.
    #[test]
    fn a_text_value_reads_only_as_text() {
        let v = MetadataValue::from("hello");
        assert_eq!(v.as_str(), Some("hello"));
        assert!(v.is_string());
        assert!(!v.is_i64());
    }

    /// 42 reads as the integer 42 and as the number 42.0.
    #[test]
    fn an_integer_value_reads_as_integer_and_number() {
        let v = MetadataValue::from(42_i64);
        assert_eq!(v.as_i64(), Some(42));
        assert!(v.is_i64());
        assert!(v.is_number());
        assert_eq!(v.as_f64(), Some(42.0));
    }

    /// 2.72 reads as a number but not as an integer.
    #[test]
    fn a_decimal_value_reads_as_a_number_not_an_integer() {
        let v = MetadataValue::Number(2.72);
        assert_eq!(v.as_f64(), Some(2.72));
        assert!(v.is_number());
        assert!(!v.is_i64());
    }

    /// `true` reads back as the boolean true.
    #[test]
    fn a_boolean_value_reads_as_a_boolean() {
        let v = MetadataValue::from(true);
        assert_eq!(v.as_bool(), Some(true));
        assert!(v.is_boolean());
    }

    /// A list of "a" and "b" reads back as a list of two strings.
    #[test]
    fn string_array_accessors() {
        let v = MetadataValue::from(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(v.as_string_array().unwrap().len(), 2);
    }

    /// A null value says it is null.
    #[test]
    fn null_is_null() {
        assert!(MetadataValue::Null.is_null());
    }

    /// "hi", 42, true and null print as `hi`, `42`, `true` and `null`, with
    /// no quotes or type names.
    #[test]
    fn metadata_values_print_as_plain_text() {
        assert_eq!(MetadataValue::from("hi").to_string(), "hi");
        assert_eq!(MetadataValue::from(42_i64).to_string(), "42");
        assert_eq!(MetadataValue::from(true).to_string(), "true");
        assert_eq!(MetadataValue::Null.to_string(), "null");
    }

    /// Text, a whole number, a decimal and a flag each answer yes only to
    /// their own type check. A check that always said yes would let text be
    /// saved where a number was declared.
    #[test]
    fn each_type_question_answers_only_for_its_own_type() {
        let text = MetadataValue::from("hi");
        let whole = MetadataValue::from(42_i64);
        let fractional = MetadataValue::Number(1.5);
        let flag = MetadataValue::from(true);

        assert!(text.is_string());
        assert!(!text.is_number());
        assert!(!text.is_null());

        assert!(whole.is_number());
        assert!(whole.is_i64());
        assert!(!whole.is_string());

        assert!(
            fractional.is_number(),
            "a float is a number even though it is not an integer"
        );
        assert!(!fractional.is_i64());

        assert!(flag.is_boolean());
        assert!(!flag.is_number());
        assert!(!flag.is_string());
        assert!(!flag.is_null());
    }

    /// true and false read back as stored. The text "true" and null give
    /// nothing, so no flag is made up on the way out.
    #[test]
    fn reading_a_bool_gives_back_what_was_stored() {
        assert_eq!(MetadataValue::from(true).as_bool(), Some(true));
        assert_eq!(MetadataValue::from(false).as_bool(), Some(false));
        assert_eq!(MetadataValue::from("true").as_bool(), None);
        assert_eq!(MetadataValue::Null.as_bool(), None);
    }
}
