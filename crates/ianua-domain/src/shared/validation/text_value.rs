//! The one shape every validated text type has.

use crate::shared::validation::error::ValidationError;
use crate::shared::validation::validator::Validator;

/// A piece of text the domain only holds once it has passed its rules.
///
/// A type names the field its errors carry and the rules it is held to,
/// usually one of the [`rules`](crate::shared::validation::rules) sets. Every value is built
/// through [`checked`](Self::checked). The `text_value!` macro builds `new`,
/// `TryFrom<String>` and deserialization on it. A type that writes its own
/// constructor calls it too.
pub(crate) trait TextValue: Sized {
    /// The field name errors carry, such as `tool_name`.
    const FIELD: &'static str;

    /// Adds the rules a value must pass to `check`.
    fn rules(check: Validator<'_>) -> Validator<'_>;

    /// The value in the form it is stored and compared in, before it is
    /// checked.
    ///
    /// Most types keep it as given. A case-insensitive name lower-cases it.
    #[must_use]
    fn normalized(value: String) -> String {
        value
    }

    /// The value in stored form, once it passes this type's rules.
    ///
    /// # Errors
    ///
    /// - The first [`ValidationError`] the value breaks, naming
    ///   [`FIELD`](Self::FIELD).
    fn checked(value: String) -> Result<String, ValidationError> {
        let value = Self::normalized(value);
        Self::rules(Validator::new(Self::FIELD, &value)).validate_first()?;
        Ok(value)
    }
}

/// Declares a text type held to the rules of its [`TextValue`] impl.
///
/// The type is the text itself, serialized as a plain string. It can only be
/// built through [`TextValue::checked`]: by `new`, by `TryFrom<String>`, or by
/// deserializing, which goes through `TryFrom<String>`. It renders as the
/// text and gives it back with `as_str`.
///
/// Written `text_value! { redacted ... }`, the type holds something that must
/// not reach a log. Its `Debug` prints only its name and it does not render.
/// Two values compare in a time that does not show where they differ.
macro_rules! text_value {
    (redacted $(#[$meta:meta])* $vis:vis struct $name:ident;) => {
        $(#[$meta])*
        #[derive(Clone, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(try_from = "String"))]
        $vis struct $name(String);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                $crate::shared::security::constant_time::same_secret(self.0.as_bytes(), other.0.as_bytes())
            }
        }

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        $crate::shared::validation::text_value!(@checked $vis $name);
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident;) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(try_from = "String"))]
        $vis struct $name(String);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        $crate::shared::validation::text_value!(@checked $vis $name);
    };
    (@checked $vis:vis $name:ident) => {
        impl $name {
            /// Checks `value` against this type's rules and wraps it.
            ///
            /// # Errors
            ///
            /// - The first
            ///   [`ValidationError`](crate::shared::validation::ValidationError)
            ///   the value breaks.
            $vis fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::shared::validation::ValidationError> {
                <Self as crate::shared::validation::TextValue>::checked(value.into()).map(Self)
            }

            /// The text.
            #[must_use]
            $vis fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = crate::shared::validation::ValidationError;

            /// Deserialization goes through the validating constructor, so a
            /// value read from JSON is held to the same rules as one built in
            /// code.
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

pub(crate) use text_value;

#[cfg(test)]
mod tests {
    use super::*;

    text_value! {
        /// A name used only by these tests.
        struct Sample;
    }

    impl TextValue for Sample {
        const FIELD: &'static str = "sample";

        fn rules(check: Validator<'_>) -> Validator<'_> {
            check.not_empty().length(1..=8)
        }

        fn normalized(value: String) -> String {
            value.to_ascii_lowercase()
        }
    }

    /// A sample type that lower-cases its value gets `ABC` and keeps `abc`.
    #[test]
    fn a_value_is_stored_in_its_normal_form() {
        assert_eq!(Sample::new("ABC").unwrap().as_str(), "abc");
    }

    /// An empty value is refused, and the error names the type's field,
    /// `sample`.
    #[test]
    fn a_value_breaking_a_rule_names_the_field() {
        let error = Sample::new("").unwrap_err();

        assert_eq!(error.field(), Some("sample"));
    }

    /// Building from a `String` with `TryFrom`, as deserializing does,
    /// refuses a twelve-character value over the limit of eight and accepts
    /// `ok`.
    #[test]
    fn a_value_read_from_text_meets_the_same_rules() {
        assert!(Sample::try_from("toolongvalue".to_owned()).is_err());
        assert_eq!(Sample::try_from("ok".to_owned()).unwrap().to_string(), "ok");
    }

    text_value! {
        redacted
        /// A value used only by these tests that must not be printed.
        struct Hidden;
    }

    impl TextValue for Hidden {
        const FIELD: &'static str = "hidden";

        fn rules(check: Validator<'_>) -> Validator<'_> {
            check.not_empty()
        }
    }

    /// A redacted value holding `s3cret` prints as `Hidden(<redacted>)` in
    /// `Debug`. The code that needs the text still gets it from `as_str`.
    #[test]
    fn a_redacted_value_is_not_printed() {
        let hidden = Hidden::new("s3cret").unwrap();

        assert_eq!(format!("{hidden:?}"), "Hidden(<redacted>)");
        assert_eq!(hidden.as_str(), "s3cret");
    }
}
