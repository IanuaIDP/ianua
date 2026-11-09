use crate::shared::validation::error::ValidationError;

/// A check of its own that a value adds to a [`Validator`](crate::shared::validation::Validator).
///
/// Common checks such as length, charset and boundary are methods on
/// [`Validator`](crate::shared::validation::Validator). This trait is for checks only some
/// values need, such as:
///
/// - a password policy, like "has an uppercase letter" or "has a digit"
/// - a format only one value object uses
///
/// # Implementing
///
/// Write the rule next to the value object or policy that needs it. Add it
/// to a validator with [`Validator::rule`](crate::shared::validation::Validator::rule).
///
/// # Examples
///
/// ```
/// # use ianua_domain::shared::validation::{Rule, ValidationError};
/// struct MustContainDigit;
///
/// impl Rule for MustContainDigit {
///     fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
///         if value.bytes().any(|b| b.is_ascii_digit()) {
///             return None;
///         }
///         Some(ValidationError::Custom {
///             field,
///             code: "missing_digit".to_owned(),
///             message: format!("{field} must contain at least one digit.").into(),
///         })
///     }
/// }
/// ```
pub trait Rule: Send + Sync {
    /// The failure, or `None` when the value passes.
    ///
    /// `field` comes from the validator, so the error names the input that
    /// failed.
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError>;
}
