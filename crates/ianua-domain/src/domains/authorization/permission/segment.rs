//! One segment of a permission name: an area or an action.

use std::fmt;

use crate::domains::authorization::permission::MAX_SEGMENT_LENGTH;
use crate::message;
use crate::shared::validation::{Charset, ValidationError, Validator};

/// One half of a customer-defined permission: a resource key, or an action.
///
/// Both halves follow the same rule. They also appear in the tenant's
/// catalogue, as the key of a resource type and of an action on it. One type
/// for all four means a name a role accepts is never one the catalogue
/// refuses.
///
/// # Examples
///
/// ```
/// # use ianua_domain::domains::authorization::permission::PermissionSegment;
/// assert!(PermissionSegment::new("permission_resource", "project").is_ok());
/// assert!(PermissionSegment::new("permission_action", "Write").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct PermissionSegment(String);

#[cfg(feature = "serde")]
impl TryFrom<String> for PermissionSegment {
    type Error = ValidationError;

    /// Deserializing goes through [`PermissionSegment::new`], so a malformed
    /// stored or sent value is refused.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new("permission_segment", value)
    }
}

impl PermissionSegment {
    /// Creates a validated segment, reporting failures against `field`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the value is empty.
    /// - [`ValidationError`] if it is longer than 64 characters.
    /// - [`ValidationError`] if it holds anything but lowercase ASCII
    ///   letters, digits, hyphens, underscores and `*`.
    pub fn new(field: &'static str, value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        Validator::new(field, &value)
            .identifier(
                1..=MAX_SEGMENT_LENGTH,
                Charset::LOWERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::UNDERSCORE
                    | Charset::ASTERISK,
            )
            .validate_first()?;

        Ok(Self(value))
    }

    /// The validated segment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this segment is the `*` wildcard.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0 == "*"
    }

    /// Refuses the `idp` prefix that system permissions reserve.
    ///
    /// Used on resource keys only. An app that could name a resource `idp`
    /// could make a permission that looks like one the platform checks.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the segment is `idp`, or starts with `idp-`
    ///   or `idp_`.
    pub fn ensure_not_reserved(&self, field: &'static str) -> Result<(), ValidationError> {
        if self.0 == "idp" || self.0.starts_with("idp_") || self.0.starts_with("idp-") {
            return Err(ValidationError::Custom {
                field,
                code: "reserved_prefix".to_owned(),
                message: message!(
                    "authorization-cannot-use-the-reserved-idp-prefix",
                    format!(
                        "{field} cannot use the reserved 'idp' prefix. \
                     This prefix is reserved for system permissions."
                    )
                ),
            });
        }
        Ok(())
    }
}

impl fmt::Display for PermissionSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The segment `project` prints as `project`, and `*` prints as `*`.
    /// That text goes into the permission string a token carries.
    #[test]
    fn a_segment_displays_as_the_value_it_holds() {
        assert_eq!(
            PermissionSegment::new("segment", "project")
                .unwrap()
                .to_string(),
            "project"
        );
        assert_eq!(
            PermissionSegment::new("segment", "*").unwrap().to_string(),
            "*"
        );
    }
}
