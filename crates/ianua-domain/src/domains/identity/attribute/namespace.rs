//! Which half of a user's custom attributes an attribute belongs to, and
//! who may write each.

use crate::message;
use crate::shared::errors::DomainError;

/// The namespace an attribute belongs to.
///
/// The split is about who may write. It is also why two attributes may share
/// a key. Ann picks her own `tier`, and the billing system keeps another
/// `tier` for her. They are different fields with the same name. Merged, one
/// would overwrite the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AttributeNamespace {
    /// Kept by the person the attribute describes, or by an administrator
    /// acting for them.
    User,
    /// Kept by administrators and by the application. The person the
    /// attribute describes may not write it.
    App,
}

impl AttributeNamespace {
    /// Both namespaces, so a caller iterating them cannot miss one.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::User, Self::App]
    }

    /// The name stored in the `namespace` column.
    ///
    /// It matches what the column's CHECK constraint allows and what stored
    /// rows hold.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::App => "app",
        }
    }

    /// Reads a stored name back.
    ///
    /// It gives `None` for anything the column should not hold. The caller
    /// reports that as corrupt data, not as bad input.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "app" => Some(Self::App),
            _ => None,
        }
    }

    /// Whether the person an attribute describes may write it themselves.
    #[must_use]
    pub fn writable_by_subject(self) -> bool {
        matches!(self, Self::User)
    }

    /// Refuses `writer` when they may not write an attribute in this
    /// namespace.
    ///
    /// Access rules may read app attributes. Ann must not set her own
    /// `app.tier` to premium.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person the attribute describes
    ///   writes one in [`Self::App`].
    pub fn ensure_writable_by(self, writer: AttributeWriter) -> Result<(), DomainError> {
        match (writer, self.writable_by_subject()) {
            (AttributeWriter::Holder, false) => Err(DomainError::forbidden(message!(
                "identity-an-app-attribute-is-kept-by",
                "an app attribute is kept by administrators and the application, not by the person it describes"
            ))),
            (AttributeWriter::Holder | AttributeWriter::Administrator, _) => Ok(()),
        }
    }
}

/// Who writes a custom attribute's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeWriter {
    /// The person the attribute describes, on their own account.
    Holder,
    /// An administrator or the application, acting for the tenant.
    Administrator,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each namespace is stored by name and reads back as the same
    /// namespace.
    #[test]
    fn a_namespace_survives_the_round_trip() {
        for namespace in AttributeNamespace::all() {
            assert_eq!(
                AttributeNamespace::parse(namespace.as_str()),
                Some(*namespace)
            );
        }
    }

    /// The namespaces are stored as exactly "user" and "app". The column's
    /// CHECK constraint and stored rows use those strings.
    #[test]
    fn the_stored_discriminants_are_the_ones_the_column_permits() {
        assert_eq!(AttributeNamespace::User.as_str(), "user");
        assert_eq!(AttributeNamespace::App.as_str(), "app");
    }

    /// Stored values such as "User", "APP" or "user " with a space are not
    /// namespaces. Each reads back as nothing, so a corrupt row is never
    /// guessed at.
    #[test]
    fn an_unknown_namespace_is_refused_rather_than_defaulted() {
        for unknown in ["User", "APP", "admin", "", "user "] {
            assert!(
                AttributeNamespace::parse(unknown).is_none(),
                "{unknown:?} was read as a namespace"
            );
        }
    }

    /// Ann may write her own user attributes but not her app attributes.
    #[test]
    fn only_the_user_namespace_is_writable_by_its_subject() {
        assert!(AttributeNamespace::User.writable_by_subject());
        assert!(!AttributeNamespace::App.writable_by_subject());
    }

    /// The full list holds both namespaces.
    #[test]
    fn all_lists_both_namespaces() {
        assert_eq!(AttributeNamespace::all().len(), 2);
    }

    /// A holder is refused writes to app attributes but may write user
    /// attributes; administrators may write app attributes.
    #[test]
    fn a_person_writes_only_their_user_attributes() {
        assert!(matches!(
            AttributeNamespace::App.ensure_writable_by(AttributeWriter::Holder),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            AttributeNamespace::User
                .ensure_writable_by(AttributeWriter::Holder)
                .is_ok()
        );
        assert!(
            AttributeNamespace::App
                .ensure_writable_by(AttributeWriter::Administrator)
                .is_ok()
        );
    }
}
