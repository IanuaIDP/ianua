//! Permissions a tenant's own application defines and enforces.

use std::fmt;

use crate::domains::authorization::permission::PermissionSegment;
use crate::shared::validation::ValidationError;
use crate::types::PermissionName;

/// A permission the customer defines for their own app.
///
/// The `IdP` stores these in roles and gives them no meaning of its own. The
/// gateway can require one on a route. It passes the caller's permissions to
/// the app in its signed assertion, and the customer's app checks them.
///
/// # Validation
///
/// Both resource and action are checked on construction:
/// - Only lowercase ASCII letters, digits, hyphens, underscores and the `*`
///   wildcard. So no spaces or control characters.
/// - 1 to 64 characters each.
/// - The resource cannot be `idp`, or start with `idp_` or `idp-`. System
///   permissions reserve that prefix.
///
/// # Examples
///
/// ```
/// # use ianua_domain::domains::authorization::permission::CustomPermission;
/// let perm = CustomPermission::new("project", "write").unwrap();
/// assert_eq!(perm.to_string(), "project:write");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "CustomPermissionWire"))]
pub struct CustomPermission {
    resource: PermissionSegment,
    action: PermissionSegment,
}

/// A custom permission as it arrives, before [`CustomPermission::new`] has
/// checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct CustomPermissionWire {
    resource: String,
    action: String,
}

#[cfg(feature = "serde")]
impl TryFrom<CustomPermissionWire> for CustomPermission {
    type Error = ValidationError;

    /// A permission read from a stored role or an API body is held to the
    /// same rules as one built in code, reserved `idp` resource included.
    fn try_from(wire: CustomPermissionWire) -> Result<Self, Self::Error> {
        Self::new(wire.resource, wire.action)
    }
}

impl CustomPermission {
    /// Creates a checked customer-defined permission.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if either segment is empty or longer than 64
    ///   characters.
    /// - [`ValidationError`] if either segment holds a character not allowed.
    /// - [`ValidationError`] if the resource uses the reserved `idp` prefix.
    pub fn new(
        resource: impl Into<String>,
        action: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let resource = PermissionSegment::new("permission_resource", resource)?;
        resource.ensure_not_reserved("permission_resource")?;
        let action = PermissionSegment::new("permission_action", action)?;

        Ok(Self { resource, action })
    }

    /// Parses a `resource:action` permission. `None` for anything else,
    /// system permissions included.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (resource, action) = s.split_once(':')?;
        Self::new(resource, action).ok()
    }

    /// Whether any of `held` grants this permission. That is the same
    /// permission, or one with `*` in place of its resource or action.
    ///
    /// `held` is permissions written out, as a token or the gateway carries
    /// them. Anything that is not a custom permission is ignored.
    #[must_use]
    pub fn held_in(&self, held: &[PermissionName]) -> bool {
        held.iter()
            .filter_map(|held| Self::parse(held.as_str()))
            .any(|held| held.matches(self.resource.as_str(), self.action.as_str()))
    }

    /// Whether someone holding `held` may give out every one of `to_grant`.
    ///
    /// Each must be covered by something held. That is the same permission,
    /// or one with `*` in its place. Only someone holding a wildcard at least
    /// as wide may give out a wildcard, so `orders:read` never covers
    /// `orders:*`. `held` should already include what the catalogue's
    /// ladders confer.
    #[must_use]
    pub fn can_delegate(held: &[Self], to_grant: &[Self]) -> bool {
        to_grant.iter().all(|wanted| {
            held.iter()
                .any(|own| own.matches(wanted.resource.as_str(), wanted.action.as_str()))
        })
    }

    /// The resource this permission applies to.
    #[must_use]
    pub fn resource(&self) -> &PermissionSegment {
        &self.resource
    }

    /// The action allowed on the resource.
    #[must_use]
    pub fn action(&self) -> &PermissionSegment {
        &self.action
    }

    /// Whether this permission grants `action` on `resource`.
    ///
    /// A held `*:*` matches everything. A held `project:*` matches any
    /// action on projects.
    #[must_use]
    pub fn matches(&self, resource: &str, action: &str) -> bool {
        let resource_ok = self.resource.is_wildcard() || self.resource.as_str() == resource;
        let action_ok = self.action.is_wildcard() || self.action.as_str() == action;
        resource_ok && action_ok
    }
}

impl fmt::Display for CustomPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant defines `project:read`. The permission keeps `project` as its
    /// resource and `read` as its action.
    #[test]
    fn creates_simple_permission() {
        let perm = CustomPermission::new("project", "read").unwrap();
        assert_eq!(perm.resource().as_str(), "project");
        assert_eq!(perm.action().as_str(), "read");
    }

    /// The permission on invoices with action write prints as
    /// `invoice:write`, the form tokens and the gateway carry.
    #[test]
    fn display_is_colon_separated() {
        let perm = CustomPermission::new("invoice", "write").unwrap();
        assert_eq!(perm.to_string(), "invoice:write");
    }

    /// Creating a custom permission on the reserved `idp` resource returns the
    /// `reserved_prefix` validation code.
    #[test]
    fn rejects_idp_resource() {
        let err = CustomPermission::new("idp", "manage").unwrap_err();
        assert_eq!(err.code(), "reserved_prefix");
    }

    /// A tenant defines `*:*`. The wildcard is a valid resource and a valid
    /// action.
    #[test]
    fn wildcards_are_valid_permission_segments() {
        assert!(CustomPermission::new("*", "*").is_ok());
    }

    /// Someone holds `*:*`. It grants any action on any resource, here
    /// `everything` on `anything`.
    #[test]
    fn wildcard_matches_everything() {
        let perm = CustomPermission::new("*", "*").unwrap();
        assert!(perm.matches("anything", "everything"));
    }

    /// Someone holds `project:read`. It grants reading projects and not
    /// writing them.
    #[test]
    fn a_custom_permission_matches_only_its_resource_and_action() {
        let perm = CustomPermission::new("project", "read").unwrap();
        assert!(perm.matches("project", "read"));
        assert!(!perm.matches("project", "write"));
    }

    /// A tenant defines `Project:read` with a capital letter. It is refused,
    /// so `Project` and `project` never name two different permissions.
    #[test]
    fn uppercase_resources_are_refused() {
        assert!(CustomPermission::new("Project", "read").is_err());
    }

    /// `billing:admin` is written to JSON and read back. It comes back
    /// equal to the original.
    #[cfg(feature = "serde")]
    #[test]
    fn custom_permission_roundtrips_through_json() {
        let original = CustomPermission::new("billing", "admin").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let restored: CustomPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    /// Deserializing a custom permission on the reserved `idp` resource is rejected.
    #[cfg(feature = "serde")]
    #[test]
    fn a_custom_permission_on_the_reserved_resource_is_refused_on_deserialize() {
        let json = r#"{"resource":"idp","action":"manage"}"#;

        assert!(serde_json::from_str::<CustomPermission>(json).is_err());
    }

    /// The segment `*` is a wildcard, and `read` and `project` are not. A
    /// wrong answer either grants every action or takes a working grant away.
    #[test]
    fn only_the_asterisk_is_a_wildcard() {
        assert!(
            PermissionSegment::new("segment", "*")
                .unwrap()
                .is_wildcard()
        );
        assert!(
            !PermissionSegment::new("segment", "read")
                .unwrap()
                .is_wildcard()
        );
        assert!(
            !PermissionSegment::new("segment", "project")
                .unwrap()
                .is_wildcard()
        );
    }

    mod custom_delegation {
        use super::*;

        fn perms(values: &[&str]) -> Vec<CustomPermission> {
            values
                .iter()
                .map(|value| CustomPermission::parse(value).unwrap())
                .collect()
        }

        /// Someone holds `orders:refund`. They may give `orders:refund` to
        /// others.
        #[test]
        fn what_you_hold_you_can_give_out() {
            assert!(CustomPermission::can_delegate(
                &perms(&["orders:refund"]),
                &perms(&["orders:refund"])
            ));
        }

        /// Neither order-reading rights nor an empty permission set allows
        /// granting `orders:refund`.
        #[test]
        fn what_you_do_not_hold_you_cannot_give_out() {
            assert!(!CustomPermission::can_delegate(
                &perms(&["orders:read"]),
                &perms(&["orders:refund"])
            ));
            assert!(!CustomPermission::can_delegate(
                &[],
                &perms(&["orders:refund"])
            ));
        }

        /// Someone holds `orders:*`. They may give out `orders:refund` and
        /// `orders:*`, but not `invoices:read`.
        #[test]
        fn a_wildcard_held_covers_what_it_matches() {
            let held = perms(&["orders:*"]);

            assert!(CustomPermission::can_delegate(
                &held,
                &perms(&["orders:refund", "orders:*"])
            ));
            assert!(!CustomPermission::can_delegate(
                &held,
                &perms(&["invoices:read"])
            ));
        }

        /// Delegation cannot widen `orders:read` to `orders:*` or `orders:*` to `*:*`.
        #[test]
        fn a_narrow_permission_never_covers_a_wildcard() {
            assert!(!CustomPermission::can_delegate(
                &perms(&["orders:read"]),
                &perms(&["orders:*"])
            ));
            assert!(!CustomPermission::can_delegate(
                &perms(&["orders:*"]),
                &perms(&["*:*"])
            ));
        }

        /// Someone who holds no app permissions gives out none. That is
        /// allowed.
        #[test]
        fn giving_out_nothing_needs_nothing() {
            assert!(CustomPermission::can_delegate(&[], &[]));
        }
    }
}
