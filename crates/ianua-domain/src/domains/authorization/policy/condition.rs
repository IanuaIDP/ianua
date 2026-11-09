//! Policy conditions: the tests that decide when a rule applies.
//!
//! The gateway's request policy and the tenant's access policy both read
//! them, so every condition a rule can carry is declared here once.

use crate::domains::authorization::permission::CustomPermission;
use crate::domains::authorization::policy::claims::{ClaimName, ClaimValue};
use crate::domains::authorization::policy::time_window::TimeWindow;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{
    CanonicalPath, CidrRange, CountryCode, GroupId, HostName, HttpMethod, PathPrefix, RoleId,
    Timezone,
};

/// One condition that must hold for a policy rule to apply.
///
/// A rule applies only when all its conditions hold.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyCondition {
    /// The request path is the prefix or under it, on a `/` boundary. So
    /// `/admin` covers `/admin/users` but not `/administrator`.
    PathPrefix(PathPrefix),

    /// The request path matches exactly, both in canonical form. So
    /// `/admin/delete/` and `/admin/delete` are the same rule.
    PathExact(CanonicalPath),

    /// The user holds a specific role.
    ///
    /// Named by the role's id, never its name. Sam may edit roles. He
    /// renames a role, or gives a deleted role's name to a new one, and a
    /// rule keyed on the name starts matching someone else.
    RoleIs(RoleId),

    /// The user does not hold a specific role.
    RoleIsNot(RoleId),

    /// The user's country is in the given list.
    CountryIn(Vec<CountryCode>),

    /// The user's country is not in the given list.
    CountryNotIn(Vec<CountryCode>),

    /// The device is not in the trusted device list.
    DeviceUnknown,

    /// The device is in the trusted device list.
    DeviceKnown,

    /// The risk level is at or above the given threshold.
    RiskAtLeast(RiskThreshold),

    /// The HTTP method is one of the given values. Stored as the methods'
    /// wire names, such as `"GET"`. A name in any case is read as that
    /// method.
    MethodIn(#[cfg_attr(feature = "serde", serde(with = "method_names"))] Vec<HttpMethod>),

    /// The request is for a sensitive operation, such as a password change,
    /// a role assignment or a key rotation.
    SensitiveOperation,

    /// The caller is in a group, or in a group under it.
    ///
    /// Named by the group's id, never its name, for the reason
    /// [`RoleIs`](Self::RoleIs) gives.
    GroupIs(GroupId),

    /// The caller is in neither a group nor any group under it.
    GroupIsNot(GroupId),

    /// The caller holds a permission of the tenant's app: itself, through
    /// a wildcard such as `project:*`, or through the resource type's
    /// ladder.
    PermissionHeld(CustomPermission),

    /// An attribute of the caller, or a claim their sign-in carried, holds
    /// exactly `value`.
    ClaimEquals {
        /// The attribute or claim.
        name: ClaimName,
        /// The value it must hold.
        value: ClaimValue,
    },

    /// The request comes from an address in one of these ranges.
    SourceIpIn(Vec<CidrRange>),

    /// The request comes from an address in none of these ranges.
    SourceIpNotIn(Vec<CidrRange>),

    /// The request arrives inside a stretch of the day, read in the
    /// window's timezone.
    TimeWithin(TimeWindow),

    /// The request is for one of these hosts, compared without regard to
    /// case.
    HostIn(Vec<HostName>),
}

/// The most entries a list condition may name: every country there is, and
/// more ranges or hosts than one rule should read.
const MAX_LISTED: usize = 250;

impl PolicyCondition {
    /// Checks the condition can mean what it says.
    ///
    /// `CountryNotIn` or `SourceIpNotIn` over an empty list would match
    /// every request. `MethodIn`, `SourceIpIn` or `HostIn` over an empty
    /// list would match none. A rule built on either would do the opposite
    /// of what it reads as.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Count`] when a list condition names nothing.
    /// - [`ValidationError::Count`] when it names more than 250 entries, the
    ///   number of countries there are.
    pub fn check(&self) -> Result<(), ValidationError> {
        match self {
            Self::CountryIn(countries) | Self::CountryNotIn(countries) => {
                validate_count("countries", countries.len(), 1..=MAX_LISTED)
            }
            Self::MethodIn(methods) => validate_count("methods", methods.len(), 1..=MAX_LISTED),
            Self::SourceIpIn(ranges) | Self::SourceIpNotIn(ranges) => {
                validate_count("ranges", ranges.len(), 1..=MAX_LISTED)
            }
            Self::HostIn(hosts) => validate_count("hosts", hosts.len(), 1..=MAX_LISTED),
            Self::PathPrefix(_)
            | Self::PathExact(_)
            | Self::RoleIs(_)
            | Self::RoleIsNot(_)
            | Self::DeviceUnknown
            | Self::DeviceKnown
            | Self::RiskAtLeast(_)
            | Self::SensitiveOperation
            | Self::GroupIs(_)
            | Self::GroupIsNot(_)
            | Self::PermissionHeld(_)
            | Self::ClaimEquals { .. }
            | Self::TimeWithin(_) => Ok(()),
        }
    }

    /// The timezone the condition reads the time in, when it reads one.
    #[must_use]
    pub fn timezone(&self) -> Option<&Timezone> {
        match self {
            Self::TimeWithin(window) => Some(window.zone()),
            Self::PathPrefix(_)
            | Self::PathExact(_)
            | Self::RoleIs(_)
            | Self::RoleIsNot(_)
            | Self::CountryIn(_)
            | Self::CountryNotIn(_)
            | Self::DeviceUnknown
            | Self::DeviceKnown
            | Self::RiskAtLeast(_)
            | Self::MethodIn(_)
            | Self::SensitiveOperation
            | Self::GroupIs(_)
            | Self::GroupIsNot(_)
            | Self::PermissionHeld(_)
            | Self::ClaimEquals { .. }
            | Self::SourceIpIn(_)
            | Self::SourceIpNotIn(_)
            | Self::HostIn(_) => None,
        }
    }
}

/// Stores `MethodIn` as the methods' wire names.
#[cfg(feature = "serde")]
mod method_names {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::types::HttpMethod;

    pub(super) fn serialize<S: Serializer>(
        methods: &[HttpMethod],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(methods.iter().map(HttpMethod::as_str))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<HttpMethod>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|name| {
                HttpMethod::parse(&name.to_ascii_uppercase())
                    .ok_or_else(|| D::Error::custom(format!("`{name}` is not an HTTP method")))
            })
            .collect()
    }
}

/// Risk level threshold for policy conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RiskThreshold {
    /// Low risk or above, so it matches whenever the risk is known.
    Low,
    /// Medium risk or above.
    Medium,
    /// High risk or above.
    High,
    /// Critical risk only.
    Critical,
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    /// A condition on GET and DELETE is written to JSON as
    /// `["GET","DELETE"]`, the wire names stored policies hold.
    #[cfg(feature = "serde")]
    #[test]
    fn methods_are_stored_by_their_wire_names() {
        let condition = PolicyCondition::MethodIn(vec![HttpMethod::Get, HttpMethod::Delete]);

        let json = serde_json::to_string(&condition).unwrap();

        assert_eq!(json, r#"{"MethodIn":["GET","DELETE"]}"#);
    }

    /// A stored condition names the method `get` in lower case. It is read
    /// as GET.
    #[cfg(feature = "serde")]
    #[test]
    fn a_method_in_any_case_is_read_as_that_method() {
        let condition: PolicyCondition = serde_json::from_str(r#"{"MethodIn":["get"]}"#).unwrap();

        assert!(matches!(condition, PolicyCondition::MethodIn(m) if m == [HttpMethod::Get]));
    }

    /// A stored condition names the method `FETCH`, which does not exist.
    /// Reading it is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_word_that_is_no_method_is_refused() {
        assert!(serde_json::from_str::<PolicyCondition>(r#"{"MethodIn":["FETCH"]}"#).is_err());
    }

    /// Deserializing a path-prefix condition rejects `/a/../b` while accepting `/admin`.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_path_prefix_is_checked() {
        assert!(serde_json::from_str::<PolicyCondition>(r#"{"PathPrefix":"/a/../b"}"#).is_err());
        assert!(serde_json::from_str::<PolicyCondition>(r#"{"PathPrefix":"/admin"}"#).is_ok());
    }
}
