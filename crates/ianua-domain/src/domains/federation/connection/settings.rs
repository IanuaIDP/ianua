//! What a connection lets its provider do: make accounts, prove addresses,
//! prove factors and fill profile fields.

use crate::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use crate::domains::federation::control::FederationRight;
use crate::domains::federation::vouched_identity::ProviderFactor;

/// Whether signing in through a connection creates an account that does not
/// exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitProvisioning {
    /// The account is created on its first sign-in.
    Enabled,
    /// A sign-in with no matching account is refused.
    Disabled,
}

/// Whether a provider's word on an email address is enough to sign someone
/// in to the existing account with that address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTrust {
    /// The address is only taken as proven when the provider says it
    /// verified it. The default: many providers let a person set their own
    /// address, and taking it on trust would let them sign in as whoever
    /// already has it.
    Unverified,
    /// The provider is the authority for these addresses: its directory
    /// assigns them and its users cannot change them. Set by a federation
    /// admin who knows that to be true of this provider.
    Authoritative,
}

/// Whether a provider's report of how someone signed in there counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceTrust {
    /// What the provider says about factors is not taken: a sign-in through
    /// it counts as a single factor. The default, since nothing stops a
    /// provider from claiming more than it checked.
    Untrusted,
    /// The provider's report of a multi-factor or hardware-key sign-in is
    /// believed. Set by a federation admin who knows the provider enforces
    /// what it reports.
    Trusted,
}

impl EmailTrust {
    /// The right choosing this setting needs. Trusting the provider's
    /// addresses lets it speak for more people. Taking that back only stops
    /// it.
    pub(crate) fn needs(self) -> FederationRight {
        match self {
            Self::Authoritative => FederationRight::TrustConnection,
            Self::Unverified => FederationRight::EditConnection,
        }
    }
}

impl AssuranceTrust {
    /// The right choosing this setting needs. Believing the provider's
    /// factors lets it lift sessions. Taking that back only stops it.
    pub(crate) fn needs(self) -> FederationRight {
        match self {
            Self::Trusted => FederationRight::TrustConnection,
            Self::Untrusted => FederationRight::EditConnection,
        }
    }

    /// The factor a provider's report of `factor` proves under this
    /// setting. An untrusted provider proves none, whatever it reports.
    pub(crate) fn proves(self, factor: ProviderFactor) -> FactorProved {
        match (self, factor) {
            (Self::Trusted, ProviderFactor::HardwareKey) => {
                FactorProved::Proved(MfaFactor::ProviderHardwareKey)
            }
            (Self::Trusted, ProviderFactor::Performed) => {
                FactorProved::Proved(MfaFactor::ProviderMultiFactor)
            }
            (Self::Trusted, ProviderFactor::NotPerformed)
            | (
                Self::Untrusted,
                ProviderFactor::HardwareKey
                | ProviderFactor::Performed
                | ProviderFactor::NotPerformed,
            ) => FactorProved::NoneYet,
        }
    }
}

/// A profile field a provider claim may fill on the account.
///
/// Only these. A claim never fills the address, which needs its own proof,
/// nor a role or a group. Roles and groups come from a provider only
/// through the connection's [`GroupMapping`](crate::domains::federation::connection::GroupMapping),
/// which is off until an admin turns it on, and where every role or group
/// mapped is checked as a grant by the person mapping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileField {
    /// The name shown for the person.
    DisplayName,
    /// The language they read.
    Locale,
    /// The timezone they live in.
    Timezone,
}

impl ProfileField {
    /// The stable name the field is stored and sent under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DisplayName => "display_name",
            Self::Locale => "locale",
            Self::Timezone => "timezone",
        }
    }

    /// The field stored or sent under `s`, or `None` for a name no field
    /// has, such as `email` or `role`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "display_name" => Some(Self::DisplayName),
            "locale" => Some(Self::Locale),
            "timezone" => Some(Self::Timezone),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each profile field is written under its name and read back as
    /// itself, so a stored mapping comes back as it was saved.
    #[test]
    fn a_profile_field_reads_back_from_its_name() {
        for field in [
            ProfileField::DisplayName,
            ProfileField::Locale,
            ProfileField::Timezone,
        ] {
            assert_eq!(ProfileField::parse(field.as_str()), Some(field));
        }
    }

    /// Email, roles, groups and account status are rejected as profile
    /// field names, keeping them outside profile claim mapping.
    #[test]
    fn the_address_and_roles_are_not_profile_fields() {
        for name in ["email", "role", "roles", "groups", "status"] {
            assert_eq!(ProfileField::parse(name), None, "{name}");
        }
    }
}
