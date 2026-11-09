//! How a caller is allowed to prove who they are.
//!
//! Tenants and organizations pick from the same set and use the same MFA
//! levels. So these types live here, not inside either one's configuration.

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::message;
use crate::shared::errors::DomainError;

/// Authentication methods an account boundary can enable.
///
/// Each tenant or organization chooses which methods its users may log in
/// with. Sign-in checks this choice before it looks at any credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthMethod {
    /// Email and password.
    Password,

    /// Passwordless login with a link sent by email.
    MagicLink,

    /// Passwordless login with a `WebAuthn` passkey.
    Passkey,

    /// Enterprise SAML federation.
    Saml,

    /// Enterprise OIDC federation.
    Oidc,
}

impl AuthMethod {
    /// The stable name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::MagicLink => "magic_link",
            Self::Passkey => "passkey",
            Self::Saml => "saml",
            Self::Oidc => "oidc",
        }
    }

    /// Whether an identity provider vouches for a sign-in this way.
    #[must_use]
    pub fn is_federated(self) -> bool {
        match self {
            Self::Saml | Self::Oidc => true,
            Self::Password | Self::MagicLink | Self::Passkey => false,
        }
    }

    /// Whether a sign-in this way can ever reach `baseline`, under the
    /// boundary's `mfa` policy.
    ///
    /// | baseline | passkey | single sign-on            | password, magic link |
    /// |----------|---------|---------------------------|----------------------|
    /// | AAL1     | yes     | yes                       | yes                  |
    /// | AAL2     | yes     | yes                       | only with MFA on     |
    /// | AAL3     | yes     | yes, if the provider proves it | no              |
    ///
    /// It agrees with `assurance_level_for`. Wherever this says yes, some
    /// factor the method can be completed with reaches the baseline. So a
    /// method that cannot meet the baseline is never admitted. Passwords and
    /// magic links never reach AAL3, because hardware assurance means a
    /// passkey or a provider that proved a hardware key. Whether one sign-in
    /// really got there is decided when its session is completed, not here.
    ///
    #[must_use]
    pub fn can_reach(self, baseline: AssuranceLevel, mfa: MfaPolicy) -> bool {
        match (baseline, self) {
            (AssuranceLevel::Aal1, _)
            | (
                AssuranceLevel::Aal2 | AssuranceLevel::Aal3,
                Self::Passkey | Self::Saml | Self::Oidc,
            ) => true,
            (AssuranceLevel::Aal2, Self::Password | Self::MagicLink) => mfa != MfaPolicy::Disabled,
            (AssuranceLevel::Aal3, Self::Password | Self::MagicLink) => false,
        }
    }
}

/// Refuses a set of enabled methods when none of them can reach `baseline`
/// under `mfa`.
///
/// A tenant or organization set up that way refuses every sign-in. Then no
/// one could sign in to change it back.
///
/// # Errors
///
/// - [`DomainError::Validation`] when no method can reach the baseline. The
///   message names what would make it reachable.
pub(crate) fn ensure_baseline_reachable(
    methods: &[AuthMethod],
    baseline: AssuranceLevel,
    mfa: MfaPolicy,
) -> Result<(), DomainError> {
    if methods.iter().any(|method| method.can_reach(baseline, mfa)) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "authentication-no-enabled-way-of-signing-in",
        format!(
            "no enabled way of signing in can reach the required assurance ({baseline:?}); \
         enable passkeys or single sign-on, or turn second factors on"
        )
    )))
}

/// Multi-factor authentication policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MfaPolicy {
    /// MFA is not available to these users.
    Disabled,

    /// Users may enroll in MFA if they choose.
    Optional,

    /// All users must complete MFA to authenticate.
    Required,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::mfa_factor::{
        FactorProved, MfaFactor, assurance_level_for,
    };

    const METHODS: [AuthMethod; 5] = [
        AuthMethod::Password,
        AuthMethod::MagicLink,
        AuthMethod::Passkey,
        AuthMethod::Saml,
        AuthMethod::Oidc,
    ];
    const LEVELS: [AssuranceLevel; 3] = [
        AssuranceLevel::Aal1,
        AssuranceLevel::Aal2,
        AssuranceLevel::Aal3,
    ];
    const POLICIES: [MfaPolicy; 3] = [
        MfaPolicy::Disabled,
        MfaPolicy::Optional,
        MfaPolicy::Required,
    ];

    /// The factors a sign-in this way can be completed with under `mfa`: what
    /// the method itself may prove, what a provider may prove, and, with
    /// second factors on, the ones a person sets up.
    fn completions(method: AuthMethod, mfa: MfaPolicy) -> Vec<FactorProved> {
        let mut factors = vec![FactorProved::NoneYet];
        match method {
            AuthMethod::Passkey => factors.push(FactorProved::Proved(MfaFactor::HardwareKey)),
            AuthMethod::Saml | AuthMethod::Oidc => factors.extend([
                FactorProved::Proved(MfaFactor::ProviderMultiFactor),
                FactorProved::Proved(MfaFactor::ProviderHardwareKey),
            ]),
            AuthMethod::Password | AuthMethod::MagicLink => {}
        }
        if mfa != MfaPolicy::Disabled {
            factors.extend([
                FactorProved::Proved(MfaFactor::Totp),
                FactorProved::Proved(MfaFactor::Passkey),
            ]);
        }
        factors
    }

    /// A method is never admitted when every way of completing it falls short
    /// of the baseline. Each "yes" from `can_reach` is backed by
    /// `assurance_level_for`.
    #[test]
    fn every_way_in_the_gate_admits_can_meet_the_baseline() {
        for method in METHODS {
            for baseline in LEVELS {
                for mfa in POLICIES {
                    if !method.can_reach(baseline, mfa) {
                        continue;
                    }
                    let best = completions(method, mfa)
                        .into_iter()
                        .map(|factor| assurance_level_for(method, factor))
                        .max()
                        .unwrap_or(AssuranceLevel::Aal1);
                    assert!(
                        best.satisfies(baseline),
                        "{method:?} at {baseline:?} under {mfa:?} is admitted but reaches only {best:?}"
                    );
                }
            }
        }
    }

    /// Hardware assurance means a passkey, or a provider proving a hardware
    /// key. A password or a magic link never gets there. Single sign-on can.
    #[test]
    fn only_passkeys_and_single_sign_on_can_reach_hardware_assurance() {
        for mfa in POLICIES {
            assert!(!AuthMethod::Password.can_reach(AssuranceLevel::Aal3, mfa));
            assert!(!AuthMethod::MagicLink.can_reach(AssuranceLevel::Aal3, mfa));
            assert!(AuthMethod::Passkey.can_reach(AssuranceLevel::Aal3, mfa));
            assert!(AuthMethod::Saml.can_reach(AssuranceLevel::Aal3, mfa));
        }
    }

    /// With second factors off, a password can never be more than a
    /// password, so it cannot meet a two-factor baseline.
    #[test]
    fn a_password_cannot_meet_two_factors_while_second_factors_are_off() {
        assert!(!AuthMethod::Password.can_reach(AssuranceLevel::Aal2, MfaPolicy::Disabled));
        assert!(AuthMethod::Password.can_reach(AssuranceLevel::Aal2, MfaPolicy::Optional));
    }
}
