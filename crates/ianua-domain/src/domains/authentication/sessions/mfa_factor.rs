//! The specific second factor that satisfied a session's MFA requirement.

use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::assurance::{AssuranceLevel, StrongestFactor};

/// The second factor a sign-in proved.
///
/// This is not the same as a sign-in that owes nothing more. A provider
/// sign-in can be complete with no factor recorded. A live TOTP code and a
/// one-time recovery code both complete a sign-in, at different assurance.
/// This records what proved it. See `SignInProgress::assurance_level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MfaFactor {
    /// An RFC 6238 TOTP code, checked at sign-in.
    Totp,
    /// A one-time code mailed to the account's address and typed back.
    ///
    /// Mail is read on any device, so it proves the mailbox again rather
    /// than a device held. NIST SP 800-63B does not accept it as an
    /// out-of-band authenticator. It answers a second factor a tenant asks
    /// for but adds no assurance, and it answers nothing after a magic link,
    /// which proved the same mailbox.
    EmailCode,
    /// A one-time code texted to the number the factor was set up with.
    /// A restricted authenticator under NIST SP 800-63B: a SIM swap reads
    /// it. It answers a second factor a tenant asks for but adds no
    /// assurance, so it never counts as a strong sign-in.
    SmsCode,
    /// A single-use recovery code. It stands in for the second factor and
    /// does not prove the person holds it.
    RecoveryCode,
    /// A passkey whose authenticator was attested at registration as a
    /// hardware security key, so the key cannot be copied off it. Only this
    /// passkey reaches hardware assurance. A passkey that may be synced does
    /// not.
    HardwareKey,
    /// A passkey used as the second factor, one that may be a synced copy.
    Passkey,
    /// A link sent to the person's verified address, and followed. It proves
    /// the mailbox, not a second factor. It answers a risk signal for someone
    /// who has no factor, and adds no assurance.
    EmailConfirmation,
    /// The identity provider reported a multi-factor sign-in, through a
    /// connection the tenant trusts to report it.
    ProviderMultiFactor,
    /// The identity provider reported a hardware-key sign-in, through a
    /// connection the tenant trusts to report it.
    ProviderHardwareKey,
}

impl MfaFactor {
    /// Whether an identity provider reported this factor, rather than ianua
    /// checking it.
    #[must_use]
    pub fn is_reported_by_provider(self) -> bool {
        match self {
            Self::ProviderMultiFactor | Self::ProviderHardwareKey => true,
            Self::Totp
            | Self::EmailCode
            | Self::SmsCode
            | Self::RecoveryCode
            | Self::HardwareKey
            | Self::Passkey
            | Self::EmailConfirmation => false,
        }
    }

    /// Whether a sign-in can still owe `owed` once this factor was proved.
    /// A recovery code or an email confirmation can leave a factor to set
    /// up. Every other factor settles the sign-in.
    #[must_use]
    pub fn may_leave_owed(self, owed: SecondFactor) -> bool {
        match self {
            Self::RecoveryCode | Self::EmailConfirmation => {
                matches!(owed, SecondFactor::NotOwed | SecondFactor::Enrol)
            }
            Self::Totp
            | Self::EmailCode
            | Self::SmsCode
            | Self::HardwareKey
            | Self::Passkey
            | Self::ProviderMultiFactor
            | Self::ProviderHardwareKey => owed == SecondFactor::NotOwed,
        }
    }
}

/// The second factor a sign-in proved, or that it has proved none yet.
///
/// It is one value, not an optional factor. So "no second factor" is a case
/// that every reader of a sign-in's assurance must name. It is never a
/// missing value that a check could read as "proved".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorProved {
    /// No second factor yet, only the sign-in method.
    NoneYet,
    /// This factor, the strongest proved so far.
    Proved(MfaFactor),
}

impl FactorProved {
    /// The factor a stored column records. An empty column means none yet.
    #[must_use]
    pub fn from_stored(factor: Option<MfaFactor>) -> Self {
        factor.map_or(Self::NoneYet, Self::Proved)
    }

    /// The factor as storage keeps it.
    #[must_use]
    pub fn stored(self) -> Option<MfaFactor> {
        match self {
            Self::NoneYet => None,
            Self::Proved(factor) => Some(factor),
        }
    }
}

/// The assurance level that `auth_method` reaches with the second factor
/// the session recorded, if any.
///
/// This is the one place the mapping lives. `Session::assurance_level` calls
/// it. So does `token_lookup` in `ianua-infra`, which builds the proxy's
/// caller from a small SQL join instead of a full `Session`. So the two
/// always agree.
///
/// | factor recorded                          | level |
/// |------------------------------------------|-------|
/// | `HardwareKey`, `ProviderHardwareKey`     | AAL3  |
/// | `Totp`, `Passkey`, `ProviderMultiFactor` | AAL2  |
/// | none, `RecoveryCode`, `EmailConfirmation`, `EmailCode`, `SmsCode` | AAL2 after a passkey sign-in, otherwise AAL1 |
///
/// A passkey sign-in alone is AAL2. The passkey may be a synced copy, so it
/// reaches hardware assurance only when the session recorded an attested
/// `HardwareKey`. A recovery code stands in for the second factor, and an
/// email confirmation or a mailed code proves only the mailbox, so none of
/// them adds assurance. A texted code is a restricted authenticator a SIM
/// swap reads, so it adds none either: it never meets AAL2, a step-up for a
/// sensitive action, or a policy asking for a strong sign-in. Single
/// sign-on counts for more than a password only when a trusted provider
/// reported the factor. What cannot be shown is never assumed.
#[must_use]
pub(crate) fn assurance_level_for(
    auth_method: AuthMethod,
    mfa_method: FactorProved,
) -> AssuranceLevel {
    let strongest = match mfa_method {
        FactorProved::Proved(MfaFactor::HardwareKey | MfaFactor::ProviderHardwareKey) => {
            StrongestFactor::HardwareMfa
        }
        FactorProved::Proved(
            MfaFactor::Totp | MfaFactor::Passkey | MfaFactor::ProviderMultiFactor,
        ) => StrongestFactor::SoftwareMfa,
        FactorProved::Proved(
            MfaFactor::RecoveryCode
            | MfaFactor::EmailConfirmation
            | MfaFactor::EmailCode
            | MfaFactor::SmsCode,
        )
        | FactorProved::NoneYet => first_factor_alone(auth_method),
    };
    AssuranceLevel::from_factor(strongest)
}

/// What a sign-in method proves with nothing added to it.
fn first_factor_alone(auth_method: AuthMethod) -> StrongestFactor {
    match auth_method {
        AuthMethod::Passkey => StrongestFactor::SoftwareMfa,
        AuthMethod::Password | AuthMethod::MagicLink | AuthMethod::Saml | AuthMethod::Oidc => {
            StrongestFactor::PasswordOrSso
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::owed::Enrolment;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;

    const METHODS: [AuthMethod; 5] = [
        AuthMethod::Password,
        AuthMethod::MagicLink,
        AuthMethod::Passkey,
        AuthMethod::Saml,
        AuthMethod::Oidc,
    ];

    /// The common sign-ins keep their levels. A password alone or with a
    /// recovery code is AAL1, with TOTP AAL2, and a passkey alone AAL2.
    /// A change to the mapping that moves one of them fails here.
    #[test]
    fn the_long_standing_answers_hold() {
        password_assurance();
        provider_assurance();
        passkey_assurance();
    }

    /// Passwords reach AAL2 with TOTP and remain at AAL1 with recovery codes.
    fn password_assurance() {
        assert_eq!(
            assurance_level_for(AuthMethod::Password, FactorProved::NoneYet),
            AssuranceLevel::Aal1
        );
        assert_eq!(
            assurance_level_for(AuthMethod::Password, FactorProved::Proved(MfaFactor::Totp)),
            AssuranceLevel::Aal2
        );
        assert_eq!(
            assurance_level_for(
                AuthMethod::Password,
                FactorProved::Proved(MfaFactor::RecoveryCode)
            ),
            AssuranceLevel::Aal1
        );
    }

    /// A provider sign-in reaches AAL2 only once a second factor is proved.
    fn provider_assurance() {
        assert_eq!(
            assurance_level_for(AuthMethod::Saml, FactorProved::NoneYet),
            AssuranceLevel::Aal1
        );
        assert_eq!(
            assurance_level_for(AuthMethod::Oidc, FactorProved::Proved(MfaFactor::Totp)),
            AssuranceLevel::Aal2
        );
    }

    /// A passkey reaches AAL2, while an attested hardware key reaches AAL3.
    fn passkey_assurance() {
        assert_eq!(
            assurance_level_for(AuthMethod::Passkey, FactorProved::NoneYet),
            AssuranceLevel::Aal2
        );
        assert_eq!(
            assurance_level_for(
                AuthMethod::Passkey,
                FactorProved::Proved(MfaFactor::HardwareKey)
            ),
            AssuranceLevel::Aal3
        );
    }

    /// An attested hardware key gives AAL3 whatever the first step was,
    /// password, magic link, passkey or single sign-on.
    #[test]
    fn a_hardware_key_reaches_aal3_after_any_first_factor() {
        for method in METHODS {
            assert_eq!(
                assurance_level_for(method, FactorProved::Proved(MfaFactor::HardwareKey)),
                AssuranceLevel::Aal3,
                "{method:?}"
            );
        }
    }

    /// Email confirmation leaves every sign-in method at its initial assurance level.
    #[test]
    fn an_email_confirmation_adds_no_assurance() {
        for method in METHODS {
            assert_eq!(
                assurance_level_for(method, FactorProved::Proved(MfaFactor::EmailConfirmation)),
                assurance_level_for(method, FactorProved::NoneYet),
                "{method:?}"
            );
        }
    }

    /// A mailed code does not increase the assurance of any sign-in method.
    #[test]
    fn a_mailed_code_adds_no_assurance() {
        for method in METHODS {
            assert_eq!(
                assurance_level_for(method, FactorProved::Proved(MfaFactor::EmailCode)),
                assurance_level_for(method, FactorProved::NoneYet),
                "{method:?}"
            );
        }
    }

    /// A texted code does not increase the assurance of any sign-in method.
    #[test]
    fn a_texted_code_adds_no_assurance() {
        for method in METHODS {
            assert_eq!(
                assurance_level_for(method, FactorProved::Proved(MfaFactor::SmsCode)),
                assurance_level_for(method, FactorProved::NoneYet),
                "{method:?}"
            );
        }
    }

    /// For a sensitive action, a password with a texted code falls short;
    /// a password with an authenticator-app code meets the policy.
    #[test]
    fn a_texted_code_never_passes_a_sensitive_step_up() {
        let policy = StepUpPolicy::relaxed();
        let with = |factor| {
            let reached = assurance_level_for(AuthMethod::Password, FactorProved::Proved(factor));
            policy.admits_sensitive_action(reached, Enrolment::Enrolled)
        };

        assert!(with(MfaFactor::SmsCode).is_err());
        assert!(with(MfaFactor::Totp).is_ok());
    }

    /// A password followed by a passkey that may be synced reaches AAL2, not
    /// AAL3.
    #[test]
    fn a_passkey_as_second_factor_is_aal2() {
        assert_eq!(
            assurance_level_for(
                AuthMethod::Password,
                FactorProved::Proved(MfaFactor::Passkey)
            ),
            AssuranceLevel::Aal2
        );
    }

    /// A trusted SAML provider reports multi-factor and the session reaches
    /// AAL2. A trusted OIDC provider reports a hardware key and it reaches
    /// AAL3.
    #[test]
    fn single_sign_on_counts_only_what_a_trusted_provider_proved() {
        assert_eq!(
            assurance_level_for(
                AuthMethod::Saml,
                FactorProved::Proved(MfaFactor::ProviderMultiFactor)
            ),
            AssuranceLevel::Aal2
        );
        assert_eq!(
            assurance_level_for(
                AuthMethod::Oidc,
                FactorProved::Proved(MfaFactor::ProviderHardwareKey)
            ),
            AssuranceLevel::Aal3
        );
    }
}
