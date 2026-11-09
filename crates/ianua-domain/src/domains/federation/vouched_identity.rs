//! What an external identity provider vouches for when it signs someone in,
//! the same whether it answered over OIDC or SAML.

use crate::types::{ConnectionId, Email, Fact, FederatedSubject};

/// Whether the provider says it checked that the email address belongs to
/// the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderEmailVerification {
    /// The provider says it verified the address.
    Confirmed,
    /// The provider says the address is not verified.
    Denied,
    /// The provider says nothing either way. SAML never does, and many OIDC
    /// providers leave the claim out.
    Unstated,
}

impl ProviderEmailVerification {
    /// Reads OIDC's `email_verified` claim.
    #[must_use]
    pub fn from_claim(email_verified: Option<bool>) -> Self {
        match email_verified {
            Some(true) => Self::Confirmed,
            Some(false) => Self::Denied,
            None => Self::Unstated,
        }
    }
}

/// Whether the provider says the person proved a second factor when they
/// signed in there, and how strong it was.
///
/// This is only what the provider claims. The connection decides whether
/// ianua believes it, in `FederatedIdpConnection::proven_factor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFactor {
    /// The provider reports a multi-factor sign-in that used a hardware key.
    HardwareKey,
    /// The provider reports a multi-factor sign-in.
    Performed,
    /// The provider reports nothing that amounts to one.
    NotPerformed,
}

/// SAML authentication context classes that mean a hardware key was held
/// and unlocked, such as a smartcard and its PIN.
///
/// Only `SmartcardPKI` is listed, because its definition requires the PIN.
/// Plain `Smartcard` says a card was shown and nothing about unlocking it.
/// That is one factor, so it counts as no second factor.
const HARDWARE_KEY_SAML_CONTEXTS: [&str; 1] =
    ["urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"];

/// SAML authentication context classes that mean more than one factor. These
/// are the ones the major providers send for a multi-factor sign-in.
const MULTI_FACTOR_SAML_CONTEXTS: [&str; 5] = [
    "http://schemas.microsoft.com/claims/multipleauthn",
    "https://refeds.org/profile/mfa",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
];

impl ProviderFactor {
    /// Reads OIDC's `amr` claim from RFC 8176. Only `mfa` counts as more than
    /// one factor, because the other values name single methods. A hardware
    /// key is `hwk` together with `mfa`. `hwk` alone is one method, not two.
    #[must_use]
    pub fn from_oidc_amr(amr: &[String]) -> Self {
        let says = |value: &str| amr.iter().any(|method| method == value);
        match (says("mfa"), says("hwk")) {
            (true, true) => Self::HardwareKey,
            (true, false) => Self::Performed,
            (false, true | false) => Self::NotPerformed,
        }
    }

    /// Reads a SAML assertion's `AuthnContextClassRef`. An unknown or absent
    /// class counts as a single factor.
    #[must_use]
    pub fn from_saml_context(class_ref: Fact<&str>) -> Self {
        match class_ref {
            Fact::Known(class) if HARDWARE_KEY_SAML_CONTEXTS.contains(&class) => Self::HardwareKey,
            Fact::Known(class) if MULTI_FACTOR_SAML_CONTEXTS.contains(&class) => Self::Performed,
            Fact::Known(_) | Fact::Unknown => Self::NotPerformed,
        }
    }
}

/// What a provider vouched for about the person signing in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VouchedIdentity {
    connection_id: ConnectionId,
    subject: FederatedSubject,
    email: Email,
    email_verification: ProviderEmailVerification,
    factor: ProviderFactor,
}

/// The facts a [`VouchedIdentity`] is made from.
pub struct VouchedFacts {
    /// The connection the provider answered through.
    pub connection_id: ConnectionId,
    /// Who the person is at the provider.
    pub subject: FederatedSubject,
    /// The address the provider gave for them.
    pub email: Email,
    /// Whether the provider says it verified that address.
    pub email_verification: ProviderEmailVerification,
    /// Whether the provider says a second factor was proved.
    pub factor: ProviderFactor,
}

impl VouchedIdentity {
    /// The identity `facts` describe.
    #[must_use]
    pub fn new(facts: VouchedFacts) -> Self {
        let VouchedFacts {
            connection_id,
            subject,
            email,
            email_verification,
            factor,
        } = facts;
        Self {
            connection_id,
            subject,
            email,
            email_verification,
            factor,
        }
    }

    /// The connection the provider answered through. Only that connection's
    /// trust settings and domains apply to what it vouched for.
    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Who the person is at the provider.
    #[must_use]
    pub fn subject(&self) -> &FederatedSubject {
        &self.subject
    }

    /// The address the provider gave for them.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// Whether the provider says it verified that address.
    #[must_use]
    pub fn email_verification(&self) -> ProviderEmailVerification {
        self.email_verification
    }

    /// Whether the provider says a second factor was proved.
    #[must_use]
    pub fn factor(&self) -> ProviderFactor {
        self.factor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amr(methods: &[&str]) -> Vec<String> {
        methods.iter().map(|m| (*m).to_owned()).collect()
    }

    /// An OIDC token says `email_verified: true`, `false`, or leaves it out.
    /// These read as confirmed, denied and unstated, so a missing claim is
    /// never taken as a yes.
    #[test]
    fn the_email_verified_claim_reads_as_confirmed_denied_or_unstated() {
        assert_eq!(
            ProviderEmailVerification::from_claim(Some(true)),
            ProviderEmailVerification::Confirmed
        );
        assert_eq!(
            ProviderEmailVerification::from_claim(Some(false)),
            ProviderEmailVerification::Denied
        );
        assert_eq!(
            ProviderEmailVerification::from_claim(None),
            ProviderEmailVerification::Unstated
        );
    }

    /// A token whose `amr` is password plus `mfa` reads as two factors.
    /// Password plus `otp`, or an empty `amr`, reads as one. Only `mfa`
    /// says the provider checked more than one factor.
    #[test]
    fn an_oidc_sign_in_counts_as_two_factors_only_when_amr_says_mfa() {
        assert_eq!(
            ProviderFactor::from_oidc_amr(&amr(&["pwd", "mfa"])),
            ProviderFactor::Performed
        );
        assert_eq!(
            ProviderFactor::from_oidc_amr(&amr(&["pwd", "otp"])),
            ProviderFactor::NotPerformed
        );
        assert_eq!(
            ProviderFactor::from_oidc_amr(&[]),
            ProviderFactor::NotPerformed
        );
    }

    /// Microsoft's `multipleauthn` class reads as two factors. A password
    /// class or no class at all reads as one.
    #[test]
    fn a_saml_sign_in_counts_as_two_factors_only_for_a_known_multi_factor_class() {
        assert_eq!(
            ProviderFactor::from_saml_context(Fact::Known(
                "http://schemas.microsoft.com/claims/multipleauthn"
            )),
            ProviderFactor::Performed
        );
        assert_eq!(
            ProviderFactor::from_saml_context(Fact::Known(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            )),
            ProviderFactor::NotPerformed
        );
        assert_eq!(
            ProviderFactor::from_saml_context(Fact::Unknown),
            ProviderFactor::NotPerformed
        );
    }

    /// `hwk` with `mfa`, and SAML's `SmartcardPKI`, read as a hardware key.
    /// `hwk` alone names one method and reads as no second factor.
    #[test]
    fn a_hardware_key_is_read_only_with_more_than_one_factor() {
        assert_eq!(
            ProviderFactor::from_oidc_amr(&amr(&["hwk", "mfa"])),
            ProviderFactor::HardwareKey
        );
        assert_eq!(
            ProviderFactor::from_oidc_amr(&amr(&["hwk"])),
            ProviderFactor::NotPerformed
        );
        assert_eq!(
            ProviderFactor::from_saml_context(Fact::Known(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
            )),
            ProviderFactor::HardwareKey
        );
    }

    /// SAML's plain Smartcard context reports no second factor because it
    /// does not establish that the card was unlocked with a PIN.
    #[test]
    fn a_smartcard_without_its_pin_is_not_a_second_factor() {
        assert_eq!(
            ProviderFactor::from_saml_context(Fact::Known(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
            )),
            ProviderFactor::NotPerformed
        );
    }
}
