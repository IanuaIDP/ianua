//! The keys a SAML connection trusts and holds: the provider's signing
//! certificates, and this platform's own key for assertions sealed to it.

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CertificatePem, SealedSecret, Setting};

/// The certificates a provider's answers may be signed with: the current
/// one, and the next one while the provider rolls its key over.
///
/// An answer signed with either is taken while both are set. So a provider
/// that publishes its next certificate ahead of the switch signs nobody
/// out on the day it switches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpCertificates {
    current: CertificatePem,
    next: Setting<CertificatePem>,
}

impl IdpCertificates {
    /// Only `current`.
    #[must_use]
    pub fn single(current: CertificatePem) -> Self {
        Self {
            current,
            next: Setting::Unset,
        }
    }

    /// `current`, and `next` taken beside it until the provider switches.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `next` is `current` again.
    pub fn rolling_over(
        current: CertificatePem,
        next: CertificatePem,
    ) -> Result<Self, DomainError> {
        if next == current {
            return Err(DomainError::invalid(message!(
                "federation-the-next-certificate-is-the-current",
                "the next certificate is the current one; name a new one"
            )));
        }
        Ok(Self {
            current,
            next: Setting::Set(next),
        })
    }

    /// The certificate the provider signs with now.
    #[must_use]
    pub fn current(&self) -> &CertificatePem {
        &self.current
    }

    /// The certificate it will sign with next, while it rolls over.
    #[must_use]
    pub fn upcoming(&self) -> Option<&CertificatePem> {
        self.next.value()
    }

    /// Every certificate an answer may be signed with.
    pub fn accepted(&self) -> impl Iterator<Item = &CertificatePem> {
        std::iter::once(&self.current).chain(self.next.value())
    }

    /// Whether an answer signed with `certificate` is taken.
    #[must_use]
    pub fn accepts(&self, certificate: &CertificatePem) -> bool {
        self.accepted().any(|accepted| accepted == certificate)
    }

    /// The next certificate as the only one, once the provider switched.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when no next certificate is set.
    pub fn rolled_over(&self) -> Result<Self, DomainError> {
        let Some(next) = self.next.value() else {
            return Err(DomainError::conflict(message!(
                "federation-no-next-certificate-is-set-to",
                "no next certificate is set to roll over to"
            )));
        };
        Ok(Self::single(next.clone()))
    }

    /// Whether these take a certificate `before` did not: someone new may
    /// now sign answers.
    pub(crate) fn adds_beyond(&self, before: &Self) -> bool {
        self.accepted()
            .any(|certificate| !before.accepts(certificate))
    }
}

/// Whether this platform signs the sign-in requests it sends a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthnRequestSigning {
    /// Requests go unsigned. Most providers take them.
    Unsigned,
    /// Requests are signed with the tenant's signing key, and the
    /// metadata says so, for a provider that answers only signed ones.
    Signed,
}

/// This platform's key for assertions a provider encrypts to it.
///
/// The private key is sealed by the platform before it is stored, whether
/// the platform made the pair or the tenant uploaded it. The certificate
/// is published in this platform's metadata, for the provider to encrypt
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpEncryptionKey {
    certificate: CertificatePem,
    sealed_private_key: SealedSecret,
}

impl SpEncryptionKey {
    /// The pair of `certificate` and the private key sealed as
    /// `sealed_private_key`.
    #[must_use]
    pub fn new(certificate: CertificatePem, sealed_private_key: SealedSecret) -> Self {
        Self {
            certificate,
            sealed_private_key,
        }
    }

    /// The certificate published for the provider to encrypt to.
    #[must_use]
    pub fn certificate(&self) -> &CertificatePem {
        &self.certificate
    }

    /// The private key, sealed. Only the crypto adapter opens it.
    #[must_use]
    pub fn sealed_private_key(&self) -> &SealedSecret {
        &self.sealed_private_key
    }
}

/// Whether a provider's assertions must come encrypted to this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionDecryption {
    /// Assertions come signed but readable.
    NotExpected,
    /// Assertions must come encrypted to this key. A readable one is
    /// refused, since the browser it passed through could read and keep
    /// it.
    Required(SpEncryptionKey),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(body: &str) -> CertificatePem {
        CertificatePem::new(format!(
            "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
        ))
        .unwrap()
    }

    /// Okta publishes its next certificate ahead of the switch. Answers
    /// signed with either are taken until then.
    #[test]
    fn both_certificates_are_taken_while_rolling_over() {
        let certificates =
            IdpCertificates::rolling_over(certificate("MIIC"), certificate("MIID")).unwrap();

        assert!(certificates.accepts(&certificate("MIIC")));
        assert!(certificates.accepts(&certificate("MIID")));
        assert!(!certificates.accepts(&certificate("MIIE")));
    }

    /// Once Okta switched, the next certificate becomes the only one, and
    /// the old one is no longer taken.
    #[test]
    fn rolling_over_drops_the_old_certificate() {
        let certificates =
            IdpCertificates::rolling_over(certificate("MIIC"), certificate("MIID")).unwrap();

        let rolled = certificates.rolled_over().unwrap();

        assert_eq!(rolled.current(), &certificate("MIID"));
        assert!(!rolled.accepts(&certificate("MIIC")));
    }

    /// With no next certificate set there is nothing to roll over to.
    #[test]
    fn rolling_over_without_a_next_certificate_is_refused() {
        let result = IdpCertificates::single(certificate("MIIC")).rolled_over();

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// The same certificate given as current and next is refused, since it
    /// would roll over to itself.
    #[test]
    fn the_next_certificate_must_differ_from_the_current_one() {
        let result = IdpCertificates::rolling_over(certificate("MIIC"), certificate("MIIC"));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Adding a next certificate lets someone new sign; rolling over to it
    /// does not, since it was already taken.
    #[test]
    fn only_a_new_certificate_adds_a_signer() {
        let single = IdpCertificates::single(certificate("MIIC"));
        let rolling =
            IdpCertificates::rolling_over(certificate("MIIC"), certificate("MIID")).unwrap();

        assert!(rolling.adds_beyond(&single));
        assert!(!rolling.rolled_over().unwrap().adds_beyond(&rolling));
    }

    /// The encryption key prints without its sealed private key.
    #[test]
    fn the_encryption_key_never_prints_its_private_key() {
        let key = SpEncryptionKey::new(
            certificate("MIIC"),
            SealedSecret::new("v1.secretbytes").unwrap(),
        );

        assert!(!format!("{key:?}").contains("secretbytes"));
    }
}
