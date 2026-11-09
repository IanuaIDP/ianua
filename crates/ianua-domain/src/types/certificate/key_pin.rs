//! The SHA-256 pin of a public key.

use std::fmt;

use crate::shared::validation::ValidationError;
use crate::types::CertificateFingerprint;

/// The SHA-256 digest of a public key, the bytes a certificate's
/// `subjectPublicKey` holds. It names a key whatever certificate carries
/// it, so a certificate issued again for the same key keeps the same pin.
///
/// It reads and writes as a [`CertificateFingerprint`] does: `sha256:` and
/// 64 lower-case hex digits, also read as colon-separated pairs or plain
/// hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKeyPin([u8; 32]);

impl PublicKeyPin {
    /// The pin with this digest, as a hashing adapter computed it.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Reads a pin written as `sha256:<hex>`, as colon-separated hex pairs,
    /// or as plain hex.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the text is not 32 bytes of hex in one of
    ///   those forms.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        CertificateFingerprint::parse(text).map(|read| Self(*read.digest()))
    }

    /// The 32 SHA-256 bytes used to compare the presented key with the stored pin.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PublicKeyPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&CertificateFingerprint::from_digest(self.0), f)
    }
}

impl fmt::Debug for PublicKeyPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyPin({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    /// A pin read back from how it is written is the same pin.
    #[test]
    fn a_pin_reads_back_from_its_written_form() {
        let pin = PublicKeyPin::parse(HEX).unwrap();

        assert_eq!(pin.to_string(), format!("sha256:{HEX}"));
        assert_eq!(PublicKeyPin::parse(&pin.to_string()).unwrap(), pin);
    }

    /// Text that is not a SHA-256 digest is refused.
    #[test]
    fn a_short_pin_is_refused() {
        assert!(PublicKeyPin::parse("sha256:abcd").is_err());
    }
}
