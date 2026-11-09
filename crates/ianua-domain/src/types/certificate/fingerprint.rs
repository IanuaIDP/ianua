//! The SHA-256 fingerprint of a certificate.

use std::fmt;

use crate::message;
use crate::shared::validation::ValidationError;

/// The SHA-256 digest of a certificate's DER encoding. It names a client
/// certificate, an LDAP client's certificate or a service's certificate.
///
/// It holds the 32 bytes, so two fingerprints are compared by digest and
/// never by how they were written. It reads `sha256:<hex>`, colon-separated
/// hex pairs or plain hex, in either case. It is always written as
/// `sha256:` and 64 lower-case hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct CertificateFingerprint([u8; 32]);

/// The prefix the written form carries.
const PREFIX: &str = "sha256:";

impl CertificateFingerprint {
    /// The fingerprint with this digest, as a hashing adapter computed it.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Reads a fingerprint written as `sha256:<hex>`, as colon-separated hex
    /// pairs, or as plain hex.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the text is not 32 bytes of hex in one of
    ///   those forms.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        let hex = text.strip_prefix(PREFIX).unwrap_or(text);
        let digits: String = if hex.contains(':') {
            colon_pairs(hex).ok_or_else(invalid)?
        } else {
            hex.to_owned()
        };
        decode_hex(&digits).map(Self).ok_or_else(invalid)
    }

    /// The 32 SHA-256 bytes used for certificate equality, independent of textual spelling.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The digits of hex written in colon-separated pairs, when every group is
/// a pair.
fn colon_pairs(text: &str) -> Option<String> {
    text.split(':')
        .all(|pair| pair.len() == 2)
        .then(|| text.replace(':', ""))
}

/// Decodes exactly 32 bytes of hexadecimal after validating every input digit.
fn decode_hex(digits: &str) -> Option<[u8; 32]> {
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0u8; 32];
    let (pairs, _) = digits.as_bytes().as_chunks::<2>();
    for (byte, pair) in digest.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

/// Explains the accepted digest forms without exposing any credential material.
fn invalid() -> ValidationError {
    ValidationError::Custom {
        field: "certificate_fingerprint",
        code: "invalid_fingerprint".to_owned(),
        message: message!(
            "values-certificate-fingerprint-must-be-a-sha",
            "certificate_fingerprint must be a SHA-256 digest: `sha256:` and 64 hex \
                  digits, or 32 colon-separated hex pairs."
        ),
    }
}

impl TryFrom<String> for CertificateFingerprint {
    type Error = ValidationError;

    /// Reads every form [`parse`](Self::parse) does, so a fingerprint stored
    /// in any of them loads.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<CertificateFingerprint> for String {
    fn from(fingerprint: CertificateFingerprint) -> Self {
        fingerprint.to_string()
    }
}

impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PREFIX)?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateFingerprint({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fn colon(hex: &str) -> String {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":")
    }

    /// One digest is written with `sha256:`, as plain hex, as colon pairs
    /// and as upper-case colon pairs. All four read as the same fingerprint.
    #[test]
    fn every_written_form_reads_as_the_same_digest() {
        let canonical = CertificateFingerprint::parse(&format!("sha256:{HEX}")).unwrap();

        assert_eq!(CertificateFingerprint::parse(HEX).unwrap(), canonical);
        assert_eq!(
            CertificateFingerprint::parse(&colon(HEX)).unwrap(),
            canonical
        );
        assert_eq!(
            CertificateFingerprint::parse(&colon(&HEX.to_uppercase())).unwrap(),
            canonical
        );
    }

    /// A fingerprint read from upper-case colon pairs is written back as
    /// `sha256:` and lower-case hex.
    #[test]
    fn a_fingerprint_is_written_as_sha256_and_lower_case_hex() {
        let fingerprint = CertificateFingerprint::parse(&colon(&HEX.to_uppercase())).unwrap();

        assert_eq!(fingerprint.to_string(), format!("sha256:{HEX}"));
    }

    /// A fingerprint made from a digest gives back that digest. Its written
    /// form parses back to the same fingerprint.
    #[test]
    fn a_digest_reads_back_as_itself() {
        let fingerprint = CertificateFingerprint::from_digest([7; 32]);

        assert_eq!(fingerprint.digest(), &[7; 32]);
        assert_eq!(
            CertificateFingerprint::parse(&fingerprint.to_string()).unwrap(),
            fingerprint
        );
    }

    /// Empty text, a bare prefix, 31 or 33 bytes, non-hex letters, three
    /// pairs, doubled colons and a base64 digest are all refused.
    #[test]
    fn anything_but_32_bytes_of_hex_is_refused() {
        for text in [
            "",
            "sha256:",
            &HEX[..62],
            &format!("{HEX}00"),
            &HEX.replace('a', "g"),
            "ab:cd:ef",
            &format!("sha256:{}", colon(HEX).replace(':', "::")),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
        ] {
            assert!(
                CertificateFingerprint::parse(text).is_err(),
                "{text:?} was accepted"
            );
        }
    }
}
