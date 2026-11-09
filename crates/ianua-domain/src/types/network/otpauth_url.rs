use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    redacted
    /// An `otpauth://` URI for TOTP enrollment.
    ///
    /// It carries the TOTP seed in its `secret` parameter, so it never
    /// prints. Whoever reads it from a log holds the second factor.
    ///
    /// It becomes the QR code an authenticator app scans. It follows the
    /// Google Authenticator Key URI Format.
    ///
    /// Rules:
    /// - Not empty.
    /// - ASCII only.
    /// - 15 to 2048 characters.
    /// - No control characters or whitespace.
    /// - Starts with `otpauth://totp/`.
    pub struct OtpauthUrl;
}

impl TextValue for OtpauthUrl {
    const FIELD: &'static str = "otpauth_url";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .ascii_only()
            .length(15..=2048)
            .no_control_chars()
            .no_whitespace()
            .rule(&TotpScheme)
    }
}

/// The `otpauth://totp/` prefix an authenticator app reads.
struct TotpScheme;

impl Rule for TotpScheme {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value.starts_with("otpauth://totp/") {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "otpauth_scheme_required".to_owned(),
            message: message!(
                "values-url-must-use-otpauth-totp-scheme",
                "URL must use otpauth://totp/ scheme."
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Alice's enrollment URI, `otpauth://totp/Ianua:alice@acme.com` with a
    /// secret and issuer, is accepted.
    #[test]
    fn accepts_valid_otpauth_uri() {
        let url = OtpauthUrl::new(
            "otpauth://totp/Ianua:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=Ianua",
        )
        .unwrap();
        assert!(url.as_str().starts_with("otpauth://totp/"));
    }

    /// A web address, `https://example.com`, is refused. An authenticator
    /// app cannot enroll from it.
    #[test]
    fn https_addresses_cannot_enroll_authenticators() {
        assert!(OtpauthUrl::new("https://example.com").is_err());
    }

    /// An empty setup link is refused before authenticator enrollment.
    #[test]
    fn an_empty_enrollment_uri_is_refused() {
        assert!(OtpauthUrl::new("").is_err());
    }

    /// An `otpauth://hotp/` URI is refused. Only time-based codes are
    /// enrolled.
    #[test]
    fn rejects_plain_otpauth_without_totp() {
        assert!(OtpauthUrl::new("otpauth://hotp/Test:user?secret=ABC").is_err());
    }

    /// Debug formatting hides the enrollment seed while the full URI remains
    /// available through the accessor for a QR code.
    #[test]
    fn the_seed_never_prints() {
        let url =
            OtpauthUrl::new("otpauth://totp/Ianua:bob@acme.com?secret=ABC&issuer=Ianua").unwrap();

        assert!(!format!("{url:?}").contains("ABC"));
        assert_eq!(
            url.as_str(),
            "otpauth://totp/Ianua:bob@acme.com?secret=ABC&issuer=Ianua"
        );
    }
}
