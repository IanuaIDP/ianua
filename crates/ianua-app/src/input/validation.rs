//! Input validation helpers for use cases.
//!
//! Validates opaque tokens and codes received from untrusted clients.
//! Prevents oversized input from reaching hashers or storage.

use ianua_domain::shared::validation::{ValidationError, Validator};

use crate::error::AppError;

/// Maximum length for opaque tokens (refresh tokens, auth codes, device codes).
const MAX_TOKEN_LENGTH: usize = 2048;

/// Maximum length for client secrets.
const MAX_SECRET_LENGTH: usize = 512;

/// Maximum length for a code a person types (device user code, TOTP code).
const MAX_SHORT_CODE_LENGTH: usize = 20;

/// Password length bounds.
const PASSWORD_MIN: usize = 8;
const PASSWORD_MAX: usize = 256;

/// PKCE verifier: RFC 7636 requires 43-128 characters, unreserved ASCII.
const PKCE_VERIFIER_MIN: usize = 43;
const PKCE_VERIFIER_MAX: usize = 128;

/// Validates an opaque token (refresh token, auth code, device code).
///
/// # Errors
///
/// Returns `AppError::Domain` if the token is empty or exceeds max length.
pub(crate) fn validate_token(field: &'static str, value: &str) -> Result<(), AppError> {
    Validator::new(field, value)
        .not_empty()
        .length(1..=MAX_TOKEN_LENGTH)
        .validate_first()
        .map_err(invalid_input)
}

/// Validates a client secret.
///
/// # Errors
///
/// Returns `AppError::Domain` if the secret is empty or exceeds max length.
pub(crate) fn validate_secret(field: &'static str, value: &str) -> Result<(), AppError> {
    Validator::new(field, value)
        .not_empty()
        .length(1..=MAX_SECRET_LENGTH)
        .validate_first()
        .map_err(invalid_input)
}

/// Validates a short user-facing code (device authorization user code, TOTP code).
///
/// # Errors
///
/// Returns `AppError::Domain` if the code is empty or exceeds 20 characters.
pub(crate) fn validate_short_code(field: &'static str, value: &str) -> Result<(), AppError> {
    Validator::new(field, value)
        .not_empty()
        .length(1..=MAX_SHORT_CODE_LENGTH)
        .validate_first()
        .map_err(invalid_input)
}

/// Validates a password (minimum 8 characters, maximum 256).
///
/// # Errors
///
/// Returns `AppError::Domain` if the password is too short or too long.
pub(crate) fn validate_password(value: &str) -> Result<(), AppError> {
    Validator::new("password", value)
        .not_empty()
        .length(PASSWORD_MIN..=PASSWORD_MAX)
        .validate_first()
        .map_err(invalid_input)
}

/// Validates a PKCE code verifier (RFC 7636 Section 4.1).
///
/// # Errors
///
/// Returns `AppError::Domain` if the verifier doesn't meet RFC 7636 requirements.
pub(crate) fn validate_pkce_verifier(value: &str) -> Result<(), AppError> {
    Validator::new("code_verifier", value)
        .not_empty()
        .ascii_only()
        .length(PKCE_VERIFIER_MIN..=PKCE_VERIFIER_MAX)
        .validate_first()
        .map_err(invalid_input)
}

/// The error a caller sees for input that fails validation.
fn invalid_input(err: ValidationError) -> AppError {
    AppError::Domain(err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether validation returned a domain refusal.
    fn refused(result: &Result<(), AppError>) -> bool {
        matches!(result, Err(AppError::Domain(_)))
    }

    /// Empty and oversized client secrets fail validation while an ordinary secret passes.
    #[test]
    fn a_secret_must_be_present_and_within_its_limit() {
        assert!(validate_secret("client_secret", "s3cret").is_ok());
        assert!(refused(&validate_secret("client_secret", "")));
        assert!(refused(&validate_secret(
            "client_secret",
            &"s".repeat(MAX_SECRET_LENGTH + 1)
        )));
    }

    /// A device code of twenty characters is accepted. An empty one, or one
    /// of twenty-one, is refused.
    #[test]
    fn a_short_code_must_be_present_and_at_most_twenty_characters() {
        assert!(validate_short_code("user_code", &"C".repeat(20)).is_ok());
        assert!(refused(&validate_short_code("user_code", "")));
        assert!(refused(&validate_short_code("user_code", &"C".repeat(21))));
    }

    /// Ann's password may be 8 to 256 characters long. One character fewer
    /// or more is refused.
    #[test]
    fn a_password_must_be_between_eight_and_two_hundred_fifty_six_characters() {
        assert!(validate_password(&"p".repeat(8)).is_ok());
        assert!(validate_password(&"p".repeat(256)).is_ok());
        assert!(refused(&validate_password(&"p".repeat(7))));
        assert!(refused(&validate_password(&"p".repeat(257))));
    }

    /// A PKCE verifier of the shortest allowed length is accepted. One too
    /// short, one too long, or one with letters outside the allowed set is
    /// refused.
    #[test]
    fn a_pkce_verifier_must_meet_rfc_7636_length_and_charset() {
        assert!(validate_pkce_verifier(&"v".repeat(PKCE_VERIFIER_MIN)).is_ok());
        assert!(refused(&validate_pkce_verifier(
            &"v".repeat(PKCE_VERIFIER_MIN - 1)
        )));
        assert!(refused(&validate_pkce_verifier(
            &"v".repeat(PKCE_VERIFIER_MAX + 1)
        )));
        assert!(refused(&validate_pkce_verifier(
            &"é".repeat(PKCE_VERIFIER_MIN)
        )));
    }
}
