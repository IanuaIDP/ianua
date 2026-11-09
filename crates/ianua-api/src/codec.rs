//! Transport codecs for the HTTP boundary.
//!
//! Encoders and decoders that map between wire formats (base64 text carried
//! over JSON) and domain primitives (raw bytes). Handlers call these rather
//! than inlining codec details, keeping handlers as pure orchestration.

use base64::Engine;
use ianua_domain::message;

use crate::error::ApiError;

/// Encodes raw bytes as URL-safe base64 without padding.
///
/// This is the alphabet WebAuthn uses for challenges, attestation and
/// assertion responses, and credential ids.
pub(crate) fn url_safe_no_pad_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes URL-safe base64 without padding into raw bytes.
///
/// # Errors
///
/// Returns [`ApiError`] as a validation error when `encoded` is not valid
/// URL-safe base64.
pub(crate) fn url_safe_no_pad_decode(encoded: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| {
            ApiError::validation(message!(
                "api-invalid-base64-encoding",
                "invalid base64 encoding"
            ))
        })
}
