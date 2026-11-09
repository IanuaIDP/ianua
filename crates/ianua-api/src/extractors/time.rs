//! Timestamp query-parameter parsing.
//!
//! Shared RFC 3339 parser for query-string timestamps (`since`, `before`,
//! `until`) so every endpoint reads them the same way instead of
//! re-implementing the parse-and-map-to-validation-error dance.

use ianua_domain::message;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::ApiError;

/// Parses an RFC 3339 timestamp from a query string.
///
/// # Errors
///
/// Returns [`ApiError`] as a validation error when `raw` is not a valid
/// RFC 3339 timestamp.
pub(crate) fn parse_rfc3339(raw: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|e| {
        ApiError::validation(message!(
            "api-invalid-timestamp",
            format!("invalid timestamp: {e}")
        ))
    })
}

/// How long a rotated secret keeps working beside its replacement, from a
/// body's `overlap_seconds`: not at all when it is left out, as after a
/// leak.
///
/// # Errors
///
/// Returns [`ApiError`] as a validation error when `seconds` is zero,
/// negative or longer than any lifetime.
pub(crate) fn rotation_overlap(
    seconds: Option<i64>,
) -> Result<ianua_domain::types::RotationOverlap, ApiError> {
    let Some(seconds) = seconds else {
        return Ok(ianua_domain::types::RotationOverlap::Immediate);
    };
    ianua_domain::types::Lifetime::seconds(seconds)
        .map(ianua_domain::types::RotationOverlap::For)
        .map_err(ApiError::validation)
}
