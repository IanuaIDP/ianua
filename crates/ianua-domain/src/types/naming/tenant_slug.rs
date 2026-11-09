use std::fmt;

use crate::message;
use crate::shared::config::SlugLimits;
use crate::shared::validation::{ValidationError, Validator};

/// The URL-safe slug that names a tenant in subdomains and API paths.
///
/// For example, `"acme"` in `acme.ianua.example.com` or
/// `/v1/tenants/acme/...`.
///
/// It follows the DNS subdomain rules of RFC 952:
/// - Its length is within the bounds of [`SlugLimits`].
/// - Lowercase letters, digits and hyphens only.
/// - It starts and ends with a letter or digit.
/// - No two hyphens in a row.
/// - It is not one of the slugs kept for platform hosts, such as `api` or
///   `www`.
///
/// This type only checks a slug. Making one from a display name, such as
/// `"Acme Corporation"` into `"acme-corporation"`, belongs in the
/// application layer.
///
/// # Examples
///
/// ```
/// # use ianua_domain::types::TenantSlug;
/// # use ianua_domain::shared::config::SlugLimits;
/// let limits = SlugLimits::default();
/// let slug = TenantSlug::new("acme", &limits).unwrap();
/// assert_eq!(slug.as_str(), "acme");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
pub struct TenantSlug(String);

impl TryFrom<String> for TenantSlug {
    type Error = ValidationError;

    /// Reading JSON goes through [`TenantSlug::new`] with the default
    /// limits, so a reserved or malformed slug cannot arrive as JSON.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value, &SlugLimits::default())
    }
}

impl TenantSlug {
    /// Checks a string already in slug form against `limits`.
    ///
    /// The input is already a slug, such as one from a database row or a URL
    /// path segment. Nothing is reshaped.
    ///
    /// # Errors
    ///
    /// Returns the first [`ValidationError`] for non-ASCII text, length outside
    /// `limits`, characters other than lowercase letters/digits/hyphens, leading or
    /// trailing hyphens, consecutive hyphens, or a reserved slug.
    pub fn new(value: impl Into<String>, limits: &SlugLimits) -> Result<Self, ValidationError> {
        let value = value.into();

        Validator::new("slug", &value)
            .slug(limits)
            .validate_first()?;

        if RESERVED_SLUGS.contains(&value.as_str()) {
            return Err(reserved_error(&value));
        }

        Ok(Self(value))
    }

    /// The slug as text, for URLs, headers and database queries.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Slugs kept for platform subdomains and routes.
///
/// A tenant or organization may not claim any of these. Each would take the
/// name of a platform host, such as `api.ianua.io` or the marketing site.
const RESERVED_SLUGS: &[&str] = &[
    "api",
    "app",
    "www",
    "admin",
    "dashboard",
    "auth",
    "login",
    "logout",
    "account",
    "settings",
    "billing",
    "mail",
    "smtp",
    "imap",
    "mx",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "ftp",
    "gateway",
    "proxy",
    "cdn",
    "static",
    "assets",
    "media",
    "status",
    "health",
    "metrics",
    "docs",
    "blog",
    "help",
    "support",
    "about",
    "pricing",
    "contact",
    "internal",
    "system",
    "root",
    "webhooks",
    "ws",
    "grpc",
    "ianua",
];

/// The error for a reserved slug.
fn reserved_error(value: &str) -> ValidationError {
    ValidationError::Custom {
        field: "slug",
        code: "reserved_slug".to_owned(),
        message: message!(
            "values-is-reserved-and-cannot-be-used",
            format!("'{value}' is reserved and cannot be used")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SlugLimits {
        SlugLimits::default()
    }

    /// Slugs such as `acme`, `globex-corp`, `tenant123` and `a1` are all
    /// accepted.
    #[test]
    fn accepts_valid_slugs() {
        let l = limits();
        let valid = [
            "acme",
            "globex-corp",
            "tenant123",
            "a1",
            "my-long-tenant-name",
        ];
        for slug in valid {
            assert!(TenantSlug::new(slug, &l).is_ok(), "expected valid: {slug}");
        }
    }

    /// A two-character slug, the default minimum, is accepted.
    #[test]
    fn accepts_at_min_length() {
        assert!(TenantSlug::new("ab", &limits()).is_ok());
    }

    /// Platform host names such as `api` are refused with `reserved_slug`
    /// rather than made available as tenant addresses.
    #[test]
    fn rejects_reserved_slugs() {
        let l = limits();
        for slug in ["api", "app", "www", "admin", "ianua", "webhooks"] {
            let err = TenantSlug::new(slug, &l).expect_err(slug);
            assert_eq!(err.code(), "reserved_slug");
        }
    }

    /// A 63-character slug, the default maximum and the DNS label limit, is
    /// accepted.
    #[test]
    fn accepts_at_max_length() {
        let max = "a".repeat(63);
        assert!(TenantSlug::new(max, &limits()).is_ok());
    }

    /// A one-character slug is refused as too short.
    #[test]
    fn rejects_too_short() {
        assert!(matches!(
            TenantSlug::new("a", &limits()),
            Err(ValidationError::Length { actual: 1, .. })
        ));
    }

    /// An empty slug is refused as too short.
    #[test]
    fn empty_slugs_report_their_zero_length() {
        assert!(matches!(
            TenantSlug::new("", &limits()),
            Err(ValidationError::Length { actual: 0, .. })
        ));
    }

    /// A 64-character slug is refused as too long.
    #[test]
    fn rejects_one_over_max_length() {
        let over = "a".repeat(64);
        assert!(matches!(
            TenantSlug::new(over, &limits()),
            Err(ValidationError::Length { actual: 64, .. })
        ));
    }

    /// `ACME` in capitals is refused for its characters, not lowered.
    #[test]
    fn uppercase_slugs_report_invalid_characters() {
        assert!(matches!(
            TenantSlug::new("ACME", &limits()),
            Err(ValidationError::InvalidCharacters { .. })
        ));
    }

    /// `ac me` with a space is refused for its characters.
    #[test]
    fn spaces_in_slugs_report_invalid_characters() {
        assert!(matches!(
            TenantSlug::new("ac me", &limits()),
            Err(ValidationError::InvalidCharacters { .. })
        ));
    }

    /// `-acme` starts with a hyphen and is refused.
    #[test]
    fn rejects_leading_hyphen() {
        assert!(matches!(
            TenantSlug::new("-acme", &limits()),
            Err(ValidationError::InvalidBoundary { .. })
        ));
    }

    /// `acme-` ends with a hyphen and is refused.
    #[test]
    fn rejects_trailing_hyphen() {
        assert!(matches!(
            TenantSlug::new("acme-", &limits()),
            Err(ValidationError::InvalidBoundary { .. })
        ));
    }

    /// `my--tenant` with two hyphens in a row is refused.
    #[test]
    fn rejects_consecutive_hyphens() {
        assert!(TenantSlug::new("my--tenant", &limits()).is_err());
    }

    /// `café` is refused as not ASCII.
    #[test]
    fn rejects_unicode_characters() {
        assert!(matches!(
            TenantSlug::new("café", &limits()),
            Err(ValidationError::NotAscii { .. })
        ));
    }

    /// A slug with an emoji is refused as not ASCII.
    #[test]
    fn emoji_in_slugs_report_non_ascii() {
        assert!(matches!(
            TenantSlug::new("team👋", &limits()),
            Err(ValidationError::NotAscii { .. })
        ));
    }

    /// A zero-width space in a tenant slug produces a non-ASCII error instead
    /// of creating a visually indistinguishable address.
    #[test]
    fn rejects_zero_width_space() {
        assert!(matches!(
            TenantSlug::new("ab\u{200B}cd", &limits()),
            Err(ValidationError::NotAscii { .. })
        ));
    }

    /// A slug with a NUL byte inside it is refused.
    #[test]
    fn rejects_null_bytes() {
        assert!(TenantSlug::new("ab\x00cd", &limits()).is_err());
    }

    /// A slug with a line break inside it is refused.
    #[test]
    fn slugs_with_newlines_are_refused() {
        assert!(TenantSlug::new("ab\ncd", &limits()).is_err());
    }

    /// With a minimum of 5, `abcd` is refused and `abcde` accepted.
    #[test]
    fn respects_custom_min_length() {
        let l = SlugLimits {
            min_length: 5,
            max_length: 63,
        };
        assert!(TenantSlug::new("abcd", &l).is_err());
        assert!(TenantSlug::new("abcde", &l).is_ok());
    }

    /// With a maximum of 10, ten characters pass and eleven are refused.
    #[test]
    fn respects_custom_max_length() {
        let l = SlugLimits {
            min_length: 2,
            max_length: 10,
        };
        assert!(TenantSlug::new("a".repeat(10), &l).is_ok());
        assert!(TenantSlug::new("a".repeat(11), &l).is_err());
    }

    /// The slug `acme` prints as `acme`.
    #[test]
    fn display_returns_inner_value() {
        let slug = TenantSlug::new("acme", &limits()).unwrap();
        assert_eq!(slug.to_string(), "acme");
    }

    /// `globex-corp` reads from JSON and writes back the same. `ACME` and
    /// the reserved `api` in JSON are refused, as in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_slug_read_from_json_is_validated() {
        let slug: TenantSlug = serde_json::from_str("\"globex-corp\"").unwrap();

        assert_eq!(serde_json::to_string(&slug).unwrap(), "\"globex-corp\"");
        assert!(serde_json::from_str::<TenantSlug>("\"ACME\"").is_err());
        assert!(serde_json::from_str::<TenantSlug>("\"api\"").is_err());
    }
}
