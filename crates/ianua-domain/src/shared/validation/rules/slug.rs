//! Tenant and organization slugs: one DNS label.

use crate::shared::config::SlugLimits;
use crate::shared::validation::boundary::Boundary;
use crate::shared::validation::charset::Charset;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks a tenant slug, which is one DNS label.
    ///
    /// The rules:
    /// - ASCII only
    /// - length within the configured limits
    /// - lowercase letters, digits and hyphens only
    /// - starts and ends with a letter or digit
    /// - no two hyphens in a row
    #[must_use]
    pub fn slug(self, limits: &SlugLimits) -> Self {
        self.ascii_only()
            .length(limits.min_length..=limits.max_length)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
            .boundaries(Boundary::Alphanumeric)
            .no_consecutive(b'-')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `acme` passes under the default limits.
    #[test]
    fn slug_accepts_valid() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "acme")
                .slug(&limits)
                .validate()
                .is_empty()
        );
    }

    /// `my-cool-tenant` passes. Single hyphens between words are allowed.
    #[test]
    fn slug_accepts_with_hyphens() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "my-cool-tenant")
                .slug(&limits)
                .validate()
                .is_empty()
        );
    }

    /// `my--tenant` is refused for its two hyphens in a row.
    #[test]
    fn slug_rejects_consecutive_hyphens() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "my--tenant")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// `ACME` is refused. A slug is lowercase only, so `acme` and `ACME`
    /// cannot become two tenants with one host name.
    #[test]
    fn slug_rejects_uppercase() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "ACME")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// `-acme` is refused, since a DNS label may not start with a hyphen.
    #[test]
    fn slug_rejects_leading_hyphen() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "-acme")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// With limits of 5 to 10, the four-letter `abcd` is refused and the
    /// five-letter `abcde` passes.
    #[test]
    fn slug_respects_custom_limits() {
        let limits = SlugLimits {
            min_length: 5,
            max_length: 10,
        };
        assert!(
            Validator::new("slug", "abcd")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
        assert!(
            Validator::new("slug", "abcde")
                .slug(&limits)
                .validate()
                .is_empty()
        );
    }

    /// A slug cannot contain directory-traversal dots and slashes.
    #[test]
    fn slug_rejects_path_traversal() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "../../../etc/passwd")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// Percent-encoded directory traversal is invalid in a slug.
    #[test]
    fn slug_rejects_url_encoded_traversal() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "%2e%2e%2fetc")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// Double-encoded traversal is rejected by slug validation.
    #[test]
    fn slug_rejects_double_encoded_traversal() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "%252e%252e")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// An embedded null byte makes a slug invalid.
    #[test]
    fn slug_rejects_null_byte() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "acme\x00corp")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// A slug containing CRLF is rejected.
    #[test]
    fn slug_rejects_crlf() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "acme\r\ncorp")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// A slug holding a quote, a semicolon and SQL is refused by its
    /// charset.
    #[test]
    fn slug_rejects_sql_injection() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "acme';drop table--")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// Script markup cannot form a valid slug.
    #[test]
    fn slug_rejects_script_tag() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "<script>alert(1)</script>")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// A Cyrillic lookalike is rejected even when it resembles an ASCII slug.
    #[test]
    fn slug_rejects_unicode_homoglyph() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "\u{0430}cme")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// A zero-width joiner is invalid inside a slug.
    #[test]
    fn slug_rejects_zero_width_joiner() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "ac\u{200D}me")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }

    /// A right-to-left override is invalid inside a slug.
    #[test]
    fn slug_rejects_right_to_left_override() {
        let limits = SlugLimits::default();
        assert!(
            Validator::new("slug", "ac\u{202E}me")
                .slug(&limits)
                .validate_first()
                .is_err()
        );
    }
}
