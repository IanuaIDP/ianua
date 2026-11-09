use crate::shared::validation::rules::url::{self as web_url, UrlRules, UrlShape};
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// An HTTP origin: a scheme, a host and an optional port. `*` stands for
    /// any origin.
    ///
    /// Examples: `https://app.acme.com`, `http://localhost:3000`, `*`.
    pub struct Origin;
}

impl TextValue for Origin {
    const FIELD: &'static str = "origin";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.rule(&WildcardOrOrigin)
    }
}

const RULES: UrlRules = UrlRules {
    schemes: &["http", "https"],
    max_len: 2048,
    shape: UrlShape::OriginOnly,
};

impl Origin {
    /// Whether this is the wildcard origin `*`.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0 == "*"
    }

    /// Whether this origin matches a request origin. It matches when it is
    /// `*` or exactly the same text.
    #[must_use]
    pub fn matches(&self, request_origin: &str) -> bool {
        self.is_wildcard() || self.0 == request_origin
    }
}

/// `*`, or a web origin under [`RULES`].
struct WildcardOrOrigin;

impl Rule for WildcardOrOrigin {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value == "*" {
            return None;
        }
        web_url::parse(field, value, RULES).err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `https://app.acme.com` is accepted, kept as written and is not the
    /// wildcard.
    #[test]
    fn accepts_https_origin() {
        let o = Origin::new("https://app.acme.com").unwrap();
        assert_eq!(o.as_str(), "https://app.acme.com");
        assert!(!o.is_wildcard());
    }

    /// A local dev origin, `http://localhost:3000`, is accepted with its
    /// port.
    #[test]
    fn accepts_http_with_port() {
        let o = Origin::new("http://localhost:3000").unwrap();
        assert_eq!(o.as_str(), "http://localhost:3000");
    }

    /// `*` is accepted and reports itself as the wildcard.
    #[test]
    fn a_star_identifies_the_wildcard_origin() {
        let o = Origin::new("*").unwrap();
        assert!(o.is_wildcard());
    }

    /// The wildcard matches a request from `https://anything.com`.
    #[test]
    fn wildcard_matches_any() {
        let o = Origin::new("*").unwrap();
        assert!(o.matches("https://anything.com"));
    }

    /// A configured Acme origin matches itself and excludes an unrelated
    /// site's origin.
    #[test]
    fn an_origin_matches_only_itself() {
        let o = Origin::new("https://app.acme.com").unwrap();
        assert!(o.matches("https://app.acme.com"));
        assert!(!o.matches("https://evil.com"));
    }

    /// Empty text is refused before it can participate in cross-origin matching.
    #[test]
    fn an_empty_origin_is_refused() {
        assert!(Origin::new("").is_err());
    }

    /// `app.acme.com` with no scheme is refused.
    #[test]
    fn rejects_no_scheme() {
        assert!(Origin::new("app.acme.com").is_err());
    }

    /// `https://app.acme.com:8443` prints as given, port included. That text
    /// is compared with a browser's `Origin` header.
    #[test]
    fn renders_as_the_origin_it_was_built_from() {
        let origin = Origin::new("https://app.acme.com:8443").unwrap();

        assert_eq!(origin.to_string(), "https://app.acme.com:8443");
    }
}
