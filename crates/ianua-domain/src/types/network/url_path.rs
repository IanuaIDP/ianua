use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// A URL path, such as `/api/v1/projects`.
    ///
    /// It follows the shared URL path rules:
    /// - Not empty, ASCII only, and at most 2048 characters.
    /// - Starts with `/`.
    /// - No control characters, whitespace, backslash, `?` or `#`.
    /// - No `.` or `..` segment, written plainly or percent-encoded.
    pub struct UrlPath;
}

impl TextValue for UrlPath {
    const FIELD: &'static str = "path";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.url_path(2048)
    }
}

impl UrlPath {
    /// `/healthz`, the path a backend's health is probed on unless its
    /// service names another.
    #[must_use]
    pub(crate) fn health_probe() -> Self {
        Self("/healthz".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `/api/v1/projects` is accepted and kept as written.
    #[test]
    fn accepts_simple_path() {
        let p = UrlPath::new("/api/v1/projects").unwrap();
        assert_eq!(p.as_str(), "/api/v1/projects");
    }

    /// A single slash is sufficient to identify the server's root resource.
    #[test]
    fn the_root_path_is_accepted() {
        assert!(UrlPath::new("/").is_ok());
    }

    /// `/api/v1/users?limit=10` is refused. A path is matched against the
    /// request's path alone, so one with a query would match nothing.
    #[test]
    fn rejects_a_query() {
        assert!(UrlPath::new("/api/v1/users?limit=10").is_err());
    }

    /// Empty text is refused before it can be used for route matching.
    #[test]
    fn an_empty_url_path_is_refused() {
        assert!(UrlPath::new("").is_err());
    }

    /// `api/v1/projects` with no leading `/` is refused.
    #[test]
    fn rejects_no_leading_slash() {
        assert!(UrlPath::new("api/v1/projects").is_err());
    }

    /// A path with a NUL byte inside it is refused.
    #[test]
    fn rejects_control_chars() {
        assert!(UrlPath::new("/api\x00/v1").is_err());
    }

    /// `/api/ünits` holds a non-ASCII letter and is refused.
    #[test]
    fn rejects_non_ascii() {
        assert!(UrlPath::new("/api/ünits").is_err());
    }

    /// The health probe path is one `new` accepts as well, so the default
    /// probe holds a path the rules allow.
    #[test]
    fn the_health_probe_path_meets_the_rules() {
        let probe = UrlPath::health_probe();

        assert_eq!(UrlPath::new(probe.as_str()).unwrap(), probe);
    }

    /// The path `/health` prints as `/health`.
    #[test]
    fn display_returns_value() {
        let p = UrlPath::new("/health").unwrap();
        assert_eq!(p.to_string(), "/health");
    }
}
