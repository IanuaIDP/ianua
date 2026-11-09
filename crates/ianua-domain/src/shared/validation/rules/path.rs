//! URL paths: the paths routes match, tools call and probes request.

use crate::message;
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks an absolute URL path of at most `max_bytes`.
    ///
    /// The rules:
    /// - not empty, ASCII only, no control characters
    /// - everything [`absolute_path`](Self::absolute_path) requires
    #[must_use]
    pub fn url_path(self, max_bytes: usize) -> Self {
        self.not_empty()
            .ascii_only()
            .length(1..=max_bytes)
            .no_control_chars()
            .absolute_path()
    }

    /// Checks a request target as a client sends it: an absolute path, then
    /// an optional `?` and query.
    ///
    /// The rules:
    /// - not empty, at most `max_bytes`, ASCII only
    /// - no control characters or whitespace
    /// - the path before `?` meets everything
    ///   [`absolute_path`](Self::absolute_path) requires, so it names the
    ///   resource the gateway forwards to
    #[must_use]
    pub fn request_target(mut self, max_bytes: usize) -> Self {
        self = self
            .not_empty()
            .ascii_only()
            .length(1..=max_bytes)
            .no_control_chars()
            .no_whitespace();
        let path = self
            .value
            .split_once('?')
            .map_or(self.value, |(path, _)| path);
        let Some(problem) = path_problem(path) else {
            return self;
        };
        self.errors.push(ValidationError::Custom {
            field: self.field,
            code: "invalid_path".to_owned(),
            message: message!("values-message", format!("{} {problem}.", self.field)),
        });
        self
    }

    /// Requires an absolute URL path that every reader resolves to itself.
    ///
    /// It starts with `/` and holds no backslash, `?`, `#` or whitespace.
    /// No segment is `.` or `..`, whether written plainly or percent-encoded.
    /// The gateway decodes and resolves those before it matches a path. So a
    /// path holding one would either match nothing or reach somewhere else.
    #[must_use]
    pub fn absolute_path(mut self) -> Self {
        let Some(problem) = path_problem(self.value) else {
            return self;
        };
        self.errors.push(ValidationError::Custom {
            field: self.field,
            code: "invalid_path".to_owned(),
            message: message!("values-message", format!("{} {problem}.", self.field)),
        });
        self
    }
}

/// What is wrong with an absolute URL path, if anything.
fn path_problem(path: &str) -> Option<&'static str> {
    if !path.starts_with('/') {
        return Some("must start with '/'");
    }
    if path.contains(['\\', '?', '#']) || path.chars().any(char::is_whitespace) {
        return Some("must not hold a backslash, '?', '#' or whitespace");
    }
    let decoded = crate::shared::web::percent::decode_lenient(path);
    let moves = decoded.contains('\\')
        || decoded
            .split('/')
            .any(|segment| matches!(segment, "." | ".."));
    moves.then_some("must not hold a '.' or '..' segment, plain or percent-encoded")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> Result<(), ValidationError> {
        Validator::new("path", value)
            .absolute_path()
            .validate_first()
    }

    /// The root, a plain path, a route template with `{id}`, a trailing
    /// slash and an encoded space all pass.
    #[test]
    fn an_ordinary_absolute_path_is_accepted() {
        for value in [
            "/",
            "/orders",
            "/orders/{id}/items",
            "/a/b/",
            "/files/%20report",
        ] {
            assert!(path(value).is_ok(), "{value} was refused");
        }
    }

    /// Path validation refuses the tested literal and encoded traversal,
    /// backslash, delimiter, and whitespace forms.
    #[test]
    fn a_path_that_moves_is_refused() {
        for value in [
            "orders",
            "/orders/../admin",
            "/orders/./x",
            "/orders/%2e%2e/admin",
            "/orders/%2E%2e",
            "/orders%2f..%2fadmin",
            "/orders\\admin",
            "/orders%5cadmin",
            "/orders?x=1",
            "/orders#top",
            "/orders /x",
        ] {
            assert!(path(value).is_err(), "{value} was accepted");
        }
    }

    /// A 65-byte path is refused under a limit of 32 and passes under a
    /// limit of 65.
    #[test]
    fn a_path_longer_than_allowed_is_refused() {
        let long = format!("/{}", "a".repeat(64));

        assert!(
            Validator::new("path", &long)
                .url_path(32)
                .validate_first()
                .is_err()
        );
        assert!(
            Validator::new("path", &long)
                .url_path(65)
                .validate_first()
                .is_ok()
        );
    }

    fn target(value: &str) -> bool {
        Validator::new("target", value)
            .request_target(2048)
            .validate_first()
            .is_ok()
    }

    /// `/repos/1?force=true` passes as a request target, though a bare path
    /// may not hold `?`. The root `/` passes too.
    #[test]
    fn a_request_target_may_carry_a_query() {
        assert!(target("/repos/1?force=true"));
        assert!(target("/"));
    }

    /// A query does not hide an invalid dot segment; relative paths, query
    /// whitespace, and fragments are also rejected.
    #[test]
    fn a_request_target_whose_path_moves_is_refused() {
        for value in [
            "repos",
            "/repos/../admin?x=1",
            "/repos/%2e%2e?x",
            "/repos?a b",
            "/repos#x",
        ] {
            assert!(!target(value), "{value} was accepted");
        }
    }
}
