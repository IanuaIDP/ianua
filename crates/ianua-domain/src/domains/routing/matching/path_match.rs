//! Whether a route's path pattern fits a request path, and how specific it is.
//!
//! The pattern language has three parts, each a whole path segment:
//!
//! - Literal text, which must be equal ignoring ASCII case, as in `/health`.
//! - `{name}`, which fits any one non-empty segment and captures it, as in
//!   `/users/{id}`.
//! - A trailing `/*`, which fits the prefix itself and anything below it. It
//!   captures the remainder as `rest`. So `/orders/*` fits `/orders`,
//!   `/orders/` and `/orders/42/items`.
//!
//! Literal segments ignore case because many upstreams do. IIS, a Windows
//! file share or a case-insensitive framework serve `/ADMIN` as `/admin`.
//! Matched case-sensitively, `/ADMIN` would pass the strict `/admin/*` route
//! and fall to a broader `/*` one, while the upstream still serves the admin
//! page. What a pattern captures keeps the case the client sent, since an id
//! or a file name may depend on it.
//!
//! The gateway and every other caller decide through this one module. So a
//! pattern means the same thing wherever it is read.

use std::cmp::Ordering;

use crate::types::CanonicalPath;

/// The name the remainder after a trailing `/*` is captured under.
pub const REST: &str = "rest";

/// The parts of a path a pattern captured, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captures(Vec<(String, String)>);

impl Captures {
    /// The value captured as `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(captured, _)| captured == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every capture as a name and its value, in the order the pattern
    /// names them, the remainder after `/*` last as [`REST`]. A route's
    /// parameter rules read path parameters from these.
    #[must_use]
    pub fn entries(&self) -> &[(String, String)] {
        &self.0
    }
}

/// The captures, if `pattern` fits `path`.
///
/// Only a [`CanonicalPath`] is matched. It is decoded once and has no empty,
/// `.` or `..` segment. It also holds nothing an upstream reads as more than
/// the path, such as `;`, `%`, `\`, `?`, `#` or control characters. So the
/// path a route was matched on is the path the upstream reads. And
/// `/public/..;/admin` can never match an open route while reaching a closed
/// one.
#[must_use]
pub fn captures(pattern: &str, path: &CanonicalPath) -> Option<Captures> {
    let (fixed, tail) = split(pattern);
    let mut path_segments = path.segments();
    let mut found = Vec::new();

    for part in segments(fixed) {
        let segment = path_segments.next()?;
        match parameter(part) {
            Some(name) => found.push((name.to_owned(), segment.to_owned())),
            None if part.eq_ignore_ascii_case(segment) => {}
            None => return None,
        }
    }

    let rest: Vec<&str> = path_segments.collect();
    match tail {
        Tail::Closed if !rest.is_empty() => return None,
        Tail::Closed => {}
        Tail::CatchAll => found.push((REST.to_owned(), rest.join("/"))),
    }
    Some(Captures(found))
}

/// How a pattern ends: at its last segment, or open below it with `/*`.
///
/// The cases are declared from least to most specific, so the derived order
/// ranks a closed pattern above a catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tail {
    /// It ends in `/*` and fits anything below its fixed part.
    CatchAll,
    /// It fits only paths with exactly its segments.
    Closed,
}

/// How specific a pattern is. A greater value is more specific.
///
/// An exact path beats one with `{name}`, which beats one ending in `/*`.
/// Between two that end in `/*`, the longer fixed part is more specific. So
/// `/api/users/*` beats `/api/*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Specificity {
    tail: Tail,
    literals: usize,
    segments: usize,
}

impl Specificity {
    /// The specificity of `pattern`.
    #[must_use]
    pub fn of(pattern: &str) -> Self {
        let (fixed, tail) = split(pattern);
        let parts: Vec<&str> = segments(fixed).collect();
        Self {
            tail,
            literals: parts.iter().filter(|p| parameter(p).is_none()).count(),
            segments: parts.len(),
        }
    }
}

impl Ord for Specificity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.tail
            .cmp(&other.tail)
            .then(self.literals.cmp(&other.literals))
            .then(self.segments.cmp(&other.segments))
    }
}

impl PartialOrd for Specificity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The part before a trailing `/*`, and how the pattern ends.
fn split(pattern: &str) -> (&str, Tail) {
    match pattern.strip_suffix("/*") {
        Some(fixed) => (fixed, Tail::CatchAll),
        None => (pattern, Tail::Closed),
    }
}

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|segment| !segment.is_empty())
}

fn parameter(part: &str) -> Option<&str> {
    part.strip_prefix('{')
        .and_then(|inner| inner.strip_suffix('}'))
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn fits(pattern: &str, path: &str) -> Option<Captures> {
        captures(pattern, &CanonicalPath::new(path).unwrap())
    }

    /// The pattern `/health` fits `/health`. It does not fit `/health/live`
    /// or `/healthz`.
    #[test]
    fn an_exact_pattern_fits_only_itself() {
        assert!(fits("/health", "/health").is_some());
        assert!(fits("/health", "/health/live").is_none());
        assert!(fits("/health", "/healthz").is_none());
    }

    /// `/users/{id}` fits `/users/42` and captures `42` as `id`. It does not
    /// fit `/users/42/orders` or `/users`.
    #[test]
    fn a_parameter_fits_one_segment_and_captures_it() {
        let found = fits("/users/{id}", "/users/42").unwrap();

        assert_eq!(found.get("id"), Some("42"));
        assert!(fits("/users/{id}", "/users/42/orders").is_none());
        assert!(fits("/users/{id}", "/users").is_none());
    }

    /// `/orgs/{org}/repos/{repo}/*` on `/orgs/acme/repos/api/issues/7` lists
    /// both parameters in the pattern's order, then the remainder.
    #[test]
    fn the_captures_list_every_entry_in_the_patterns_order() {
        let found = fits(
            "/orgs/{org}/repos/{repo}/*",
            "/orgs/acme/repos/api/issues/7",
        )
        .unwrap();

        let entries: Vec<(&str, &str)> = found
            .entries()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();

        assert_eq!(
            entries,
            [("org", "acme"), ("repo", "api"), (REST, "issues/7")]
        );
    }

    /// Literal path matching ignores ASCII case for exact and catch-all
    /// patterns, while `/admin` still does not match `/admins`.
    #[test]
    fn a_literal_segment_fits_in_any_ascii_case() {
        assert!(fits("/admin/*", "/ADMIN/users").is_some());
        assert!(fits("/admin/*", "/Admin/users").is_some());
        assert!(fits("/admin", "/aDmIn").is_some());
        assert!(fits("/admin", "/admins").is_none());
    }

    /// `/files/{name}/*` fits `/FILES/Report.PDF/Page/2`. The name is
    /// captured as `Report.PDF` and the rest as `Page/2`, as the client sent
    /// them.
    #[test]
    fn captured_values_keep_the_case_they_were_sent_in() {
        let found = fits("/files/{name}/*", "/FILES/Report.PDF/Page/2").unwrap();

        assert_eq!(found.get("name"), Some("Report.PDF"));
        assert_eq!(found.get(REST), Some("Page/2"));
    }

    /// `/orders/*` fits `/orders` with an empty rest, and `/orders/42/items`
    /// with rest `42/items`. It does not fit `/order` or `/ordersx`.
    #[test]
    fn a_trailing_star_fits_the_prefix_itself_and_everything_below() {
        assert_eq!(fits("/orders/*", "/orders").unwrap().get(REST), Some(""));
        assert_eq!(
            fits("/orders/*", "/orders/42/items").unwrap().get(REST),
            Some("42/items")
        );
        assert!(fits("/orders/*", "/order").is_none());
        assert!(fits("/orders/*", "/ordersx").is_none());
    }

    /// `/*` fits `/` with an empty rest and `/a/b` with rest `a/b`.
    #[test]
    fn a_root_star_fits_every_path() {
        assert_eq!(fits("/*", "/").unwrap().get(REST), Some(""));
        assert_eq!(fits("/*", "/a/b").unwrap().get(REST), Some("a/b"));
    }

    /// `/api/users` is more specific than `/api/{name}`, which is more
    /// specific than `/api/*`.
    #[test]
    fn an_exact_path_beats_a_parameter_which_beats_a_star() {
        let exact = Specificity::of("/api/users");
        let param = Specificity::of("/api/{name}");
        let star = Specificity::of("/api/*");

        assert!(exact > param);
        assert!(param > star);
    }

    /// `/api/users/*` is more specific than `/api/*`, so a request under
    /// `/api/users` takes the narrower route.
    #[test]
    fn a_longer_prefix_is_more_specific_than_a_shorter_one() {
        assert!(Specificity::of("/api/users/*") > Specificity::of("/api/*"));
    }

    /// Canonical paths reject queries, fragments, percent escapes, bare
    /// percent signs, backslashes, newlines and semicolon forms before matching.
    #[test]
    fn a_path_an_upstream_reads_differently_cannot_be_matched() {
        for path in [
            "/api/fetch%3Furl=evil.net",
            "/users/42?role=admin",
            "/users/42#x",
            "/users/100%",
            "/users/a\\b",
            "/users/a\nb",
            "/public/..;/admin/users",
            "/admin;x",
        ] {
            assert!(CanonicalPath::new(path).is_err(), "{path:?} was accepted");
        }
    }

    proptest! {
        /// However the client cases the literal segments, the pattern fits,
        /// and the captured id keeps the case it was sent in.
        #[test]
        fn literal_case_never_decides_a_match_and_captures_keep_theirs(
            literals in prop::collection::vec("[a-z]{1,8}", 1..4),
            upper in prop::collection::vec(any::<bool>(), 4),
            id in "[a-zA-Z0-9]{1,8}",
        ) {
            let pattern = format!("/{}/{{id}}", literals.join("/"));
            let sent: Vec<String> = literals
                .iter()
                .zip(&upper)
                .map(|(literal, &up)| match up {
                    true => literal.to_ascii_uppercase(),
                    false => literal.clone(),
                })
                .collect();
            let path = format!("/{}/{id}", sent.join("/"));

            let found = fits(&pattern, &path);

            prop_assert_eq!(found.as_ref().and_then(|c| c.get("id")), Some(id.as_str()));
        }
    }
}
