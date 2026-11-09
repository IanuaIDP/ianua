//! The one spelling of a request path that routing and policy compare.

use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// A request path in its one canonical spelling. Routes, policy rules,
    /// resource scopes and decoy lists are compared against it.
    ///
    /// A path a client sends and a path a person writes in a rule go through
    /// the same steps, so the two always agree:
    ///
    /// - Each segment is percent-decoded exactly once.
    /// - Empty segments and a trailing `/` are dropped, so `/a//b/` is
    ///   `/a/b`.
    /// - A segment that still holds `%` after decoding, or that decodes to
    ///   `/`, is refused.
    /// - `;`, `\`, `?`, `#`, control characters, invisible characters and
    ///   `.` or `..` segments are refused, written plainly or encoded.
    ///   Upstream servers read them as something other than part of the
    ///   path.
    /// - A segment that starts or ends with a space, or ends with `.`, is
    ///   refused, because some servers drop those.
    ///
    /// A path that cannot be made canonical is refused, not guessed at. A
    /// rule whose path could be spelled two ways would let a request written
    /// the other way past it.
    #[derive(PartialOrd, Ord)]
    pub struct CanonicalPath;
}

impl TextValue for CanonicalPath {
    const FIELD: &'static str = "path";

    fn normalized(value: String) -> String {
        canonical_form(value)
    }

    fn rules(check: Validator<'_>) -> Validator<'_> {
        canonical_rules(check)
    }
}

impl CanonicalPath {
    /// The root path, `/`.
    #[must_use]
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    /// The path's segments, in order. The root has none.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|segment| !segment.is_empty())
    }

    /// The path spelled for a request line: each segment percent-encoded
    /// where it holds anything a path segment may not carry plainly.
    ///
    /// A canonical path is decoded, so `/files private` goes upstream as
    /// `/files%20private`. Read back through [`CanonicalPath::new`] it is the
    /// same path again, so what is forwarded is what was matched.
    #[must_use]
    pub fn to_wire(&self) -> String {
        wire_spelling(self.segments())
    }
}

/// The wire spelling of the path made of `segments`, each already decoded.
pub(crate) fn wire_spelling<'a>(segments: impl IntoIterator<Item = &'a str>) -> String {
    let encoded: Vec<String> = segments
        .into_iter()
        .map(crate::shared::web::percent::encode_path_segment)
        .collect();
    format!("/{}", encoded.join("/"))
}

/// The longest path held, in characters.
const MAX_CHARS: usize = 2048;

/// The rules a canonical path meets, shared with every type that holds one.
pub(crate) fn canonical_rules(check: Validator<'_>) -> Validator<'_> {
    check
        .not_empty()
        .char_length(1..=MAX_CHARS)
        .rule(&Canonical)
}

/// `value` decoded once per segment, with empty segments and the trailing
/// `/` dropped. A segment that cannot be decoded cleanly is kept as
/// written, so the rules refuse it instead of a guess being stored.
pub(crate) fn canonical_form(value: String) -> String {
    if !value.starts_with('/') {
        return value;
    }
    let segments: Vec<String> = value
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(decoded_segment)
        .collect();
    format!("/{}", segments.join("/"))
}

fn decoded_segment(raw: &str) -> String {
    let Some(bytes) = crate::shared::web::percent::decode_strict(raw) else {
        return raw.to_owned();
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return raw.to_owned();
    };
    if text.contains(['/', '%']) {
        return raw.to_owned();
    }
    text
}

/// What a canonical path never holds.
struct Canonical;

impl Rule for Canonical {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let problem = canonical_problem(value)?;
        Some(ValidationError::Custom {
            field,
            code: "invalid_path".to_owned(),
            message: message!("agents-message", format!("{field} {problem}.")),
        })
    }
}

fn canonical_problem(path: &str) -> Option<&'static str> {
    let Some(rest) = path.strip_prefix('/') else {
        return Some("must start with '/'");
    };
    if rest.is_empty() {
        return None;
    }
    rest.split('/').find_map(segment_problem)
}

fn segment_problem(segment: &str) -> Option<&'static str> {
    if segment.is_empty() {
        return Some("must not hold an empty segment");
    }
    if matches!(segment, "." | "..") {
        return Some("must not hold a '.' or '..' segment");
    }
    if segment.contains(['%', ';', '\\', '?', '#']) {
        return Some(
            "must not hold '%' (after decoding once), ';', a backslash, '?' or '#', written plainly or encoded",
        );
    }
    if segment.chars().any(char::is_control) {
        return Some("must not hold a control character");
    }
    if segment
        .chars()
        .any(crate::shared::validation::invisible::is_invisible)
    {
        return Some("must not hold an invisible character");
    }
    let trimmed_by_some_servers = segment.ends_with('.')
        || segment.starts_with(char::is_whitespace)
        || segment.ends_with(char::is_whitespace);
    if trimmed_by_some_servers {
        return Some(
            "must not start or end a segment with a space, or end one with '.', which some servers drop",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn canonical(raw: &str) -> String {
        CanonicalPath::new(raw).unwrap().as_str().to_owned()
    }

    /// `/api/v1/projects` and the root `/` need no change and are kept as
    /// written.
    #[test]
    fn a_plain_path_is_kept() {
        assert_eq!(canonical("/api/v1/projects"), "/api/v1/projects");
        assert_eq!(canonical("/"), "/");
    }

    /// Trailing slashes and empty segments collapse to the same canonical
    /// path, including repeated slashes at the root.
    #[test]
    fn empty_segments_and_a_trailing_slash_are_dropped() {
        assert_eq!(canonical("/admin/delete/"), "/admin/delete");
        assert_eq!(canonical("/a//b"), "/a/b");
        assert_eq!(canonical("//"), "/");
    }

    /// `/files%20private` becomes `/files private`, and `/caf%C3%A9` and
    /// `/café` both become `/café`.
    #[test]
    fn each_segment_is_decoded_once() {
        assert_eq!(canonical("/files%20private"), "/files private");
        assert_eq!(canonical("/caf%C3%A9"), "/café");
        assert_eq!(canonical("/café"), "/café");
    }

    /// `api/v1` with no leading `/`, and an empty path, are both refused.
    #[test]
    fn a_path_that_does_not_start_at_the_root_is_refused() {
        assert!(CanonicalPath::new("api/v1").is_err());
        assert!(CanonicalPath::new("").is_err());
    }

    /// Dot segments, path parameters, encoded delimiters and malformed
    /// escapes are refused instead of letting upstream parsing change the path.
    #[test]
    fn every_spelling_that_an_upstream_reads_differently_is_refused() {
        for raw in [
            "/public/..;/admin",
            "/admin;x",
            "/a/../b",
            "/a/./b",
            "/a/%2e%2e/b",
            "/a/%2E/b",
            "/a%2Fb",
            "/a%5Cb",
            "/a\\b",
            "/a%3Fb",
            "/a%23b",
            "/a%3bb",
            "/a%00b",
            "/a\nb",
            "/a%252e%252e/b",
            "/a%25",
            "/a%zz",
            "/a%",
            "/a%C3",
        ] {
            assert!(CanonicalPath::new(raw).is_err(), "{raw:?} was accepted");
        }
    }

    /// Segment edges that servers may trim, and invisible characters, are
    /// refused; spaces and dots inside an ordinary segment remain valid.
    #[test]
    fn a_segment_some_servers_trim_is_refused() {
        for raw in [
            "/admin.",
            "/admin%2e",
            "/admin%20",
            "/admin%09",
            "/%20admin",
            "/admin%C2%A0",
            "/ad%E2%80%8Bmin",
            "/admin.../x",
        ] {
            assert!(CanonicalPath::new(raw).is_err(), "{raw:?} was accepted");
        }
        assert!(CanonicalPath::new("/files%20private/v1.2").is_ok());
    }

    /// `/a/b c` gives the segments `a` and `b c`, in that order. The root
    /// gives none.
    #[test]
    fn the_segments_are_read_in_order() {
        let path = CanonicalPath::new("/a/b c").unwrap();

        assert_eq!(path.segments().collect::<Vec<_>>(), ["a", "b c"]);
        assert_eq!(CanonicalPath::root().segments().count(), 0);
    }

    /// `/files private/café/v1.2` goes on the wire as
    /// `/files%20private/caf%C3%A9/v1.2`, and the root as `/`.
    #[test]
    fn the_wire_spelling_encodes_what_a_request_line_cannot_carry() {
        let path = CanonicalPath::new("/files%20private/caf%C3%A9/v1.2").unwrap();

        assert_eq!(path.to_wire(), "/files%20private/caf%C3%A9/v1.2");
        assert_eq!(CanonicalPath::root().to_wire(), "/");
    }

    proptest! {
        /// Parsing the canonical spelling again gives the same path, so a
        /// stored path reads back exactly as it was compared.
        #[test]
        fn canonical_form_is_stable(raw in "(/[a-zA-Z0-9%;. _-]{0,6}){0,6}/?") {
            if let Ok(path) = CanonicalPath::new(&raw) {
                prop_assert_eq!(CanonicalPath::new(path.as_str()).unwrap(), path);
            }
        }

        /// Whatever is accepted holds none of the characters an upstream
        /// could read as something other than the path.
        #[test]
        fn nothing_accepted_holds_a_delimiter(raw in "(/[a-zA-Z0-9%;.?#\\\\ /_-]{0,8}){0,5}") {
            if let Ok(path) = CanonicalPath::new(&raw) {
                let text = path.as_str();
                prop_assert!(!text.contains(['%', ';', '\\', '?', '#']));
                prop_assert!(!text.contains("//"));
                prop_assert!(text == "/" || !text.ends_with('/'));
                prop_assert!(path.segments().all(|s| s != "." && s != ".."));
            }
        }

        /// The wire spelling of any canonical path reads back as that path.
        #[test]
        fn the_wire_spelling_reads_back_as_the_same_path(
            segments in proptest::collection::vec(
                "[a-zA-Z0-9]{1,3}[ é.~!$&'()*+,=:@_-]?[a-zA-Z0-9]{1,3}",
                0..5,
            ),
        ) {
            let path = CanonicalPath::new(format!("/{}", segments.join("/"))).unwrap();

            prop_assert_eq!(CanonicalPath::new(path.to_wire()).unwrap(), path);
        }
    }
}
