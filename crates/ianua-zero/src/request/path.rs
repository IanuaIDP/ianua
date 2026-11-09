//! A request's path in the domain's one canonical spelling. Spelling it
//! again for the wire is the domain's too, [`CanonicalPath::to_wire`].
//!
//! The gateway does not normalise paths itself. It hands the path to
//! [`CanonicalPath`], the spelling routes, tenant policy rules and resource
//! scopes are all written in, so the path a route matched is the path a
//! policy judged. A path the domain cannot make canonical, such as one with
//! a dot segment, an encoded slash or a second layer of encoding, is
//! refused rather than resolved: a `..` an upstream would resolve one way
//! and a rule another is exactly the gap a traversal goes through.

use http::Uri;
use ianua_domain::types::CanonicalPath;

/// The canonical path `uri` names, or `None` when it has none: an
/// asterisk-form target, or a path the domain refuses.
pub(crate) fn request_path(uri: &Uri) -> Option<CanonicalPath> {
    canonical(uri.path())
}

/// The canonical spelling of a raw request path.
fn canonical(raw: &str) -> Option<CanonicalPath> {
    if !raw.starts_with('/') {
        return None;
    }
    CanonicalPath::new(raw).ok()
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::PathPrefix;
    use proptest::prelude::*;

    use super::*;

    fn read(raw: &str) -> Option<String> {
        canonical(raw).map(|path| path.as_str().to_owned())
    }

    #[test]
    fn a_plain_path_reads_as_written() {
        assert_eq!(read("/api/v1/orders").as_deref(), Some("/api/v1/orders"));
        assert_eq!(read("/").as_deref(), Some("/"));
    }

    #[test]
    fn empty_segments_and_a_trailing_slash_are_dropped() {
        assert_eq!(read("//api///orders/").as_deref(), Some("/api/orders"));
    }

    /// Plain, encoded and semicolon-suffixed dot segments produce no canonical
    /// path, including traversal between two account paths.
    #[test]
    fn a_dot_segment_is_refused_in_any_spelling() {
        for raw in [
            "/app/../admin",
            "/app/./admin",
            "/app/%2e%2e/admin",
            "/app/%2E./admin",
            "/accounts/4821/%2e%2e/%2e%2e/accounts/9999",
            "/public/..;/admin",
        ] {
            assert_eq!(read(raw), None, "{raw}");
        }
    }

    /// Decoded once here and once more upstream, `%252e%252e` would become
    /// `..` only after every check had passed.
    #[test]
    fn a_double_encoding_or_an_encoded_slash_is_refused() {
        for raw in [
            "/files/%252e%252e/admin",
            "/a%2Fb",
            "/a%5Cb",
            "/a%3Bb",
            "/a%",
        ] {
            assert_eq!(read(raw), None, "{raw}");
        }
    }

    #[test]
    fn an_asterisk_target_has_no_path() {
        assert_eq!(request_path(&Uri::from_static("*")), None);
    }

    fn segment() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9]{1,3}[ é.~!$&'()*+,=:@_-]?[a-zA-Z0-9]{1,3}"
    }

    fn any_path() -> impl Strategy<Value = Vec<String>> {
        proptest::collection::vec(segment(), 0..5)
    }

    fn plain(segments: &[String]) -> String {
        format!("/{}", segments.join("/"))
    }

    /// `segment` with the characters `mask` picks percent-encoded.
    fn encoded_where(segment: &str, mask: &[bool]) -> String {
        segment
            .chars()
            .zip(mask.iter().chain(std::iter::repeat(&false)))
            .map(|(c, encode)| match *encode {
                true => c.to_string().bytes().map(|b| format!("%{b:02x}")).collect(),
                false => c.to_string(),
            })
            .collect()
    }

    proptest! {
        /// No raw path, however malformed, panics the reader.
        #[test]
        fn reading_never_panics(raw in ".*") {
            let _ = canonical(&raw);
        }

        /// Extra slashes between, before and after segments read as one.
        #[test]
        fn doubled_slashes_read_as_one(segments in any_path(), extra in 1usize..4) {
            let gap = "/".repeat(extra + 1);
            let doubled = format!("{gap}{}{gap}", segments.join(&gap));

            prop_assert_eq!(read(&doubled), read(&plain(&segments)));
            prop_assert!(read(&plain(&segments)).is_some());
        }

        /// Percent-encoding any of a path's characters reads as the same
        /// path, so a rule cannot be dodged by encoding a letter.
        #[test]
        fn encoding_any_character_reads_as_the_same_path(
            segments in any_path(),
            mask in proptest::collection::vec(any::<bool>(), 0..40),
        ) {
            let encoded: Vec<String> = segments.iter().map(|s| encoded_where(s, &mask)).collect();

            prop_assert_eq!(read(&plain(&encoded)), read(&plain(&segments)));
        }

        /// A dot segment anywhere, plain or encoded, refuses the path.
        #[test]
        fn a_dot_segment_anywhere_is_refused(
            segments in any_path(),
            at in 0usize..5,
            dot in prop::sample::select(vec![".", "..", "%2e", "%2E%2e", ".%2E", "%2e."]),
        ) {
            let mut spelled = segments;
            spelled.insert(at.min(spelled.len()), dot.to_owned());

            prop_assert_eq!(read(&plain(&spelled)), None);
        }

        /// However the request spells its path, a tenant policy prefix
        /// covers it exactly when it covers the plain spelling, and exactly
        /// when its segments start the request's.
        #[test]
        fn prefix_coverage_agrees_with_the_domain(
            prefix in proptest::collection::vec(segment(), 1..3),
            request in any_path(),
            mask in proptest::collection::vec(any::<bool>(), 0..40),
        ) {
            let rule = PathPrefix::new(plain(&prefix)).unwrap();
            let spelled: Vec<String> = request.iter().map(|s| encoded_where(s, &mask)).collect();
            let raw = format!("/{}/", spelled.join("//"));

            let read = canonical(&raw).unwrap();
            let written = CanonicalPath::new(plain(&request)).unwrap();

            prop_assert_eq!(rule.covers(&read), rule.covers(&written));
            prop_assert_eq!(rule.covers(&read), request.starts_with(&prefix));
        }

        /// The wire spelling of a canonical path reads back as that path,
        /// so what is forwarded is what was matched.
        #[test]
        fn the_wire_spelling_reads_back_as_the_same_path(segments in any_path()) {
            let path = CanonicalPath::new(plain(&segments)).unwrap();

            prop_assert_eq!(canonical(&path.to_wire()), Some(path));
        }
    }
}
