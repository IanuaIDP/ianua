use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::CanonicalPath;
use crate::types::network::canonical_path::{canonical_form, canonical_rules};

text_value! {
    /// A path and everything under it, as a resource scope or a policy rule
    /// reaches it.
    ///
    /// It is spelled the same canonical way as [`CanonicalPath`], by the
    /// same steps. `/reports/`, `/reports//` and `/report%73` are all
    /// `/reports`. So a rule is always in the form the gateway compares
    /// paths in, and cannot miss a path it names.
    #[derive(PartialOrd, Ord)]
    pub struct PathPrefix;
}

impl TextValue for PathPrefix {
    const FIELD: &'static str = "path_prefix";

    fn normalized(value: String) -> String {
        canonical_form(value)
    }

    fn rules(check: Validator<'_>) -> Validator<'_> {
        canonical_rules(check)
    }
}

impl PathPrefix {
    /// Whether `path` is this prefix or under it, on a segment boundary.
    ///
    /// The root prefix covers every path.
    #[must_use]
    pub fn covers(&self, path: &CanonicalPath) -> bool {
        under(self.as_str(), path.as_str())
    }

    /// Whether everything this prefix reaches is also reached by `wider`.
    #[must_use]
    pub fn within(&self, wider: &Self) -> bool {
        under(wider.as_str(), self.as_str())
    }
}

/// Whether the canonical `path` is `prefix` or under it, on a segment
/// boundary.
fn under(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(raw: &str) -> CanonicalPath {
        CanonicalPath::new(raw).unwrap()
    }

    /// `/accounts`, `/accounts/48` and the root `/` are all accepted.
    #[test]
    fn a_well_formed_path_prefix_is_accepted() {
        for value in ["/accounts", "/accounts/48", "/"] {
            assert!(PathPrefix::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty prefix, one with no leading `/`, a `..` segment, a line
    /// break, a `;` and an encoded `/` are all refused.
    #[test]
    fn a_malformed_path_prefix_is_refused() {
        for value in [
            "",
            "accounts",
            "/accounts/../admin",
            "/a\nb",
            "/a;b",
            "/a%2Fb",
        ] {
            assert!(PathPrefix::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// The public prefix covers itself and its descendants, but excludes its
    /// parent and paths whose next characters continue the same segment.
    #[test]
    fn a_prefix_covers_only_whole_segments() {
        let prefix = PathPrefix::new("/api/public").unwrap();

        assert!(prefix.covers(&path("/api/public")));
        assert!(prefix.covers(&path("/api/public/docs")));
        assert!(!prefix.covers(&path("/api/public-admin")));
        assert!(!prefix.covers(&path("/api/publicx")));
        assert!(!prefix.covers(&path("/api")));
    }

    /// A prefix written as `/reports/` is kept as `/reports`.
    #[test]
    fn a_trailing_slash_is_dropped() {
        assert_eq!(PathPrefix::new("/reports/").unwrap().as_str(), "/reports");
    }

    /// Encoded spaces and repeated or trailing slashes in a prefix still
    /// cover the same decoded descendant path.
    #[test]
    fn a_prefix_written_any_way_covers_the_path_it_names() {
        let decoded = path("/files private/report");

        for written in ["/files%20private", "/files private", "//files%20private/"] {
            assert!(
                PathPrefix::new(written).unwrap().covers(&decoded),
                "{written:?} missed"
            );
        }
    }

    /// The prefix `/` covers the root itself and `/accounts/48`.
    #[test]
    fn the_root_prefix_covers_every_path() {
        let root = PathPrefix::new("/").unwrap();

        assert!(root.covers(&CanonicalPath::root()));
        assert!(root.covers(&path("/accounts/48")));
    }
}
