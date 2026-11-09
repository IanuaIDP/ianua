//! Which tools, resources and prompts a delegation reaches on an MCP server.
//!
//! An agent calls its tools over the Model Context Protocol. Every call is a
//! JSON-RPC request to one endpoint, with the same path and method. A route
//! policy matches on path and method, so it cannot tell one tool call from
//! another. The tool name in the request body has to be checked.
//!
//! So tools are their own part of a
//! [`CapabilitySet`](crate::domains::agents::authority::capability::CapabilitySet).
//! A delegation names the tools it may call, each with the class of action
//! it takes. A sub-delegation may only narrow that list. The proxy checks the
//! tool named in each request against it. The grant itself is an
//! [`McpGrant`](crate::domains::agents::authority::capability::McpGrant).
//!
//! Names match exactly, with one exception. A pattern ending in `*` covers
//! every name that starts with the text before it. A bare `*` covers every
//! tool, and only an operator who writes it grants it. An empty grant covers
//! nothing.
//!
//! An MCP server also offers resources and prompts. `resources/read` fetches
//! content and `prompts/get` fetches a template. Both can carry text the agent
//! will act on, which is how a prompt injection arrives. So each has its own
//! list. An operator can hand over a server's tools without handing over
//! everything it can read.

use crate::domains::agents::execution::tool::ToolName;
use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// A pattern for MCP tool or prompt names.
    ///
    /// It is either an exact name such as `read_file`, or a prefix ending in
    /// `*` such as `github_*`. A bare `*` covers every name. MCP servers often
    /// start all their tool names with one prefix, so `github_*` grants every
    /// tool one server offers.
    pub struct McpToolPattern;
}

impl TextValue for McpToolPattern {
    const FIELD: &'static str = "mcp_tool_pattern";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=Self::MAX_LEN)
            .no_control_chars()
            .no_whitespace()
            .rule(&TrailingWildcard)
    }
}

impl McpToolPattern {
    /// The longest pattern accepted, in characters.
    const MAX_LEN: usize = 128;

    /// The text before the `*`, when this is a prefix pattern.
    fn prefix(&self) -> Option<&str> {
        self.0.strip_suffix('*')
    }

    /// Whether the tool `name` is this exact name, or starts with this
    /// pattern's prefix.
    #[must_use]
    pub fn matches(&self, name: &ToolName) -> bool {
        self.matches_name(name.as_str())
    }

    /// Whether `name` is this exact name, or starts with this pattern's
    /// prefix. Prompt names, which have no checked type of their own, are
    /// matched through this.
    pub(super) fn matches_name(&self, name: &str) -> bool {
        match self.prefix() {
            Some(prefix) => name.starts_with(prefix),
            None => self.0 == name,
        }
    }

    /// Whether this pattern covers every name `other` matches.
    ///
    /// An exact name covers only itself, never a prefix pattern. One prefix
    /// covers another only when it starts it. So `github_*` covers
    /// `github_issue_*`, but `github_issue_*` does not cover `github_*`.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        pattern_covers(&self.0, &other.0)
    }
}

/// Whether the pattern `own` covers every name `other` matches: an exact
/// name covers only itself, a prefix ending in `*` any pattern starting
/// with it.
fn pattern_covers(own: &str, other: &str) -> bool {
    let Some(prefix) = own.strip_suffix('*') else {
        return own == other;
    };
    match other.strip_suffix('*') {
        Some(other_prefix) => other_prefix.starts_with(prefix),
        None => other.starts_with(prefix),
    }
}

/// Allows at most one `*`, and only as the last character.
struct TrailingWildcard;

impl Rule for TrailingWildcard {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let stars = value.matches('*').count();
        if stars == 0 || (stars == 1 && value.ends_with('*')) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_wildcard".to_owned(),
            message: message!(
                "agents-may-hold-one-as-its-final",
                format!("{field} may hold one `*`, as its final character")
            ),
        })
    }
}

text_value! {
    /// A pattern for the MCP resource URIs a grant may read.
    ///
    /// It is an exact URI such as `file:///etc/hosts`, a prefix ending in `/*`
    /// such as `file:///project/*`, or `*` alone for every resource. A prefix
    /// ends at a `/`, so `file:///project/*` never reaches
    /// `file:///project-secrets`. A pattern follows the same spelling rules as
    /// an [`McpResourceUri`].
    pub struct McpResourcePattern;
}

impl TextValue for McpResourcePattern {
    const FIELD: &'static str = "mcp_resource_pattern";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=MAX_RESOURCE_LEN)
            .no_control_chars()
            .no_whitespace()
            .rule(&TrailingWildcard)
            .rule(&SegmentBoundaryWildcard)
            .rule(&CanonicalUri)
    }
}

/// The longest resource URI or pattern accepted, in characters.
const MAX_RESOURCE_LEN: usize = 2048;

impl McpResourcePattern {
    fn prefix(&self) -> Option<&str> {
        self.0.strip_suffix('*')
    }
    /// Whether `uri` is this exact URI, or starts with this pattern's prefix.
    ///
    /// It takes a checked [`McpResourceUri`], not raw request text. So a URI
    /// that could resolve outside the prefix is refused before it gets here.
    #[must_use]
    pub fn matches(&self, uri: &McpResourceUri) -> bool {
        match self.prefix() {
            Some(prefix) => uri.as_str().starts_with(prefix),
            None => self.0 == uri.as_str(),
        }
    }
    /// Whether this pattern covers every URI `other` matches.
    ///
    /// An exact URI covers only itself. A prefix covers any pattern that
    /// starts with it, so `file:///project/*` covers `file:///project/src/*`.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        pattern_covers(&self.0, &other.0)
    }
}

text_value! {
    /// The URI a `resources/read` request names, checked before any grant
    /// looks at it.
    ///
    /// The MCP server may resolve a URI before reading it. So a URI that could
    /// resolve somewhere other than it says is refused. That covers `?`, `#`,
    /// a backslash, an empty segment, a `.` or `..` segment, and escapes that
    /// hide any of these. A URI that passes means what it says, so a prefix
    /// check on it is safe. A request whose URI is refused is denied.
    ///
    /// Mallory holds `file:///project/*` and asks for
    /// `file:///project/../etc/shadow`. The URI is refused, so she never
    /// reads the file.
    pub struct McpResourceUri;
}

impl TextValue for McpResourceUri {
    const FIELD: &'static str = "mcp_resource_uri";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=MAX_RESOURCE_LEN)
            .no_control_chars()
            .no_whitespace()
            .rule(&CanonicalUri)
    }
}

/// Allows a `*` only alone or right after a `/`, so a prefix ends where a
/// path segment does.
struct SegmentBoundaryWildcard;

impl Rule for SegmentBoundaryWildcard {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let prefix = value.strip_suffix('*')?;
        if prefix.is_empty() || prefix.ends_with('/') {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_wildcard".to_owned(),
            message: message!(
                "agents-may-end-in-or-be-alone",
                format!("{field} may end in `/*`, or be `*` alone")
            ),
        })
    }
}

/// Refuses a URI that a careless server could resolve to another path.
///
/// Patterns follow the same rule, so a pattern and the URIs it is compared
/// with are spelled the same way.
///
/// It refuses:
///
/// - `?` and `#`. The text after them is not split into segments here, yet a
///   server may resolve it.
/// - A malformed percent-escape.
/// - An escape for `.`, `/`, `\` or `%`. The last catches double encoding.
/// - An escape that decodes to a control character.
/// - A backslash.
/// - An empty path segment after the scheme. `notes://p//etc` can join onto
///   an absolute path.
/// - A `.` or `..` segment.
struct CanonicalUri;

impl Rule for CanonicalUri {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if uri_resolves_as_written(value) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "non_canonical_uri".to_owned(),
            message: message!(
                "agents-may-not-hold-an-empty-segment",
                format!(
                    "{field} may not hold `?`, `#`, `\\`, an empty segment or a `.` or `..` segment, or hide one in an escape"
                )
            ),
        })
    }
}

/// Whether `value` can resolve only to the path it spells out.
fn uri_resolves_as_written(value: &str) -> bool {
    if value.contains(['?', '#', '\\']) {
        return false;
    }
    let Some(decoded) = crate::shared::web::percent::decode_strict(value) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let lowered = value.to_ascii_lowercase();
    let hides_structure = ["%2e", "%2f", "%5c", "%25"]
        .iter()
        .any(|escape| lowered.contains(escape));
    let path = value.split_once("://").map_or(value, |(_, rest)| rest);
    !hides_structure
        && !decoded.chars().any(char::is_control)
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(value: &str) -> McpToolPattern {
        McpToolPattern::new(value).unwrap()
    }

    fn tool_name(value: &str) -> ToolName {
        ToolName::new(value).unwrap()
    }

    /// The pattern `read_file` matches `read_file` only. It does not match
    /// `write_file`, nor `read_file_unsafe`, which merely starts the same way.
    #[test]
    fn a_literal_pattern_matches_only_that_tool() {
        let read = pattern("read_file");
        assert!(read.matches(&tool_name("read_file")));
        assert!(!read.matches(&tool_name("write_file")));
        assert!(
            !read.matches(&tool_name("read_file_unsafe")),
            "a literal is not a prefix"
        );
    }

    /// The pattern `github_*` matches `github_create_issue` and the bare
    /// `github_`. It does not match `gitlab_create_issue`.
    #[test]
    fn a_prefix_pattern_matches_the_names_beneath_it() {
        let github = pattern("github_*");
        assert!(github.matches(&tool_name("github_create_issue")));
        assert!(github.matches(&tool_name("github_")));
        assert!(!github.matches(&tool_name("gitlab_create_issue")));
    }

    /// An operator grants the pattern `*`. It matches any tool name, such as
    /// `anything` or `read_file`.
    #[test]
    fn a_bare_star_matches_every_tool() {
        let all = pattern("*");
        assert!(all.matches(&tool_name("anything")));
        assert!(all.matches(&tool_name("read_file")));
    }

    /// An agent holding `github_*` may hand on `github_issue_*` or the single
    /// tool `github_create_issue`. One holding `*` may hand on `read_file`.
    #[test]
    fn a_broader_prefix_covers_a_narrower_one() {
        assert!(pattern("github_*").covers(&pattern("github_issue_*")));
        assert!(pattern("github_*").covers(&pattern("github_create_issue")));
        assert!(pattern("*").covers(&pattern("read_file")));
    }

    /// An exact tool pattern does not cover a broader prefix or all tools,
    /// and a narrow GitHub prefix does not cover the wider GitHub prefix.
    #[test]
    fn a_narrower_pattern_never_covers_a_broader_one() {
        assert!(!pattern("github_issue_*").covers(&pattern("github_*")));
        assert!(!pattern("read_file").covers(&pattern("read_*")));
        assert!(!pattern("read_file").covers(&pattern("*")));
    }

    /// An agent holding `read_file` may hand on `read_file`. It may not hand
    /// on `write_file`.
    #[test]
    fn a_literal_covers_only_itself() {
        assert!(pattern("read_file").covers(&pattern("read_file")));
        assert!(!pattern("read_file").covers(&pattern("write_file")));
    }

    /// The patterns `git*hub` and `*_file` are refused. Only a trailing `*`
    /// is a wildcard, so no pattern reads as matching in the middle.
    #[test]
    fn rejects_a_star_that_is_not_the_last_character() {
        assert!(McpToolPattern::new("git*hub").is_err());
        assert!(McpToolPattern::new("*_file").is_err());
    }

    /// A tool pattern that is empty, holds a space, or runs to 129
    /// characters is refused.
    #[test]
    fn rejects_empty_whitespace_and_overlong_patterns() {
        assert!(McpToolPattern::new("").is_err());
        assert!(McpToolPattern::new("read file").is_err());
        assert!(McpToolPattern::new("x".repeat(129)).is_err());
    }

    /// A serialized tool pattern with a wildcard in the middle cannot
    /// deserialize, preserving constructor validation for stored patterns.
    #[cfg(feature = "serde")]
    #[test]
    fn deserialization_goes_through_the_validating_constructor() {
        let malformed = serde_json::from_str::<McpToolPattern>("\"git*hub\"");
        assert!(
            malformed.is_err(),
            "a stored pattern must not bypass validation"
        );
    }

    fn tool(value: &str) -> McpToolPattern {
        McpToolPattern::new(value).unwrap()
    }

    fn uri(value: &str) -> McpResourceUri {
        McpResourceUri::new(value).unwrap()
    }

    fn resource(value: &str) -> McpResourcePattern {
        McpResourcePattern::new(value).unwrap()
    }

    /// A tool pattern built from `github_*` and a resource pattern built from
    /// `file:///project/*` each give back that same text.
    #[test]
    fn a_pattern_keeps_the_text_it_was_built_from() {
        assert_eq!(tool("github_*").as_str(), "github_*");
        assert_eq!(resource("file:///project/*").as_str(), "file:///project/*");
    }

    /// A grant of `file:///etc/hosts` reads that file only. It does not reach
    /// `file:///etc/passwd` or `file:///etc/hosts.bak`.
    #[test]
    fn a_literal_resource_pattern_matches_only_that_uri() {
        let hosts = resource("file:///etc/hosts");

        assert!(hosts.matches(&uri("file:///etc/hosts")));
        assert!(!hosts.matches(&uri("file:///etc/passwd")));
        assert!(
            !hosts.matches(&uri("file:///etc/hosts.bak")),
            "a literal is not a prefix"
        );
    }

    /// A grant of `file:///project/*` reads `file:///project/README.md` and the
    /// directory itself. It does not reach `file:///etc/hosts`.
    #[test]
    fn a_prefix_resource_pattern_matches_the_uris_beneath_it() {
        let project = resource("file:///project/*");

        assert!(project.matches(&uri("file:///project/README.md")));
        assert!(project.matches(&uri("file:///project/")));
        assert!(!project.matches(&uri("file:///etc/hosts")));
    }

    /// A resource prefix covers narrower prefixes and files beneath it,
    /// while neither covers the broader prefix. Exact file patterns cover
    /// themselves and refuse other files.
    #[test]
    fn a_broader_resource_pattern_covers_a_narrower_one_and_not_the_reverse() {
        assert!(resource("file:///project/*").covers(&resource("file:///project/src/*")));
        assert!(resource("file:///project/*").covers(&resource("file:///project/README.md")));
        assert!(!resource("file:///project/src/*").covers(&resource("file:///project/*")));
        assert!(!resource("file:///project/README.md").covers(&resource("file:///project/*")));
        assert!(resource("file:///etc/hosts").covers(&resource("file:///etc/hosts")));
        assert!(!resource("file:///etc/hosts").covers(&resource("file:///etc/passwd")));
    }

    /// Resource URIs containing dot segments, encoded path structure or
    /// backslashes are refused. An encoded space within a filename is accepted.
    #[test]
    fn a_uri_that_could_resolve_elsewhere_is_refused() {
        for bad in [
            "file:///project/../etc/shadow",
            "file:///project/./x",
            "file:///project/%2e%2e/secrets",
            "file:///project/%2E%2E/secrets",
            "file:///project/x%2fy",
            "file:///project/..%5c..%5cetc",
            "file:///project\\..\\etc",
        ] {
            assert!(McpResourceUri::new(bad).is_err(), "{bad} was accepted");
        }
        assert!(McpResourceUri::new("file:///project/a%20b.md").is_ok());
    }

    /// Resource URIs with queries, fragments, double encoding, empty path
    /// segments, encoded NULs or malformed escapes are refused.
    #[test]
    fn a_uri_that_hides_its_path_from_the_check_is_refused() {
        for bad in [
            "file:///project/x?/../../etc/passwd",
            "file:///project/x#/../../etc/passwd",
            "file:///project/%252e%252e/%252e%252e/etc/passwd",
            "notes://project//etc/passwd",
            "file:///project//etc/passwd",
            "file:///project/a%00/../../x",
            "file:///project/a%00b",
            "file:///project/a%zz",
            "file:///project/a%",
        ] {
            assert!(McpResourceUri::new(bad).is_err(), "{bad} was accepted");
        }
    }

    /// Resource patterns with `//`, a double-encoded dot or a `?` are refused,
    /// as URIs with them are. `notes://project/*` is accepted.
    #[test]
    fn a_pattern_is_held_to_the_same_spelling_as_a_uri() {
        for bad in [
            "notes://project//*",
            "file:///project/%252e/*",
            "file:///p?x/*",
        ] {
            assert!(McpResourcePattern::new(bad).is_err(), "{bad} was accepted");
        }
        assert!(McpResourcePattern::new("notes://project/*").is_ok());
    }

    /// A resource wildcard attached directly to a path segment is refused.
    /// A wildcard after a slash or standing alone is accepted.
    #[test]
    fn a_wildcard_must_follow_a_slash_or_stand_alone() {
        assert!(McpResourcePattern::new("file:///project*").is_err());
        assert!(McpResourcePattern::new("file:///project/*").is_ok());
        assert!(McpResourcePattern::new("*").is_ok());
    }

    /// Resource patterns containing parent traversal are refused whether
    /// the parent segment is literal or percent-encoded.
    #[test]
    fn a_pattern_that_steps_up_cannot_be_granted() {
        assert!(McpResourcePattern::new("file:///project/../*").is_err());
        assert!(McpResourcePattern::new("file:///project/%2e%2e/*").is_err());
    }
}
