//! What path the upstream sees, given the path the client asked for.

use std::collections::BTreeSet;

use crate::domains::routing::matching::path_match::{Captures, REST};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::shared::web::percent::encode_path_segment;
use crate::types::network::wire_spelling;
use crate::types::{CanonicalPath, UrlPath};

/// How the matched request path is turned into the path forwarded upstream.
///
/// The public path and the internal path often differ by more than a prefix.
/// A request for `/v1/users/{id}` may need to reach a backend that serves
/// `/internal/user/{id}`. A template covers that case.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PathRewrite {
    /// Forward the path exactly as it arrived.
    #[default]
    Keep,
    /// Forward only what the pattern's trailing `/*` caught: every segment
    /// before it is dropped, `{name}` ones too. See
    /// [`PathRewrite::forwarded`].
    StripPrefix,
    /// Build the forwarded path from a template over the matched parameters.
    Template(PathTemplate),
}

impl PathRewrite {
    /// Checks that `pattern` captures every parameter this rewrite uses.
    ///
    /// A template may name a parameter the pattern never captures. Then every
    /// request on the route would fail, though the route looked fine when it
    /// was saved. So the mismatch is refused when the route is saved.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the first parameter the pattern
    ///   does not capture.
    pub fn validate_against(&self, pattern: &UrlPath) -> Result<(), DomainError> {
        let Self::Template(template) = self else {
            return Ok(());
        };

        let declared = parameters_in(pattern.as_str());
        for name in template.parameters() {
            if !declared.contains(name.as_str()) {
                return Err(DomainError::invalid(message!(
                    "routing-path-rewrite-names-which-the-path",
                    format!(
                        "path rewrite names {{{name}}}, which the path pattern does not capture"
                    )
                )));
            }
        }
        Ok(())
    }

    /// The path the upstream is sent for `path`, spelled for the wire and
    /// without a query. `captured` is what the route's pattern took from
    /// `path`.
    ///
    /// - [`PathRewrite::Keep`] forwards `path` as matched.
    /// - [`PathRewrite::StripPrefix`] drops every segment the pattern's
    ///   fixed part matched, literal and `{name}` alike, and forwards what
    ///   the trailing `/*` caught. A pattern with no `/*` forwards the root.
    ///   So `/tenants/{id}/*` forwards `/tenants/7/orders/1` as `/orders/1`.
    ///   A route that must keep `id` says so with a template,
    ///   `/{id}/{rest}`, rather than leaving the rule to guess which
    ///   segments were the prefix.
    /// - [`PathRewrite::Template`] renders the template from `captured`,
    ///   each value encoded for the wire.
    ///
    /// `None` when the template names something `captured` lacks or renders
    /// a path that does not read as a [`ForwardedPath`]. A route saved through the use case
    /// never does either, so the caller treats `None` as a corrupt route and
    /// refuses the request.
    #[must_use]
    pub fn forwarded(&self, path: &CanonicalPath, captured: &Captures) -> Option<ForwardedPath> {
        let spelled = match self {
            Self::Keep => path.to_wire(),
            Self::StripPrefix => below_prefix(captured),
            Self::Template(template) => {
                template.render(|name| captured.get(name).map(wire_value))?
            }
        };
        ForwardedPath::new(spelled).ok()
    }
}

text_value! {
    /// The path an upstream is sent, spelled for the wire and without a
    /// query: `/files%20private`, never `/files private`.
    ///
    /// It reads back as a [`CanonicalPath`], so what is forwarded is a path
    /// routing and policy could have matched, never one with a `..` segment,
    /// a space or a `?` in it.
    pub struct ForwardedPath;
}

impl TextValue for ForwardedPath {
    const FIELD: &'static str = "forwarded_path";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.url_path(MAX_FORWARDED_BYTES).rule(&ReadsAsCanonical)
    }
}

/// The longest forwarded path, in bytes: the longest canonical path with
/// every character four UTF-8 bytes, each percent-encoded.
const MAX_FORWARDED_BYTES: usize = 3 * 4 * 2048;

/// A forwarded path decodes to a canonical path.
struct ReadsAsCanonical;

impl Rule for ReadsAsCanonical {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if CanonicalPath::new(value).is_ok() {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_path".to_owned(),
            message: message!(
                "routing-must-read-as-a-canonical-path",
                format!("{field} must read as a canonical path.")
            ),
        })
    }
}

/// What the trailing `/*` caught, spelled for the wire: the root when the
/// pattern has no `/*` or caught nothing.
fn below_prefix(captured: &Captures) -> String {
    let rest = captured.get(REST).unwrap_or_default();
    wire_spelling(rest.split('/').filter(|segment| !segment.is_empty()))
}

/// A captured value spelled for the wire. What `/*` caught holds several
/// segments; each is encoded and the slashes between them kept.
fn wire_value(value: &str) -> String {
    value
        .split('/')
        .map(encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

text_value! {
    /// A template for the forwarded path. It is literal text with `{name}`
    /// placeholders.
    pub struct PathTemplate;
}

impl TextValue for PathTemplate {
    const FIELD: &'static str = "path";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.url_path(2048).rule(&BalancedPlaceholders)
    }
}

impl PathTemplate {
    /// Every parameter name this template interpolates, in order.
    #[must_use]
    pub fn parameters(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut rest = self.0.as_str();
        while let Some((name, after)) = next_placeholder(rest) {
            names.push(name.to_owned());
            rest = after;
        }
        names
    }

    /// Renders the forwarded path, resolving each `{name}` through `lookup`.
    ///
    /// `None` when a placeholder resolves to nothing. A route saved through
    /// the use case never does that, since [`PathRewrite::validate_against`]
    /// refuses the pair. So the caller should treat `None` as a corrupt route
    /// and refuse the request. It must not forward a path with a literal
    /// brace in it.
    #[must_use]
    pub fn render(&self, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
        let mut out = String::with_capacity(self.0.len());
        let mut rest = self.0.as_str();

        while let Some((before, opened)) = rest.split_once('{') {
            let (name, after) = opened.split_once('}')?;
            out.push_str(before);
            out.push_str(&lookup(name)?);
            rest = after;
        }

        out.push_str(rest);
        Some(out)
    }
}

/// The parameter names a route pattern captures.
///
/// The pattern language is `{name}` for one segment and a trailing `/*` for
/// the rest, captured as `rest`. See
/// [`crate::domains::routing::matching::path_match`].
fn parameters_in(pattern: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = pattern;
    while let Some((name, after)) = next_placeholder(rest) {
        names.insert(name.to_owned());
        rest = after;
    }
    if pattern.ends_with("/*") {
        names.insert(REST.to_owned());
    }
    names
}

/// The name inside the first closed `{name}` of `text`, and the text after it.
fn next_placeholder(text: &str) -> Option<(&str, &str)> {
    let (_, opened) = text.split_once('{')?;
    opened.split_once('}')
}

/// Every `{` closed by a `}` around a non-empty name, none nested.
struct BalancedPlaceholders;

impl Rule for BalancedPlaceholders {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let problem = placeholder_problem(value)?;
        Some(ValidationError::Custom {
            field,
            code: "invalid_placeholder".to_owned(),
            message: message!("routing-path-rewrite", format!("path rewrite {problem}")),
        })
    }
}

/// What follows an opened `{` so far: nothing yet, or a name.
#[derive(Clone, Copy)]
enum OpenName {
    Empty,
    Named,
}

/// What is wrong with the placeholders in `value`, if anything.
fn placeholder_problem(value: &str) -> Option<&'static str> {
    let mut open: Option<OpenName> = None;
    for ch in value.chars() {
        open = match (ch, open) {
            ('{', Some(_)) => return Some("has a nested '{'"),
            ('{', None) => Some(OpenName::Empty),
            ('}', None) => return Some("has a '}' with no opening '{'"),
            ('}', Some(OpenName::Empty)) => return Some("has an empty '{}' placeholder"),
            ('}', Some(OpenName::Named)) => None,
            (_, Some(_)) => Some(OpenName::Named),
            (_, None) => None,
        };
    }
    open.map(|_| "has an unclosed '{'")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(s: &str) -> UrlPath {
        UrlPath::new(s).unwrap()
    }

    /// A route given no rewrite forwards the path exactly as it arrived.
    #[test]
    fn keep_is_the_default() {
        assert_eq!(PathRewrite::default(), PathRewrite::Keep);
    }

    /// The template `/internal/user/{id}/prefs/{key}` lists `id` then `key`.
    #[test]
    fn a_template_lists_the_parameters_it_uses() {
        let t = PathTemplate::new("/internal/user/{id}/prefs/{key}").unwrap();

        assert_eq!(t.parameters(), vec!["id".to_owned(), "key".to_owned()]);
    }

    /// An operator writes `/internal/user/{id}`. The template reads back as
    /// exactly that, since the proxy renders from it and the operator edits
    /// what they see.
    #[test]
    fn a_template_reads_back_as_the_path_it_was_written_as() {
        let t = PathTemplate::new("/internal/user/{id}").unwrap();

        assert_eq!(t.as_str(), "/internal/user/{id}");
    }

    /// The template `/internal/health` has no parameters. It renders as that
    /// path whatever was captured.
    #[test]
    fn a_template_with_no_parameters_is_a_fixed_path() {
        let t = PathTemplate::new("/internal/health").unwrap();

        assert!(t.parameters().is_empty());
        assert_eq!(t.render(|_| None).unwrap(), "/internal/health");
    }

    /// `/internal/user/{id}` with `id` captured as `42` renders as
    /// `/internal/user/42`.
    #[test]
    fn render_substitutes_every_placeholder() {
        let t = PathTemplate::new("/internal/user/{id}").unwrap();

        let rendered = t.render(|name| (name == "id").then(|| "42".to_owned()));

        assert_eq!(rendered.unwrap(), "/internal/user/42");
    }

    /// `/internal/user/{id}` is rendered with no `id` captured. It gives
    /// nothing, so no path with a literal `{id}` is forwarded.
    #[test]
    fn render_gives_up_when_a_parameter_is_missing() {
        let t = PathTemplate::new("/internal/user/{id}").unwrap();

        assert!(t.render(|_| None).is_none());
    }

    /// Templates with an unclosed `{`, a stray `}`, nested braces or an
    /// empty `{}` are each refused.
    #[test]
    fn malformed_braces_are_refused() {
        for bad in [
            "/internal/{id",
            "/internal/id}",
            "/internal/{{id}}",
            "/internal/{}",
        ] {
            assert!(
                PathTemplate::new(bad).is_err(),
                "{bad} should not be a valid template"
            );
        }
    }

    /// The template `internal/{id}` has no leading slash. It is refused as
    /// not a path.
    #[test]
    fn a_template_must_still_be_a_path() {
        assert!(PathTemplate::new("internal/{id}").is_err());
    }

    /// A stored template has an unclosed brace or no leading slash. Reading
    /// it is refused, so the route fails when read and not on every request.
    #[cfg(feature = "serde")]
    #[test]
    fn a_malformed_template_is_refused_on_deserialize() {
        for bad in [r#""/internal/{id""#, r#""internal/{id}""#] {
            assert!(
                serde_json::from_str::<PathTemplate>(bad).is_err(),
                "{bad} must be refused"
            );
        }
    }

    /// A rewrite to `/internal/user/{id}` is written to JSON and read back.
    /// It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_template_rewrite_round_trips_through_json() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/user/{id}").unwrap());

        let json = serde_json::to_string(&rewrite).unwrap();

        assert_eq!(serde_json::from_str::<PathRewrite>(&json).unwrap(), rewrite);
    }

    /// A template uses `{id}` but the pattern `/v1/users/{user}` captures
    /// only `user`. The pair is refused, so the route is not saved broken.
    #[test]
    fn a_template_naming_an_uncaptured_parameter_is_refused() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/user/{id}").unwrap());

        let result = rewrite.validate_against(&pattern("/v1/users/{user}"));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A template uses `{id}` and the pattern `/v1/users/{id}` captures it.
    /// The pair is accepted.
    #[test]
    fn a_template_naming_a_captured_parameter_is_accepted() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/user/{id}").unwrap());

        assert!(rewrite.validate_against(&pattern("/v1/users/{id}")).is_ok());
    }

    /// The pattern `/v1/*` captures the remainder as `rest`. A template
    /// `/internal/{rest}` is accepted against it.
    #[test]
    fn a_wildcard_pattern_captures_rest() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/{rest}").unwrap());

        assert!(rewrite.validate_against(&pattern("/v1/*")).is_ok());
    }

    fn forwarded(rewrite: &PathRewrite, pattern: &str, path: &str) -> Option<String> {
        let path = CanonicalPath::new(path).unwrap();
        let captured =
            crate::domains::routing::matching::path_match::captures(pattern, &path).unwrap();
        rewrite
            .forwarded(&path, &captured)
            .map(|forwarded| forwarded.as_str().to_owned())
    }

    /// `/files/a%20b` is a path to forward. A relative path, a space, a
    /// query and a `..` segment, plain or encoded, are refused.
    #[test]
    fn a_forwarded_path_reads_as_a_canonical_path() {
        assert_eq!(
            ForwardedPath::new("/files/a%20b").unwrap().as_str(),
            "/files/a%20b"
        );
        for refused in ["files", "/a b", "/a?x=1", "/a/../b", "/a/%2e%2e/b"] {
            assert!(ForwardedPath::new(refused).is_err(), "{refused} was kept");
        }
    }

    /// `/files/a b` is kept and goes upstream as `/files/a%20b`, never with
    /// a bare space.
    #[test]
    fn keep_forwards_the_matched_path_spelled_for_the_wire() {
        assert_eq!(
            forwarded(&PathRewrite::Keep, "/files/*", "/files/a%20b").unwrap(),
            "/files/a%20b"
        );
    }

    /// `/api/v1/*` strips `/api/v1/users/123` to `/users/123`, and
    /// `/api/v1` itself to the root.
    #[test]
    fn strip_prefix_forwards_what_the_wildcard_caught() {
        let strip = PathRewrite::StripPrefix;

        assert_eq!(
            forwarded(&strip, "/api/v1/*", "/api/v1/users/123").unwrap(),
            "/users/123"
        );
        assert_eq!(forwarded(&strip, "/api/v1/*", "/api/v1").unwrap(), "/");
    }

    /// `/tenants/{id}/*` strips the captured id with the literal before it:
    /// `/tenants/7/orders/1` is forwarded as `/orders/1`, the same whatever
    /// the id was.
    #[test]
    fn strip_prefix_drops_a_parameter_before_the_wildcard_too() {
        let strip = PathRewrite::StripPrefix;

        assert_eq!(
            forwarded(&strip, "/tenants/{id}/*", "/tenants/7/orders/1").unwrap(),
            "/orders/1"
        );
        assert_eq!(
            forwarded(&strip, "/tenants/{id}/*", "/Tenants/x%20y").unwrap(),
            "/"
        );
    }

    /// A closed pattern has nothing below its prefix, so it forwards the
    /// root.
    #[test]
    fn strip_prefix_on_a_closed_pattern_forwards_the_root() {
        assert_eq!(
            forwarded(&PathRewrite::StripPrefix, "/users/{id}", "/users/42").unwrap(),
            "/"
        );
    }

    /// Keeping the id the strip would drop is a template's job:
    /// `/{id}/{rest}` forwards `/tenants/7/orders/1` as `/7/orders/1`.
    #[test]
    fn a_template_keeps_what_strip_prefix_would_drop() {
        let keep_id = PathRewrite::Template(PathTemplate::new("/{id}/{rest}").unwrap());

        assert_eq!(
            forwarded(&keep_id, "/tenants/{id}/*", "/tenants/7/orders/1").unwrap(),
            "/7/orders/1"
        );
    }

    /// A captured value with a space goes upstream encoded.
    #[test]
    fn a_template_encodes_what_it_captured() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/user/{id}").unwrap());

        assert_eq!(
            forwarded(&rewrite, "/v1/users/{id}", "/v1/users/a%20b").unwrap(),
            "/internal/user/a%20b"
        );
    }

    /// A template naming a parameter the pattern never captured forwards
    /// nothing, rather than a path with a literal `{id}` in it.
    #[test]
    fn a_template_naming_an_uncaptured_parameter_forwards_nothing() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/{id}").unwrap());

        assert!(forwarded(&rewrite, "/v1/*", "/v1/x").is_none());
    }

    /// Keeping the path and stripping the prefix use no parameters. Both are
    /// accepted against `/v1/*`.
    #[test]
    fn keep_and_strip_prefix_need_no_parameters() {
        assert!(
            PathRewrite::Keep
                .validate_against(&pattern("/v1/*"))
                .is_ok()
        );
        assert!(
            PathRewrite::StripPrefix
                .validate_against(&pattern("/v1/*"))
                .is_ok()
        );
    }
}
