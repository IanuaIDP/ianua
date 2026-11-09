//! Custom CSS in the only form a page may render.

use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::branding::MAX_CSS_BYTES;

text_value! {
    /// Custom CSS that is safe to place in a page: plain rules only.
    ///
    /// A tenant's own [`RawCss`](crate::types::branding::RawCss) could read secrets out of
    /// the page. Eve writes one attribute selector per character of a hidden
    /// token, each loading a different `url()`, and her server learns the
    /// token. Raw CSS could also import a stylesheet or draw a fake form over
    /// the real one.
    ///
    /// A sanitizer parses the raw CSS with a real CSS parser and writes back
    /// only what this type accepts. This type then checks the result again,
    /// so even a careless sanitizer cannot hand a page anything else:
    ///
    /// - Rules of the form `selectors { property: value; ... }` and nothing
    ///   else. No at-rule, comment or escape.
    /// - Selectors of letters, digits, `.`, `#`, `_`, `-`, `:`, `,`, `>`,
    ///   `+`, `~`, `*` and whitespace. No attribute selector and no `(`.
    /// - Properties from [`ALLOWED_PROPERTIES`]: colours, borders, spacing,
    ///   font size and weight, and alignment.
    /// - Values of letters, digits, `#`, `.`, `%`, `,`, `-` and spaces. The
    ///   only functions are `rgb`, `rgba`, `hsl` and `hsla`. No `url`, quote
    ///   or `/`.
    pub struct SanitizedCss;
}

impl TextValue for SanitizedCss {
    const FIELD: &'static str = "custom_css";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().max_bytes(MAX_CSS_BYTES).rule(&PlainRules)
    }
}

/// The properties a sanitized stylesheet may set.
pub const ALLOWED_PROPERTIES: [&str; 21] = [
    "color",
    "background-color",
    "border",
    "border-color",
    "border-width",
    "border-style",
    "border-radius",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "font-size",
    "font-weight",
    "text-align",
    "line-height",
];

/// The only functions a value may call.
const ALLOWED_FUNCTIONS: [&str; 4] = ["rgb", "rgba", "hsl", "hsla"];

struct PlainRules;

impl Rule for PlainRules {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let problem = stylesheet_problem(value)?;
        Some(ValidationError::Custom {
            field,
            code: "unsafe_css".to_owned(),
            message: message!("agents-message", format!("{field} {problem}.")),
        })
    }
}

fn stylesheet_problem(css: &str) -> Option<&'static str> {
    let mut rest = css.trim();
    while !rest.is_empty() {
        let Some((selectors, after)) = rest.split_once('{') else {
            return Some("must be rules of the form `selectors { property: value; }`");
        };
        let Some((body, remainder)) = after.split_once('}') else {
            return Some("has a rule that is never closed");
        };
        if let Some(problem) = selector_problem(selectors).or_else(|| body_problem(body)) {
            return Some(problem);
        }
        rest = remainder.trim_start();
    }
    None
}

fn selector_problem(selectors: &str) -> Option<&'static str> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || " .#_-:,>+~*\n\t".contains(c);
    if selectors.trim().is_empty() || !selectors.chars().all(allowed) {
        return Some("may only use plain selectors: no attribute selector, quote, escape or `(`");
    }
    None
}

fn body_problem(body: &str) -> Option<&'static str> {
    body.split(';')
        .map(str::trim)
        .filter(|declaration| !declaration.is_empty())
        .find_map(declaration_problem)
}

fn declaration_problem(declaration: &str) -> Option<&'static str> {
    let Some((property, value)) = declaration.split_once(':') else {
        return Some("must write each declaration as `property: value`");
    };
    if !ALLOWED_PROPERTIES.contains(&property.trim().to_ascii_lowercase().as_str()) {
        return Some("may only set colours, borders, spacing, font size and weight, and alignment");
    }
    value_problem(value.trim())
}

fn value_problem(value: &str) -> Option<&'static str> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || " #.%,-()".contains(c);
    if value.is_empty() || !value.chars().all(allowed) {
        return Some("may only use plain values: no quote, `/`, escape or `url`");
    }
    let calls_only_colours = value.rsplit('(').skip(1).all(ends_with_allowed_function);
    if !calls_only_colours {
        return Some("may only call rgb, rgba, hsl or hsla");
    }
    None
}

fn ends_with_allowed_function(before: &str) -> bool {
    let name: String = before
        .chars()
        .rev()
        .take_while(char::is_ascii_alphabetic)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    ALLOWED_FUNCTIONS.contains(&name.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rules that set padding, colours with `rgb()`, rounded borders, font
    /// size and margins on plain selectors are all accepted.
    #[test]
    fn plain_visual_rules_are_accepted() {
        for css in [
            ".login { padding: 20px; color: #333; }",
            "body{background-color:rgb(16, 24, 40)}",
            ".btn, .link:hover > span { border-radius: 4px; font-weight: 600 }",
            "h1 { font-size: 1.5em; text-align: center; }\n.card { margin: 0 auto; }",
        ] {
            assert!(SanitizedCss::new(css).is_ok(), "{css:?} was refused");
        }
    }

    /// A selector inspecting the value of a hidden CSRF field is refused,
    /// keeping sensitive attributes out of rendered style rules.
    #[test]
    fn an_attribute_selector_is_refused() {
        assert!(
            SanitizedCss::new("input[name=csrf_token][value^=a] { background-color: red }")
                .is_err()
        );
    }

    /// Resource loading, generated content, positioning, unsupported selectors
    /// and malformed CSS are refused instead of entering the rendered stylesheet.
    #[test]
    fn anything_that_loads_or_draws_content_is_refused() {
        for css in [
            ".a { background-color: url(https://evil.example/a) }",
            ".a { background-color: url(x) }",
            "@import url(https://evil.example/x.css);",
            "@font-face { color: red }",
            ".a { content: 'Sign in here' }",
            ".a::before { content: x }",
            ".a { background: image-set(x 1x) }",
            ".a { color: expression(alert(1)) }",
            ".a { color: \\72 ed }",
            "/* x */ .a { color: red }",
            ".a { color: \"red\" }",
            ".a { position: fixed }",
            ".a:not(.b) { color: red }",
            ".a { color: red",
            "just text",
        ] {
            assert!(SanitizedCss::new(css).is_err(), "{css:?} was accepted");
        }
    }
}
