//! The tenant's custom CSS made safe: parsed as a browser parses it, and
//! written back from the parsed rules, keeping only what an allow-list
//! names.
//!
//! Nothing is copied from the tenant's text. Each kept selector, property
//! and value is written again from its tokens, so a comment, an escape, a
//! string, an at-rule or a `url()` is never written at all: there is no
//! way to spell one that survives. What is kept:
//!
//! - selectors of names, classes, ids, `*`, `:` pseudo-classes and the
//!   combinators, no attribute selector and no function such as `:not()`;
//! - the properties `SanitizedCss` allows: colours, borders, spacing, font
//!   size and weight, alignment;
//! - values of names, numbers, units, percentages, hex colours, commas,
//!   and the colour functions `rgb`, `rgba`, `hsl` and `hsla`. No other
//!   function, so no `url()`, `expression()`, `image-set()` or `var()`.
//!
//! A declaration that breaks a rule is dropped alone; a rule left with no
//! declaration, or whose selectors break a rule, is dropped whole. A page
//! loads nothing from anywhere through what is kept, so there are no
//! allowed origins to name. What is written is checked once more as it
//! becomes a `SanitizedCss`.
//!
//! The input is bounded before a token of it is read: a `RawCss` cannot be
//! made, by hand or from a request body, past `MAX_CSS_BYTES`, so the
//! sanitizer never sees more. The reader does not recurse, so depth costs
//! no stack: a stylesheet nested as deep as that length allows is read in
//! a few passes over its tokens.

use ianua_app::ports::branding::CssSanitizer;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::branding::ALLOWED_PROPERTIES;
use ianua_domain::types::{RawCss, SanitizedCss};

use crate::css::sheet::{Declaration, Rule, rules};
use crate::css::tokens::{Token, tokens};

/// The functions a value may call.
const COLOUR_FUNCTIONS: [&str; 4] = ["rgb", "rgba", "hsl", "hsla"];

/// The tenant's CSS parsed and written back through an allow-list.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowListCssSanitizer;

impl CssSanitizer for AllowListCssSanitizer {
    fn sanitize(&self, raw: &RawCss) -> Result<SanitizedCss, DomainError> {
        let kept: Vec<String> = rules(&tokens(raw.as_str()))
            .iter()
            .filter_map(written_rule)
            .collect();
        if kept.is_empty() {
            return Err(DomainError::invalid(message!(
                "infra-the-custom-css-holds-no-rule",
                "the custom CSS holds no rule a page may render"
            )));
        }
        Ok(SanitizedCss::new(kept.join("\n"))?)
    }
}

/// `rule` written back with what it may keep, or `None` when nothing of
/// it may be kept.
fn written_rule(rule: &Rule) -> Option<String> {
    let selectors = written_selectors(&rule.prelude)?;
    let declarations: Vec<String> = rule
        .declarations
        .iter()
        .filter_map(written_declaration)
        .collect();
    if declarations.is_empty() {
        return None;
    }
    Some(format!("{selectors} {{ {} }}", declarations.join(" ")))
}

/// A rule's selectors written back, or `None` when one of them is more
/// than plain names, classes, ids, pseudo-classes and combinators.
fn written_selectors(prelude: &[Token]) -> Option<String> {
    let mut written = String::new();
    for token in prelude {
        written.push_str(&selector_part(token)?);
    }
    let written = collapsed(&written);
    (!written.is_empty()).then_some(written)
}

/// One token of a selector written back.
fn selector_part(token: &Token) -> Option<String> {
    match token {
        Token::Ident(name) if is_plain(name, Spelling::Selector) => Some(name.clone()),
        Token::Hash(name) if is_plain(name, Spelling::Selector) => Some(format!("#{name}")),
        Token::Delim(mark @ ('.' | '*' | '>' | '+' | '~')) => Some(mark.to_string()),
        Token::Colon => Some(":".to_owned()),
        Token::Comma => Some(",".to_owned()),
        Token::Whitespace => Some(" ".to_owned()),
        Token::Ident(_)
        | Token::Hash(_)
        | Token::Delim(_)
        | Token::Function(_)
        | Token::AtKeyword(_)
        | Token::Quoted
        | Token::BadString
        | Token::Url
        | Token::BadUrl
        | Token::Number(_)
        | Token::Percentage(_)
        | Token::Dimension(..)
        | Token::Semicolon
        | Token::OpenParen
        | Token::CloseParen
        | Token::OpenSquare
        | Token::CloseSquare
        | Token::OpenCurly
        | Token::CloseCurly
        | Token::Cdo
        | Token::Cdc => None,
    }
}

/// `declaration` written back as `property: value;`, or `None` when its
/// property is not allowed or its value is more than plain.
fn written_declaration(declaration: &Declaration) -> Option<String> {
    let property = declaration.property.to_ascii_lowercase();
    if !ALLOWED_PROPERTIES.contains(&property.as_str()) {
        return None;
    }
    let value = written_value(without_important(&declaration.value))?;
    Some(format!("{property}: {value};"))
}

/// A value written back, or `None` when it holds anything but names,
/// numbers, hex colours, commas and calls of the colour functions.
fn written_value(value: &[Token]) -> Option<String> {
    let mut written = String::new();
    let mut open_calls: usize = 0;
    for token in value {
        match value_part(token)? {
            Part::Plain(text) => written.push_str(&text),
            Part::OpensCall(text) => {
                open_calls = open_calls.saturating_add(1);
                written.push_str(&text);
            }
            Part::ClosesCall => {
                open_calls = open_calls.checked_sub(1)?;
                written.push(')');
            }
        }
    }
    let written = collapsed(&written);
    (open_calls == 0 && !written.is_empty()).then_some(written)
}

/// One token of a value as it is written back.
enum Part {
    /// Plain text: a name, a number, a hex colour, a comma or a space.
    Plain(String),
    /// The opening of a call to a colour function, such as `rgb(`.
    OpensCall(String),
    /// The `)` closing a call.
    ClosesCall,
}

/// The opening of a call to `name`, when it is a colour function.
fn colour_call(name: &str) -> Option<Part> {
    let name = name.to_ascii_lowercase();
    COLOUR_FUNCTIONS
        .contains(&name.as_str())
        .then(|| Part::OpensCall(format!("{name}(")))
}

/// One token of a value written back, or `None` when it is not plain.
fn value_part(token: &Token) -> Option<Part> {
    match token {
        Token::Ident(name) if is_plain(name, Spelling::Value) => Some(Part::Plain(name.clone())),
        Token::Hash(name) if is_plain(name, Spelling::Value) => {
            Some(Part::Plain(format!("#{name}")))
        }
        Token::Number(number) => number_part(number, ""),
        Token::Percentage(number) => number_part(number, "%"),
        Token::Dimension(number, unit) => dimension_part(number, unit),
        Token::Comma => Some(Part::Plain(",".to_owned())),
        Token::Whitespace => Some(Part::Plain(" ".to_owned())),
        Token::Function(name) => colour_call(name),
        Token::CloseParen => Some(Part::ClosesCall),
        Token::Ident(_)
        | Token::Hash(_)
        | Token::AtKeyword(_)
        | Token::Quoted
        | Token::BadString
        | Token::Url
        | Token::BadUrl
        | Token::Colon
        | Token::Semicolon
        | Token::OpenParen
        | Token::OpenSquare
        | Token::CloseSquare
        | Token::OpenCurly
        | Token::CloseCurly
        | Token::Cdo
        | Token::Cdc
        | Token::Delim(_) => None,
    }
}

/// A validated number followed by its already-checked unit or percent sign.
fn number_part(number: &str, suffix: &str) -> Option<Part> {
    plain_number(number).map(|number| Part::Plain(format!("{number}{suffix}")))
}

/// A dimension is emitted only when its unit needs no CSS escaping.
fn dimension_part(number: &str, unit: &str) -> Option<Part> {
    if !unit.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    number_part(number, unit)
}

/// `number` without a leading `+`, which a plain value never writes, when
/// it is digits, a point, a minus and an exponent alone.
fn plain_number(number: &str) -> Option<String> {
    let number = number.strip_prefix('+').unwrap_or(number);
    let plain = number
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | 'e' | 'E'));
    (plain && !number.is_empty()).then(|| number.to_owned())
}

/// Where a name is written, which decides the characters it may hold.
#[derive(Debug, Clone, Copy)]
enum Spelling {
    /// In a selector: letters, digits, `-` and `_`.
    Selector,
    /// In a value: letters, digits and `-`.
    Value,
}

/// Whether `name` holds only the characters `spelling` allows, so writing
/// it back needs no escape.
fn is_plain(name: &str, spelling: Spelling) -> bool {
    let allowed = |c: char| match spelling {
        Spelling::Selector => c.is_ascii_alphanumeric() || matches!(c, '-' | '_'),
        Spelling::Value => c.is_ascii_alphanumeric() || c == '-',
    };
    !name.is_empty() && name.chars().all(allowed)
}

/// `value` without a closing `!important`, which a sanitized stylesheet
/// does not keep.
fn without_important(value: &[Token]) -> &[Token] {
    let Some((Token::Ident(word), before)) = value.split_last() else {
        return value;
    };
    if !word.eq_ignore_ascii_case("important") {
        return value;
    }
    let before = trim_end_whitespace(before);
    match before.split_last() {
        Some((Token::Delim('!'), rest)) => trim_end_whitespace(rest),
        Some(_) | None => value,
    }
}

/// `tokens` without the whitespace at their end.
fn trim_end_whitespace(tokens: &[Token]) -> &[Token] {
    let end = tokens
        .iter()
        .rposition(|token| *token != Token::Whitespace)
        .map_or(0, |last| last.saturating_add(1));
    tokens.get(..end).unwrap_or_default()
}

/// `text` with its runs of spaces made one and its ends trimmed.
fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::branding::MAX_CSS_BYTES;

    use super::*;

    fn sanitized(css: &str) -> Result<String, DomainError> {
        AllowListCssSanitizer
            .sanitize(&RawCss::new(css).unwrap())
            .map(|kept| kept.as_str().to_owned())
    }

    /// Plain rules come back written the platform's way, with what they
    /// said kept.
    #[test]
    fn plain_rules_are_kept() {
        let kept = sanitized(
            ".login{padding:20px;color:#333}\nbody { background-color: RGB(16, 24, 40) !important }",
        )
        .unwrap();

        assert_eq!(
            kept,
            ".login { padding: 20px; color: #333; }\nbody { background-color: rgb(16, 24, 40); }"
        );
    }

    /// URL spellings, image sets and variables are removed while the adjacent
    /// plain colour declaration survives.
    #[test]
    fn every_url_is_dropped() {
        for value in [
            "url(https://evil.test/a)",
            "url('https://evil.test/a')",
            "\\75 rl(https://evil.test/a)",
            "u\\72l(x)",
            "image-set('x' 1x)",
            "var(--leak)",
        ] {
            let css = format!(".a {{ background-color: {value}; color: red }}");

            let kept = sanitized(&css).unwrap();

            assert_eq!(kept, ".a { color: red; }", "{value}");
        }
    }

    /// Imports, media rules and font-face rules are dropped, including an import
    /// split by a comment; the ordinary margin rule remains.
    #[test]
    fn at_rules_are_dropped() {
        let css = "@import url(https://evil.test/x.css);\n@im/**/port 'x';\n\
                   @media all { .a { color: red } }\n@font-face { color: red }\n.b { margin: 0 }";

        assert_eq!(sanitized(css).unwrap(), ".b { margin: 0; }");
    }

    /// Script expressions, script addresses and behavior bindings are removed
    /// while the plain colour declaration remains.
    #[test]
    fn script_in_any_form_is_dropped() {
        let css = ".a { color: expression(alert(1)); border-color: javascript:alert(1); \
                   behavior: url(x.htc); -moz-binding: url(x); color: blue }";

        assert_eq!(sanitized(css).unwrap(), ".a { color: blue; }");
    }

    /// Attribute selectors and selector functions lose their entire rules;
    /// a plain hover selector with a child combinator remains.
    #[test]
    fn selectors_beyond_plain_ones_drop_the_rule() {
        let css = "input[name=csrf][value^=a] { color: red }\n.a:not(.b) { color: red }\n\
                   .a:has(input) { color: red }\n.ok:hover > span { color: red }";

        assert_eq!(sanitized(css).unwrap(), ".ok:hover > span { color: red; }");
    }

    /// Content, positioning and quoted colour values are discarded, including
    /// an escaped quote, while font weight remains.
    #[test]
    fn drawing_and_strings_are_dropped() {
        let css = ".a::before { content: 'Sign in here'; position: fixed; color: \"red\"; \
                   color: \\22 red; font-weight: 600 }";

        assert_eq!(sanitized(css).unwrap(), ".a::before { font-weight: 600; }");
    }

    /// A brace and nested selector inside a function are discarded with the
    /// malformed declaration, leaving only the enclosing rule's margin.
    #[test]
    fn a_smuggled_brace_closes_nothing() {
        let css = ".a { color: rgb(}; .evil[x] { color: red } ); margin: 0 }";

        assert_eq!(sanitized(css).unwrap(), ".a { margin: 0; }");
    }

    /// A stylesheet with nothing a page may render is refused, rather than
    /// saved as nothing.
    #[test]
    fn nothing_left_is_refused() {
        for css in [
            "@import url(x.css);",
            "/* only a comment */",
            ".a { position: fixed }",
        ] {
            assert!(
                matches!(sanitized(css), Err(DomainError::Validation(_))),
                "{css}"
            );
        }
    }

    /// Nesting up to the stylesheet length bound is discarded without losing
    /// the preceding plain rule or overflowing the stack.
    #[test]
    fn nesting_as_deep_as_the_limit_allows_is_read_without_recursion() {
        let plain = ".a { color: red }\n";
        let depth = (MAX_CSS_BYTES - plain.len() - 14) / 2;
        let css = format!(
            "{plain}.b {{ color: {}{} }}",
            "(".repeat(depth),
            ")".repeat(depth)
        );

        assert_eq!(sanitized(&css).unwrap(), ".a { color: red; }");
    }

    /// A stylesheet filled with unclosed blocks up to the input bound fails validation.
    #[test]
    fn unclosed_blocks_up_to_the_limit_are_refused() {
        let css = ".a{".repeat(MAX_CSS_BYTES / 3);

        assert!(matches!(sanitized(&css), Err(DomainError::Validation(_))));
    }

    /// Everything kept passes the domain's own check of a sanitized
    /// stylesheet, however the tenant wrote it.
    #[test]
    fn what_is_kept_passes_the_domains_check() {
        let css = "H1 , .x>Y ~ z { MARGIN : -1.5em auto ; Line-Height: 1.2 ; \
                   color: hsla(120, 50%, +50%, .5) }\n#Main_Area{border:1px solid #ABC}";

        let kept = sanitized(css).unwrap();

        assert!(SanitizedCss::new(kept.clone()).is_ok(), "{kept}");
        assert!(kept.contains("margin: -1.5em auto;"));
        assert!(kept.contains("color: hsla(120, 50%, 50%, .5);"));
    }
}
