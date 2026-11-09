//! Literal and placeholder reading without evaluating source or template code.

use std::collections::BTreeSet;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

use crate::catalog::Syntax;

/// The decoded string literals in a macro, including nested groups, in source order.
pub(crate) fn strings(tokens: TokenStream) -> Vec<syn::LitStr> {
    let mut found = Vec::new();
    let mut tokens = tokens.into_iter().peekable();
    while let Some(token) = tokens.next() {
        match token {
            TokenTree::Punct(punctuation) if punctuation.as_char() == '#' => {
                if matches!(tokens.peek(), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket)
                {
                    tokens.next();
                }
            }
            TokenTree::Group(group) => found.extend(strings(group.stream())),
            TokenTree::Literal(literal) => {
                if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    found.push(syn::LitStr::new(&text.value(), literal.span()));
                }
            }
            _ => {}
        }
    }
    found
}

/// Named or positional substitutions, retaining their original formatting grammar.
pub(crate) fn placeholders(text: &str, syntax: Syntax) -> BTreeSet<String> {
    match syntax {
        Syntax::Plain => BTreeSet::new(),
        Syntax::RustFormat => rust_placeholders(text),
        Syntax::MiniJinja => template_placeholders(text),
    }
}

/// Reads Rust replacement fields while leaving doubled literal braces alone.
fn rust_placeholders(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = text;
    let mut fields = FieldNames::default();
    while let Some(start) = rest.find('{') {
        rest = &rest[start + 1..];
        if let Some(escaped) = rest.strip_prefix('{') {
            rest = escaped;
            continue;
        }
        let Some(end) = rest.find('}') else { break };
        found.insert(fields.name(&rest[..end]));
        rest = &rest[end + 1..];
    }
    found
}

/// Names the replacement fields of one Rust format string in order.
#[derive(Default)]
pub(crate) struct FieldNames {
    next_position: usize,
}

impl FieldNames {
    /// The field's name without its format spec; an unnamed field takes
    /// the next positional index, as `format!` counts them.
    pub(crate) fn name(&mut self, field: &str) -> String {
        let name = field.split(':').next().unwrap_or_default().trim();
        if !name.is_empty() {
            return name.to_owned();
        }
        let position = self.next_position;
        self.next_position += 1;
        position.to_string()
    }
}

/// Reads Jinja expressions and control tags, allowing quoted prose to be translated.
fn template_placeholders(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (opening, closing) in [("{{", "}}"), ("{%", "%}")] {
        let mut rest = text;
        while let Some(start) = rest.find(opening) {
            rest = &rest[start + opening.len()..];
            let Some(end) = rest.find(closing) else { break };
            found.insert(format!(
                "{opening}{}{closing}",
                without_quoted_values(&rest[..end])
            ));
            rest = &rest[end + closing.len()..];
        }
    }
    found
}

/// Keeps an expression's structure while replacing quoted contents with a marker.
fn without_quoted_values(text: &str) -> String {
    let mut found = String::new();
    let mut quoted = None;
    let mut escaped = false;
    for character in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quoted, character) {
            (Some(_), '\\') => escaped = true,
            (Some(quote), character) if quote == character => quoted = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => {
                quoted = Some(character);
                found.push_str("\"text\"");
            }
            (None, character) if !character.is_whitespace() => found.push(character),
            _ => {}
        }
    }
    found
}

/// Whether otherwise unclassified text contains words a translator may need to inspect.
pub(crate) fn prose(text: &str) -> bool {
    let words = text
        .split_whitespace()
        .filter(|word| word.chars().any(char::is_alphabetic))
        .count();
    words >= 2
        && !text.trim_start().starts_with("SELECT ")
        && !text.trim_start().starts_with("INSERT ")
        && !text.trim_start().starts_with("UPDATE ")
        && !text.trim_start().starts_with("DELETE ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Escaped braces are text, while positional and named values remain separate substitutions.
    #[test]
    fn rust_placeholders_keep_named_and_positional_values() {
        let found = placeholders("{{literal}} {name} {} {:02} {count:?}", Syntax::RustFormat);
        assert_eq!(found, ["0", "1", "count", "name"].map(str::to_owned).into());
    }

    /// A macro's raw and escaped strings are decoded without treating comments as text.
    #[test]
    fn nested_macros_keep_decoded_literals_and_their_lines() {
        let tokens: TokenStream = "format!(r#\"Hello {name}\"#, nested(\"Line\\nnext\"))"
            .parse()
            .unwrap();
        let found = strings(tokens);
        assert_eq!(
            found.iter().map(syn::LitStr::value).collect::<Vec<_>>(),
            ["Hello {name}", "Line\nnext"]
        );
    }

    /// Macro documentation is excluded while the refusal literal remains in the collected strings.
    #[test]
    fn macro_documentation_is_not_a_message_literal() {
        let tokens: TokenStream =
            "#[doc = \"A documented domain value\"] struct Name; \"An actual refusal\""
                .parse()
                .unwrap();
        let found = strings(tokens);
        assert_eq!(
            found.iter().map(syn::LitStr::value).collect::<Vec<_>>(),
            ["An actual refusal"]
        );
    }

    /// A template can translate a default greeting while retaining the expression and its variables.
    #[test]
    fn template_prose_changes_but_expressions_remain_identifiable() {
        let original = "{% if name %}Hello {{ name | default(\"there\") }}{% endif %}";
        let translated = "{% if name %}Hallo {{ name | default(\"du\") }}{% endif %}";
        assert_eq!(
            placeholders(original, Syntax::MiniJinja),
            placeholders(translated, Syntax::MiniJinja)
        );
        assert_ne!(
            placeholders(original, Syntax::MiniJinja),
            placeholders("Hallo {{ other }}", Syntax::MiniJinja)
        );
    }
}
