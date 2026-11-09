//! A stylesheet's rules, read from its tokens as the CSS Syntax Module
//! Level 3 parser reads them: at-rules and their blocks set apart whole,
//! each other rule a prelude of selectors and a block of declarations.
//!
//! Blocks are matched by their own kind of bracket, the way a browser
//! matches them, so a stray `}` inside a function or a string cannot end a
//! rule early and smuggle what follows into the next one. Nothing is
//! recursive: a stylesheet nested a thousand blocks deep is read like any
//! other.

use crate::css::tokens::Token;

/// One rule of the form `selectors { declarations }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    /// The tokens before the block: the selectors.
    pub(crate) prelude: Vec<Token>,
    /// The declarations the block holds.
    pub(crate) declarations: Vec<Declaration>,
}

/// One `property: value` of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    /// The property, as written.
    pub(crate) property: String,
    /// The tokens of its value, without the whitespace around it.
    pub(crate) value: Vec<Token>,
}

/// The rules of a stylesheet's `tokens`. At-rules, and a rule whose block
/// never opens, are left out.
pub(crate) fn rules(tokens: &[Token]) -> Vec<Rule> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        if matches!(token, Token::Whitespace | Token::Cdo | Token::Cdc) {
            at = at.saturating_add(1);
            continue;
        }
        if matches!(token, Token::AtKeyword(_)) {
            at = past_at_rule(tokens, at);
            continue;
        }
        let (rule, end) = qualified_rule(tokens, at);
        found.extend(rule);
        at = end;
    }
    found
}

/// The place just past the at-rule starting at `start`: past its `;`, or
/// past its block.
fn past_at_rule(tokens: &[Token], start: usize) -> usize {
    let mut at = start.saturating_add(1);
    while let Some(token) = tokens.get(at) {
        if *token == Token::Semicolon {
            return at.saturating_add(1);
        }
        if *token == Token::OpenCurly {
            return block_end(tokens, at);
        }
        at = past_component(tokens, at);
    }
    at
}

/// The rule starting at `start`, when its block opens, and the place just
/// past it.
fn qualified_rule(tokens: &[Token], start: usize) -> (Option<Rule>, usize) {
    let mut at = start;
    while let Some(token) = tokens.get(at) {
        if *token == Token::OpenCurly {
            let end = block_end(tokens, at);
            let prelude = tokens.get(start..at).unwrap_or_default();
            let rule = Rule {
                prelude: trimmed(prelude).to_vec(),
                declarations: declarations(inside_block(tokens, at, end)),
            };
            return (Some(rule), end);
        }
        at = past_component(tokens, at);
    }
    (None, at)
}

/// What the block opened at `open` and ended just before `end` holds,
/// without its brackets; to the end of the tokens when it never closed.
fn inside_block(tokens: &[Token], open: usize, end: usize) -> &[Token] {
    let last = end.saturating_sub(1);
    let closed = last > open && tokens.get(last) == Some(&Token::CloseCurly);
    let inner_end = if closed { last } else { end };
    tokens
        .get(open.saturating_add(1)..inner_end)
        .unwrap_or_default()
}

/// The declarations of a block's `tokens`, each ending at a `;` outside
/// any inner block. A piece that is not `name: value`, such as a nested
/// rule or an at-rule, is left out.
fn declarations(tokens: &[Token]) -> Vec<Declaration> {
    let mut found = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        if *token == Token::Semicolon {
            found.extend(declaration(tokens.get(start..at).unwrap_or_default()));
            start = at.saturating_add(1);
        }
        at = past_component(tokens, at);
    }
    found.extend(declaration(tokens.get(start..).unwrap_or_default()));
    found
}

/// The declaration `piece` holds, when it is a name, a colon and a value
/// with no block in it.
fn declaration(piece: &[Token]) -> Option<Declaration> {
    let piece = trimmed(piece);
    let (Token::Ident(property), rest) = piece.split_first()? else {
        return None;
    };
    let (Token::Colon, value) = trimmed(rest).split_first()? else {
        return None;
    };
    if value.contains(&Token::OpenCurly) {
        return None;
    }
    Some(Declaration {
        property: property.clone(),
        value: trimmed(value).to_vec(),
    })
}

/// The place just past the component at `at`: past a whole block when it
/// opens one, past the token itself otherwise.
fn past_component(tokens: &[Token], at: usize) -> usize {
    match tokens.get(at) {
        Some(Token::OpenCurly | Token::OpenSquare | Token::OpenParen | Token::Function(_)) => {
            block_end(tokens, at)
        }
        Some(_) | None => at.saturating_add(1),
    }
}

/// The place just past the block opened at `start`, each inner block
/// closed by its own kind of bracket; the end of the tokens when it never
/// closes.
fn block_end(tokens: &[Token], start: usize) -> usize {
    let mut waiting: Vec<Token> = Vec::new();
    let mut at = start;
    while let Some(token) = tokens.get(at) {
        at = at.saturating_add(1);
        if let Some(closer) = closer_of(token) {
            waiting.push(closer);
            continue;
        }
        if waiting.last() == Some(token) {
            waiting.pop();
        }
        if waiting.is_empty() {
            return at;
        }
    }
    at
}

/// The token that closes the block `token` opens, if it opens one.
fn closer_of(token: &Token) -> Option<Token> {
    match token {
        Token::OpenCurly => Some(Token::CloseCurly),
        Token::OpenSquare => Some(Token::CloseSquare),
        Token::OpenParen | Token::Function(_) => Some(Token::CloseParen),
        Token::Ident(_)
        | Token::AtKeyword(_)
        | Token::Hash(_)
        | Token::Quoted
        | Token::BadString
        | Token::Url
        | Token::BadUrl
        | Token::Number(_)
        | Token::Percentage(_)
        | Token::Dimension(..)
        | Token::Whitespace
        | Token::Colon
        | Token::Semicolon
        | Token::Comma
        | Token::CloseParen
        | Token::CloseSquare
        | Token::CloseCurly
        | Token::Cdo
        | Token::Cdc
        | Token::Delim(_) => None,
    }
}

/// `tokens` without the whitespace at either end.
fn trimmed(tokens: &[Token]) -> &[Token] {
    let start = tokens
        .iter()
        .position(|token| *token != Token::Whitespace)
        .unwrap_or(tokens.len());
    let end = tokens
        .iter()
        .rposition(|token| *token != Token::Whitespace)
        .map_or(start, |last| last.saturating_add(1));
    tokens.get(start..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::css::tokens::tokens;

    fn properties(css: &str) -> Vec<Vec<String>> {
        rules(&tokens(css))
            .into_iter()
            .map(|rule| rule.declarations.into_iter().map(|d| d.property).collect())
            .collect()
    }

    /// Two rules read as two, each with its declarations in order.
    #[test]
    fn rules_read_with_their_declarations() {
        let read = properties(".a { color: red; padding: 0 } .b{margin:1px;}");

        assert_eq!(read, [vec!["color", "padding"], vec!["margin"]]);
    }

    /// Import and media at-rules are omitted with their contents, leaving
    /// the following ordinary rule readable.
    #[test]
    fn an_at_rule_is_left_out_whole() {
        let read =
            properties("@import url(x.css); @media print { .a { color: red } } .b { color: blue }");

        assert_eq!(read, [vec!["color"]]);
    }

    /// A brace inside a function does not end the enclosing rule; its next
    /// declaration and the following rule remain separate.
    #[test]
    fn a_brace_inside_parentheses_closes_nothing() {
        let read = rules(&tokens(
            ".a { color: x(}); background-color: red } .b { margin: 0 }",
        ));

        assert_eq!(read.len(), 2);
        assert_eq!(read[0].declarations[1].property, "background-color");
    }

    /// A nested rule inside a block is not a declaration and is left out,
    /// with what follows it up to the next `;`.
    #[test]
    fn a_nested_rule_is_not_a_declaration() {
        let read = properties(".a { color: red; .b { color: blue } ; padding: 0 }");

        assert_eq!(read, [vec!["color", "padding"]]);
    }

    /// A rule whose block never opens is left out, and one never closed
    /// keeps what it holds.
    #[test]
    fn unopened_rules_are_left_out() {
        assert!(rules(&tokens("just text")).is_empty());
        assert_eq!(properties(".a { color: red"), [vec!["color"]]);
    }

    /// A rule with 20,000 nested parentheses parses as one rule without overflowing the stack.
    #[test]
    fn deep_nesting_reads_without_recursion() {
        let deep = format!(
            ".a {{ color: {}red{} }}",
            "(".repeat(20_000),
            ")".repeat(20_000)
        );

        let read = rules(&tokens(&deep));

        assert_eq!(read.len(), 1);
    }
}
