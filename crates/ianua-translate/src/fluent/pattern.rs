//! A message's text as Fluent reads it: plain text and named variables,
//! written so Fluent's whitespace and brace rules cannot change a character.

use crate::catalog::Syntax;
use crate::collect::tokens::FieldNames;

/// The indentation of a continuation line inside a multiline value.
const INDENT: &str = "    ";

/// One piece of a message: literal text, or a value supplied at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
    /// Text shown exactly as written.
    Text(String),
    /// A Fluent variable, written `{ $name }`.
    Variable(String),
}

/// The pieces of a source or translation, with adjacent text merged.
/// Rust's escaped braces become text and each replacement field becomes a
/// variable; a positional field `{}` or `{0}` becomes `$arg0`. Format
/// specs such as `:?` are dropped, since the caller formats the value.
pub(crate) fn segments(text: &str, syntax: Syntax) -> Vec<Segment> {
    match syntax {
        Syntax::RustFormat => rust_segments(text),
        Syntax::Plain | Syntax::MiniJinja => vec![Segment::Text(text.to_owned())],
    }
}

/// Merges neighbouring text so two readings of one message compare equal.
pub(crate) fn merged(pieces: impl IntoIterator<Item = Segment>) -> Vec<Segment> {
    let mut merged: Vec<Segment> = Vec::new();
    for piece in pieces {
        match (merged.last_mut(), piece) {
            (_, Segment::Text(text)) if text.is_empty() => {}
            (Some(Segment::Text(previous)), Segment::Text(text)) => previous.push_str(&text),
            (_, piece) => merged.push(piece),
        }
    }
    merged
}

/// The Fluent value for these pieces, without the `key =` before it.
/// A multiline value starts on its own indented line.
pub(crate) fn value(segments: &[Segment]) -> String {
    let pieces = pieces(segments);
    let multiline = pieces.contains(&Piece::Char('\n'));
    let mut written = String::new();
    if multiline {
        written.push('\n');
        written.push_str(INDENT);
    }
    let mut index = 0;
    while index < pieces.len() {
        index = write_piece(&pieces, index, &mut written);
    }
    written
}

fn rust_segments(text: &str) -> Vec<Segment> {
    let mut found = Vec::new();
    let mut fields = FieldNames::default();
    let mut literal = String::new();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match (character, characters.peek()) {
            ('{', Some('{')) | ('}', Some('}')) => {
                characters.next();
                literal.push(character);
            }
            ('{', _) => {
                let field: String = characters
                    .by_ref()
                    .take_while(|next| *next != '}')
                    .collect();
                found.push(Segment::Text(std::mem::take(&mut literal)));
                found.push(Segment::Variable(variable(&fields.name(&field))));
            }
            _ => literal.push(character),
        }
    }
    found.push(Segment::Text(literal));
    merged(found)
}

/// A Fluent variable name for a Rust field name: positional fields become
/// `arg<n>`, anything outside Fluent's identifier characters becomes `_`.
fn variable(name: &str) -> String {
    if name.starts_with(|character: char| character.is_ascii_digit()) {
        return format!("arg{name}");
    }
    name.chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => character,
            _ => '_',
        })
        .collect()
}

/// A message flattened into characters and variables for lookahead.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Char(char),
    Variable(String),
}

fn pieces(segments: &[Segment]) -> Vec<Piece> {
    segments
        .iter()
        .flat_map(|segment| match segment {
            Segment::Text(text) => text.chars().map(Piece::Char).collect::<Vec<_>>(),
            Segment::Variable(name) => vec![Piece::Variable(name.clone())],
        })
        .collect()
}

/// Writes the piece at `index` and returns the index after what was written.
fn write_piece(pieces: &[Piece], index: usize, written: &mut String) -> usize {
    match &pieces[index] {
        Piece::Variable(name) => {
            written.push_str(&format!("{{ ${name} }}"));
            index + 1
        }
        Piece::Char('\n') => {
            written.push('\n');
            if !matches!(pieces.get(index + 1), Some(Piece::Char('\n')) | None) {
                written.push_str(INDENT);
            }
            index + 1
        }
        Piece::Char(' ' | '\t') => write_blank_run(pieces, index, written),
        Piece::Char(character) => {
            write_character(*character, at_line_start(pieces, index), written);
            index + 1
        }
    }
}

/// Writes a run of spaces and tabs, quoting it where Fluent would trim it:
/// at the start of a line, and before a line end or the end of the value.
fn write_blank_run(pieces: &[Piece], start: usize, written: &mut String) -> usize {
    let end = (start..pieces.len())
        .find(|index| !matches!(pieces[*index], Piece::Char(' ' | '\t')))
        .unwrap_or(pieces.len());
    let run: String = pieces[start..end]
        .iter()
        .filter_map(|piece| match piece {
            Piece::Char(character) => Some(*character),
            Piece::Variable(_) => None,
        })
        .collect();
    let trimmed =
        at_line_start(pieces, start) || matches!(pieces.get(end), None | Some(Piece::Char('\n')));
    if trimmed {
        written.push_str(&format!("{{\"{run}\"}}"));
        return end;
    }
    written.push_str(&run);
    end
}

/// Writes one character, quoting braces always and the characters that
/// would start a variant, a default variant or an attribute at a line start.
fn write_character(character: char, line_start: bool, written: &mut String) {
    let special =
        matches!(character, '{' | '}') || (line_start && matches!(character, '[' | '*' | '.'));
    if special {
        written.push_str(&format!("{{\"{character}\"}}"));
        return;
    }
    written.push(character);
}

fn at_line_start(pieces: &[Piece], index: usize) -> bool {
    index == 0 || pieces[index - 1] == Piece::Char('\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Segment {
        Segment::Text(value.to_owned())
    }

    fn variable(value: &str) -> Segment {
        Segment::Variable(value.to_owned())
    }

    /// Named, positional and escaped fields each become what Fluent expects.
    #[test]
    fn rust_fields_become_variables_and_escaped_braces_text() {
        assert_eq!(
            segments(
                "{{literal}} {name} moved from {:?} to {}",
                Syntax::RustFormat
            ),
            [
                text("{literal} "),
                variable("name"),
                text(" moved from "),
                variable("arg0"),
                text(" to "),
                variable("arg1"),
            ]
        );
    }

    /// Explicit positions keep their number, so a reordered translation stays correct.
    #[test]
    fn explicit_positions_keep_their_number() {
        assert_eq!(
            segments("{1} before {0}", Syntax::RustFormat),
            [variable("arg1"), text(" before "), variable("arg0")]
        );
    }

    /// Plain text keeps its braces as text.
    #[test]
    fn plain_text_is_one_text_segment() {
        assert_eq!(
            segments("has an empty '{}' placeholder", Syntax::Plain),
            [text("has an empty '{}' placeholder")]
        );
    }

    /// Braces are quoted, since Fluent reads them as a placeable.
    #[test]
    fn braces_are_quoted() {
        assert_eq!(
            value(&[text("rules like `a { b: c; }`")]),
            "rules like `a {\"{\"} b: c; {\"}\"}`"
        );
    }

    /// Leading and trailing spaces are quoted so Fluent can preserve the message's spacing.
    #[test]
    fn edge_spaces_are_quoted() {
        assert_eq!(
            value(&[text(" of "), variable("count")]),
            "{\" \"}of { $count }"
        );
        assert_eq!(
            value(&[variable("count"), text(" items ")]),
            "{ $count } items{\" \"}"
        );
    }

    /// A multiline value is indented and its special line starts quoted.
    #[test]
    fn multiline_values_are_indented() {
        assert_eq!(
            value(&[text("First\n[second]\n\nthird")]),
            "\n    First\n    {\"[\"}second]\n\n    third"
        );
    }
}
