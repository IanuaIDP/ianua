//! Reads a generated resource back with Fluent's own parser, so a file is
//! only written when every message parses to exactly the intended text.

use std::collections::BTreeMap;

use fluent_syntax::ast::{Entry, Expression, InlineExpression, Pattern, PatternElement};
use fluent_syntax::parser;

use crate::error::{Error, Result};
use crate::fluent::pattern::{Segment, merged};

/// Every message of a resource with the pieces Fluent reads from it.
///
/// # Errors
///
/// Refuses a resource with syntax errors, unparsed content, terms, message
/// attributes or placeables other than variables and quoted text.
pub(crate) fn read_back(file: &str, source: &str) -> Result<BTreeMap<String, Vec<Segment>>> {
    let resource = parser::parse(source).map_err(|(_, errors)| Error::Fluent {
        file: file.to_owned(),
        detail: format!("{errors:?}"),
    })?;
    let mut messages = BTreeMap::new();
    for entry in resource.body {
        let Some((key, pattern)) = message(file, entry)? else {
            continue;
        };
        messages.insert(key.to_owned(), segments(file, key, pattern)?);
    }
    Ok(messages)
}

/// The key and value of a message entry; comments are skipped and
/// anything else is refused.
fn message<'s>(file: &str, entry: Entry<&'s str>) -> Result<Option<(&'s str, Pattern<&'s str>)>> {
    match entry {
        Entry::Message(message) if message.attributes.is_empty() => {
            let key = message.id.name;
            let value = message.value.ok_or_else(|| unexpected(file, key))?;
            Ok(Some((key, value)))
        }
        Entry::Comment(_) | Entry::GroupComment(_) | Entry::ResourceComment(_) => Ok(None),
        Entry::Message(message) => Err(unexpected(file, message.id.name)),
        Entry::Term(term) => Err(unexpected(file, term.id.name)),
        Entry::Junk { content } => Err(unexpected(file, content)),
    }
}

fn segments(file: &str, key: &str, pattern: Pattern<&str>) -> Result<Vec<Segment>> {
    let pieces = pattern
        .elements
        .into_iter()
        .map(|element| match element {
            PatternElement::TextElement { value } => Ok(Segment::Text(value.to_owned())),
            PatternElement::Placeable { expression } => placeable(file, key, expression),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(merged(pieces))
}

fn placeable(file: &str, key: &str, expression: Expression<&str>) -> Result<Segment> {
    match expression {
        Expression::Inline(InlineExpression::StringLiteral { value }) => {
            Ok(Segment::Text(value.to_owned()))
        }
        Expression::Inline(InlineExpression::VariableReference { id }) => {
            Ok(Segment::Variable(id.name.to_owned()))
        }
        _ => Err(unexpected(file, key)),
    }
}

fn unexpected(file: &str, at: &str) -> Error {
    Error::Fluent {
        file: file.to_owned(),
        detail: format!("unexpected content at {at}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quoted text and variables read back as the text and values they stand for.
    #[test]
    fn quoted_text_and_variables_read_back() {
        let read = read_back(
            "people.ftl",
            "# a comment\n\npeople-invite = {\" \"}Invite {\"{\"}{ $name }{\"}\"}\n",
        )
        .unwrap();
        assert_eq!(
            read["people-invite"],
            [
                Segment::Text(" Invite {".to_owned()),
                Segment::Variable("name".to_owned()),
                Segment::Text("}".to_owned()),
            ]
        );
    }

    /// A malformed line makes the whole Fluent resource fail validation.
    #[test]
    fn junk_is_refused() {
        assert!(read_back("people.ftl", "people-invite = Hi\n{ broken\n").is_err());
    }
}
