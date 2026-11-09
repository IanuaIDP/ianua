//! A bound on how deep an XML document nests, read from its raw text before
//! any parser sees it.
//!
//! The XML parser descends one call per level. A document nested deep
//! enough exhausts the stack and takes the process down, so the limit must
//! hold before the parser runs, whoever sent the document: a SAML provider,
//! or a cloud API answering a call.

/// Why the raw text of a document was refused before parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreadable {
    /// Its elements nest deeper than allowed.
    TooDeep,
    /// It carries a document type, which may declare entities.
    DocumentType,
}

/// A piece of markup, as the depth scan counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Markup {
    /// A start tag, one level deeper.
    Opening,
    /// An end tag, one level back.
    Closing,
    /// An empty element, a comment, a processing instruction or a CDATA
    /// section: no change of level.
    Level,
}

/// Refuses text whose elements nest deeper than `most_depth`, or that
/// carries a document type, read in one pass. Text the scan cannot follow
/// is left to the parser, which refuses it as not well-formed.
///
/// # Errors
///
/// Returns the [`Unreadable`] reason the text was refused for.
pub(crate) fn ensure_shallow(xml: &str, most_depth: usize) -> Result<(), Unreadable> {
    let bytes = xml.as_bytes();
    let mut depth = 0_usize;
    let mut at = 0_usize;
    while let Some(start) = next_markup(bytes, at) {
        let (markup, end) = markup_at(bytes, start)?;
        depth = match markup {
            Markup::Opening => depth.saturating_add(1),
            Markup::Closing => depth.saturating_sub(1),
            Markup::Level => depth,
        };
        if depth > most_depth {
            return Err(Unreadable::TooDeep);
        }
        at = end;
    }
    Ok(())
}

/// Where the next `<` at or after `from` is.
fn next_markup(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|byte| *byte == b'<')
        .map(|offset| from.saturating_add(offset))
}

/// What the markup starting at `start` is, and where it ends.
fn markup_at(bytes: &[u8], start: usize) -> Result<(Markup, usize), Unreadable> {
    let rest = bytes.get(start..).unwrap_or_default();
    if rest.starts_with(b"<!--") {
        return Ok((Markup::Level, past(bytes, start, b"-->")));
    }
    if rest.starts_with(b"<![CDATA[") {
        return Ok((Markup::Level, past(bytes, start, b"]]>")));
    }
    if rest.starts_with(b"<!") {
        return Err(Unreadable::DocumentType);
    }
    if rest.starts_with(b"<?") {
        return Ok((Markup::Level, past(bytes, start, b"?>")));
    }
    if rest.starts_with(b"</") {
        return Ok((Markup::Closing, past(bytes, start, b">")));
    }
    Ok(start_tag_at(bytes, start))
}

/// Whether the start tag at `start` opens an element or is empty, and
/// where it ends: at the first `>` outside a quoted attribute value.
fn start_tag_at(bytes: &[u8], start: usize) -> (Markup, usize) {
    let mut quote: Option<u8> = None;
    for (index, byte) in bytes.iter().enumerate().skip(start.saturating_add(1)) {
        quote = match (quote, *byte) {
            (None, b'"' | b'\'') => Some(*byte),
            (None, b'>') => return (opening_or_empty(bytes, index), index.saturating_add(1)),
            (Some(open), close) if open == close => None,
            (current, _) => current,
        };
    }
    (Markup::Level, bytes.len())
}

/// Whether the tag closed by the `>` at `close` is empty, `/>`, or opens
/// an element.
fn opening_or_empty(bytes: &[u8], close: usize) -> Markup {
    match close.checked_sub(1).and_then(|before| bytes.get(before)) {
        Some(b'/') => Markup::Level,
        Some(_) | None => Markup::Opening,
    }
}

/// The position just past the first `terminator` after `from`, or the end
/// of the text when there is none.
fn past(bytes: &[u8], from: usize, terminator: &[u8]) -> usize {
    bytes
        .get(from..)
        .and_then(|rest| {
            rest.windows(terminator.len())
                .position(|window| window == terminator)
        })
        .map_or(bytes.len(), |offset| {
            from.saturating_add(offset).saturating_add(terminator.len())
        })
}

/// `code`, an error code an outside service's XML reply names, when it is
/// a plain word such a service would send; `unknown` otherwise, so nothing
/// else it echoed reaches an error.
pub(crate) fn plain_word(code: &str) -> &str {
    let plain = !code.is_empty()
        && code.len() <= 64
        && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '.');
    if plain {
        return code;
    }
    "unknown"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The raw XML scan rejects 200 nested elements against a depth limit of 48.
    #[test]
    fn text_nested_past_the_limit_is_refused() {
        let xml = format!("{}{}", "<a>".repeat(200), "</a>".repeat(200));

        assert_eq!(ensure_shallow(&xml, 48), Err(Unreadable::TooDeep));
    }

    /// The depth is counted as a parser reads the markup: a `>` inside a
    /// quoted value, an empty element, and tags inside a comment or a CDATA
    /// section change no level, so text nested to the limit passes.
    #[test]
    fn text_nested_to_the_limit_passes() {
        let inner = r#"<b x=">" y='/>'/><!-- <c><c><c> --><![CDATA[<d><d>]]>"#;
        let xml = format!("{}{inner}{}", "<a>".repeat(3), "</a>".repeat(3));

        assert_eq!(ensure_shallow(&xml, 3), Ok(()));
    }

    /// Quoted `/>` text does not hide element nesting from the depth limit.
    #[test]
    fn nesting_hidden_behind_quoted_values_is_refused() {
        let xml = format!("{}{}", r#"<a v="/>">"#.repeat(4), "</a>".repeat(4));

        assert_eq!(ensure_shallow(&xml, 3), Err(Unreadable::TooDeep));
    }

    /// The raw XML scan rejects a document type containing an entity declaration.
    #[test]
    fn a_document_type_is_refused() {
        let xml = r#"<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>"#;

        assert_eq!(ensure_shallow(xml, 48), Err(Unreadable::DocumentType));
    }
}
