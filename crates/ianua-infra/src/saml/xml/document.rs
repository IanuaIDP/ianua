//! Reading SAML XML safely: a message decoded within a size, parsed with no
//! DTD and a bound on its nodes and depth, refused when it holds comments
//! or processing instructions or names one `ID` twice, and its elements
//! found by namespace and name, never by name alone.
//!
//! A signed message is read only through these helpers, so the element a
//! check reads is the element its signature covers: there is no search
//! through the text for something that looks like one.

use std::collections::HashSet;
use std::io::Read as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::read::DeflateDecoder;
use ianua_domain::shared::errors::DomainError;
use roxmltree::{Document, Node, ParsingOptions};

use crate::reading::xml::{Unreadable, ensure_shallow as ensure_within_depth};

/// The SAML protocol namespace.
pub(crate) const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// The SAML assertion namespace.
pub(crate) const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// The SAML metadata namespace.
pub(crate) const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// The XML Signature namespace.
pub(crate) const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The XML Encryption namespace.
pub(crate) const XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#";

/// The longest message read, once decoded and inflated.
pub(crate) const MOST_MESSAGE_BYTES: usize = 512 * 1024;

/// The longest base64 text read, which decodes to at most
/// [`MOST_MESSAGE_BYTES`].
const MOST_ENCODED_BYTES: usize = MOST_MESSAGE_BYTES / 3 * 4 + 4;

/// The most nodes a document may hold.
const MOST_NODES: u32 = 20_000;

/// The deepest an element may sit. A SAML message nests a handful of
/// levels; far deeper is an attempt to exhaust the stack.
const MOST_DEPTH: usize = 48;

/// Whether a document may carry comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Comments {
    /// Refused: a signed message, where a comment splits the text a
    /// signature covers from the text a reader takes.
    Refused,
    /// Taken and skipped: a document nobody signs here, such as metadata.
    Skipped,
}

/// The text of a POST-bound message: base64 of the XML.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it is longer than allowed, not
/// base64, or not UTF-8.
pub(crate) fn from_base64(encoded: &str) -> Result<String, DomainError> {
    utf8(decoded(encoded)?)
}

/// The text of a Redirect-bound message: base64 of the deflated XML.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it is not base64, does not
/// inflate, inflates past the size allowed, or is not UTF-8.
pub(crate) fn from_deflated_base64(encoded: &str) -> Result<String, DomainError> {
    let deflated = decoded(encoded)?;
    let mut inflated = Vec::new();
    DeflateDecoder::new(deflated.as_slice())
        .take(limit_plus_one())
        .read_to_end(&mut inflated)
        .map_err(|_| refused("the message does not inflate"))?;
    if inflated.len() > MOST_MESSAGE_BYTES {
        return Err(refused("the message is larger than allowed"));
    }
    utf8(inflated)
}

/// `xml` parsed: no DTD, a bound on nodes and depth, every `ID` once, and
/// comments as `comments` says. Processing instructions are always
/// refused.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the text is not well-formed or
/// breaks any of these rules.
pub(crate) fn parse(xml: &str, comments: Comments) -> Result<Document<'_>, DomainError> {
    if xml.len() > MOST_MESSAGE_BYTES {
        return Err(refused("the message is larger than allowed"));
    }
    ensure_shallow(xml)?;
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: MOST_NODES,
        ..ParsingOptions::default()
    };
    let document = Document::parse_with_options(xml, options)
        .map_err(|_| refused("the message is not well-formed XML"))?;
    ensure_plain(&document, comments)?;
    ensure_unique_ids(&document)?;
    Ok(document)
}

/// Whether `node` is the element `name` in `namespace`.
pub(crate) fn is(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

/// The element children of `node`, in order.
pub(crate) fn elements<'a, 'input>(node: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    node.children().filter(Node::is_element).collect()
}

/// The children of `node` that are the element `name` in `namespace`.
pub(crate) fn children<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children()
        .filter(move |child| is(*child, namespace, name))
}

/// The one child of `node` that is `name` in `namespace`, if there is one.
///
/// # Errors
///
/// Returns `DomainError::Validation` when there are two or more.
pub(crate) fn only_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> Result<Option<Node<'a, 'input>>, DomainError> {
    let mut found = children(node, namespace, name);
    let first = found.next();
    if found.next().is_some() {
        return Err(refused("an element appears twice where it may appear once"));
    }
    Ok(first)
}

/// The one child of `node` that is `name` in `namespace`.
///
/// # Errors
///
/// Returns `DomainError::Validation` with `missing` when there is none, or
/// when there are two or more.
pub(crate) fn required_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
    missing: &'static str,
) -> Result<Node<'a, 'input>, DomainError> {
    only_child(node, namespace, name)?.ok_or_else(|| refused(missing))
}

/// The text of `element`, every text child joined and trimmed.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it holds an element, since its
/// text then is not one value.
pub(crate) fn text_of(element: Node<'_, '_>) -> Result<String, DomainError> {
    if element.children().any(|child| child.is_element()) {
        return Err(refused("an element holds markup where it should hold text"));
    }
    let text: String = element
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect();
    Ok(text.trim().to_owned())
}

/// The attribute `name` of `element`.
///
/// # Errors
///
/// Returns `DomainError::Validation` with `missing` when it is absent.
pub(crate) fn required_attribute<'a>(
    element: Node<'a, '_>,
    name: &str,
    missing: &'static str,
) -> Result<&'a str, DomainError> {
    element.attribute(name).ok_or_else(|| refused(missing))
}

/// Refuses an element that is not SAML 2.0.
///
/// # Errors
///
/// Returns `DomainError::Validation` when its `Version` is anything but
/// `2.0`.
pub(crate) fn ensure_version(element: Node<'_, '_>) -> Result<(), DomainError> {
    if element.attribute("Version") != Some("2.0") {
        return Err(refused("the message is not SAML 2.0"));
    }
    Ok(())
}

/// A refusal of input, with a fixed reason that quotes nothing it read.
pub(crate) fn refused(why: &'static str) -> DomainError {
    DomainError::invalid(why)
}

/// `text` with the characters XML reserves escaped, for text and for
/// attribute values in double quotes.
pub(crate) fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `encoded` decoded from base64, whitespace dropped, within the size a
/// message may have.
fn decoded(encoded: &str) -> Result<Vec<u8>, DomainError> {
    let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() > MOST_ENCODED_BYTES {
        return Err(refused("the message is larger than allowed"));
    }
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| refused("the message is not base64"))
}

fn utf8(bytes: Vec<u8>) -> Result<String, DomainError> {
    String::from_utf8(bytes).map_err(|_| refused("the message is not UTF-8"))
}

/// One byte past the size allowed, so a longer inflation is seen.
fn limit_plus_one() -> u64 {
    u64::try_from(MOST_MESSAGE_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// Refuses processing instructions, and comments unless `comments` skips
/// them.
fn ensure_plain(document: &Document<'_>, comments: Comments) -> Result<(), DomainError> {
    let refuses_comment = |node: &Node<'_, '_>| node.is_comment() && comments == Comments::Refused;
    if document
        .descendants()
        .any(|node| node.is_pi() || refuses_comment(&node))
    {
        return Err(refused(
            "the message holds comments or processing instructions",
        ));
    }
    Ok(())
}

/// Refuses text whose elements nest deeper than [`MOST_DEPTH`], or that
/// carries a document type, read from the raw text before the parser runs.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the text nests too deep or
/// carries a document type.
fn ensure_shallow(xml: &str) -> Result<(), DomainError> {
    ensure_within_depth(xml, MOST_DEPTH).map_err(|unreadable| match unreadable {
        Unreadable::TooDeep => refused("the message nests deeper than allowed"),
        Unreadable::DocumentType => refused("the message carries a document type"),
    })
}

/// Refuses a document naming one `ID` on two elements, so a reference can
/// only ever mean one of them.
fn ensure_unique_ids(document: &Document<'_>) -> Result<(), DomainError> {
    let mut seen = HashSet::new();
    let ids = document
        .descendants()
        .filter_map(|node| node.attribute("ID"));
    for id in ids {
        if !seen.insert(id) {
            return Err(refused("the message names one ID twice"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::*;

    fn deflated(xml: &str) -> String {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).unwrap();
        STANDARD.encode(encoder.finish().unwrap())
    }

    /// A message posted as base64, with the line breaks some providers add,
    /// reads back as its XML.
    #[test]
    fn a_posted_message_is_read_with_its_line_breaks() {
        let encoded = STANDARD.encode("<a/>");
        let wrapped = format!("{}\n{}", &encoded[..2], &encoded[2..]);

        assert_eq!(from_base64(&wrapped).unwrap(), "<a/>");
    }

    /// A message sent by redirect inflates back to its XML.
    #[test]
    fn a_redirected_message_inflates() {
        assert_eq!(from_deflated_base64(&deflated("<a/>")).unwrap(), "<a/>");
    }

    /// A compressed message whose expanded content exceeds the size limit is rejected.
    #[test]
    fn a_message_inflating_past_its_limit_is_refused() {
        let bomb = format!("<a>{}</a>", "x".repeat(MOST_MESSAGE_BYTES + 10));

        let read = from_deflated_base64(&deflated(&bomb));

        assert!(matches!(read, Err(DomainError::Validation(_))));
    }

    /// A document containing a DTD fails parsing before its entities can be accepted.
    #[test]
    fn a_document_with_a_dtd_is_refused() {
        let xml = r#"<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>"#;

        assert!(parse(xml, Comments::Refused).is_err());
    }

    /// A comment splitting a name is rejected when comments are forbidden;
    /// the same document remains parseable when comments may be skipped.
    #[test]
    fn a_comment_in_a_signed_message_is_refused() {
        let xml = "<a>admin@acme.com<!---->.evil.com</a>";

        assert!(parse(xml, Comments::Refused).is_err());
        assert!(parse(xml, Comments::Skipped).is_ok());
    }

    /// Duplicate IDs make a signature reference ambiguous and fail document parsing.
    #[test]
    fn a_document_naming_one_id_twice_is_refused() {
        let xml = r#"<a><b ID="_1"/><c ID="_1"/></a>"#;

        assert!(parse(xml, Comments::Refused).is_err());
    }

    /// Two hundred nested elements exceed the document depth limit and are rejected.
    #[test]
    fn a_deeply_nested_document_is_refused() {
        let xml = format!("{}{}", "<a>".repeat(200), "</a>".repeat(200));

        assert!(parse(&xml, Comments::Refused).is_err());
    }

    /// The depth is counted as the parser reads the markup: a `>` inside a
    /// quoted value, an empty element, and tags inside a comment or a CDATA
    /// section change no level, so a message nested to the limit reads.
    #[test]
    fn a_document_nested_to_the_limit_reads() {
        let inner = r#"<b x=">" y='/>'/><!-- <c><c><c> --><![CDATA[<d><d>]]>"#;
        let xml = format!(
            "{}{inner}{}",
            r#"<a v="&lt;">"#.repeat(MOST_DEPTH - 1),
            "</a>".repeat(MOST_DEPTH - 1)
        );

        assert!(parse(&xml, Comments::Skipped).is_ok());
    }

    /// Quoted `/>` values cannot disguise nested elements as empty tags;
    /// the document still fails the depth limit.
    #[test]
    fn nesting_hidden_behind_quoted_values_is_refused() {
        let xml = format!(
            "{}{}",
            r#"<a v="/>">"#.repeat(MOST_DEPTH + 1),
            "</a>".repeat(MOST_DEPTH + 1)
        );

        assert!(parse(&xml, Comments::Refused).is_err());
    }

    /// An element is found only by its namespace and name: one of the same
    /// name in another namespace is not it.
    #[test]
    fn an_element_is_known_by_its_namespace() {
        let xml = format!(
            r#"<r xmlns:saml="{ASSERTION}" xmlns:evil="urn:evil"><evil:Issuer/><saml:Issuer>x</saml:Issuer></r>"#
        );
        let document = parse(&xml, Comments::Refused).unwrap();

        let found = only_child(document.root_element(), ASSERTION, "Issuer").unwrap();

        assert_eq!(text_of(found.unwrap()).unwrap(), "x");
    }

    /// Text extraction rejects child markup instead of returning only part of a name.
    #[test]
    fn text_holding_markup_is_refused() {
        let document = parse("<a>x<b/>y</a>", Comments::Refused).unwrap();

        assert!(text_of(document.root_element()).is_err());
    }
}
