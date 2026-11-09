//! Exclusive XML canonicalization without comments
//! (`http://www.w3.org/2001/10/xml-exc-c14n#`), the form XML Signature
//! digests and signs, written from the parsed tree.
//!
//! Working on the tree, not the text, means the element read is the
//! element digested: the signature an enveloped transform leaves out is
//! left out by its node, never by searching the text for something that
//! looks like one. Names keep the prefixes they were written with; a
//! namespace is declared where it is first used in the output, and again
//! only where its meaning changes.

use std::collections::BTreeSet;

use ianua_domain::shared::errors::DomainError;
use roxmltree::{Node, NodeId, NodeType};

use crate::saml::xml::document::refused;

/// The `xml` prefix, bound everywhere and never declared.
const XML_PREFIX: &str = "xml";

/// What a canonical form leaves out, and the prefixes it declares beyond
/// those it uses.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Subset<'a> {
    /// The node left out with everything under it, as the enveloped
    /// signature transform leaves out the signature.
    pub(crate) omitted: Option<NodeId>,
    /// The prefixes an `InclusiveNamespaces` list names, `""` for the
    /// default namespace.
    pub(crate) inclusive: &'a [String],
}

/// The canonical form of `apex` and everything under it but what `subset`
/// leaves out.
///
/// # Errors
///
/// Returns `DomainError::Validation` when an element's name cannot be read
/// from the document.
pub(crate) fn canonical(apex: Node<'_, '_>, subset: Subset<'_>) -> Result<String, DomainError> {
    let mut writer = Writer {
        out: String::new(),
        subset,
        rendered: Vec::new(),
    };
    let mut pending = vec![Step::Visit(apex)];
    while let Some(step) = pending.pop() {
        match step {
            Step::Visit(node) => writer.visit(node, &mut pending)?,
            Step::Close {
                name,
                declared_before,
            } => writer.close(name, declared_before),
        }
    }
    Ok(writer.out)
}

/// One step of the walk, kept on a stack of its own rather than the call
/// stack, so no document nests deep enough to exhaust it.
enum Step<'a, 'input> {
    /// A node still to be written, with everything under it.
    Visit(Node<'a, 'input>),
    /// The end tag of an element whose children are written, and how many
    /// namespace declarations were in force before it.
    Close {
        name: &'input str,
        declared_before: usize,
    },
}

/// The canonical text being written, and the namespaces the elements
/// around the current one declared.
struct Writer<'a> {
    out: String,
    subset: Subset<'a>,
    rendered: Vec<(String, String)>,
}

impl Writer<'_> {
    fn visit<'a, 'input>(
        &mut self,
        node: Node<'a, 'input>,
        pending: &mut Vec<Step<'a, 'input>>,
    ) -> Result<(), DomainError> {
        if Some(node.id()) == self.subset.omitted {
            return Ok(());
        }
        match node.node_type() {
            NodeType::Element => self.open(node, pending),
            NodeType::Text => {
                self.out
                    .push_str(&escaped_text(node.text().unwrap_or_default()));
                Ok(())
            }
            NodeType::PI => {
                self.instruction(node);
                Ok(())
            }
            NodeType::Comment | NodeType::Root => Ok(()),
        }
    }

    /// Writes the start tag of `node` and queues its children and its end
    /// tag, in that order.
    fn open<'a, 'input>(
        &mut self,
        node: Node<'a, 'input>,
        pending: &mut Vec<Step<'a, 'input>>,
    ) -> Result<(), DomainError> {
        let name = qualified_name(node)?;
        let declared_before = self.rendered.len();
        self.out.push('<');
        self.out.push_str(name);
        for (prefix, uri) in self.declarations(node, name) {
            write_declaration(&mut self.out, &prefix, &uri);
            self.rendered.push((prefix, uri));
        }
        for (qualified, value) in sorted_attributes(node) {
            self.out.push(' ');
            self.out.push_str(qualified);
            self.out.push_str("=\"");
            self.out.push_str(&escaped_attribute(value));
            self.out.push('"');
        }
        self.out.push('>');
        pending.push(Step::Close {
            name,
            declared_before,
        });
        pending.extend(node.children().rev().map(Step::Visit));
        Ok(())
    }

    fn close(&mut self, name: &str, declared_before: usize) {
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
        self.rendered.truncate(declared_before);
    }

    fn instruction(&mut self, node: Node<'_, '_>) {
        let Some(instruction) = node.pi() else {
            return;
        };
        self.out.push_str("<?");
        self.out.push_str(instruction.target);
        if let Some(value) = instruction.value {
            self.out.push(' ');
            self.out.push_str(value);
        }
        self.out.push_str("?>");
    }

    /// The namespaces `node` declares in canonical form: each prefix it
    /// uses, or the inclusive list names, whose meaning differs from the
    /// one the nearest element around it declared. The default namespace
    /// comes first, then the prefixes in order.
    fn declarations(&self, node: Node<'_, '_>, name: &str) -> Vec<(String, String)> {
        let mut used: BTreeSet<String> = BTreeSet::new();
        used.insert(prefix_of(name).to_owned());
        used.extend(
            node.attributes()
                .filter_map(|attribute| attribute_name(node, &attribute))
                .map(prefix_of)
                .filter(|prefix| !prefix.is_empty())
                .map(str::to_owned),
        );
        used.extend(
            self.subset
                .inclusive
                .iter()
                .filter(|prefix| prefix.is_empty() || bound(node, prefix).is_some())
                .cloned(),
        );
        used.into_iter()
            .filter(|prefix| prefix != XML_PREFIX)
            .filter_map(|prefix| {
                let uri = bound(node, &prefix).unwrap_or_default().to_owned();
                (self.nearest(&prefix) != uri).then_some((prefix, uri))
            })
            .collect()
    }

    /// The meaning the nearest element around declared for `prefix`, empty
    /// when none did.
    fn nearest(&self, prefix: &str) -> &str {
        self.rendered
            .iter()
            .rev()
            .find(|(declared, _)| declared == prefix)
            .map_or("", |(_, uri)| uri.as_str())
    }
}

/// The namespace `prefix` means at `node`, `""` for the default.
fn bound<'a>(node: Node<'a, '_>, prefix: &str) -> Option<&'a str> {
    let asked = if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    };
    node.lookup_namespace_uri(asked)
}

fn write_declaration(out: &mut String, prefix: &str, uri: &str) {
    if prefix.is_empty() {
        out.push_str(" xmlns=\"");
    } else {
        out.push_str(" xmlns:");
        out.push_str(prefix);
        out.push_str("=\"");
    }
    out.push_str(&escaped_attribute(uri));
    out.push('"');
}

/// The element's name as written, prefix included.
fn qualified_name<'input>(node: Node<'_, 'input>) -> Result<&'input str, DomainError> {
    let text = node.document().input_text();
    let start = node.range().start.saturating_add(1);
    let rest = text
        .get(start..)
        .ok_or_else(|| refused("an element's name cannot be read"))?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(rest.len());
    rest.get(..end)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| refused("an element's name cannot be read"))
}

/// The attribute's name as written, prefix included.
fn attribute_name<'input>(
    node: Node<'_, 'input>,
    attribute: &roxmltree::Attribute<'_, 'input>,
) -> Option<&'input str> {
    node.document().input_text().get(attribute.range_qname())
}

/// The element's attributes in canonical order, by namespace and then by
/// local name, each with its name as written and its value as read.
fn sorted_attributes<'a, 'input>(node: Node<'a, 'input>) -> Vec<(&'input str, &'a str)> {
    let mut attributes: Vec<(&str, &str, &'input str, &'a str)> = node
        .attributes()
        .filter_map(|attribute| {
            let written = attribute_name(node, &attribute)?;
            Some((
                attribute.namespace().unwrap_or_default(),
                attribute.name(),
                written,
                attribute.value(),
            ))
        })
        .collect();
    attributes.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    attributes
        .into_iter()
        .map(|(_, _, written, value)| (written, value))
        .collect()
}

fn prefix_of(name: &str) -> &str {
    name.split_once(':').map_or("", |(prefix, _)| prefix)
}

fn escaped_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

fn escaped_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use roxmltree::Document;

    use super::*;

    fn whole(xml: &str) -> String {
        let document = Document::parse(xml).unwrap();
        canonical(document.root_element(), Subset::default()).unwrap()
    }

    /// An empty element is written open and closed, the declaration and
    /// comments are dropped, and attributes come in canonical order.
    #[test]
    fn a_document_takes_its_canonical_form() {
        let xml = r#"<?xml version="1.0"?><r xmlns:b="urn:b" xmlns:a="urn:a" b:x="1" a:y="2" z="3"><!-- note --><e/></r>"#;

        assert_eq!(
            whole(xml),
            r#"<r xmlns:a="urn:a" xmlns:b="urn:b" z="3" a:y="2" b:x="1"><e></e></r>"#
        );
    }

    /// A namespace the element never uses is not declared, and one its
    /// parent already declared is not declared again.
    #[test]
    fn only_namespaces_in_use_are_declared_once() {
        let xml = r#"<p:r xmlns:p="urn:p" xmlns:unused="urn:u"><p:c/></p:r>"#;

        assert_eq!(whole(xml), r#"<p:r xmlns:p="urn:p"><p:c></p:c></p:r>"#);
    }

    /// An element taken out of its document declares the namespaces it
    /// uses that were declared above it, so it reads the same anywhere.
    #[test]
    fn a_subtree_declares_what_it_inherited() {
        let xml = r#"<p:r xmlns:p="urn:p"><p:c a="1">t</p:c></p:r>"#;
        let document = Document::parse(xml).unwrap();
        let child = document.root_element().first_element_child().unwrap();

        let form = canonical(child, Subset::default()).unwrap();

        assert_eq!(form, r#"<p:c xmlns:p="urn:p" a="1">t</p:c>"#);
    }

    /// An omitted node is left out with everything under it, and nothing
    /// else is.
    #[test]
    fn the_omitted_node_is_left_out() {
        let xml = r#"<r><keep/><drop><deep/></drop><keep2/></r>"#;
        let document = Document::parse(xml).unwrap();
        let drop = document
            .descendants()
            .find(|node| node.has_tag_name("drop"))
            .unwrap();

        let form = canonical(
            document.root_element(),
            Subset {
                omitted: Some(drop.id()),
                inclusive: &[],
            },
        )
        .unwrap();

        assert_eq!(form, "<r><keep></keep><keep2></keep2></r>");
    }

    /// Canonicalizing 5,000 nested elements preserves the XML on a 256 KiB thread stack.
    /// Parsing uses a separate, larger stack so the test isolates the canonicalizer.
    #[test]
    fn a_deep_element_is_written_without_the_call_stack() {
        let depth = 5_000;
        let xml = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));

        let document = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(256 * 1024 * 1024)
                .spawn_scoped(scope, || Document::parse(&xml).unwrap())
                .unwrap()
                .join()
                .unwrap()
        });

        let form = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn_scoped(scope, || {
                    canonical(document.root_element(), Subset::default()).unwrap()
                })
                .unwrap()
                .join()
                .unwrap()
        });

        assert_eq!(form, xml);
    }

    /// Text and attribute values are escaped the canonical way, whatever
    /// entities they were written with.
    #[test]
    fn text_and_values_are_escaped_canonically() {
        let xml = "<r a=\"x&amp;y&quot;&#9;\">a &amp; b &lt; c &gt; d &#65;</r>";

        assert_eq!(
            whole(xml),
            "<r a=\"x&amp;y&quot;&#x9;\">a &amp; b &lt; c &gt; d A</r>"
        );
    }

    /// A default namespace undeclared below an element that declared one
    /// is undeclared in the output too.
    #[test]
    fn a_default_namespace_is_undeclared_where_it_ends() {
        let xml = r#"<r xmlns="urn:d"><c xmlns=""/></r>"#;

        assert_eq!(whole(xml), r#"<r xmlns="urn:d"><c xmlns=""></c></r>"#);
    }

    /// A prefix the inclusive list names is declared even where only a
    /// value uses it, as `xsi:type="xs:string"` does.
    #[test]
    fn an_inclusive_prefix_is_declared_though_unused() {
        let xml = r#"<p:r xmlns:p="urn:p" xmlns:xs="urn:xs"><p:c/></p:r>"#;
        let document = Document::parse(xml).unwrap();
        let inclusive = vec!["xs".to_owned()];

        let form = canonical(
            document.root_element(),
            Subset {
                omitted: None,
                inclusive: &inclusive,
            },
        )
        .unwrap();

        assert_eq!(
            form,
            r#"<p:r xmlns:p="urn:p" xmlns:xs="urn:xs"><p:c></p:c></p:r>"#
        );
    }

    /// A plain assertion reads as exclusive canonicalization writes it: the
    /// unused `xs` declaration dropped and the attributes in name order, as
    /// every provider computes the digest over.
    #[test]
    fn a_plain_assertion_reads_as_the_standard_writes_it() {
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.acme.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">00u1</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>ann@acme.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#;

        assert_eq!(
            whole(xml),
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" IssueInstant="2024-01-01T00:00:00Z" Version="2.0"><saml:Issuer>https://idp.acme.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">00u1</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>ann@acme.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#
        );
    }
}
