//! An enveloped XML signature checked as an outside app checks it, with
//! code of its own: the signed element in exclusive canonical form,
//! digested and compared, and the signature over the canonical
//! `SignedInfo` checked against a certificate the identity provider
//! published. None of the platform's code is used, so a fault in how it
//! signs shows here as a refusal. The app signs its own requests the same
//! way, with a P-256 key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePublicKey as _;
use roxmltree::{Document, Node, NodeType};
use rsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

/// The XML signature namespace.
pub(super) const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Exclusive canonicalization, without comments.
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// The enveloped-signature transform.
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// SHA-256 as a digest method.
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// RSA with SHA-256, PKCS #1 v1.5.
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// ECDSA with SHA-256.
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

/// Why a signature does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broken {
    /// The element carries no signature of its own.
    Unsigned,
    /// The signature covers another element.
    CoversAnother,
    /// It names an algorithm or transform an app does not accept here.
    Algorithm(String),
    /// The element is not what was digested.
    DigestDiffers,
    /// No published certificate's key made the signature.
    SignatureDiffers,
    /// Something it needs is missing or unreadable.
    Malformed(&'static str),
}

/// Checks the enveloped signature on `element` against the certificates
/// `published`, each DER-encoded.
///
/// # Errors
///
/// [`Broken`] says why the signature does not hold.
pub fn verify(element: Node<'_, '_>, published: &[Vec<u8>]) -> Result<(), Broken> {
    let signature = child(element, DSIG, "Signature").ok_or(Broken::Unsigned)?;
    let info = child(signature, DSIG, "SignedInfo").ok_or(Broken::Malformed("SignedInfo"))?;
    ensure_covers(element, info)?;
    ensure_digest(element, signature, info)?;
    let method = child(info, DSIG, "SignatureMethod")
        .and_then(|method| method.attribute("Algorithm"))
        .ok_or(Broken::Malformed("SignatureMethod"))?;
    let value = decoded(child(signature, DSIG, "SignatureValue"))?;
    let signed = canonical(info, None);
    published
        .iter()
        .any(|certificate| made_by(certificate, method, signed.as_bytes(), &value))
        .then_some(())
        .ok_or(Broken::SignatureDiffers)
}

/// `xml` with an enveloped signature by `key` on its root element, placed
/// right after the root's first child, its `Issuer`.
///
/// # Panics
///
/// When `xml` is not a document with an `ID` on its root and a first
/// child to place the signature after.
/// Signing is fixture construction; malformed fixture XML must fail before it is sent.
#[allow(clippy::expect_used)]
#[must_use]
pub fn enveloped(xml: &str, key: &p256::ecdsa::SigningKey) -> String {
    let document = Document::parse(xml).expect("a document to sign");
    let root = document.root_element();
    let id = root.attribute("ID").expect("the root's ID");
    let place = root
        .first_element_child()
        .expect("an Issuer to sign after")
        .range()
        .end;
    let digest = STANDARD.encode(Sha256::digest(canonical(root, None).as_bytes()));
    let signed_info = format!(
        r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{ECDSA_SHA256}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    let wrapped = format!(r#"<ds:Signature xmlns:ds="{DSIG}">{signed_info}</ds:Signature>"#);
    let around = Document::parse(&wrapped).expect("the signature's SignedInfo");
    let info = around
        .root_element()
        .first_element_child()
        .expect("the SignedInfo");
    let signature: p256::ecdsa::Signature = key.sign(canonical(info, None).as_bytes());
    let value = STANDARD.encode(signature.to_bytes());
    let block = format!(
        r#"<ds:Signature xmlns:ds="{DSIG}">{signed_info}<ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature>"#
    );
    format!("{}{block}{}", &xml[..place], &xml[place..])
}

/// Checks the signature references `element` by its `ID`, through the
/// enveloped and exclusive transforms alone, canonicalized exclusively.
fn ensure_covers(element: Node<'_, '_>, info: Node<'_, '_>) -> Result<(), Broken> {
    let canonicalization = child(info, DSIG, "CanonicalizationMethod")
        .and_then(|method| method.attribute("Algorithm"))
        .ok_or(Broken::Malformed("CanonicalizationMethod"))?;
    ensure_algorithm(canonicalization, EXC_C14N)?;
    let reference = child(info, DSIG, "Reference").ok_or(Broken::Malformed("Reference"))?;
    let id = element.attribute("ID").ok_or(Broken::Malformed("ID"))?;
    if reference.attribute("URI") != Some(format!("#{id}").as_str()) {
        return Err(Broken::CoversAnother);
    }
    let transforms: Vec<&str> = child(reference, DSIG, "Transforms")
        .map(|transforms| {
            elements(transforms)
                .filter_map(|transform| transform.attribute("Algorithm"))
                .collect()
        })
        .unwrap_or_default();
    if transforms != [ENVELOPED, EXC_C14N] {
        return Err(Broken::Algorithm(transforms.join(" ")));
    }
    Ok(())
}

/// Checks the digest the signature names is that of `element` without
/// `signature`, in exclusive canonical form.
fn ensure_digest(
    element: Node<'_, '_>,
    signature: Node<'_, '_>,
    info: Node<'_, '_>,
) -> Result<(), Broken> {
    let reference = child(info, DSIG, "Reference").ok_or(Broken::Malformed("Reference"))?;
    let method = child(reference, DSIG, "DigestMethod")
        .and_then(|method| method.attribute("Algorithm"))
        .ok_or(Broken::Malformed("DigestMethod"))?;
    ensure_algorithm(method, SHA256)?;
    let named = decoded(child(reference, DSIG, "DigestValue"))?;
    let digest = Sha256::digest(canonical(element, Some(signature)).as_bytes());
    if named != digest.as_slice() {
        return Err(Broken::DigestDiffers);
    }
    Ok(())
}

/// Whether the key of `certificate`, DER-encoded, made `value` over
/// `signed` by the signature method `method`.
#[must_use]
pub fn made_by(certificate: &[u8], method: &str, signed: &[u8], value: &[u8]) -> bool {
    let Some(key) = Certificate::from_der(certificate)
        .ok()
        .and_then(|certificate| {
            certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .ok()
        })
    else {
        return false;
    };
    match method {
        RSA_SHA256 => rsa_made(&key, signed, value),
        ECDSA_SHA256 => ecdsa_made(&key, signed, value),
        _ => false,
    }
}

/// Whether the RSA key `spki` made `value` over `signed`.
fn rsa_made(spki: &[u8], signed: &[u8], value: &[u8]) -> bool {
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(spki) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(value) else {
        return false;
    };
    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
        .verify(signed, &signature)
        .is_ok()
}

/// Whether the P-256 key `spki` made `value`, the raw `r` and `s` an XML
/// signature carries, over `signed`.
fn ecdsa_made(spki: &[u8], signed: &[u8], value: &[u8]) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(spki) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(value) else {
        return false;
    };
    key.verify(signed, &signature).is_ok()
}

fn ensure_algorithm(named: &str, accepted: &str) -> Result<(), Broken> {
    if named != accepted {
        return Err(Broken::Algorithm(named.to_owned()));
    }
    Ok(())
}

/// The base64 text of `node`, decoded, whitespace ignored.
fn decoded(node: Option<Node<'_, '_>>) -> Result<Vec<u8>, Broken> {
    let text: String = node
        .and_then(|node| node.text())
        .ok_or(Broken::Malformed("a base64 value"))?
        .split_whitespace()
        .collect();
    STANDARD
        .decode(text)
        .map_err(|_| Broken::Malformed("a base64 value"))
}

/// The child element of `node` named `name` in `namespace`, the first
/// when there are several.
pub(super) fn child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<Node<'a, 'input>> {
    elements(node).find(|child| {
        child.tag_name().namespace() == Some(namespace) && child.tag_name().name() == name
    })
}

/// The child elements of `node`.
fn elements<'a, 'input>(node: Node<'a, 'input>) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(Node::is_element)
}

/// The exclusive canonical form of `apex`, without comments, leaving out
/// `omitted` and all within it.
#[must_use]
pub fn canonical(apex: Node<'_, '_>, omitted: Option<Node<'_, '_>>) -> String {
    let mut writer = Writer {
        out: String::new(),
        omitted,
        rendered: Vec::new(),
    };
    writer.node(apex);
    writer.out
}

/// The canonical text written so far, what is left out, and the
/// namespaces the elements around the current one declared.
struct Writer<'a, 'input> {
    out: String,
    omitted: Option<Node<'a, 'input>>,
    rendered: Vec<(String, String)>,
}

impl Writer<'_, '_> {
    fn node(&mut self, node: Node<'_, '_>) {
        if self
            .omitted
            .is_some_and(|omitted| omitted.id() == node.id())
        {
            return;
        }
        match node.node_type() {
            NodeType::Element => self.element(node),
            NodeType::Text => self
                .out
                .push_str(&escaped_text(node.text().unwrap_or_default())),
            NodeType::Root | NodeType::Comment | NodeType::PI => {}
        }
    }

    fn element(&mut self, node: Node<'_, '_>) {
        let name = written_name(node);
        let declared_before = self.rendered.len();
        let declarations = self.declarations(node, name);
        self.out.push('<');
        self.out.push_str(name);
        for (prefix, uri) in declarations {
            self.out.push_str(&declaration(&prefix, &uri));
            self.rendered.push((prefix, uri));
        }
        for (written, value) in sorted_attributes(node) {
            self.out
                .push_str(&format!(" {written}=\"{}\"", escaped_attribute(value)));
        }
        self.out.push('>');
        for child in node.children() {
            self.node(child);
        }
        self.out.push_str(&format!("</{name}>"));
        self.rendered.truncate(declared_before);
    }

    /// The namespace declarations `node` carries in canonical form: each
    /// prefix it or its attributes use whose meaning differs from the one
    /// the nearest element around it declared, the default first.
    fn declarations(&self, node: Node<'_, '_>, name: &str) -> Vec<(String, String)> {
        let mut used = std::collections::BTreeSet::new();
        used.insert(prefix_of(name).to_owned());
        for attribute in node.attributes() {
            let prefix = prefix_of(attribute_name(node, &attribute));
            if !prefix.is_empty() {
                used.insert(prefix.to_owned());
            }
        }
        used.into_iter()
            .filter(|prefix| prefix != "xml")
            .filter_map(|prefix| {
                let asked = (!prefix.is_empty()).then_some(prefix.as_str());
                let uri = node
                    .lookup_namespace_uri(asked)
                    .unwrap_or_default()
                    .to_owned();
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

fn declaration(prefix: &str, uri: &str) -> String {
    let uri = escaped_attribute(uri);
    match prefix.is_empty() {
        true => format!(" xmlns=\"{uri}\""),
        false => format!(" xmlns:{prefix}=\"{uri}\""),
    }
}

/// The element's name as written, prefix included.
fn written_name<'input>(node: Node<'_, 'input>) -> &'input str {
    let text = node.document().input_text();
    let rest = text.get(node.range().start + 1..).unwrap_or_default();
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(rest.len());
    rest.get(..end).unwrap_or_default()
}

/// The attribute's name as written, prefix included.
fn attribute_name<'input>(
    node: Node<'_, 'input>,
    attribute: &roxmltree::Attribute<'_, 'input>,
) -> &'input str {
    node.document()
        .input_text()
        .get(attribute.range_qname())
        .unwrap_or_default()
}

/// The element's attributes in canonical order, by namespace and then by
/// local name, each with its name as written and its value.
fn sorted_attributes<'a, 'input>(node: Node<'a, 'input>) -> Vec<(&'input str, &'a str)> {
    let mut attributes: Vec<_> = node
        .attributes()
        .map(|attribute| {
            (
                attribute.namespace().unwrap_or_default(),
                attribute.name(),
                attribute_name(node, &attribute),
                attribute.value(),
            )
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
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#xD;")
}

fn escaped_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

#[cfg(test)]
mod tests {
    use p256::pkcs8::DecodePrivateKey as _;

    use super::*;

    /// A request Ledger signs passes the check against Ledger's own
    /// certificate, and fails it once a word is changed.
    #[test]
    fn a_signed_request_passes_the_check_until_changed() {
        let pair = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["ledger.example".to_owned()])
            .unwrap()
            .self_signed(&pair)
            .unwrap();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&pair.serialize_der()).unwrap();
        let xml = r#"<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1"><s:Issuer>https://ledger.example/saml</s:Issuer><s:NameID>pat</s:NameID></p:LogoutRequest>"#;
        let published = [certificate.der().to_vec()];

        let signed = enveloped(xml, &key);
        let changed = signed.replace(">pat<", ">mallory<");

        let checked_as = |xml: &str| {
            let document = Document::parse(xml).unwrap();
            verify(document.root_element(), &published)
        };
        assert_eq!(checked_as(&signed), Ok(()));
        assert_eq!(checked_as(&changed), Err(Broken::DigestDiffers));
    }

    /// A document written loosely comes out in canonical form: attributes
    /// in order, only the namespaces used, empty elements opened and
    /// closed, and nothing left of the part left out.
    #[test]
    fn the_canonical_form_keeps_what_is_used_and_leaves_out_the_signature() {
        let xml = r#"<p:Response xmlns:p="urn:p" xmlns:s="urn:s" xmlns:unused="urn:u" b="2" a="1"><s:Issuer>me &amp; you</s:Issuer><ds:Signature xmlns:ds="urn:d"/><s:Empty/></p:Response>"#;
        let document = roxmltree::Document::parse(xml).unwrap();
        let root = document.root_element();
        let signature = root.children().nth(1).unwrap();

        let canonical = canonical(root, Some(signature));

        assert_eq!(
            canonical,
            r#"<p:Response xmlns:p="urn:p" a="1" b="2"><s:Issuer xmlns:s="urn:s">me &amp; you</s:Issuer><s:Empty xmlns:s="urn:s"></s:Empty></p:Response>"#
        );
    }
}
