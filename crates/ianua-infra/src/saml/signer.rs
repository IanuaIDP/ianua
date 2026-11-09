//! Signing the SAML documents this platform sends with the tenant's key:
//! an enveloped signature on the document's root element.
//!
//! The digest is taken over the root's exclusive canonical form, so a
//! response holding an assertion that is already signed covers that
//! signature too. The signature goes right after the root's `Issuer`, where
//! the SAML schema places it, and names the key by its id; the key itself
//! is published in the metadata, never sent along.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::ports::crypto::{XmlSigner, XmlSigningKey};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::KeyId;
use roxmltree::{Document, Node};

use crate::saml::xml::canonical::{Subset, canonical};
use crate::saml::xml::document::{
    ASSERTION, Comments, DSIG, elements, escaped, is, only_child, parse,
};
use crate::saml::xml::keys::{DigestMethod, PrivateKey};
use crate::saml::xml::signature::{ENVELOPED, EXC_C14N};

/// Signs SAML documents with enveloped XML signatures.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvelopedXmlSigner;

#[async_trait]
impl XmlSigner for EnvelopedXmlSigner {
    async fn sign_xml(&self, xml: &str, key: &XmlSigningKey<'_>) -> Result<String, DomainError> {
        enveloped(xml, &PrivateKey::of(key)?, key.kid)
    }
}

/// `xml` with an enveloped signature by `signer` on its root element,
/// naming the key as `kid`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the document is not one this
/// platform wrote to be signed: not well-formed, its root without an `ID`
/// or with a signature already, or holding nothing to place one beside.
pub(crate) fn enveloped(
    xml: &str,
    signer: &PrivateKey,
    kid: &KeyId,
) -> Result<String, DomainError> {
    let document = parse(xml, Comments::Refused).map_err(DomainError::infra)?;
    let root = document.root_element();
    let id = signable_id(root)?;
    let place = signature_place(&document)?;
    let digested = canonical(root, Subset::default()).map_err(DomainError::infra)?;
    let digest = STANDARD.encode(DigestMethod::Sha256.digest(digested.as_bytes()));
    let signed_info = signed_info(id, signer, &digest);
    let signature_value =
        STANDARD.encode(signer.sign(canonical_signed_info(&signed_info)?.as_bytes())?);
    let block = format!(
        r#"<ds:Signature xmlns:ds="{DSIG}">{signed_info}<ds:SignatureValue>{signature_value}</ds:SignatureValue><ds:KeyInfo><ds:KeyName>{kid}</ds:KeyName></ds:KeyInfo></ds:Signature>"#,
        kid = escaped(kid.as_str()),
    );
    let (before, after) = xml
        .get(..place)
        .zip(xml.get(place..))
        .ok_or_else(|| DomainError::infra_msg("the signature has no place in the document"))?;
    Ok(format!("{before}{block}{after}"))
}

/// The root's `ID`, once it is a plain XML id and the root is unsigned.
fn signable_id<'a>(root: Node<'a, '_>) -> Result<&'a str, DomainError> {
    let id = root
        .attribute("ID")
        .filter(|id| is_xml_id(id))
        .ok_or_else(|| DomainError::infra_msg("the document to sign has no ID to sign it under"))?;
    let already = only_child(root, DSIG, "Signature").map_err(DomainError::infra)?;
    if already.is_some() {
        return Err(DomainError::infra_msg(
            "the document to sign is signed already",
        ));
    }
    Ok(id)
}

/// Where the signature goes: after the root's `Issuer`, or before its
/// first child when it has none.
fn signature_place(document: &Document<'_>) -> Result<usize, DomainError> {
    let root = document.root_element();
    let first_element = elements(root).first().copied();
    if let Some(issuer) = first_element.filter(|first| is(*first, ASSERTION, "Issuer")) {
        return Ok(issuer.range().end);
    }
    root.first_child()
        .map(|child| child.range().start)
        .ok_or_else(|| DomainError::infra_msg("the document to sign holds nothing to sign beside"))
}

/// The `SignedInfo` of a signature over the element `id`, as written into
/// the document: its prefix is declared by the `Signature` around it.
fn signed_info(id: &str, signer: &PrivateKey, digest: &str) -> String {
    format!(
        r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{method}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{digest_method}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
        method = signer.method().uri(),
        digest_method = DigestMethod::Sha256.uri(),
    )
}

/// The canonical form of `signed_info`, as a verifier computes it in the
/// signed document: the namespaces around it are used by none of its
/// elements, so only the signature's own is declared.
fn canonical_signed_info(signed_info: &str) -> Result<String, DomainError> {
    let wrapped = format!(r#"<ds:Signature xmlns:ds="{DSIG}">{signed_info}</ds:Signature>"#);
    let document = parse(&wrapped, Comments::Refused).map_err(DomainError::infra)?;
    let info = document
        .root_element()
        .first_element_child()
        .ok_or_else(|| DomainError::infra_msg("the signature's SignedInfo is missing"))?;
    canonical(info, Subset::default()).map_err(DomainError::infra)
}

/// Whether `id` is an XML id: a letter or `_` first, then letters, digits,
/// `_`, `-` and `.`, so it can stand in a reference unescaped.
fn is_xml_id(id: &str) -> bool {
    let mut chars = id.chars();
    let starts_well = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
    starts_well && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

    use super::*;
    use crate::saml::xml::keys::tests::TestKey;
    use crate::saml::xml::signature::{SignatureCheck, checked};

    /// `xml` signed by `key`, as a provider or an app would sign it.
    pub(crate) fn signed(xml: &str, key: &TestKey) -> String {
        enveloped(xml, &PrivateKey::of(&key.signing()).unwrap(), &key.kid).unwrap()
    }

    const ASSERTION_XML: &str = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0"><saml:Issuer>https://idp.acme.com</saml:Issuer><saml:Subject><saml:NameID>ann</saml:NameID></saml:Subject></saml:Assertion>"#;

    fn verified(xml: &str, key: &TestKey) -> bool {
        let document = parse(xml, Comments::Refused).unwrap();
        checked(document.root_element(), &[key.trusted()]) == Ok(SignatureCheck::Verified)
    }

    /// Every kind of tenant key signs an assertion that verifies against
    /// the certificate of that key.
    #[tokio::test]
    async fn every_kind_of_key_signs_a_verifiable_assertion() {
        for algorithm in [
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Es256,
            SigningAlgorithm::EdDsa,
        ] {
            let key = TestKey::new(algorithm);

            let signed = EnvelopedXmlSigner
                .sign_xml(ASSERTION_XML, &key.signing())
                .await
                .unwrap();

            assert!(verified(&signed, &key), "{algorithm:?}");
        }
    }

    /// The signature goes right after the `Issuer`, where the SAML schema
    /// places it, and names the key by its id.
    #[test]
    fn the_signature_follows_the_issuer() {
        let key = TestKey::new(SigningAlgorithm::Es256);

        let signed = signed(ASSERTION_XML, &key);

        assert!(signed.contains("</saml:Issuer><ds:Signature"));
        assert!(signed.contains("<ds:KeyName>key-1</ds:KeyName>"));
    }

    /// A response holding a signed assertion is signed around it: both
    /// signatures verify, the response's covering the assertion's.
    #[test]
    fn a_response_around_a_signed_assertion_verifies_as_a_whole() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let assertion = signed(ASSERTION_XML, &key);
        let response = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"><saml:Issuer>https://idp.acme.com</saml:Issuer>{assertion}</samlp:Response>"#
        );

        let signed_response = signed(&response, &key);

        let document = parse(&signed_response, Comments::Refused).unwrap();
        let inner = document.root_element().last_element_child().unwrap();
        assert!(verified(&signed_response, &key));
        assert_eq!(
            checked(inner, &[key.trusted()]),
            Ok(SignatureCheck::Verified)
        );
    }

    /// Signing fails for an element without an ID or one that already has a signature.
    #[test]
    fn a_document_that_cannot_be_signed_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let signer = PrivateKey::of(&key.signing()).unwrap();
        let without_id = ASSERTION_XML.replace(r#" ID="_a1""#, "");
        let twice = signed(ASSERTION_XML, &key);

        assert!(enveloped(&without_id, &signer, &key.kid).is_err());
        assert!(enveloped(&twice, &signer, &key.kid).is_err());
    }
}
