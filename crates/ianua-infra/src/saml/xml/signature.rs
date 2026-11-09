//! Enveloped XML signatures as SAML uses them, checked so that what is
//! signed is what is read.
//!
//! A signature is taken only as a direct child of the element it signs,
//! referring to that element by its own `ID`, with exactly the transforms
//! SAML signs with (enveloped, then exclusive canonicalization) and
//! algorithms from a fixed list. The digest is computed over that very
//! element in the parsed tree, its signature left out by node, so no
//! wrapped or moved copy can stand in for what the caller then reads. The
//! key comes from the certificates the caller trusts, never from the
//! signature's own `KeyInfo`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use roxmltree::{Document, Node};

use crate::saml::xml::canonical::{Subset, canonical};
use crate::saml::xml::document::{DSIG, elements, is, only_child, text_of};
use crate::saml::xml::keys::{DigestMethod, SignatureMethod, TrustedKey};

/// Exclusive XML canonicalization without comments.
pub(crate) const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// The transform that leaves the signature out of what it signs.
pub(crate) const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Whether an element came signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureCheck {
    /// It carried no signature.
    Absent,
    /// It carried one, and the signature verified against a trusted key.
    Verified,
}

/// Why a signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureRefused {
    /// The signature is not one this platform checks: misplaced, of an
    /// algorithm or a shape it does not take.
    Malformed(&'static str),
    /// The signature is well-formed but does not verify against any key
    /// trusted for the sender.
    DoesNotVerify,
}

impl SignatureRefused {
    /// The refusal as bad input, however it failed: for a check whose
    /// port reports every bad message as invalid.
    pub(crate) fn as_invalid(self) -> DomainError {
        match self {
            Self::Malformed(why) => DomainError::invalid(why),
            Self::DoesNotVerify => DomainError::invalid(message!(
                "infra-the-signature-does-not-verify",
                "the signature does not verify"
            )),
        }
    }

    /// The refusal as bad input when malformed, and as forbidden when it
    /// does not verify: someone tried to speak for a sender.
    pub(crate) fn as_forbidden(self) -> DomainError {
        match self {
            Self::Malformed(why) => DomainError::invalid(why),
            Self::DoesNotVerify => DomainError::forbidden(message!(
                "infra-the-signature-does-not-verify",
                "the signature does not verify"
            )),
        }
    }
}

/// Whether `element` is signed, checked against `keys`.
///
/// # Errors
///
/// Returns [`SignatureRefused`] when it carries a signature that is
/// malformed, misplaced or does not verify against any of `keys`.
pub(crate) fn checked(
    element: Node<'_, '_>,
    keys: &[TrustedKey],
) -> Result<SignatureCheck, SignatureRefused> {
    let Some(signature) = only_child(element, DSIG, "Signature")
        .map_err(|_| SignatureRefused::Malformed("an element carries two signatures"))?
    else {
        return Ok(SignatureCheck::Absent);
    };
    let parts = Parts::read(signature)?;
    parts.ensure_digest(element, signature)?;
    let signed_info = canonical(
        parts.signed_info,
        Subset {
            omitted: None,
            inclusive: &parts.info_prefixes,
        },
    )
    .map_err(|_| SignatureRefused::Malformed("a signature cannot be canonicalized"))?;
    let verifies = |key: &TrustedKey| {
        key.verifies(parts.method, signed_info.as_bytes(), &parts.signature_value)
    };
    if !keys.iter().any(verifies) {
        return Err(SignatureRefused::DoesNotVerify);
    }
    Ok(SignatureCheck::Verified)
}

/// Refuses a document holding a signature anywhere `may_hold` does not
/// allow one, so no signature sits where nothing checks it.
///
/// # Errors
///
/// Returns `DomainError::Validation` naming no part of the document.
pub(crate) fn ensure_placed<'a, 'input>(
    document: &'a Document<'input>,
    may_hold: impl Fn(Node<'a, 'input>) -> bool,
) -> Result<(), DomainError> {
    let misplaced = document
        .descendants()
        .filter(|node| is(*node, DSIG, "Signature"))
        .any(|signature| !signature.parent_element().is_some_and(&may_hold));
    if misplaced {
        return Err(DomainError::invalid(message!(
            "infra-the-message-holds-a-signature-where",
            "the message holds a signature where none is checked"
        )));
    }
    Ok(())
}

/// The prefixes an `InclusiveNamespaces` child of `node` lists, `""` for
/// `#default`.
///
/// # Errors
///
/// Returns [`SignatureRefused::Malformed`] when `node` holds anything else.
fn inclusive_prefixes(node: Node<'_, '_>) -> Result<Vec<String>, SignatureRefused> {
    let children = elements(node);
    match children.as_slice() {
        [] => Ok(Vec::new()),
        [list] if is(*list, EXC_C14N, "InclusiveNamespaces") => Ok(list
            .attribute("PrefixList")
            .unwrap_or_default()
            .split_whitespace()
            .map(|prefix| if prefix == "#default" { "" } else { prefix })
            .map(str::to_owned)
            .collect()),
        _ => Err(SignatureRefused::Malformed(
            "a canonicalization carries parameters this platform does not take",
        )),
    }
}

/// A `<Signature>` read in the one shape SAML signs with.
struct Parts<'a, 'input> {
    signed_info: Node<'a, 'input>,
    info_prefixes: Vec<String>,
    method: SignatureMethod,
    reference: &'a str,
    reference_prefixes: Vec<String>,
    digest: DigestMethod,
    digest_value: Vec<u8>,
    signature_value: Vec<u8>,
}

impl<'a, 'input> Parts<'a, 'input> {
    /// Reads the fixed signature shape and its permitted algorithms.
    fn read(signature: Node<'a, 'input>) -> Result<Self, SignatureRefused> {
        let shape = SignatureRefused::Malformed("a signature is not in the shape SAML signs with");
        let [signed_info, value] = signature_children(signature)?;
        let [canonicalization, method_node, reference] = signed_info_parts(signed_info)?;
        if !elements(method_node).is_empty() {
            return Err(shape);
        }
        let info_prefixes = canonicalization_prefixes(canonicalization)?;
        let method = algorithm(method_node)
            .and_then(SignatureMethod::from_uri)
            .ok_or(SignatureRefused::Malformed(
                "a signature algorithm this platform does not take",
            ))?;
        let read = read_reference(reference)?;
        Ok(Self {
            signed_info,
            info_prefixes,
            method,
            reference: read.uri,
            reference_prefixes: read.prefixes,
            digest: read.digest,
            digest_value: read.value,
            signature_value: base64_text(value)?,
        })
    }

    /// Checks that the reference and digest cover the element holding this signature.
    fn ensure_digest(
        &self,
        element: Node<'_, '_>,
        signature: Node<'_, '_>,
    ) -> Result<(), SignatureRefused> {
        let id = element
            .attribute("ID")
            .ok_or(SignatureRefused::Malformed("a signed element has no ID"))?;
        if self.reference != format!("#{id}") {
            return Err(SignatureRefused::Malformed(
                "a signature refers to another element than the one holding it",
            ));
        }
        let digested = canonical(
            element,
            Subset {
                omitted: Some(signature.id()),
                inclusive: &self.reference_prefixes,
            },
        )
        .map_err(|_| SignatureRefused::Malformed("a signed element cannot be canonicalized"))?;
        if self.digest.digest(digested.as_bytes()) != self.digest_value {
            return Err(SignatureRefused::DoesNotVerify);
        }
        Ok(())
    }
}

/// Reads the signed information and value, allowing only an optional key-info sibling.
fn signature_children<'a, 'input>(
    signature: Node<'a, 'input>,
) -> Result<[Node<'a, 'input>; 2], SignatureRefused> {
    let shape = SignatureRefused::Malformed("a signature is not in the shape SAML signs with");
    let children = elements(signature);
    let (signed_info, value) = match children.as_slice() {
        [info, value] => (*info, *value),
        [info, value, key_info] if is(*key_info, DSIG, "KeyInfo") => (*info, *value),
        _ => return Err(shape),
    };
    if !is(signed_info, DSIG, "SignedInfo") || !is(value, DSIG, "SignatureValue") {
        return Err(shape);
    }
    Ok([signed_info, value])
}

/// The `CanonicalizationMethod`, `SignatureMethod` and `Reference` of a
/// `SignedInfo`, which holds nothing else.
fn signed_info_parts<'a, 'input>(
    signed_info: Node<'a, 'input>,
) -> Result<[Node<'a, 'input>; 3], SignatureRefused> {
    let children = elements(signed_info);
    let [canonicalization, method, reference] = children.as_slice() else {
        return Err(SignatureRefused::Malformed(
            "a signature signs more or less than one reference",
        ));
    };
    let in_order = is(*canonicalization, DSIG, "CanonicalizationMethod")
        && is(*method, DSIG, "SignatureMethod")
        && is(*reference, DSIG, "Reference");
    if !in_order {
        return Err(SignatureRefused::Malformed(
            "a signature is not in the shape SAML signs with",
        ));
    }
    Ok([*canonicalization, *method, *reference])
}

/// The inclusive prefixes of the canonicalization `SignedInfo` names,
/// which must be exclusive canonicalization without comments.
fn canonicalization_prefixes(node: Node<'_, '_>) -> Result<Vec<String>, SignatureRefused> {
    if algorithm(node) != Some(EXC_C14N) {
        return Err(SignatureRefused::Malformed(
            "a signature canonicalizes in a way this platform does not take",
        ));
    }
    inclusive_prefixes(node)
}

/// What a `Reference` says.
struct ReadReference<'a> {
    /// The element it points at.
    uri: &'a str,
    /// The inclusive prefixes of its canonicalization.
    prefixes: Vec<String>,
    /// How its digest was made.
    digest: DigestMethod,
    /// The digest itself.
    value: Vec<u8>,
}

/// What `reference` says: the element it points at, the inclusive prefixes
/// of its canonicalization, and its digest.
fn read_reference<'a>(reference: Node<'a, '_>) -> Result<ReadReference<'a>, SignatureRefused> {
    let shape =
        SignatureRefused::Malformed("a signature's reference is not in the shape SAML signs with");
    let uri = reference.attribute("URI").ok_or(shape)?;
    let children = elements(reference);
    let [transforms, method, value] = children.as_slice() else {
        return Err(shape);
    };
    if !is(*transforms, DSIG, "Transforms")
        || !is(*method, DSIG, "DigestMethod")
        || !is(*value, DSIG, "DigestValue")
    {
        return Err(shape);
    }
    let prefixes = transform_prefixes(*transforms)?;
    let digest =
        algorithm(*method)
            .and_then(DigestMethod::from_uri)
            .ok_or(SignatureRefused::Malformed(
                "a digest algorithm this platform does not take",
            ))?;
    Ok(ReadReference {
        uri,
        prefixes,
        digest,
        value: base64_text(*value)?,
    })
}

/// The inclusive prefixes of the transforms, which must be exactly the
/// enveloped signature and then exclusive canonicalization.
fn transform_prefixes(transforms: Node<'_, '_>) -> Result<Vec<String>, SignatureRefused> {
    let children = elements(transforms);
    let [enveloped, exclusive] = children.as_slice() else {
        return Err(SignatureRefused::Malformed(
            "a signature transforms in a way this platform does not take",
        ));
    };
    let pinned = is(*enveloped, DSIG, "Transform")
        && algorithm(*enveloped) == Some(ENVELOPED)
        && elements(*enveloped).is_empty()
        && is(*exclusive, DSIG, "Transform")
        && algorithm(*exclusive) == Some(EXC_C14N);
    if !pinned {
        return Err(SignatureRefused::Malformed(
            "a signature transforms in a way this platform does not take",
        ));
    }
    inclusive_prefixes(*exclusive)
}

fn algorithm<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    node.attribute("Algorithm")
}

/// The base64 text of `node`, line breaks dropped.
fn base64_text(node: Node<'_, '_>) -> Result<Vec<u8>, SignatureRefused> {
    let unreadable = SignatureRefused::Malformed("a signature's value is not base64");
    let text = text_of(node).map_err(|_| unreadable)?;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(compact.as_bytes()).map_err(|_| unreadable)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

    use super::*;
    use crate::saml::signer::tests::signed;
    use crate::saml::xml::document::{Comments, parse};
    use crate::saml::xml::keys::tests::TestKey;

    const ASSERTION: &str = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0"><saml:Issuer>https://idp.acme.com</saml:Issuer><saml:Subject><saml:NameID>ann</saml:NameID></saml:Subject></saml:Assertion>"#;

    fn check(xml: &str, key: &TestKey) -> Result<SignatureCheck, SignatureRefused> {
        let document = parse(xml, Comments::Refused).unwrap();
        checked(document.root_element(), &[key.trusted()])
    }

    /// An assertion signed with the provider's key verifies against its
    /// certificate.
    #[test]
    fn a_signed_element_verifies() {
        let key = TestKey::new(SigningAlgorithm::Es256);

        let result = check(&signed(ASSERTION, &key), &key);

        assert_eq!(result, Ok(SignatureCheck::Verified));
    }

    /// An element with no signature reads as unsigned, for the caller to
    /// decide what that means.
    #[test]
    fn an_unsigned_element_is_absent() {
        let key = TestKey::new(SigningAlgorithm::Es256);

        assert_eq!(check(ASSERTION, &key), Ok(SignatureCheck::Absent));
    }

    /// Changing a name after signing makes the assertion fail signature verification.
    #[test]
    fn a_tampered_element_does_not_verify() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let tampered = signed(ASSERTION, &key).replace(">ann<", ">admin<");

        assert_eq!(check(&tampered, &key), Err(SignatureRefused::DoesNotVerify));
    }

    /// A signature made with another key does not verify against the trusted key.
    #[test]
    fn a_signature_by_another_key_does_not_verify() {
        let provider = TestKey::new(SigningAlgorithm::Es256);
        let mallory = TestKey::new(SigningAlgorithm::Es256);

        let result = check(&signed(ASSERTION, &mallory), &provider);

        assert_eq!(result, Err(SignatureRefused::DoesNotVerify));
    }

    /// A signature reference that names a different element is malformed.
    #[test]
    fn a_signature_naming_another_element_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let moved = signed(ASSERTION, &key).replace(r#"ID="_a1""#, r#"ID="_a2""#);

        assert!(matches!(
            check(&moved, &key),
            Err(SignatureRefused::Malformed(_))
        ));
    }

    /// Declaring RSA with SHA-1 makes the signature malformed rather than selecting that algorithm.
    #[test]
    fn a_signature_by_a_weak_algorithm_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let weakened = signed(ASSERTION, &key).replace(
            SignatureMethod::EcdsaSha256.uri(),
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        );

        assert!(matches!(
            check(&weakened, &key),
            Err(SignatureRefused::Malformed(_))
        ));
    }

    /// A signature nested outside the permitted location fails validation.
    #[test]
    fn a_signature_where_none_is_checked_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let inner = signed(ASSERTION, &key);
        let wrapped = format!(r#"<r><e>{inner}</e></r>"#);
        let document = parse(&wrapped, Comments::Refused).unwrap();

        let placed = ensure_placed(&document, |parent| parent == document.root_element());

        assert!(placed.is_err());
    }
}
