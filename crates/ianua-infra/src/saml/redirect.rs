//! The HTTP-Redirect binding: a message deflated into a query string, and
//! the signature over the query itself rather than inside the XML.
//!
//! The signed octets are the parameters exactly as they travel, still
//! URL-encoded, in the order the binding fixes: the message, `RelayState`
//! when there is one, then `SigAlg`. A signature is checked only for the
//! message it was read beside, so a signed query cannot vouch for another.

use std::borrow::Cow;
use std::io::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use ianua_domain::shared::errors::DomainError;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::saml::xml::keys::{PrivateKey, SignatureMethod, TrustedKey};
use crate::saml::xml::signature::{SignatureCheck, SignatureRefused};

/// What a query value escapes: everything but the characters RFC 3986
/// leaves unreserved.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The parameters a message travels under.
const MESSAGE_PARAMETERS: [&str; 2] = ["SAMLRequest", "SAMLResponse"];

/// Every parameter the binding reads or signs.
const BINDING_PARAMETERS: [&str; 5] = [
    "SAMLRequest",
    "SAMLResponse",
    "RelayState",
    "SigAlg",
    "Signature",
];

/// The query carrying the request `xml` and `relay_state`, signed by
/// `signer` when there is one.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the request cannot be
/// deflated or signed.
pub(crate) fn request_query(
    xml: &str,
    relay_state: &str,
    signer: Option<&PrivateKey>,
) -> Result<String, DomainError> {
    let mut query = format!(
        "SAMLRequest={}&RelayState={}",
        encoded(&deflated(xml)?),
        encoded(relay_state)
    );
    let Some(signer) = signer else {
        return Ok(query);
    };
    query.push_str("&SigAlg=");
    query.push_str(&encoded(signer.method().uri()));
    let signature = STANDARD.encode(signer.sign(query.as_bytes())?);
    query.push_str("&Signature=");
    query.push_str(&encoded(&signature));
    Ok(query)
}

/// A signature as the binding carried it beside a message.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedQuery<'a> {
    /// The `SigAlg` parameter, decoded.
    pub(crate) algorithm: &'a str,
    /// The `Signature` parameter, decoded: base64.
    pub(crate) signature: &'a str,
    /// The query string exactly as it arrived.
    pub(crate) query: &'a str,
}

/// Whether `signed` is a signature over the query carrying `message`, by
/// one of `keys`.
///
/// # Errors
///
/// Returns [`SignatureRefused`] when the algorithm is not one this
/// platform takes, the query is not in the binding's shape or carries
/// another message, or the signature does not verify.
pub(crate) fn checked(
    signed: &SignedQuery<'_>,
    message: &str,
    keys: &[TrustedKey],
) -> Result<SignatureCheck, SignatureRefused> {
    let method = SignatureMethod::from_uri(signed.algorithm).ok_or(SignatureRefused::Malformed(
        "a signature algorithm this platform does not take",
    ))?;
    let octets = signed_octets(signed, message)?;
    let compact: String = signed
        .signature
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let signature = STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| SignatureRefused::Malformed("a signature's value is not base64"))?;
    if !keys
        .iter()
        .any(|key| key.verifies(method, octets.as_bytes(), &signature))
    {
        return Err(SignatureRefused::DoesNotVerify);
    }
    Ok(SignatureCheck::Verified)
}

/// Rebuilds the signed query bytes after checking the carried message and algorithm.
fn signed_octets(signed: &SignedQuery<'_>, message: &str) -> Result<String, SignatureRefused> {
    let pairs = raw_pairs(signed.query);
    ensure_plain_names(&pairs)?;
    let (name, carried) = message_parameter(&pairs)?;
    if decoded(carried).as_deref() != Some(message) {
        return Err(SignatureRefused::DoesNotVerify);
    }
    let algorithm = only(&pairs, "SigAlg")?.ok_or(SignatureRefused::Malformed(
        "a signed query names no algorithm",
    ))?;
    if decoded(algorithm).as_deref() != Some(signed.algorithm) {
        return Err(SignatureRefused::DoesNotVerify);
    }
    let mut octets = format!("{name}={carried}");
    if let Some(relay_state) = only(&pairs, "RelayState")? {
        octets.push_str("&RelayState=");
        octets.push_str(relay_state);
    }
    octets.push_str("&SigAlg=");
    octets.push_str(algorithm);
    Ok(octets)
}

/// `xml` deflated and in base64, as the binding carries a message.
fn deflated(xml: &str) -> Result<String, DomainError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(xml.as_bytes())
        .map_err(DomainError::infra)?;
    let bytes = encoder.finish().map_err(DomainError::infra)?;
    Ok(STANDARD.encode(bytes))
}

fn encoded(value: &str) -> String {
    utf8_percent_encode(value, QUERY_VALUE).to_string()
}

/// A query value decoded as forms are: `+` is a space.
fn decoded(value: &str) -> Option<String> {
    percent_decode_str(&value.replace('+', " "))
        .decode_utf8()
        .ok()
        .map(Cow::into_owned)
}

/// The query's parameters, each name and value still encoded.
fn raw_pairs(query: &str) -> Vec<(&str, &str)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect()
}

/// Refuses a query naming a binding parameter in an encoded form, such as
/// `Relay%53tate`. A reader that decodes names takes it for the parameter,
/// while the signed octets are built from the names as written, so the
/// value acted on could differ from the value signed.
fn ensure_plain_names(pairs: &[(&str, &str)]) -> Result<(), SignatureRefused> {
    let disguised = pairs.iter().any(|(name, _)| {
        decoded(name)
            .is_some_and(|plain| plain != *name && BINDING_PARAMETERS.contains(&plain.as_str()))
    });
    if disguised {
        return Err(SignatureRefused::Malformed(
            "a signed query names a parameter in an encoded form",
        ));
    }
    Ok(())
}

/// The value of the parameter `name`, if the query carries it once.
fn only<'q>(pairs: &[(&'q str, &'q str)], name: &str) -> Result<Option<&'q str>, SignatureRefused> {
    let mut values = pairs
        .iter()
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| *value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SignatureRefused::Malformed(
            "a signed query names a parameter twice",
        ));
    }
    Ok(first)
}

/// The one message the query carries, and the parameter it came under.
fn message_parameter<'q>(
    pairs: &[(&'q str, &'q str)],
) -> Result<(&'static str, &'q str), SignatureRefused> {
    let mut carried = Vec::new();
    for name in MESSAGE_PARAMETERS {
        if let Some(value) = only(pairs, name)? {
            carried.push((name, value));
        }
    }
    let [one] = carried.as_slice() else {
        return Err(SignatureRefused::Malformed(
            "a signed query carries more or fewer than one message",
        ));
    };
    Ok(*one)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

    use super::*;
    use crate::saml::xml::document::from_deflated_base64;
    use crate::saml::xml::keys::tests::TestKey;

    const REQUEST: &str =
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"/>"#;

    /// A query as the browser brings it: the parameters decoded, the
    /// signed query as it arrived.
    struct Arrived {
        query: String,
        message: String,
        algorithm: String,
        signature: String,
    }

    impl Arrived {
        fn of(query: String) -> Self {
            let value = |name: &str| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default()
            };
            Self {
                message: value("SAMLRequest"),
                algorithm: value("SigAlg"),
                signature: value("Signature"),
                query,
            }
        }

        fn check(&self, key: &TestKey) -> Result<SignatureCheck, SignatureRefused> {
            let signed = SignedQuery {
                algorithm: &self.algorithm,
                signature: &self.signature,
                query: &self.query,
            };
            checked(&signed, &self.message, &[key.trusted()])
        }
    }

    fn signed_by(key: &TestKey) -> Arrived {
        let signer = PrivateKey::of(&key.signing()).unwrap();
        Arrived::of(request_query(REQUEST, "_r1", Some(&signer)).unwrap())
    }

    /// A signed request query verifies against the sender's key, and its
    /// message inflates back to the request.
    #[test]
    fn a_signed_query_verifies() {
        let key = TestKey::new(SigningAlgorithm::Rs256);

        let arrived = signed_by(&key);

        assert_eq!(arrived.check(&key), Ok(SignatureCheck::Verified));
        assert_eq!(from_deflated_base64(&arrived.message).unwrap(), REQUEST);
    }

    /// An unsigned query carries the request and its relay state alone.
    #[test]
    fn an_unsigned_query_carries_no_signature() {
        let query = request_query(REQUEST, "_r1", None).unwrap();

        assert!(query.starts_with("SAMLRequest="));
        assert!(query.ends_with("&RelayState=_r1"));
    }

    /// Changing the relay state invalidates the signed query.
    #[test]
    fn a_changed_relay_state_does_not_verify() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let mut arrived = signed_by(&key);
        arrived.query = arrived.query.replace("RelayState=_r1", "RelayState=_r2");

        assert_eq!(arrived.check(&key), Err(SignatureRefused::DoesNotVerify));
    }

    /// The query signature does not verify when checked against a different message.
    #[test]
    fn a_signature_beside_another_message_does_not_verify() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let mut arrived = signed_by(&key);
        arrived.message = STANDARD.encode("<other/>");

        assert_eq!(arrived.check(&key), Err(SignatureRefused::DoesNotVerify));
    }

    /// A query declaring RSA with SHA-1 is malformed instead of selecting that algorithm.
    #[test]
    fn a_weak_algorithm_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Rs256);
        let mut arrived = signed_by(&key);
        arrived.algorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_owned();

        assert!(matches!(
            arrived.check(&key),
            Err(SignatureRefused::Malformed(_))
        ));
    }

    /// Duplicate relay-state parameters make the query malformed rather than choosing one value.
    #[test]
    fn a_parameter_given_twice_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let mut arrived = signed_by(&key);
        arrived.query.push_str("&RelayState=_r2");

        assert!(matches!(
            arrived.check(&key),
            Err(SignatureRefused::Malformed(_))
        ));
    }

    /// An encoded relay-state parameter name is rejected even beside a valid signed parameter.
    #[test]
    fn a_parameter_named_in_an_encoded_form_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let mut arrived = signed_by(&key);
        arrived.query.push_str("&Relay%53tate=_r2");

        assert!(matches!(
            arrived.check(&key),
            Err(SignatureRefused::Malformed(_))
        ));
    }
}
