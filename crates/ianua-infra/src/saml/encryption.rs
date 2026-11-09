//! Sealed assertions (XML Encryption): opening one a provider sealed to
//! this platform's key, and sealing one this platform sends to an app.
//!
//! The content is AES-GCM, so a changed ciphertext fails to open instead of
//! opening to something else; AES-CBC is refused, since its padding
//! errors let an attacker decrypt a captured assertion piece by piece. The
//! content key travels sealed with RSA-OAEP. Anyone can post a sealed key
//! here and time how the private key handles it, so it is opened with
//! aws-lc-rs, whose RSA decryption takes the same time whatever the sealed
//! key holds, and not with the `rsa` crate, whose decryption leaks it
//! through timing (RUSTSEC-2023-0071). Every failure to open reads the
//! same, so nothing learns which part failed.

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit as _, Nonce};
use async_trait::async_trait;
use aws_lc_rs::rsa::{
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OaepAlgorithm, OaepPrivateDecryptingKey,
    PrivateDecryptingKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::ports::federation::AssertionEncrypter;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::CertificatePem;
use roxmltree::Node;
use zeroize::Zeroizing;

use crate::crypto::certificates::pem::private_key_in;
use crate::saml::xml::document::{
    ASSERTION, DSIG, MOST_MESSAGE_BYTES, XMLENC, elements, is, only_child, text_of,
};
use crate::saml::xml::keys::{random_bytes, rsa_key_of};

/// The XML Encryption 1.1 namespace.
const XMLENC11: &str = "http://www.w3.org/2009/xmlenc11#";

/// AES-128 in GCM mode.
pub(crate) const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";

/// AES-256 in GCM mode.
pub(crate) const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

/// RSA-OAEP with MGF1 over SHA-1, the transport most providers use.
pub(crate) const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

/// RSA-OAEP as XML Encryption 1.1 names it, its digests given apart.
pub(crate) const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

/// SHA-1, as an OAEP digest, the default.
const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

/// SHA-256, as an OAEP digest.
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// MGF1 over SHA-1, the default.
const MGF1_SHA1: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha1";

/// MGF1 over SHA-256.
const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";

/// What an encrypted element holds, as XML Encryption types it.
const ELEMENT_TYPE: &str = "http://www.w3.org/2001/04/xmlenc#Element";

/// The length of a GCM nonce, written before the ciphertext.
const NONCE_BYTES: usize = 12;

/// The one refusal every failure to open gives.
fn unopenable() -> DomainError {
    DomainError::invalid(message!(
        "infra-the-encrypted-assertion-cannot-be-opened",
        "the encrypted assertion cannot be opened"
    ))
}

/// The private RSA key a connection opens sealed assertions with, held by
/// aws-lc-rs. `Debug` prints nothing of it.
pub(crate) struct DecryptionKey(OaepPrivateDecryptingKey);

impl DecryptionKey {
    /// The key in `pem`, a PKCS#8 private key block.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the text holds no PKCS#8
    /// block, or one that is not an RSA key aws-lc-rs takes.
    pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<Self, DomainError> {
        let unreadable = || DomainError::infra_msg("the private key cannot be read");
        let der = private_key_in(pem).map_err(|_| unreadable())?;
        let key = PrivateDecryptingKey::from_pkcs8(&der).map_err(|_| unreadable())?;
        OaepPrivateDecryptingKey::new(key)
            .map(Self)
            .map_err(|_| unreadable())
    }

    /// The content key `sealed` holds, unsealed with `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation`, the one refusal every failure to
    /// open gives, when it was not sealed to this key with `algorithm`.
    pub(crate) fn unsealed(
        &self,
        algorithm: &'static OaepAlgorithm,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, DomainError> {
        let mut plain = Zeroizing::new(vec![0_u8; self.0.min_output_size()]);
        let length = self
            .0
            .decrypt(algorithm, sealed, plain.as_mut_slice(), None)
            .map_err(|_| unopenable())?
            .len();
        plain.truncate(length);
        Ok(plain)
    }
}

impl std::fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecryptionKey(<redacted>)")
    }
}

/// The assertion `encrypted` holds, opened with `key`.
///
/// # Errors
///
/// Returns `DomainError::Validation`, the same for every cause, when it is
/// not in a shape this platform opens, names an algorithm it does not take,
/// was sealed to another key, or was changed.
pub(crate) fn opened(encrypted: Node<'_, '_>, key: &DecryptionKey) -> Result<String, DomainError> {
    let data = only_child(encrypted, XMLENC, "EncryptedData")
        .ok()
        .flatten()
        .ok_or_else(unopenable)?;
    if data
        .attribute("Type")
        .is_some_and(|kind| kind != ELEMENT_TYPE)
    {
        return Err(unopenable());
    }
    let content = ContentCipher::of(data)?;
    let content_key = content_key(encrypted, key)?;
    let ciphertext = cipher_value(data)?;
    let plaintext = content.open(&content_key, &ciphertext)?;
    if plaintext.len() > MOST_MESSAGE_BYTES {
        return Err(unopenable());
    }
    String::from_utf8(plaintext).map_err(|_| unopenable())
}

/// Seals assertions to an app's certificate: AES-256-GCM for the content,
/// RSA-OAEP over SHA-1 for its key, the pair every service provider opens.
#[derive(Debug, Clone, Copy, Default)]
pub struct XmlEncAssertionEncrypter;

#[async_trait]
impl AssertionEncrypter for XmlEncAssertionEncrypter {
    async fn encrypt(
        &self,
        signed_assertion: &str,
        recipient: &CertificatePem,
    ) -> Result<String, DomainError> {
        sealed_for(signed_assertion, recipient)
    }
}

/// `signed_assertion` sealed to the RSA key in `recipient`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the certificate carries no
/// RSA key of at least 2048 bits, or sealing fails.
pub(crate) fn sealed_for(
    signed_assertion: &str,
    recipient: &CertificatePem,
) -> Result<String, DomainError> {
    let recipient_key = rsa_key_of(recipient).map_err(DomainError::infra)?;
    let content_key = Zeroizing::new(random_bytes::<32>()?);
    let nonce = random_bytes::<NONCE_BYTES>()?;
    let not_sealed = || DomainError::infra_msg("the assertion could not be sealed");
    let sealed = Aes256Gcm::new_from_slice(content_key.as_slice())
        .map_err(|_| not_sealed())?
        .encrypt(Nonce::from_slice(&nonce), signed_assertion.as_bytes())
        .map_err(|_| not_sealed())?;
    let wrapped_key = recipient_key
        .sealed(content_key.as_slice())
        .map_err(DomainError::infra)?;
    let content = STANDARD.encode([nonce.as_slice(), sealed.as_slice()].concat());
    Ok(encrypted_assertion(&STANDARD.encode(wrapped_key), &content))
}

/// The `<saml:EncryptedAssertion>` carrying `content`, its key sealed as
/// `wrapped_key`.
fn encrypted_assertion(wrapped_key: &str, content: &str) -> String {
    format!(
        r#"<saml:EncryptedAssertion xmlns:saml="{ASSERTION}"><xenc:EncryptedData xmlns:xenc="{XMLENC}" Type="{ELEMENT_TYPE}"><xenc:EncryptionMethod Algorithm="{AES256_GCM}"/><ds:KeyInfo xmlns:ds="{DSIG}"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{RSA_OAEP_MGF1P}"><ds:DigestMethod Algorithm="{SHA1}"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>{wrapped_key}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{content}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#
    )
}

/// The content cipher an `EncryptedData` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentCipher {
    /// AES-128 in GCM mode.
    Aes128Gcm,
    /// AES-256 in GCM mode.
    Aes256Gcm,
}

impl ContentCipher {
    fn of(data: Node<'_, '_>) -> Result<Self, DomainError> {
        let method = only_child(data, XMLENC, "EncryptionMethod")
            .ok()
            .flatten()
            .ok_or_else(unopenable)?;
        match method.attribute("Algorithm") {
            Some(AES128_GCM) => Ok(Self::Aes128Gcm),
            Some(AES256_GCM) => Ok(Self::Aes256Gcm),
            Some(_) | None => Err(unopenable()),
        }
    }

    /// `ciphertext`, its nonce first, opened under `key`.
    fn open(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DomainError> {
        if ciphertext.len() <= NONCE_BYTES {
            return Err(unopenable());
        }
        let (nonce, sealed) = ciphertext.split_at(NONCE_BYTES);
        let nonce = Nonce::from_slice(nonce);
        let opened = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| unopenable())?
                .decrypt(nonce, sealed),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| unopenable())?
                .decrypt(nonce, sealed),
        };
        opened.map_err(|_| unopenable())
    }
}

/// The content key, unsealed from the one `EncryptedKey` inside
/// `encrypted`, wherever the provider put it.
fn content_key(
    encrypted: Node<'_, '_>,
    key: &DecryptionKey,
) -> Result<Zeroizing<Vec<u8>>, DomainError> {
    let mut found = encrypted
        .descendants()
        .filter(|node| is(*node, XMLENC, "EncryptedKey"));
    let (Some(encrypted_key), None) = (found.next(), found.next()) else {
        return Err(unopenable());
    };
    let method = only_child(encrypted_key, XMLENC, "EncryptionMethod")
        .ok()
        .flatten()
        .ok_or_else(unopenable)?;
    let algorithm = transport_padding(method)?;
    let sealed = cipher_value(encrypted_key)?;
    key.unsealed(algorithm, &sealed)
}

/// The OAEP padding a key transport `method` names: its algorithm, its
/// digest and its mask function, each from a short list. The digest and
/// the mask function agree: SHA-1 with MGF1 over SHA-1, which
/// `rsa-oaep-mgf1p` always is, or SHA-256 with MGF1 over SHA-256, which
/// only XML Encryption 1.1's `rsa-oaep` can name.
fn transport_padding(method: Node<'_, '_>) -> Result<&'static OaepAlgorithm, DomainError> {
    let parameters = elements(method);
    let known = |node: &Node<'_, '_>| is(*node, DSIG, "DigestMethod") || is(*node, XMLENC11, "MGF");
    if !parameters.iter().all(known) {
        return Err(unopenable());
    }
    let named = |namespace: &'static str, name: &'static str| {
        only_child(method, namespace, name)
            .map_err(|_| unopenable())
            .map(|found| found.and_then(|node| node.attribute("Algorithm")))
    };
    let digest = named(DSIG, "DigestMethod")?;
    let mask = named(XMLENC11, "MGF")?;
    let algorithm = method.attribute("Algorithm");
    match (algorithm, digest.unwrap_or(SHA1), mask) {
        (Some(RSA_OAEP_MGF1P), SHA1, None) | (Some(RSA_OAEP), SHA1, None | Some(MGF1_SHA1)) => {
            Ok(&OAEP_SHA1_MGF1SHA1)
        }
        (Some(RSA_OAEP), SHA256, Some(MGF1_SHA256)) => Ok(&OAEP_SHA256_MGF1SHA256),
        _ => Err(unopenable()),
    }
}

/// The base64 bytes of the `CipherData/CipherValue` under `node`.
fn cipher_value(node: Node<'_, '_>) -> Result<Vec<u8>, DomainError> {
    let data = only_child(node, XMLENC, "CipherData")
        .ok()
        .flatten()
        .ok_or_else(unopenable)?;
    let value = only_child(data, XMLENC, "CipherValue")
        .ok()
        .flatten()
        .ok_or_else(unopenable)?;
    let text = text_of(value).map_err(|_| unopenable())?;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| unopenable())
}

#[cfg(test)]
pub(crate) mod tests {
    use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};
    use der::Encode as _;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

    use super::*;
    use crate::crypto::certificates::pem::certificate_in;
    use crate::saml::xml::document::{Comments, parse};
    use crate::saml::xml::keys::tests::TestKey;

    const ASSERTION_XML: &str = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>https://idp.acme.com</saml:Issuer></saml:Assertion>"#;

    /// An RSA key of this platform's, and its certificate.
    pub(crate) fn sp_key() -> (TestKey, DecryptionKey) {
        let key = TestKey::new(SigningAlgorithm::Rs256);
        let private = DecryptionKey::from_pkcs8_pem(key.private_key.expose()).unwrap();
        (key, private)
    }

    /// `assertion` sealed to `certificate`, as a provider seals it.
    pub(crate) fn sealed(assertion: &str, certificate: &CertificatePem) -> String {
        sealed_for(assertion, certificate).unwrap()
    }

    fn open(sealed: &str, key: &DecryptionKey) -> Result<String, DomainError> {
        let document = parse(sealed, Comments::Refused).unwrap();
        opened(document.root_element(), key)
    }

    /// An assertion sealed to a certificate opens with its private key, as
    /// it was.
    #[test]
    fn a_sealed_assertion_opens_with_its_key() {
        let (key, private) = sp_key();

        let sealed = sealed(ASSERTION_XML, &key.certificate);

        assert!(!sealed.contains("https://idp.acme.com"));
        assert_eq!(open(&sealed, &private).unwrap(), ASSERTION_XML);
    }

    /// A different private key cannot decrypt the sealed assertion.
    #[test]
    fn an_assertion_sealed_to_another_key_does_not_open() {
        let (key, _) = sp_key();
        let (_, other) = sp_key();

        let sealed = sealed(ASSERTION_XML, &key.certificate);

        assert!(open(&sealed, &other).is_err());
    }

    /// Flipping ciphertext bits makes decryption fail rather than returning altered plaintext.
    #[test]
    fn a_changed_ciphertext_does_not_open() {
        let (key, private) = sp_key();
        let sealed = sealed(ASSERTION_XML, &key.certificate);
        let content_start =
            sealed.rfind("<xenc:CipherValue>").unwrap() + "<xenc:CipherValue>".len();
        let mut changed = sealed.clone();
        let flipped = if &sealed[content_start + 20..content_start + 21] == "A" {
            "B"
        } else {
            "A"
        };
        changed.replace_range(content_start + 20..content_start + 21, flipped);

        assert!(open(&changed, &private).is_err());
    }

    /// Declaring AES-CBC makes the encrypted assertion unsupported and decryption fails.
    #[test]
    fn a_cbc_sealed_assertion_is_refused() {
        let (key, private) = sp_key();
        let cbc = sealed(ASSERTION_XML, &key.certificate)
            .replace(AES256_GCM, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");

        assert!(open(&cbc, &private).is_err());
    }

    /// `content_key` sealed to `certificate` under OAEP with `digest`, as a
    /// provider declaring XML Encryption 1.1's `rsa-oaep` seals it, the
    /// declared mask function written as `mask`.
    fn sealed_with_oaep(
        certificate: &CertificatePem,
        padding: &'static OaepAlgorithm,
        digest: &str,
        mask: &str,
    ) -> String {
        let spki = certificate_in(certificate.as_str())
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let public =
            OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(&spki).unwrap()).unwrap();
        let content_key = [9_u8; 32];
        let nonce = [3_u8; NONCE_BYTES];
        let sealed = Aes256Gcm::new_from_slice(&content_key)
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), ASSERTION_XML.as_bytes())
            .unwrap();
        let mut wrapped = vec![0_u8; public.ciphertext_size()];
        let length = public
            .encrypt(padding, &content_key, &mut wrapped, None)
            .unwrap()
            .len();
        wrapped.truncate(length);
        let content = STANDARD.encode([nonce.as_slice(), sealed.as_slice()].concat());
        encrypted_assertion(&STANDARD.encode(wrapped), &content).replace(
            &format!(r#"<xenc:EncryptionMethod Algorithm="{RSA_OAEP_MGF1P}"><ds:DigestMethod Algorithm="{SHA1}"/></xenc:EncryptionMethod>"#),
            &format!(r#"<xenc:EncryptionMethod Algorithm="{RSA_OAEP}"><ds:DigestMethod Algorithm="{digest}"/><xenc11:MGF xmlns:xenc11="{XMLENC11}" Algorithm="{mask}"/></xenc:EncryptionMethod>"#),
        )
    }

    /// A provider sealing the content key with `rsa-oaep` over SHA-256,
    /// its mask function over SHA-256 too, is opened.
    #[test]
    fn a_key_sealed_with_oaep_over_sha256_opens() {
        let (key, private) = sp_key();

        let sealed = sealed_with_oaep(
            &key.certificate,
            &OAEP_SHA256_MGF1SHA256,
            SHA256,
            MGF1_SHA256,
        );

        assert_eq!(open(&sealed, &private).unwrap(), ASSERTION_XML);
    }

    /// Changing the OAEP digest or making its mask function disagree prevents decryption;
    /// both failures return the same generic error.
    #[test]
    fn a_key_declared_with_another_padding_does_not_open() {
        let (key, private) = sp_key();

        let mismatched =
            sealed_with_oaep(&key.certificate, &OAEP_SHA256_MGF1SHA256, SHA1, MGF1_SHA1);
        let mixed = sealed_with_oaep(&key.certificate, &OAEP_SHA256_MGF1SHA256, SHA256, MGF1_SHA1);

        let refusal = format!("{:?}", unopenable());
        assert_eq!(
            format!("{:?}", open(&mismatched, &private).unwrap_err()),
            refusal
        );
        assert_eq!(
            format!("{:?}", open(&mixed, &private).unwrap_err()),
            refusal
        );
    }

    /// Non-RSA and unreadable stored private keys produce infrastructure errors on loading.
    #[test]
    fn a_key_that_is_not_pkcs8_rsa_is_refused() {
        let ecdsa = TestKey::new(SigningAlgorithm::Es256);

        let loaded = DecryptionKey::from_pkcs8_pem(ecdsa.private_key.expose());
        let garbage = DecryptionKey::from_pkcs8_pem(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        );

        assert!(matches!(loaded, Err(DomainError::Infrastructure(_))));
        assert!(matches!(garbage, Err(DomainError::Infrastructure(_))));
    }

    /// Encrypting for a certificate without an RSA key fails with an infrastructure error.
    #[tokio::test]
    async fn sealing_to_a_certificate_without_rsa_fails() {
        let ecdsa = TestKey::new(SigningAlgorithm::Es256);

        let result = XmlEncAssertionEncrypter
            .encrypt(ASSERTION_XML, &ecdsa.certificate)
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
