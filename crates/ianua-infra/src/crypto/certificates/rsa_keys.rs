//! RSA keys, held by aws-lc-rs: signing with PKCS#1 v1.5, checking such a
//! signature, sealing to a public key with OAEP, and drawing a new key.
//!
//! The `rsa` crate's private-key operations take a time that depends on the
//! key (RUSTSEC-2023-0071), so whoever can ask for many signatures or
//! decryptions and time them could learn the key. aws-lc-rs does them in
//! constant time, so every RSA key the platform holds or checks against is
//! held here. A key from outside holds at least [`MIN_RSA_BITS`].

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{
    KeyPair, KeySize, OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey, PublicEncryptingKey, PublicKey,
    PublicKeyComponents,
};
use aws_lc_rs::signature::{
    KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256,
    UnparsedPublicKey,
};
use der::{Decode as _, Reader as _};
use zeroize::Zeroizing;

use crate::crypto::certificates::pem::{
    pkcs1_private_key_in, private_key_in, private_key_pem, public_key_pem,
};

/// The fewest bits of RSA a key may hold.
pub(crate) const MIN_RSA_BITS: usize = 2048;

/// Why an RSA key could not be read or used. None of it names the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RsaKeyError {
    /// The text or bytes are not an RSA key in the form asked for.
    #[error("the bytes are not an RSA key")]
    Unreadable,
    /// The key holds fewer bits than the platform accepts.
    #[error("an RSA key holds fewer than {MIN_RSA_BITS} bits")]
    TooShort,
    /// The key could not sign or seal.
    #[error("the RSA key could not be used")]
    CouldNotUse,
}

/// The digest a PKCS#1 v1.5 signature is made over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaDigest {
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// A private RSA key that signs with PKCS#1 v1.5 over SHA-256. `Debug`
/// prints nothing of it.
pub(crate) struct RsaSigningKey(KeyPair);

impl RsaSigningKey {
    /// The key in `pem`, a PKCS#8 private key block.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::Unreadable`] when it holds no PKCS#8 RSA key of at
    /// least [`MIN_RSA_BITS`].
    pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<Self, RsaKeyError> {
        let der = private_key_in(pem).map_err(|_| RsaKeyError::Unreadable)?;
        KeyPair::from_pkcs8(&der)
            .map(Self)
            .map_err(|_| RsaKeyError::Unreadable)
    }

    /// The key in `pem`, a PKCS#1 `RSA PRIVATE KEY` block.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::Unreadable`] when it holds no such key.
    pub(crate) fn from_pkcs1_pem(pem: &str) -> Result<Self, RsaKeyError> {
        let der = pkcs1_private_key_in(pem).map_err(|_| RsaKeyError::Unreadable)?;
        KeyPair::from_der(&der)
            .map(Self)
            .map_err(|_| RsaKeyError::Unreadable)
    }

    /// A new key of [`MIN_RSA_BITS`], and its PKCS#8 PEM, wiped when
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::CouldNotUse`] when the key cannot be drawn or written.
    pub(crate) fn generated() -> Result<(Self, Zeroizing<String>), RsaKeyError> {
        let pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| RsaKeyError::CouldNotUse)?;
        let der = pair.as_der().map_err(|_| RsaKeyError::CouldNotUse)?;
        let pem = private_key_pem(der.as_ref());
        Ok((Self(pair), pem))
    }

    /// The PKCS#1 v1.5 signature over SHA-256 of `data`.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::CouldNotUse`] when the key cannot sign.
    pub(crate) fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, RsaKeyError> {
        let mut signature = vec![0_u8; self.0.public_modulus_len()];
        self.0
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                data,
                &mut signature,
            )
            .map_err(|_| RsaKeyError::CouldNotUse)?;
        Ok(signature)
    }

    /// The public half of this key.
    pub(crate) fn public_key(&self) -> RsaVerifyingKey {
        RsaVerifyingKey(self.0.public_key().clone())
    }
}

impl std::fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaSigningKey(<redacted>)")
    }
}

/// A public RSA key of at least [`MIN_RSA_BITS`], that checks PKCS#1 v1.5
/// signatures.
#[derive(Debug, Clone)]
pub(crate) struct RsaVerifyingKey(PublicKey);

impl RsaVerifyingKey {
    /// The key `der` holds, as SPKI or as a PKCS#1 `RSAPublicKey`.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::Unreadable`] when it is no RSA key, and
    /// [`RsaKeyError::TooShort`] when it holds fewer than [`MIN_RSA_BITS`].
    pub(crate) fn from_der(der: &[u8]) -> Result<Self, RsaKeyError> {
        let key = PublicKey::from_der(der).map_err(|_| refusal_of(der))?;
        if key.modulus_len().saturating_mul(8) < MIN_RSA_BITS {
            return Err(RsaKeyError::TooShort);
        }
        Ok(Self(key))
    }

    /// The key whose modulus is `n` and exponent `e`, each big-endian, as
    /// a JWK writes them. Leading zero bytes are passed over.
    ///
    /// # Errors
    ///
    /// As [`from_der`](Self::from_der).
    pub(crate) fn from_components(n: &[u8], e: &[u8]) -> Result<Self, RsaKeyError> {
        let components = PublicKeyComponents {
            n: without_leading_zeros(n),
            e: without_leading_zeros(e),
        };
        let spki = components.as_der().map_err(|_| RsaKeyError::Unreadable)?;
        Self::from_der(spki.as_ref())
    }

    /// The modulus, big-endian, with no leading zero byte.
    pub(crate) fn modulus(&self) -> &[u8] {
        self.0.modulus().big_endian_without_leading_zero()
    }

    /// The public exponent, big-endian, with no leading zero byte.
    pub(crate) fn exponent(&self) -> &[u8] {
        self.0.exponent().big_endian_without_leading_zero()
    }

    /// The key as SPKI DER.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::CouldNotUse`] when it cannot be written.
    pub(crate) fn spki_der(&self) -> Result<Vec<u8>, RsaKeyError> {
        self.0
            .as_der()
            .map(|der| der.as_ref().to_vec())
            .map_err(|_| RsaKeyError::CouldNotUse)
    }

    /// The key as SPKI PEM.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::CouldNotUse`] when it cannot be written.
    pub(crate) fn spki_pem(&self) -> Result<String, RsaKeyError> {
        Ok(public_key_pem(&self.spki_der()?))
    }

    /// Whether `signature` is this key's PKCS#1 v1.5 signature of `data`
    /// over `digest`.
    pub(crate) fn verifies(&self, digest: RsaDigest, data: &[u8], signature: &[u8]) -> bool {
        let algorithm = match digest {
            RsaDigest::Sha256 => &RSA_PKCS1_2048_8192_SHA256,
            RsaDigest::Sha512 => &RSA_PKCS1_2048_8192_SHA512,
        };
        UnparsedPublicKey::new(algorithm, self.0.as_ref())
            .verify(data, signature)
            .is_ok()
    }
}

impl PartialEq for RsaVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

/// A public RSA key of at least [`MIN_RSA_BITS`] to seal to with RSA-OAEP
/// over SHA-1, the transport every SAML service provider opens.
pub(crate) struct RsaSealingKey(OaepPublicEncryptingKey);

impl RsaSealingKey {
    /// The key `spki` holds.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::Unreadable`] when it is no RSA key, and
    /// [`RsaKeyError::TooShort`] when it holds fewer than [`MIN_RSA_BITS`].
    pub(crate) fn from_spki_der(spki: &[u8]) -> Result<Self, RsaKeyError> {
        let key = PublicEncryptingKey::from_der(spki).map_err(|_| refusal_of(spki))?;
        if key.key_size_bits() < MIN_RSA_BITS {
            return Err(RsaKeyError::TooShort);
        }
        OaepPublicEncryptingKey::new(key)
            .map(Self)
            .map_err(|_| RsaKeyError::Unreadable)
    }

    /// `plaintext` sealed to this key.
    ///
    /// # Errors
    ///
    /// [`RsaKeyError::CouldNotUse`] when it is too long to seal, or sealing
    /// fails.
    pub(crate) fn sealed(&self, plaintext: &[u8]) -> Result<Vec<u8>, RsaKeyError> {
        let mut sealed = vec![0_u8; self.0.ciphertext_size()];
        let length = self
            .0
            .encrypt(&OAEP_SHA1_MGF1SHA1, plaintext, &mut sealed, None)
            .map_err(|_| RsaKeyError::CouldNotUse)?
            .len();
        sealed.truncate(length);
        Ok(sealed)
    }
}

impl std::fmt::Debug for RsaSealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaSealingKey")
    }
}

/// `bytes` from their first byte that is not zero.
fn without_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

/// The refusal of a public key aws-lc-rs would not read: too short when
/// its modulus is, since aws-lc-rs refuses a short key as unreadable, and
/// unreadable otherwise.
fn refusal_of(der: &[u8]) -> RsaKeyError {
    match modulus_bits(der) {
        Some(bits) if bits < MIN_RSA_BITS => RsaKeyError::TooShort,
        Some(_) | None => RsaKeyError::Unreadable,
    }
}

/// How many bits the modulus of the RSA public key `der` holds, in its
/// SPKI or its PKCS#1 form, read without taking it for a usable key.
fn modulus_bits(der: &[u8]) -> Option<usize> {
    let spki = x509_cert::spki::SubjectPublicKeyInfoRef::try_from(der).ok();
    let pkcs1 = spki
        .as_ref()
        .and_then(|spki| spki.subject_public_key.as_bytes())
        .unwrap_or(der);
    let mut reader = der::SliceReader::new(pkcs1).ok()?;
    let modulus = reader
        .sequence(|fields| {
            let modulus = der::asn1::UintRef::decode(fields)?;
            der::asn1::UintRef::decode(fields)?;
            Ok(modulus)
        })
        .ok()?;
    Some(modulus.as_bytes().len().saturating_mul(8))
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    /// A 1024-bit RSA public key, as SPKI PEM: shorter than the platform
    /// accepts.
    pub(crate) const SHORT_RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgC+Bhj/kqM0szo2/xE8Rt0IW4
MKMq7gVo9ImPXjuYZHHtRfjADijMANIHkRoDvIYH5l8YpkvpejezUSRNkRWSGl98
4ncUK9f0XSgqnwOjrhzqn3PqPhnfJnn7TG9VeFoIUYIMEe/hGBnzlu2FHeAgjAbR
L9PI3jQ5cmMC/X3WJQIDAQAB
-----END PUBLIC KEY-----
";

    /// A fresh RSA key's PKCS#8 PEM.
    pub(crate) fn fresh_pkcs8_pem() -> String {
        let (_, pem) = RsaSigningKey::generated().unwrap();
        pem.as_str().to_owned()
    }

    /// The DER of the one block of `pem`.
    pub(crate) fn der_of(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD.decode(body).unwrap()
    }

    /// A drawn key signs, its public half checks the signature over
    /// SHA-256, and neither changed data nor the other digest checks.
    #[test]
    fn a_drawn_key_signs_and_its_public_half_checks() {
        let (key, _) = RsaSigningKey::generated().unwrap();
        let public = key.public_key();

        let signature = key.sign_sha256(b"signed info").unwrap();

        assert!(public.verifies(RsaDigest::Sha256, b"signed info", &signature));
        assert!(!public.verifies(RsaDigest::Sha256, b"signed infO", &signature));
        assert!(!public.verifies(RsaDigest::Sha512, b"signed info", &signature));
    }

    /// A key written as PKCS#8 PEM reads back as the same key.
    #[test]
    fn a_written_key_reads_back() {
        let (key, pem) = RsaSigningKey::generated().unwrap();

        let read = RsaSigningKey::from_pkcs8_pem(&pem).unwrap();

        assert_eq!(read.public_key(), key.public_key());
    }

    /// A 1024-bit RSA key is too short for either signature verification or encryption.
    #[test]
    fn a_short_key_is_refused() {
        let der = der_of(SHORT_RSA_PUBLIC_KEY);

        assert_eq!(
            RsaVerifyingKey::from_der(&der).unwrap_err(),
            RsaKeyError::TooShort
        );
        assert_eq!(
            RsaSealingKey::from_spki_der(&der).unwrap_err(),
            RsaKeyError::TooShort
        );
    }

    /// A key rebuilt from its modulus and exponent, as a JWK lists them,
    /// even with a leading zero byte, is the same key.
    #[test]
    fn a_key_rebuilt_from_its_components_is_the_same() {
        let (key, _) = RsaSigningKey::generated().unwrap();
        let public = key.public_key();
        let padded = [&[0_u8][..], public.modulus()].concat();

        let rebuilt = RsaVerifyingKey::from_components(&padded, public.exponent()).unwrap();

        assert_eq!(rebuilt, public);
    }
}
