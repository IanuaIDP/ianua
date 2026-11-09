//! The P-256 keys an agent holds and what it signs with them: compact
//! JWS for its assertions and DPoP proofs (ES256, the signature as `r`
//! then `s`), and DER signatures for a workload's attestation proof.
//!
//! The private half never leaves the key. `Debug` shows the thumbprint
//! only.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// The algorithm every key here signs with, as JOSE and the API name it.
pub const ALGORITHM: &str = "ES256";

/// A public key as a JWK (RFC 7517), the members RFC 7638 thumbprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// The curve, `P-256`.
    pub crv: String,
    /// The key type, `EC`.
    pub kty: String,
    /// The point's `x`, base64url.
    pub x: String,
    /// The point's `y`, base64url.
    pub y: String,
}

/// Why a key could not be read from what was handed over.
#[derive(Debug, thiserror::Error)]
#[error("the key is not a P-256 private key in PKCS#8")]
pub(crate) struct UnreadableKey;

/// One P-256 key pair.
#[derive(Clone)]
pub struct AgentKey {
    signing: SigningKey,
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AgentKey").field(&self.thumbprint()).finish()
    }
}

impl AgentKey {
    /// A fresh key pair, drawn from the system's randomness.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::random(&mut rand::rngs::OsRng),
        }
    }

    /// The key pair whose private half is `der`, PKCS#8, as a certificate
    /// tool writes it.
    ///
    /// # Errors
    ///
    /// [`UnreadableKey`] when `der` is no P-256 key.
    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, UnreadableKey> {
        SigningKey::from_pkcs8_der(der)
            .map(|signing| Self { signing })
            .map_err(|_| UnreadableKey)
    }

    /// The public half as SPKI PEM, as the API enrols it.
    ///
    /// # Panics
    ///
    /// Never: a P-256 public key always writes as PEM.
    /// The generated P-256 verifying key has a supported SPKI encoding.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn public_pem(&self) -> String {
        self.signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("a P-256 public key writes as PEM")
    }

    /// The public half as SPKI DER, the form an attestation binding hashes.
    ///
    /// # Panics
    ///
    /// Never: a P-256 public key always writes as DER.
    /// The generated P-256 verifying key has a supported SPKI encoding.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn public_der(&self) -> Vec<u8> {
        self.signing
            .verifying_key()
            .to_public_key_der()
            .expect("a P-256 public key writes as DER")
            .as_bytes()
            .to_vec()
    }

    /// The public half as a JWK.
    #[must_use]
    pub fn jwk(&self) -> Jwk {
        let point = self.signing.verifying_key().to_encoded_point(false);
        let coordinate = |part: Option<&p256::FieldBytes>| {
            URL_SAFE_NO_PAD.encode(part.map(p256::FieldBytes::as_slice).unwrap_or_default())
        };
        Jwk {
            crv: "P-256".to_owned(),
            kty: "EC".to_owned(),
            x: coordinate(point.x()),
            y: coordinate(point.y()),
        }
    }

    /// The JWK thumbprint (RFC 7638): SHA-256 of the required members in
    /// order, base64url.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint_of(&self.jwk())
    }

    /// The compact JWS of `claims` under `header`, signed ES256.
    #[must_use]
    pub fn signed_jws(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.signing.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// The DER signature of `bytes`, as an X.509 key signs.
    #[must_use]
    pub fn signed_der(&self, bytes: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(bytes);
        signature.to_der().as_bytes().to_vec()
    }
}

/// The RFC 7638 thumbprint of `jwk`.
#[must_use]
pub(crate) fn thumbprint_of(jwk: &Jwk) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The SHA-256 of `text`, base64url, as DPoP's `ath` carries a token's.
#[must_use]
pub(crate) fn sha256_url(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()))
}

/// The claims of the compact JWS `token`, read without checking its
/// signature: what the holder of a token may read of it.
///
/// # Errors
///
/// [`UnreadableToken`] when it is not a compact JWS with a JSON payload.
pub fn claims_of(token: &str) -> Result<Value, UnreadableToken> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(UnreadableToken);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| UnreadableToken)?;
    serde_json::from_slice(&bytes).map_err(|_| UnreadableToken)
}

/// Why a token's claims could not be read.
#[derive(Debug, thiserror::Error)]
#[error("the token is not a compact JWS with JSON claims")]
pub struct UnreadableToken;

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;

    use super::*;

    /// A signed JWS checks against the public half, the signature 64 bytes
    /// as ES256 writes it.
    #[test]
    fn a_signed_jws_checks_against_the_public_half() {
        let key = AgentKey::generate();

        let jws = key.signed_jws(
            &serde_json::json!({"alg": "ES256"}),
            &serde_json::json!({"a": 1}),
        );

        let (input, signature) = jws.rsplit_once('.').unwrap();
        let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        let verifying = VerifyingKey::from_public_key_pem(&key.public_pem()).unwrap();
        assert_eq!(signature.len(), 64);
        assert!(
            verifying
                .verify(
                    input.as_bytes(),
                    &Signature::from_slice(&signature).unwrap()
                )
                .is_ok()
        );
        assert_eq!(claims_of(&jws).unwrap(), serde_json::json!({"a": 1}));
    }

    /// The thumbprint is the base64url SHA-256 of 32 bytes, the same for
    /// the same key and another for another.
    #[test]
    fn a_thumbprint_names_one_key() {
        let key = AgentKey::generate();

        assert_eq!(key.thumbprint(), thumbprint_of(&key.jwk()));
        assert_eq!(key.thumbprint().len(), 43);
        assert_ne!(key.thumbprint(), AgentKey::generate().thumbprint());
    }

    /// What is not a compact JWS has no claims to read.
    #[test]
    fn what_is_no_jws_has_no_claims() {
        assert!(claims_of("one.two").is_err());
        assert!(claims_of("a.b.c.d").is_err());
    }
}
