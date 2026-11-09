//! The keys a JWS is signed and checked with: RSA (PKCS#1 v1.5 with
//! SHA-256), ECDSA on P-256 with SHA-256, and Ed25519. A key from outside,
//! such as a cluster's, may also be ECDSA on P-384 with SHA-384 or on
//! P-521 with SHA-512 (RFC 7518 section 3.4), checked by aws-lc-rs: the
//! platform checks those, and never signs with them.
//!
//! A key is always read for the algorithm stored beside it, so a key of
//! one kind is never used as another. An RSA key holds at least 2048 bits,
//! and is held by aws-lc-rs, whose signing takes the same time whatever
//! the key.

use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, ECDSA_P521_SHA512_FIXED, UnparsedPublicKey};
use der::Encode as _;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};

use crate::crypto::certificates::pem::public_key_in;
use crate::crypto::certificates::rsa_keys::{
    MIN_RSA_BITS, RsaDigest, RsaKeyError, RsaSigningKey, RsaVerifyingKey,
};

/// Why a key could not be read or could not sign. None of it names the key.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyError {
    /// The PEM is not a key of the algorithm it is stored with.
    #[error("the key is not a {0:?} key")]
    NotOfAlgorithm(SigningAlgorithm),
    /// An RSA key is shorter than the platform accepts.
    #[error("an RSA key holds fewer than {MIN_RSA_BITS} bits")]
    TooShort,
    /// The key could not sign.
    #[error("the key could not sign")]
    CouldNotSign,
}

impl KeyError {
    /// The refusal of an RSA key read for `algorithm`.
    pub(crate) fn of_rsa(refused: RsaKeyError, algorithm: SigningAlgorithm) -> Self {
        match refused {
            RsaKeyError::TooShort => Self::TooShort,
            RsaKeyError::Unreadable | RsaKeyError::CouldNotUse => Self::NotOfAlgorithm(algorithm),
        }
    }
}

/// A private key, read for its algorithm.
pub(crate) enum PrivateKey {
    Rsa(Box<RsaSigningKey>),
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl PrivateKey {
    /// The PKCS#8 key `pem` holds, read as a key of `algorithm`.
    pub(crate) fn from_pem(algorithm: SigningAlgorithm, pem: &str) -> Result<Self, KeyError> {
        let refused = || KeyError::NotOfAlgorithm(algorithm);
        match algorithm {
            SigningAlgorithm::Rs256 => RsaSigningKey::from_pkcs8_pem(pem)
                .map(|key| Self::Rsa(Box::new(key)))
                .map_err(|_| refused()),
            SigningAlgorithm::Es256 => p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
                .map(Self::P256)
                .map_err(|_| refused()),
            SigningAlgorithm::EdDsa => ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
                .map(Self::Ed25519)
                .map_err(|_| refused()),
        }
    }

    /// The algorithm this key signs with.
    pub(crate) fn algorithm(&self) -> JwsAlgorithm {
        match self {
            Self::Rsa(_) => JwsAlgorithm::Rs256,
            Self::P256(_) => JwsAlgorithm::Es256,
            Self::Ed25519(_) => JwsAlgorithm::EdDsa,
        }
    }

    /// The public half of an elliptic-curve key, for a proof of possession
    /// to carry. `None` for RSA: only the platform's own keys are RSA, and
    /// they never sign a proof.
    pub(crate) fn public_key(&self) -> Option<PublicKey> {
        match self {
            Self::Rsa(_) => None,
            Self::P256(key) => Some(PublicKey::P256(*key.verifying_key())),
            Self::Ed25519(key) => Some(PublicKey::Ed25519(key.verifying_key())),
        }
    }

    /// The signature of `data`, in the form JWS writes it: RSA's bytes,
    /// ECDSA's `r || s`, Ed25519's 64 bytes.
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Rsa(key) => key.sign_sha256(data).map_err(|_| KeyError::CouldNotSign),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            Self::Ed25519(key) => Ok(key.sign(data).to_bytes().to_vec()),
        }
    }
}

/// The algorithm a JWS is checked with, as its header's `alg` names it:
/// the platform's own three, and the two ECDSA curves only keys from
/// outside sign with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwsAlgorithm {
    Rs256,
    Es256,
    Es384,
    Es512,
    EdDsa,
}

impl JwsAlgorithm {
    /// The name JWS gives the algorithm in a header's `alg`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }
}

impl From<SigningAlgorithm> for JwsAlgorithm {
    fn from(algorithm: SigningAlgorithm) -> Self {
        match algorithm {
            SigningAlgorithm::Rs256 => Self::Rs256,
            SigningAlgorithm::Es256 => Self::Es256,
            SigningAlgorithm::EdDsa => Self::EdDsa,
        }
    }
}

/// An ECDSA point on P-384 or P-521, uncompressed (`0x04 || x || y`), as
/// aws-lc-rs checks a signature against it. A point off the curve checks
/// no signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EcPoint(Vec<u8>);

impl EcPoint {
    /// The point of coordinates `x` and `y`, each `size` bytes long, or
    /// `None` when either is of another length.
    pub(crate) fn of(x: &[u8], y: &[u8], size: usize) -> Option<Self> {
        if x.len() != size || y.len() != size {
            return None;
        }
        let mut point = Vec::with_capacity(size.saturating_mul(2).saturating_add(1));
        point.push(0x04);
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        Some(Self(point))
    }

    /// The `x` and `y` coordinates.
    pub(crate) fn coordinates(&self) -> (&[u8], &[u8]) {
        let coordinates = self.0.get(1..).unwrap_or_default();
        coordinates.split_at(coordinates.len() / 2)
    }
}

/// A public key, read for its algorithm. An RSA key holds at least
/// [`MIN_RSA_BITS`]: a shorter one is refused when it is read.
#[derive(Debug, Clone)]
pub(crate) enum PublicKey {
    Rsa(RsaVerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(EcPoint),
    P521(EcPoint),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// The SPKI key `pem` holds, read as a key of `algorithm`.
    pub(crate) fn from_pem(algorithm: SigningAlgorithm, pem: &str) -> Result<Self, KeyError> {
        let refused = || KeyError::NotOfAlgorithm(algorithm);
        match algorithm {
            SigningAlgorithm::Rs256 => {
                let der = public_key_in(pem)
                    .ok()
                    .and_then(|spki| spki.to_der().ok())
                    .ok_or_else(refused)?;
                RsaVerifyingKey::from_der(&der)
                    .map(Self::Rsa)
                    .map_err(|error| KeyError::of_rsa(error, algorithm))
            }
            SigningAlgorithm::Es256 => p256::ecdsa::VerifyingKey::from_public_key_pem(pem)
                .map(Self::P256)
                .map_err(|_| refused()),
            SigningAlgorithm::EdDsa => ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
                .map(Self::Ed25519)
                .map_err(|_| refused()),
        }
    }

    /// The algorithm this key signs with.
    pub(crate) fn algorithm(&self) -> JwsAlgorithm {
        match self {
            Self::Rsa(_) => JwsAlgorithm::Rs256,
            Self::P256(_) => JwsAlgorithm::Es256,
            Self::P384(_) => JwsAlgorithm::Es384,
            Self::P521(_) => JwsAlgorithm::Es512,
            Self::Ed25519(_) => JwsAlgorithm::EdDsa,
        }
    }

    /// Whether `signature` is this key's signature of `data`, in the form
    /// JWS writes it (ECDSA as `r || s`). Ed25519 is checked strictly, so a
    /// key of small order, which a signature of anyone's making passes,
    /// checks nothing.
    pub(crate) fn verifies(&self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Rsa(key) => key.verifies(RsaDigest::Sha256, data, signature),
            Self::P256(key) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
            Self::P384(point) => UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &point.0)
                .verify(data, signature)
                .is_ok(),
            Self::P521(point) => UnparsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, &point.0)
                .verify(data, signature)
                .is_ok(),
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify_strict(data, &signature).is_ok()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

    use super::*;
    use crate::crypto::certificates::rsa_keys::tests::SHORT_RSA_PUBLIC_KEY;

    /// A fresh key pair of `algorithm`, as PKCS#8 and SPKI PEM.
    pub(crate) fn pair(algorithm: SigningAlgorithm) -> (String, String) {
        let mut rng = rand::rngs::OsRng;
        match algorithm {
            SigningAlgorithm::Rs256 => {
                let (key, private) = RsaSigningKey::generated().unwrap();
                (
                    private.as_str().to_owned(),
                    key.public_key().spki_pem().unwrap(),
                )
            }
            SigningAlgorithm::Es256 => {
                let key = p256::ecdsa::SigningKey::random(&mut rng);
                (
                    key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
                    key.verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .unwrap(),
                )
            }
            SigningAlgorithm::EdDsa => {
                let key = ed25519_dalek::SigningKey::generate(&mut rng);
                (
                    key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
                    key.verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .unwrap(),
                )
            }
        }
    }

    /// Each algorithm's key signs, and its public half checks the
    /// signature; changed data does not check.
    #[test]
    fn each_algorithm_signs_and_checks() {
        for algorithm in [
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Es256,
            SigningAlgorithm::EdDsa,
        ] {
            let (private, public) = pair(algorithm);
            let signer = PrivateKey::from_pem(algorithm, &private).unwrap();
            let checker = PublicKey::from_pem(algorithm, &public).unwrap();

            let signature = signer.sign(b"header.payload").unwrap();

            assert!(
                checker.verifies(b"header.payload", &signature),
                "{algorithm:?}"
            );
            assert!(
                !checker.verifies(b"header.payloaz", &signature),
                "{algorithm:?}"
            );
        }
    }

    /// Private and public P-256 keys cannot be loaded under a different signing algorithm.
    #[test]
    fn a_key_is_read_only_for_its_own_algorithm() {
        let (private, public) = pair(SigningAlgorithm::Es256);

        assert!(PrivateKey::from_pem(SigningAlgorithm::EdDsa, &private).is_err());
        assert!(PublicKey::from_pem(SigningAlgorithm::Rs256, &public).is_err());
    }

    /// An Ed25519 identity-point key cannot verify the zero-filled signature.
    #[test]
    fn a_small_order_ed25519_key_checks_nothing() {
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        let key = PublicKey::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap());
        let mut forged = [0_u8; 64];
        forged[0] = 1;

        assert!(!key.verifies(b"header.payload", &forged));
    }

    /// Loading a 1024-bit RSA public key reports that the key is too short.
    #[test]
    fn a_short_rsa_key_is_refused() {
        let read = PublicKey::from_pem(SigningAlgorithm::Rs256, SHORT_RSA_PUBLIC_KEY);

        assert!(matches!(read, Err(KeyError::TooShort)));
    }
}
