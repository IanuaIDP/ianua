//! The public keys an attestation carries or the deployment trusts, and the
//! signatures they check.
//!
//! The scheme a signature is checked with comes from the key, never from
//! the presentation: a P-256 key checks ECDSA with SHA-256 in DER, an RSA
//! key PKCS#1 v1.5 with SHA-256, an Ed25519 key its own 64-byte signatures.
//! A key of any other kind, or an RSA key under 2048 bits, is not read at
//! all, so it checks nothing.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::Encode as _;
use der::asn1::ObjectIdentifier;
use ianua_app::ports::agents::AttestationProof;
use ianua_domain::shared::errors::DomainError;
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::DecodePublicKey as _;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::crypto::certificates::rsa_keys::{RsaDigest, RsaVerifyingKey};
use crate::proofs::attestation::binding::AttestationBinding;
use crate::proofs::attestation::refused;

/// The OID of an elliptic-curve public key.
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The OID of an RSA public key.
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The OID of an Ed25519 key, and of the signatures it makes.
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The OID of an ECDSA signature with SHA-256.
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// The OID of an RSA PKCS#1 v1.5 signature with SHA-256.
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// A public key, read for the one scheme it signs with.
pub(crate) enum PresentedKey {
    /// RSA of at least 2048 bits, PKCS#1 v1.5 with SHA-256.
    Rsa(RsaVerifyingKey),
    /// ECDSA on P-256 with SHA-256.
    P256(p256::ecdsa::VerifyingKey),
    /// Checks the identity's 64-byte signatures over attestation bindings.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PresentedKey {
    /// The key `spki` describes, or `None` for a kind this module does not
    /// check with.
    pub(crate) fn of(spki: &SubjectPublicKeyInfoOwned) -> Option<Self> {
        let der = spki.to_der().ok()?;
        let algorithm = spki.algorithm.oid;
        if algorithm == EC_PUBLIC_KEY {
            return p256::ecdsa::VerifyingKey::from_public_key_der(&der)
                .ok()
                .map(Self::P256);
        }
        if algorithm == RSA_ENCRYPTION {
            return RsaVerifyingKey::from_der(&der).ok().map(Self::Rsa);
        }
        if algorithm == ED25519 {
            return ed25519_dalek::VerifyingKey::from_public_key_der(&der)
                .ok()
                .map(Self::Ed25519);
        }
        None
    }

    /// The OID a certificate names for the signatures this key makes.
    pub(crate) fn signature_algorithm(&self) -> ObjectIdentifier {
        match self {
            Self::Rsa(_) => SHA256_WITH_RSA,
            Self::P256(_) => ECDSA_WITH_SHA256,
            Self::Ed25519(_) => ED25519,
        }
    }

    /// Whether `signature` is this key's signature of `data`.
    pub(crate) fn verifies(&self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Rsa(key) => key.verifies(RsaDigest::Sha256, data, signature),
            Self::P256(key) => p256::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
            Self::Ed25519(key) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
        }
    }
}

/// Refused unless `proof` is `key`'s signature of `binding`'s signed bytes,
/// the one thing only the holder of the presented identity's private key
/// can make, and only for this nonce and the key being enrolled.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` when the signature is not base64url
/// or does not check against `key`.
pub(crate) fn ensure_binding_signed(
    key: &PresentedKey,
    proof: &AttestationProof,
    binding: &AttestationBinding,
) -> Result<(), DomainError> {
    let signature = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(|_| refused("the proof is not base64url"))?;
    if key.verifies(&binding.signed_bytes(), &signature) {
        return Ok(());
    }
    Err(refused(
        "the proof does not check against the presented identity's key",
    ))
}

#[cfg(test)]
mod tests {
    use der::Decode as _;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use ianua_domain::types::PublicKeyPem;
    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};

    use super::*;
    use crate::crypto::certificates::rsa_keys::RsaSigningKey;
    use crate::crypto::certificates::rsa_keys::tests::{SHORT_RSA_PUBLIC_KEY, der_of};

    fn spki_of(der: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_der(der).unwrap()
    }

    /// A P-256 key checks its own DER signature and nothing else.
    #[test]
    fn a_p256_key_checks_its_der_signature() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let der = signer.verifying_key().to_public_key_der().unwrap();
        let key = PresentedKey::of(&spki_of(der.as_bytes())).unwrap();
        let signature: p256::ecdsa::Signature = signer.sign(b"nonce");

        assert!(key.verifies(b"nonce", signature.to_der().as_bytes()));
        assert!(!key.verifies(b"other", signature.to_der().as_bytes()));
    }

    /// A 2048-bit RSA key checks its own PKCS#1 v1.5 signature over SHA-256
    /// and nothing else.
    #[test]
    fn an_rsa_key_checks_its_pkcs1_signature() {
        let (signer, _) = RsaSigningKey::generated().unwrap();
        let der = signer.public_key().spki_der().unwrap();
        let key = PresentedKey::of(&spki_of(&der)).unwrap();
        let signature = signer.sign_sha256(b"nonce").unwrap();

        assert!(key.verifies(b"nonce", &signature));
        assert!(!key.verifies(b"other", &signature));
    }

    /// A 1024-bit RSA public key is too short to become an attestation identity key.
    #[test]
    fn a_short_rsa_key_is_not_read() {
        let der = der_of(SHORT_RSA_PUBLIC_KEY);

        assert!(PresentedKey::of(&spki_of(&der)).is_none());
    }

    /// A fresh Ed25519 public key as PEM, standing for the key enrolled.
    fn enrolled() -> PublicKeyPem {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        PublicKeyPem::new(
            signer
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap()
    }

    /// Associates a supplied signature with the bootstrap nonce it is presented for.
    fn proof(nonce: &AttestationNonce, signature: String) -> AttestationProof {
        AttestationProof {
            nonce: nonce.clone(),
            signature,
        }
    }

    /// The correct binding verifies; malformed proofs, foreign signatures and signatures
    /// over a bare nonce or another key's binding all fail.
    #[test]
    fn a_proof_by_another_key_or_for_another_binding_is_refused() {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let other = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let der = signer.verifying_key().to_public_key_der().unwrap();
        let key = PresentedKey::of(&spki_of(der.as_bytes())).unwrap();
        let nonce = AttestationNonce::new("n".repeat(40)).unwrap();
        let binding = AttestationBinding::of(&nonce, &enrolled()).unwrap();
        let elsewhere = AttestationBinding::of(&nonce, &enrolled()).unwrap();
        let signed = |by: &ed25519_dalek::SigningKey, bytes: &[u8]| {
            proof(&nonce, URL_SAFE_NO_PAD.encode(by.sign(bytes).to_bytes()))
        };

        assert!(
            ensure_binding_signed(&key, &proof(&nonce, "not base64!".to_owned()), &binding)
                .is_err()
        );
        assert!(
            ensure_binding_signed(&key, &signed(&other, &binding.signed_bytes()), &binding)
                .is_err()
        );
        assert!(
            ensure_binding_signed(&key, &signed(&signer, nonce.as_str().as_bytes()), &binding)
                .is_err()
        );
        assert!(
            ensure_binding_signed(&key, &signed(&signer, &elsewhere.signed_bytes()), &binding)
                .is_err()
        );
        assert!(
            ensure_binding_signed(&key, &signed(&signer, &binding.signed_bytes()), &binding)
                .is_ok()
        );
    }
}
