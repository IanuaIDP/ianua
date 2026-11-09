//! The binding of an attestation to its nonce and to the key it enrols.
//!
//! A token or a quote proves where it was made, not who presents it. Whoever
//! sees one before it is used could present it with a key of their own and
//! be enrolled in the workload's place. So the value a proof must carry is
//! not the nonce alone but the binding:
//!
//! ```text
//! SHA-256("ianua-attestation-binding-v1" || 0x00 || nonce || 0x00 || key DER)
//! ```
//!
//! where the key is the DER of the enrolled public key's
//! `SubjectPublicKeyInfo`, read back and written again so one key has one
//! form. A proof made for one key carries another binding than any other
//! key's, and is refused for it.

use der::Encode as _;
use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PublicKeyPem;
use sha2::{Digest as _, Sha256};

use crate::crypto::certificates::pem::public_key_in;
use crate::proofs::attestation::refused;

/// The words the binding's hash starts with, so it is never the hash of
/// anything else.
const BINDING_CONTEXT: &[u8] = b"ianua-attestation-binding-v1";

/// The byte between the parts the binding's hash covers. Neither the
/// context nor a nonce holds it, so no two parts can run into each other.
const SEPARATOR: [u8; 1] = [0];

/// The words a SPIFFE workload signs ahead of the binding, so its key never
/// signs bytes another protocol could take for its own.
const PROOF_CONTEXT: &str = "ianua-attestation-proof-v1:";

/// The binding of one bootstrap's nonce and the key it enrols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttestationBinding {
    digest: [u8; 32],
    hex: String,
}

impl AttestationBinding {
    /// The binding of `nonce` and the public key `key` holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Unauthorized` when `key` holds no public key
    /// that reads.
    pub(crate) fn of(nonce: &AttestationNonce, key: &PublicKeyPem) -> Result<Self, DomainError> {
        let unreadable = || refused("the enrolled key cannot be read");
        let der = public_key_in(key.as_str())
            .map_err(|_| unreadable())?
            .to_der()
            .map_err(|_| unreadable())?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(BINDING_CONTEXT)
            .chain_update(SEPARATOR)
            .chain_update(nonce.as_str().as_bytes())
            .chain_update(SEPARATOR)
            .chain_update(&der)
            .finalize()
            .into();
        Ok(Self {
            hex: data_encoding::HEXLOWER.encode(&digest),
            digest,
        })
    }

    /// The binding's 32 bytes, as a TPM quote carries them for its
    /// qualifying data.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.digest
    }

    /// The binding as 64 lower-case hex characters, as a token's audience
    /// or a signed header carries it.
    #[must_use]
    pub(crate) fn as_hex(&self) -> &str {
        &self.hex
    }

    /// The bytes a SPIFFE workload signs with its SVID's key: the proof's
    /// context words, then the binding in hex.
    #[must_use]
    pub(crate) fn signed_bytes(&self) -> Vec<u8> {
        format!("{PROOF_CONTEXT}{}", self.hex).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};

    use super::*;

    fn nonce(text: &str) -> AttestationNonce {
        AttestationNonce::new(text.repeat(40)).unwrap()
    }

    /// A fresh Ed25519 public key as PEM.
    fn key() -> PublicKeyPem {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        PublicKeyPem::new(
            signer
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap()
    }

    /// The same nonce and key always bind to the same value, in 64 hex
    /// characters and 32 bytes.
    #[test]
    fn a_nonce_and_key_bind_to_one_value() {
        let key = key();

        let first = AttestationBinding::of(&nonce("n"), &key).unwrap();
        let again = AttestationBinding::of(&nonce("n"), &key).unwrap();

        assert_eq!(first, again);
        assert_eq!(first.as_hex().len(), 64);
        assert_eq!(first.as_bytes().len(), 32);
    }

    /// Changing either the public key or nonce changes the attestation binding.
    #[test]
    fn another_key_or_nonce_binds_to_another_value() {
        let ours = key();
        let theirs = key();

        let bound = AttestationBinding::of(&nonce("n"), &ours).unwrap();

        assert_ne!(bound, AttestationBinding::of(&nonce("n"), &theirs).unwrap());
        assert_ne!(bound, AttestationBinding::of(&nonce("m"), &ours).unwrap());
    }

    /// Signed proof bytes include the proof context before the hexadecimal binding.
    #[test]
    fn the_signed_bytes_start_with_the_proof_context() {
        let bound = AttestationBinding::of(&nonce("n"), &key()).unwrap();

        let signed = bound.signed_bytes();

        assert!(signed.starts_with(PROOF_CONTEXT.as_bytes()));
        assert!(signed.ends_with(bound.as_hex().as_bytes()));
    }

    /// Unreadable public-key PEM prevents binding construction with an unauthorized error.
    #[test]
    fn an_unreadable_key_is_refused() {
        let garbled =
            PublicKeyPem::new("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n")
                .unwrap();

        let bound = AttestationBinding::of(&nonce("n"), &garbled);

        assert!(matches!(bound, Err(DomainError::Unauthorized(_))));
    }
}
