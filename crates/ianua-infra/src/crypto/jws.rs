//! JSON Web Signatures: the keys tokens are signed and checked with, the
//! compact form tokens travel in, and JSON Web Keys; with the adapters that
//! make a tenant's signing keys and publish them.

mod compact;
mod jwk;
mod keys;

use async_trait::async_trait;
use ianua_app::ports::crypto::{GeneratedKey, KeyGenerator, PublicKeyDecoder};
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{KeyId, PublicKeyPem};
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

pub(crate) use self::compact::{Compact, Header, JwsError, TokenHeader, signed, signed_under};
pub(crate) use self::jwk::{Jwk, components, read_jwk, thumbprint};
#[cfg(test)]
pub(crate) use self::keys::tests as keys_for_tests;
pub(crate) use self::keys::{JwsAlgorithm, PrivateKey, PublicKey};
use crate::crypto::certificates::rsa_keys::RsaSigningKey;
use crate::crypto::issued::made;

/// Why a key pair could not be made. None of it names the key.
#[derive(Debug, thiserror::Error)]
enum KeyGenerationError {
    /// The generator could not draw the key.
    #[error("the key pair could not be drawn")]
    CouldNotDraw,
    /// The key could not be written as PEM.
    #[error("the key pair could not be written as PEM")]
    CouldNotWrite,
}

/// The refusal of a key that could not be written as PEM, whichever
/// encoder refused it.
fn written<E>(_: E) -> KeyGenerationError {
    KeyGenerationError::CouldNotWrite
}

/// A fresh key pair of `algorithm`, as PKCS#8 and SPKI PEM.
fn fresh_pair(algorithm: SigningAlgorithm) -> Result<(String, String), KeyGenerationError> {
    let mut rng = rand::rngs::OsRng;
    match algorithm {
        SigningAlgorithm::Rs256 => {
            let (key, private) =
                RsaSigningKey::generated().map_err(|_| KeyGenerationError::CouldNotDraw)?;
            let public = key.public_key().spki_pem().map_err(written)?;
            Ok((private.as_str().to_owned(), public))
        }
        SigningAlgorithm::Es256 => {
            let key = p256::ecdsa::SigningKey::random(&mut rng);
            let private = key.to_pkcs8_pem(LineEnding::LF).map_err(written)?;
            let public = key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .map_err(written)?;
            Ok((private.to_string(), public))
        }
        SigningAlgorithm::EdDsa => {
            let key = ed25519_dalek::SigningKey::generate(&mut rng);
            let private = key.to_pkcs8_pem(LineEnding::LF).map_err(written)?;
            let public = key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .map_err(written)?;
            Ok((private.to_string(), public))
        }
    }
}

/// The maker of tenant signing keys, drawn in memory: RSA-2048, P-256 or
/// Ed25519. The private key comes back as its PEM, which the signing key
/// store seals before it is written.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs8KeyGenerator;

#[async_trait]
impl KeyGenerator for Pkcs8KeyGenerator {
    async fn generate(&self, algorithm: SigningAlgorithm) -> Result<GeneratedKey, DomainError> {
        let (private, public) = tokio::task::spawn_blocking(move || fresh_pair(algorithm))
            .await
            .map_err(DomainError::infra)?
            .map_err(DomainError::infra)?;
        Ok(GeneratedKey {
            public_key: made(PublicKeyPem::new(public))?,
            private_key: Secret::new(private),
        })
    }
}

/// The reader of a tenant's public keys into the fields its JWKS lists.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs8PublicKeyDecoder;

impl PublicKeyDecoder for Pkcs8PublicKeyDecoder {
    fn decode(
        &self,
        pem: &PublicKeyPem,
        kid: &KeyId,
        algorithm: SigningAlgorithm,
    ) -> Result<JwkComponents, DomainError> {
        let key = PublicKey::from_pem(algorithm, pem.as_str()).map_err(DomainError::infra)?;
        Ok(components(&key, kid.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key made for each algorithm signs, and its public half, read the
    /// way the JWKS reads it, checks the signature.
    #[tokio::test]
    async fn a_generated_key_signs_and_its_public_half_checks() {
        for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::EdDsa] {
            let pair = Pkcs8KeyGenerator.generate(algorithm).await.unwrap();
            let signer = PrivateKey::from_pem(algorithm, pair.private_key.expose()).unwrap();
            let checker = PublicKey::from_pem(algorithm, pair.public_key.as_str()).unwrap();

            let signature = signer.sign(b"data").unwrap();

            assert!(checker.verifies(b"data", &signature), "{algorithm:?}");
        }
    }

    /// A tenant's EC key is listed in its JWKS as a P-256 key under its
    /// `kid`.
    #[tokio::test]
    async fn a_public_key_is_listed_under_its_kid() {
        let pair = Pkcs8KeyGenerator
            .generate(SigningAlgorithm::Es256)
            .await
            .unwrap();

        let listed = Pkcs8PublicKeyDecoder
            .decode(
                &pair.public_key,
                &KeyId::new("k1").unwrap(),
                SigningAlgorithm::Es256,
            )
            .unwrap();

        assert!(
            matches!(listed, JwkComponents::Ec { ref kid, ref crv, .. } if kid == "k1" && crv == "P-256")
        );
    }

    /// An Ed25519 key stored with an RSA algorithm produces an infrastructure error.
    #[tokio::test]
    async fn a_key_listed_under_another_algorithm_is_refused() {
        let pair = Pkcs8KeyGenerator
            .generate(SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let listed = Pkcs8PublicKeyDecoder.decode(
            &pair.public_key,
            &KeyId::new("k1").unwrap(),
            SigningAlgorithm::Rs256,
        );

        assert!(matches!(listed, Err(DomainError::Infrastructure(_))));
    }
}
