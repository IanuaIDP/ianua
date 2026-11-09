//! The plain hashes protocols ask for: the PKCE challenge of a code
//! verifier (RFC 7636), the `at_hash` of an access token (OIDC Core
//! 3.1.3.6), and the SHA-256 a message's provenance is bound to.
//!
//! None is keyed: each is compared with a hash someone else made the same
//! way, so it is the protocol's hash or it matches nothing.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::broker::PayloadHasher;
use ianua_app::ports::oauth::{AtHashCalculator, PkceVerifier};
use ianua_domain::domains::agents::authority::provenance::PayloadHash;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::domains::oauth::grants::authorization_code::{
    CodeChallenge, CodeChallengeMethod,
};
use ianua_domain::domains::oauth::grants::id_token::AccessTokenHash;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use sha2::{Digest as _, Sha256, Sha512};

use crate::crypto::issued::made;

/// The PKCE challenge of a code verifier: base64url of its SHA-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256PkceVerifier;

#[async_trait]
impl PkceVerifier for Sha256PkceVerifier {
    async fn challenge_for(
        &self,
        verifier: &Secret,
        method: CodeChallengeMethod,
    ) -> Result<CodeChallenge, DomainError> {
        match method {
            CodeChallengeMethod::S256 => {
                let digest = Sha256::digest(verifier.expose().as_bytes());
                made(CodeChallenge::new(URL_SAFE_NO_PAD.encode(digest)))
            }
        }
    }
}

/// The `at_hash` of an access token: the left half of its hash under the
/// hash the ID token's algorithm signs with, in base64url. SHA-256 for
/// RS256 and ES256; SHA-512 for EdDSA, as Ed25519 hashes with it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha2AtHashCalculator;

#[async_trait]
impl AtHashCalculator for Sha2AtHashCalculator {
    async fn at_hash(
        &self,
        access_token: &Secret,
        algorithm: SigningAlgorithm,
    ) -> Result<AccessTokenHash, DomainError> {
        let token = access_token.expose().as_bytes();
        let digest = match algorithm {
            SigningAlgorithm::Rs256 | SigningAlgorithm::Es256 => Sha256::digest(token).to_vec(),
            SigningAlgorithm::EdDsa => Sha512::digest(token).to_vec(),
        };
        let left = digest.get(..digest.len() / 2).unwrap_or(&digest);
        made(AccessTokenHash::new(URL_SAFE_NO_PAD.encode(left)))
    }
}

/// The SHA-256 a message's provenance is bound to.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256PayloadHasher;

#[async_trait]
impl PayloadHasher for Sha256PayloadHasher {
    async fn hash(&self, payload: &[u8]) -> PayloadHash {
        PayloadHash::from_bytes(Sha256::digest(payload).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The challenge of RFC 7636's example verifier is the one the RFC
    /// gives.
    #[tokio::test]
    async fn the_rfc_example_verifier_gives_its_challenge() {
        let verifier = Secret::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        let challenge = Sha256PkceVerifier
            .challenge_for(&verifier, CodeChallengeMethod::S256)
            .await
            .unwrap();

        assert_eq!(
            challenge.as_str(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// An `at_hash` is half the token's hash: 16 bytes for an RS256 ID
    /// token and 32 for an EdDSA one, written in base64url.
    #[tokio::test]
    async fn an_at_hash_is_half_the_tokens_hash() {
        let token = Secret::new("an-access-token");

        let rsa = Sha2AtHashCalculator
            .at_hash(&token, SigningAlgorithm::Rs256)
            .await
            .unwrap();
        let eddsa = Sha2AtHashCalculator
            .at_hash(&token, SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        assert_eq!(rsa.as_str().len(), 22);
        assert_eq!(eddsa.as_str().len(), 43);
    }

    /// The same payload hashes alike, and another payload otherwise.
    #[tokio::test]
    async fn a_payload_hashes_to_its_own_digest() {
        let first = Sha256PayloadHasher.hash(b"order 42").await;

        assert_eq!(first, Sha256PayloadHasher.hash(b"order 42").await);
        assert_ne!(first, Sha256PayloadHasher.hash(b"order 43").await);
    }
}
