//! OAuth client ids and secrets.
//!
//! A client id reads `client_<id>`: public, but random, so one client's id
//! says nothing of another's. A secret reads `cs_<secret>` and is kept only
//! as its digest; the verifier digests under the same key.

use async_trait::async_trait;
use ianua_app::ports::oauth::{
    ClientSecretGenerator, ClientSecretVerifier, GeneratedClientCredentials, GeneratedSecret,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, TokenHash};

use crate::crypto::issued::{Issuer, made};
use crate::crypto::keys::{Purpose, RootSecret};
use crate::crypto::random::{base32, random_bytes};

/// The bytes of randomness in a client id.
const ID_BYTES: usize = 10;

/// The secrets of OAuth clients, written after their prefix.
fn secrets(root: &RootSecret) -> Issuer {
    Issuer::new(root, Purpose::ClientSecrets, "cs_")
}

/// The maker of client ids and secrets, each secret kept as its
/// HMAC-SHA256 digest.
#[derive(Debug, Clone)]
pub struct HmacClientSecretGenerator {
    secrets: Issuer,
}

impl HmacClientSecretGenerator {
    /// A maker digesting secrets under the key `root` derives for them.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            secrets: secrets(root),
        }
    }
}

#[async_trait]
impl ClientSecretGenerator for HmacClientSecretGenerator {
    async fn generate(&self) -> Result<GeneratedClientCredentials, DomainError> {
        let client_id_value = self.generate_client_id().await?;
        let (raw_secret, secret_hash) = self.secrets.issue()?;
        Ok(GeneratedClientCredentials {
            client_id_value,
            raw_secret,
            secret_hash,
        })
    }

    async fn generate_client_id(&self) -> Result<ClientId, DomainError> {
        let id = base32(&random_bytes::<ID_BYTES>()?);
        made(ClientId::new(format!("client_{id}")))
    }

    async fn generate_secret(&self) -> Result<GeneratedSecret, DomainError> {
        let (raw_secret, secret_hash) = self.secrets.issue()?;
        Ok(GeneratedSecret {
            raw_secret,
            secret_hash,
        })
    }
}

/// The check of a presented client secret against its stored digest.
#[derive(Debug, Clone)]
pub struct HmacClientSecretVerifier {
    secrets: Issuer,
}

impl HmacClientSecretVerifier {
    /// A check digesting under the key `root` derives for client secrets.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            secrets: secrets(root),
        }
    }
}

#[async_trait]
impl ClientSecretVerifier for HmacClientSecretVerifier {
    async fn verify(&self, presented: &Secret, hash: &TokenHash) -> Result<bool, DomainError> {
        Ok(self.secrets.matches(presented, hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    /// A client's secret checks against the digest it was given with, and
    /// a guessed one does not.
    #[tokio::test]
    async fn a_client_secret_checks_against_its_digest() {
        let root = test_root();
        let made = HmacClientSecretGenerator::new(&root)
            .generate()
            .await
            .unwrap();
        let verifier = HmacClientSecretVerifier::new(&root);

        let right = verifier
            .verify(&made.raw_secret, &made.secret_hash)
            .await
            .unwrap();
        let guessed = verifier
            .verify(&Secret::new("cs_guess"), &made.secret_hash)
            .await
            .unwrap();

        assert!(right);
        assert!(!guessed);
        assert!(made.client_id_value.as_str().starts_with("client_"));
        assert!(made.raw_secret.expose().starts_with("cs_"));
    }

    /// A rotated secret is new, and the old one no longer checks against
    /// the new digest.
    #[tokio::test]
    async fn a_rotated_secret_replaces_the_old() {
        let root = test_root();
        let generator = HmacClientSecretGenerator::new(&root);
        let old = generator.generate_secret().await.unwrap();

        let new = generator.generate_secret().await.unwrap();

        let verifier = HmacClientSecretVerifier::new(&root);
        assert!(
            !verifier
                .verify(&old.raw_secret, &new.secret_hash)
                .await
                .unwrap()
        );
    }
}
