//! The secrets handed out to be sealed rather than digested, since what
//! uses them needs the secret itself: the keys pushes, webhook deliveries
//! and notification posts are signed with, the external id that guards a
//! cloud role, and the nonces an agent attests to.

use async_trait::async_trait;
use ianua_app::ports::agents::AttestationNonceGenerator;
use ianua_app::ports::cloud::ExternalIdGenerator;
use ianua_app::ports::messaging::PushSecretGenerator;
use ianua_app::ports::notifications::DestinationSecretGenerator;
use ianua_app::ports::webhooks::WebhookSecretGenerator;
use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
use ianua_domain::domains::organization::cloud::credential::ExternalId;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::crypto::issued::{fresh_secret, fresh_signing_secret, made};

/// The maker of the secrets push subscriptions sign with, `psec_…`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsPushSecretGenerator;

#[async_trait]
impl PushSecretGenerator for OsPushSecretGenerator {
    async fn generate(&self) -> Result<Secret, DomainError> {
        fresh_signing_secret("psec_")
    }
}

/// The maker of the secrets webhook deliveries are signed with, `whsec_…`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsWebhookSecretGenerator;

#[async_trait]
impl WebhookSecretGenerator for OsWebhookSecretGenerator {
    async fn generate(&self) -> Result<Secret, DomainError> {
        fresh_signing_secret("whsec_")
    }
}

/// The maker of the secrets a notification destination's posts are signed
/// with, `dsec_…`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsDestinationSecretGenerator;

#[async_trait]
impl DestinationSecretGenerator for OsDestinationSecretGenerator {
    async fn generate(&self) -> Result<Secret, DomainError> {
        fresh_signing_secret("dsec_")
    }
}

/// The maker of the external ids that guard an `AssumeRole`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsExternalIdGenerator;

impl ExternalIdGenerator for OsExternalIdGenerator {
    fn generate(&self) -> Result<ExternalId, DomainError> {
        made(ExternalId::new(fresh_secret("ianua-")?.expose()))
    }
}

/// The maker of the nonces an agent's attestation must carry.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsAttestationNonceGenerator;

#[async_trait]
impl AttestationNonceGenerator for OsAttestationNonceGenerator {
    async fn generate(&self) -> Result<AttestationNonce, DomainError> {
        made(AttestationNonce::new(fresh_secret("")?.expose()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each signing secret carries its prefix and is fresh every time, and
    /// what follows the prefix is the 32-byte key in standard base64, the
    /// form a Standard Webhooks library decodes.
    #[tokio::test]
    async fn each_signing_secret_is_fresh_and_named() {
        let first = OsWebhookSecretGenerator.generate().await.unwrap();
        let second = OsWebhookSecretGenerator.generate().await.unwrap();
        let push = OsPushSecretGenerator.generate().await.unwrap();
        let post = OsDestinationSecretGenerator.generate().await.unwrap();

        assert!(first.expose().starts_with("whsec_"));
        assert!(push.expose().starts_with("psec_"));
        assert!(post.expose().starts_with("dsec_"));
        assert_ne!(first.expose(), second.expose());
        for secret in [&first, &push, &post] {
            let (_, key) = secret.expose().split_once('_').unwrap();
            assert_eq!(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
                    .unwrap()
                    .len(),
                32
            );
        }
    }

    /// An external id and a nonce pass the domain's own rules.
    #[tokio::test]
    async fn an_external_id_and_a_nonce_pass_their_rules() {
        let external = OsExternalIdGenerator.generate().unwrap();
        let nonce = OsAttestationNonceGenerator.generate().await.unwrap();

        assert!(external.as_str().starts_with("ianua-"));
        assert_eq!(nonce.as_str().len(), 52);
    }
}
