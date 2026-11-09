//! The bearer secrets handed out once and kept only as digests: SCIM
//! tokens, workflow trigger secrets, account connection states and codes,
//! connector enrollment codes, LDAP service account secrets, signal
//! receiver keys and refresh tokens.
//!
//! Each kind has its prefix and its own digest key, so a digest of one
//! kind never matches a secret of another.

use async_trait::async_trait;
use ianua_app::ports::directory::ServiceAccountSecrets;
use ianua_app::ports::federation::ScimTokenGenerator;
use ianua_app::ports::routing::ConnectorCodeGenerator;
use ianua_app::ports::signals::ReceiverKeys;
use ianua_app::ports::workflows::{ConnectionSecrets, WorkflowTriggerSecretGenerator};
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::TokenHash;

use crate::crypto::issued::Issuer;
use crate::crypto::keys::{Purpose, RootSecret};

/// The maker of SCIM bearer tokens, `scim_…`, each kept as its digest.
#[derive(Debug, Clone)]
pub struct HmacScimTokenGenerator {
    tokens: Issuer,
}

impl HmacScimTokenGenerator {
    /// A maker digesting under the key `root` derives for SCIM tokens.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            tokens: Issuer::new(root, Purpose::ScimTokens, "scim_"),
        }
    }
}

#[async_trait]
impl ScimTokenGenerator for HmacScimTokenGenerator {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.tokens.issue()
    }

    fn verify(&self, presented: &Secret, hash: &TokenHash) -> bool {
        self.tokens.matches(presented, hash)
    }
}

/// The maker of the secrets a workflow's webhook is called with, `wft_…`.
#[derive(Debug, Clone)]
pub struct HmacWorkflowTriggerSecretGenerator {
    secrets: Issuer,
}

impl HmacWorkflowTriggerSecretGenerator {
    /// A maker digesting under the key `root` derives for trigger secrets.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            secrets: Issuer::new(root, Purpose::WorkflowTriggers, "wft_"),
        }
    }
}

#[async_trait]
impl WorkflowTriggerSecretGenerator for HmacWorkflowTriggerSecretGenerator {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.secrets.issue()
    }

    fn hash_presented(&self, presented: &Secret) -> TokenHash {
        self.secrets.digest_of(presented)
    }
}

/// The maker of the one-time codes a connector enrolls with, `cnc_…`.
#[derive(Debug, Clone)]
pub struct HmacConnectorCodeGenerator {
    codes: Issuer,
}

impl HmacConnectorCodeGenerator {
    /// A maker digesting under the key `root` derives for connector codes.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            codes: Issuer::new(root, Purpose::ConnectorCodes, "cnc_"),
        }
    }
}

#[async_trait]
impl ConnectorCodeGenerator for HmacConnectorCodeGenerator {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.codes.issue()
    }

    fn hash_presented(&self, presented: &Secret) -> TokenHash {
        self.codes.digest_of(presented)
    }
}

/// The maker of the secrets LDAP service accounts bind with, `svc_…`.
#[derive(Debug, Clone)]
pub struct HmacServiceAccountSecrets {
    secrets: Issuer,
}

impl HmacServiceAccountSecrets {
    /// A maker digesting under the key `root` derives for service accounts.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            secrets: Issuer::new(root, Purpose::ServiceAccounts, "svc_"),
        }
    }
}

#[async_trait]
impl ServiceAccountSecrets for HmacServiceAccountSecrets {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.secrets.issue()
    }

    fn hash(&self, presented: &Secret) -> TokenHash {
        self.secrets.digest_of(presented)
    }
}

/// The maker of the keys signal receivers manage their streams with,
/// `rk_…`.
#[derive(Debug, Clone)]
pub struct HmacReceiverKeys {
    keys: Issuer,
}

impl HmacReceiverKeys {
    /// A maker digesting under the key `root` derives for receiver keys.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            keys: Issuer::new(root, Purpose::ReceiverKeys, "rk_"),
        }
    }
}

#[async_trait]
impl ReceiverKeys for HmacReceiverKeys {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.keys.issue()
    }

    fn hash_presented(&self, presented: &Secret) -> TokenHash {
        self.keys.digest_of(presented)
    }
}

/// The maker of the random values an account connection's sign-in at a
/// service is tied together with, `cxn_…`: the `state` and the one-time
/// code, kept as digests, and the PKCE verifier, which the URL-safe
/// alphabet and length of every value here suit.
#[derive(Debug, Clone)]
pub struct HmacConnectionSecrets {
    values: Issuer,
}

impl HmacConnectionSecrets {
    /// A maker digesting under the key `root` derives for connections.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            values: Issuer::new(root, Purpose::AccountConnections, "cxn_"),
        }
    }
}

impl ConnectionSecrets for HmacConnectionSecrets {
    fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        self.values.issue()
    }

    fn digest(&self, presented: &Secret) -> TokenHash {
        self.values.digest_of(presented)
    }
}

/// The maker of opaque refresh tokens, `rt_…`, each kept as its digest.
#[derive(Debug, Clone)]
pub struct HmacRefreshTokenGenerator {
    tokens: Issuer,
}

impl HmacRefreshTokenGenerator {
    /// A maker digesting under the key `root` derives for refresh tokens.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            tokens: Issuer::new(root, Purpose::RefreshTokens, "rt_"),
        }
    }
}

impl RefreshTokenGenerator for HmacRefreshTokenGenerator {
    fn generate(&self) -> Result<RefreshToken, DomainError> {
        let (raw, hash) = self.tokens.issue()?;
        Ok(RefreshToken::new(raw, hash))
    }

    fn hash_raw(&self, raw: &str) -> TokenHash {
        self.tokens.digest_of(&Secret::new(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    /// A SCIM token checks against its digest, and a token of another kind
    /// does not, even with the same text.
    #[tokio::test]
    async fn a_scim_token_checks_against_its_own_digest() {
        let root = test_root();
        let scim = HmacScimTokenGenerator::new(&root);
        let (token, digest) = scim.generate().await.unwrap();

        let as_trigger = HmacWorkflowTriggerSecretGenerator::new(&root).hash_presented(&token);

        assert!(scim.verify(&token, &digest));
        assert!(token.expose().starts_with("scim_"));
        assert_ne!(as_trigger, digest);
    }

    /// A refresh token's digest is the one its raw text gives again, so its
    /// session is found on refresh.
    #[test]
    fn a_refresh_token_is_found_by_its_raw_text() {
        let tokens = HmacRefreshTokenGenerator::new(&test_root());

        let token = tokens.generate().unwrap();

        assert_eq!(&tokens.hash_raw(token.raw().expose()), token.hash());
        assert!(token.raw().expose().starts_with("rt_"));
    }

    /// Each kind hands out its own prefix, and a presented secret is found
    /// by the digest it was made with.
    #[tokio::test]
    async fn each_kind_is_found_by_its_digest() {
        let root = test_root();
        let (code, code_hash) = HmacConnectorCodeGenerator::new(&root)
            .generate()
            .await
            .unwrap();
        let (secret, secret_hash) = HmacServiceAccountSecrets::new(&root)
            .generate()
            .await
            .unwrap();
        let (key, key_hash) = HmacReceiverKeys::new(&root).generate().await.unwrap();

        assert!(code.expose().starts_with("cnc_"));
        assert!(secret.expose().starts_with("svc_"));
        assert!(key.expose().starts_with("rk_"));
        assert_eq!(
            HmacConnectorCodeGenerator::new(&root).hash_presented(&code),
            code_hash
        );
        assert_eq!(
            HmacServiceAccountSecrets::new(&root).hash(&secret),
            secret_hash
        );
        assert_eq!(HmacReceiverKeys::new(&root).hash_presented(&key), key_hash);
    }
}
