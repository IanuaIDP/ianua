//! The secrets the platform hands out once and keeps only as digests,
//! and those it hands out to be sealed: API keys, client secrets, codes,
//! bearer tokens and signing secrets.
//!
//! Every secret is 256 bits from the operating system's generator,
//! written in lowercase base32 after a short prefix that says what it is,
//! so a leaked one is recognised by a scanner and never split by the `_`
//! inside it. A secret kept as a digest is digested under the key of its
//! own use, so a digest of one kind matches nothing of another. A bearer
//! presented back is digested the same way to find the caller it names.

mod api_keys;
mod bearers;
mod callers;
mod clients;
mod codes;
mod consumer_keys;
mod signing_secrets;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::TokenHash;

pub use self::api_keys::HmacApiKeyGenerator;
pub use self::bearers::{
    HmacConnectionSecrets, HmacConnectorCodeGenerator, HmacReceiverKeys, HmacRefreshTokenGenerator,
    HmacScimTokenGenerator, HmacServiceAccountSecrets, HmacWorkflowTriggerSecretGenerator,
};
pub use self::callers::HmacTokenResolver;
pub use self::clients::{HmacClientSecretGenerator, HmacClientSecretVerifier};
pub use self::codes::{HmacCodeHasher, HmacRecoveryCodeGenerator, HmacSentCodeGenerator};
pub use self::consumer_keys::{HmacConsumerKeyDigests, HmacConsumerKeyGenerator};
pub use self::signing_secrets::{
    OsAttestationNonceGenerator, OsDestinationSecretGenerator, OsExternalIdGenerator,
    OsPushSecretGenerator, OsWebhookSecretGenerator,
};
use crate::crypto::keys::{Purpose, RootSecret};
use crate::crypto::random::{base32, random_bytes};
use crate::crypto::seals::digests::KeyedDigest;

/// The bytes of randomness in every secret handed out.
const SECRET_BYTES: usize = 32;

/// A fresh secret: [`SECRET_BYTES`] of randomness in base32 after
/// `prefix`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the generator cannot be read.
pub(crate) fn fresh_secret(prefix: &str) -> Result<Secret, DomainError> {
    let bytes = random_bytes::<SECRET_BYTES>()?;
    Ok(Secret::new(format!("{prefix}{}", base32(&bytes))))
}

/// A fresh signing secret: [`SECRET_BYTES`] of randomness in standard
/// base64 after `prefix`, the form a Standard Webhooks library decodes
/// into the key it checks signatures with.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the generator cannot be read.
pub(crate) fn fresh_signing_secret(prefix: &str) -> Result<Secret, DomainError> {
    let bytes = random_bytes::<SECRET_BYTES>()?;
    Ok(Secret::new(format!("{prefix}{}", STANDARD.encode(bytes))))
}

/// A value the platform made itself, checked by its type's rules. One
/// that breaks them is the platform's fault, never the caller's, so it is
/// an infrastructure error.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the value breaks its rules.
pub(crate) fn made<T>(checked: Result<T, ValidationError>) -> Result<T, DomainError> {
    checked.map_err(DomainError::infra)
}

/// The secrets of one use: fresh ones after its prefix, kept as digests
/// under its key.
#[derive(Debug, Clone)]
pub(crate) struct Issuer {
    prefix: &'static str,
    digest: KeyedDigest,
}

impl Issuer {
    /// The secrets of `purpose`, written after `prefix`, digested under the
    /// key `root` derives for that use.
    pub(crate) fn new(root: &RootSecret, purpose: Purpose, prefix: &'static str) -> Self {
        Self {
            prefix,
            digest: KeyedDigest::of(root, purpose),
        }
    }

    /// A fresh secret and the digest it is kept as.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the generator cannot be
    /// read.
    pub(crate) fn issue(&self) -> Result<(Secret, TokenHash), DomainError> {
        let secret = fresh_secret(self.prefix)?;
        let digest = self.digest.digest(&secret);
        Ok((secret, digest))
    }

    /// The digest a presented secret is found by.
    pub(crate) fn digest_of(&self, presented: &Secret) -> TokenHash {
        self.digest.digest(presented)
    }

    /// Whether `presented` is the secret `stored` is the digest of.
    pub(crate) fn matches(&self, presented: &Secret, stored: &TokenHash) -> bool {
        self.digest.matches(presented, stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    /// A secret issued carries its prefix and 256 bits in base32, is found
    /// by its own digest, and two are never the same.
    #[test]
    fn an_issued_secret_is_found_by_its_digest() {
        let issuer = Issuer::new(&test_root(), Purpose::ScimTokens, "scim_");

        let (secret, digest) = issuer.issue().unwrap();
        let (other, _) = issuer.issue().unwrap();

        assert!(secret.expose().starts_with("scim_"));
        assert_eq!(secret.expose().len(), "scim_".len() + 52);
        assert_eq!(issuer.digest_of(&secret), digest);
        assert!(issuer.matches(&secret, &digest));
        assert!(!issuer.matches(&other, &digest));
    }
}
