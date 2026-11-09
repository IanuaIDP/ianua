//! The credential a consumer is given when it is created or its credential
//! rotated: an API key the platform makes and shows once, or a certificate
//! or token issuer the caller names.
//!
//! A caller never names an API key. The platform makes it, keeps only its
//! digest under the key consumer keys are digested with, and answers the
//! raw key this once, so a key's digest is always one the gateway's reader
//! of presented keys can match.

use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateFingerprint, FederatedSubject, HttpsUrl, Issuer};

use crate::error::{AppError, OrInternal};
use crate::ports::consumers::ConsumerKeyGenerator;

/// The credential a consumer is to sign in with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewCredential {
    /// An API key the platform makes, shown once.
    ApiKey,
    /// An X.509 client certificate, by its fingerprint.
    ClientCert {
        /// The SHA-256 fingerprint of the certificate.
        fingerprint: CertificateFingerprint,
    },
    /// Tokens the consumer signs itself, as `issuer` and `subject`, with
    /// the keys it publishes at `jwks_uri`.
    JwtBearer {
        /// The `iss` its tokens carry.
        issuer: Issuer,
        /// The `sub` its tokens carry.
        subject: FederatedSubject,
        /// Where it publishes the keys its tokens are signed with.
        jwks_uri: HttpsUrl,
    },
}

/// A credential ready to be kept, with the raw key when one was made.
pub(crate) struct IssuedCredential {
    /// What is kept: for an API key, its prefix and digest only.
    pub(crate) kind: ConsumerCredentialKind,
    /// The raw API key, shown once and never kept; `None` for a
    /// certificate or a token issuer.
    pub(crate) api_key: Option<Secret>,
}

impl NewCredential {
    /// The credential to keep, an API key made through `keys`.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when no key can be made.
    pub(crate) async fn issued(
        self,
        keys: &dyn ConsumerKeyGenerator,
    ) -> Result<IssuedCredential, AppError> {
        let kind = match self {
            Self::ApiKey => return made_key(keys).await,
            Self::ClientCert { fingerprint } => ConsumerCredentialKind::ClientCert { fingerprint },
            Self::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => ConsumerCredentialKind::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            },
        };
        Ok(IssuedCredential {
            kind,
            api_key: None,
        })
    }
}

/// A fresh API key from `keys`, kept by its prefix and digest.
async fn made_key(keys: &dyn ConsumerKeyGenerator) -> Result<IssuedCredential, AppError> {
    let generated = keys.generate().await.or_internal()?;
    Ok(IssuedCredential {
        kind: ConsumerCredentialKind::ApiKey {
            prefix: generated.key_prefix,
            key_hash: generated.key_hash,
        },
        api_key: Some(generated.raw_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::consumers::{FakeConsumerKeyGenerator, UnreachableConsumerKeys};

    /// An API key is made by the platform: its prefix and digest are kept,
    /// and the raw key is handed back once.
    #[test]
    fn an_api_key_is_made_and_kept_by_its_digest() {
        let keys = FakeConsumerKeyGenerator::new();

        let issued = block_on(NewCredential::ApiKey.issued(&keys)).unwrap();

        let raw = issued.api_key.unwrap();
        let ConsumerCredentialKind::ApiKey { prefix, key_hash } = issued.kind else {
            panic!("an API key was asked for");
        };
        assert!(raw.expose().starts_with(prefix.as_str()));
        assert_ne!(key_hash.as_str(), raw.expose());
    }

    /// A certificate is kept as named, and no key is made or shown.
    #[test]
    fn a_certificate_makes_no_key() {
        let keys = FakeConsumerKeyGenerator::new();
        let fingerprint = CertificateFingerprint::from_digest([0xaa; 32]);

        let issued = block_on(NewCredential::ClientCert { fingerprint }.issued(&keys)).unwrap();

        assert_eq!(
            issued.kind,
            ConsumerCredentialKind::ClientCert { fingerprint }
        );
        assert!(issued.api_key.is_none());
        assert_eq!(keys.made(), 0);
    }

    /// Key generation failure returns an internal error instead of a credential.
    #[test]
    fn a_key_that_cannot_be_made_is_an_internal_error() {
        let issued = block_on(NewCredential::ApiKey.issued(&UnreachableConsumerKeys));

        assert!(matches!(issued, Err(AppError::Internal(_))));
    }
}
