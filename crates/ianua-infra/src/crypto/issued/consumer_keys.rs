//! The API keys consumers present at the gateway: made by the API, read by
//! the gateway.
//!
//! A consumer key reads `<prefix>_<secret>`, as the platform's own API keys
//! do: its prefix, everything up to the last `_`, is what finds the
//! consumer, and only the digest of the whole key is kept, under a key of
//! its own use. The platform makes every key itself, `ick_<id>_<secret>`,
//! since no one else can make the digest it is kept as. A presented value
//! of any other shape, such as a JWT, whose dots no key prefix holds, is no
//! consumer key.

use async_trait::async_trait;
use ianua_app::ports::authentication::{ConsumerKeyDigests, PresentedKey};
use ianua_app::ports::consumers::ConsumerKeyGenerator;
use ianua_app::ports::shared::GeneratedApiKey;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::KeyPrefix;

use crate::crypto::issued::{fresh_secret, made};
use crate::crypto::keys::{Purpose, RootSecret};
use crate::crypto::random::{base32, random_bytes};
use crate::crypto::seals::digests::KeyedDigest;

/// The leading token of every consumer key, which tells a secret scanner
/// what a leaked one is.
const LEADING_TOKEN: &str = "ick";

/// The bytes of randomness in the id that keeps prefixes apart.
const ID_BYTES: usize = 8;

/// The maker of consumer keys, each kept as its HMAC-SHA256 digest under
/// the key the gateway's reader digests presented keys with.
#[derive(Debug, Clone)]
pub struct HmacConsumerKeyGenerator {
    digest: KeyedDigest,
}

impl HmacConsumerKeyGenerator {
    /// A maker digesting keys under the key `root` derives for consumer
    /// keys.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            digest: KeyedDigest::of(root, Purpose::ConsumerKeys),
        }
    }
}

#[async_trait]
impl ConsumerKeyGenerator for HmacConsumerKeyGenerator {
    async fn generate(&self) -> Result<GeneratedApiKey, DomainError> {
        let id = base32(&random_bytes::<ID_BYTES>()?);
        let prefix = format!("{LEADING_TOKEN}_{id}");
        let secret = fresh_secret("")?;
        let raw_key = Secret::new(format!("{prefix}_{}", secret.expose()));
        Ok(GeneratedApiKey {
            key_hash: self.digest.digest(&raw_key),
            key_prefix: made(KeyPrefix::new(prefix))?,
            raw_key,
        })
    }
}

/// The reader of presented consumer keys, digesting each with HMAC-SHA256.
#[derive(Debug, Clone)]
pub struct HmacConsumerKeyDigests {
    digest: KeyedDigest,
}

impl HmacConsumerKeyDigests {
    /// A reader digesting keys under the key `root` derives for consumer
    /// keys.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            digest: KeyedDigest::of(root, Purpose::ConsumerKeys),
        }
    }
}

/// Whether `part` holds only what a key's secret is written in.
fn is_secret_part(part: &str) -> bool {
    !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The prefix `key` is found by, when it has a consumer key's shape.
fn prefix_of(key: &str) -> Option<KeyPrefix> {
    let (prefix, secret) = key.rsplit_once('_')?;
    if !is_secret_part(secret) {
        return None;
    }
    KeyPrefix::new(prefix).ok()
}

impl ConsumerKeyDigests for HmacConsumerKeyDigests {
    fn presented(&self, key: &Secret) -> Option<PresentedKey> {
        let prefix = prefix_of(key.expose())?;
        Some(PresentedKey {
            prefix,
            digest: self.digest.digest(key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    fn reader() -> HmacConsumerKeyDigests {
        HmacConsumerKeyDigests::new(&test_root())
    }

    fn maker() -> HmacConsumerKeyGenerator {
        HmacConsumerKeyGenerator::new(&test_root())
    }

    /// A key the API makes is read at the gateway into the prefix and
    /// digest the consumer was saved with, so it signs the consumer in.
    #[tokio::test]
    async fn a_made_key_reads_back_as_its_prefix_and_digest() {
        let made = maker().generate().await.unwrap();

        let presented = reader().presented(&made.raw_key).unwrap();

        assert_eq!(presented.prefix, made.key_prefix);
        assert_eq!(presented.digest, made.key_hash);
        assert!(made.key_prefix.as_str().starts_with("ick_"));
    }

    /// A generated consumer key's stored digest matches the consumer-key digest function.
    #[tokio::test]
    async fn a_made_key_is_digested_under_the_consumer_keys_key() {
        let made = maker().generate().await.unwrap();

        assert_ne!(
            made.key_hash,
            KeyedDigest::of(&test_root(), Purpose::ApiKeys).digest(&made.raw_key)
        );
    }

    /// Two keys never share a prefix, so each finds its own consumer.
    #[tokio::test]
    async fn two_made_keys_never_share_a_prefix() {
        let first = maker().generate().await.unwrap();
        let second = maker().generate().await.unwrap();

        assert_ne!(first.key_prefix, second.key_prefix);
        assert_ne!(first.key_hash, second.key_hash);
    }

    /// A consumer key is found by all but its secret, and checked by the
    /// digest of the whole key under the consumer keys' own key.
    #[test]
    fn a_consumer_key_is_read_into_its_prefix_and_digest() {
        let key = Secret::new("sk_live_partner_7f3kq2");

        let presented = reader().presented(&key).unwrap();

        assert_eq!(presented.prefix.as_str(), "sk_live_partner");
        assert_eq!(
            presented.digest,
            KeyedDigest::of(&test_root(), Purpose::ConsumerKeys).digest(&key)
        );
    }

    /// Identical raw text yields different consumer-key and tenant-API-key digests.
    #[test]
    fn a_consumer_key_digest_is_no_api_key_digest() {
        let key = Secret::new("sk_live_partner_7f3kq2");

        let presented = reader().presented(&key).unwrap();

        assert_ne!(
            presented.digest,
            KeyedDigest::of(&test_root(), Purpose::ApiKeys).digest(&key)
        );
    }

    /// A JWT, a value without a secret after its prefix, or one with no
    /// prefix at all, is no consumer key.
    #[test]
    fn a_value_of_another_shape_is_no_consumer_key() {
        let shapes = [
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln_bmF0dXJl",
            "sk_live_partner_",
            "_7f3kq2",
            "nounderscore",
            "sk live_7f3kq2",
            "",
        ];

        for shape in shapes {
            assert!(reader().presented(&Secret::new(shape)).is_none(), "{shape}");
        }
    }
}
