//! API keys of tenants, organizations and operators.
//!
//! A key reads `<family>_<slug>_<id>_<secret>`. Its prefix, everything up
//! to the last `_`, is what a list shows and the key is looked up by; the
//! family tells the resolver which table to look in. The slug is cut to
//! keep the prefix within what a key prefix may hold; the random id after
//! it keeps every prefix apart. Only the digest of the whole key is kept.

use async_trait::async_trait;
use ianua_app::ports::shared::{ApiKeyGenerator, GeneratedApiKey, KeyFamily};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{KeyPrefix, TenantSlug};

use crate::crypto::issued::{fresh_secret, made};
use crate::crypto::keys::{Purpose, RootSecret};
use crate::crypto::random::{base32, random_bytes};
use crate::crypto::seals::digests::KeyedDigest;

/// The longest key prefix, as [`KeyPrefix`] allows.
const MAX_PREFIX: usize = 64;

/// The bytes of randomness in the id that keeps prefixes apart.
const ID_BYTES: usize = 8;

/// The leading token of each family's keys.
fn family_token(family: KeyFamily) -> &'static str {
    match family {
        KeyFamily::Tenant => "ik_live",
        KeyFamily::Organization => "oak",
        KeyFamily::Operator => "opk",
    }
}

/// The prefix of a key of `family` for `slug`, with the random `id`, the
/// slug cut so the whole fits.
fn prefix_of(family: KeyFamily, slug: &TenantSlug, id: &str) -> String {
    let family = family_token(family);
    let room = MAX_PREFIX.saturating_sub(family.len().saturating_add(id.len()).saturating_add(2));
    let slug = slug.as_str().get(..room).unwrap_or(slug.as_str());
    format!("{family}_{slug}_{id}")
}

/// The maker of API keys, each kept as its HMAC-SHA256 digest.
#[derive(Debug, Clone)]
pub struct HmacApiKeyGenerator {
    digest: KeyedDigest,
}

impl HmacApiKeyGenerator {
    /// A maker digesting keys under the key `root` derives for API keys.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            digest: KeyedDigest::of(root, Purpose::ApiKeys),
        }
    }
}

#[async_trait]
impl ApiKeyGenerator for HmacApiKeyGenerator {
    async fn generate(
        &self,
        family: KeyFamily,
        slug: &TenantSlug,
    ) -> Result<GeneratedApiKey, DomainError> {
        let id = base32(&random_bytes::<ID_BYTES>()?);
        let prefix = prefix_of(family, slug, &id);
        let secret = fresh_secret("")?;
        let raw_key = Secret::new(format!("{prefix}_{}", secret.expose()));
        Ok(GeneratedApiKey {
            key_hash: self.digest.digest(&raw_key),
            key_prefix: made(KeyPrefix::new(prefix))?,
            raw_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::config::SlugLimits;

    use super::*;
    use crate::crypto::keys::tests::test_root;

    fn slug(text: &str) -> TenantSlug {
        TenantSlug::new(text, &SlugLimits::default()).unwrap()
    }

    /// A tenant key reads `ik_live_acme_<id>_<secret>`; its prefix is all
    /// but the secret, and its digest is the digest of the whole key.
    #[tokio::test]
    async fn a_tenant_key_carries_its_family_and_slug() {
        let keys = HmacApiKeyGenerator::new(&test_root());

        let key = keys
            .generate(KeyFamily::Tenant, &slug("acme"))
            .await
            .unwrap();

        let raw = key.raw_key.expose();
        assert!(key.key_prefix.as_str().starts_with("ik_live_acme_"));
        assert!(raw.starts_with(&format!("{}_", key.key_prefix.as_str())));
        assert_eq!(
            raw.rsplit_once('_').map(|(prefix, _)| prefix),
            Some(key.key_prefix.as_str())
        );
        assert_eq!(
            key.key_hash,
            KeyedDigest::of(&test_root(), Purpose::ApiKeys).digest(&key.raw_key)
        );
    }

    /// Each family leads with its own token, so the resolver looks in the
    /// right table.
    #[tokio::test]
    async fn each_family_leads_with_its_token() {
        let keys = HmacApiKeyGenerator::new(&test_root());

        let org = keys
            .generate(KeyFamily::Organization, &slug("acme"))
            .await
            .unwrap();
        let operator = keys
            .generate(KeyFamily::Operator, &slug("ops"))
            .await
            .unwrap();

        assert!(org.key_prefix.as_str().starts_with("oak_acme_"));
        assert!(operator.key_prefix.as_str().starts_with("opk_ops_"));
    }

    /// A maximum-length tenant slug is shortened enough to generate a valid key prefix.
    #[tokio::test]
    async fn the_longest_slug_still_makes_a_key() {
        let keys = HmacApiKeyGenerator::new(&test_root());
        let longest = "a".repeat(63);

        let key = keys
            .generate(KeyFamily::Tenant, &slug(&longest))
            .await
            .unwrap();

        assert!(key.key_prefix.as_str().len() <= MAX_PREFIX);
        assert!(key.key_prefix.as_str().starts_with("ik_live_aaaa"));
    }

    /// Two keys for one tenant have different prefixes and digests.
    #[tokio::test]
    async fn two_keys_never_share_a_prefix() {
        let keys = HmacApiKeyGenerator::new(&test_root());

        let first = keys
            .generate(KeyFamily::Tenant, &slug("acme"))
            .await
            .unwrap();
        let second = keys
            .generate(KeyFamily::Tenant, &slug("acme"))
            .await
            .unwrap();

        assert_ne!(first.key_prefix.as_str(), second.key_prefix.as_str());
        assert_ne!(first.key_hash, second.key_hash);
    }
}
