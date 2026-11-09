//! Making API keys, and the families their prefixes tell apart.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{KeyPrefix, TenantSlug, TokenHash};

/// A newly generated API key.
///
/// It has no `Debug`, since it holds the raw key.
pub struct GeneratedApiKey {
    /// The full raw key, shown once (e.g. `ik_live_acme_01HXK_secret` or
    /// `opk_01HXK_secret`).
    pub raw_key: Secret,
    /// The scannable prefix the key is looked up by (e.g. `ik_live_acme_01HXK`
    /// or `opk_01HXK`).
    pub key_prefix: KeyPrefix,
    /// The hash of the full key, which is what is stored.
    pub key_hash: TokenHash,
}

/// Dyn-safe port for generating API keys.
///
/// Used for tenant (`ik_live_`), organization (`oak_`) and operator (`opk_`)
/// API keys. The [`KeyFamily`] picks the prefix; the slug goes after it.
#[async_trait]
pub trait ApiKeyGenerator: Send + Sync {
    /// Generates a new API key of the given family, with `slug` in its prefix.
    ///
    /// The family decides the leading token, `ik_live` for a tenant key and
    /// `oak` for an organization one, and the resolver reads it back to know
    /// which table to look the key up in. Passing the wrong one mints a key
    /// that authenticates nowhere.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if no random key can be made.
    async fn generate(
        &self,
        family: KeyFamily,
        slug: &TenantSlug,
    ) -> Result<GeneratedApiKey, DomainError>;
}

/// Which plane a generated API key belongs to.
///
/// The prefix is the routing information: a bearer token carries no other
/// hint of which store holds it, so the families must never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFamily {
    /// A tenant key, `ik_live_{slug}_…`.
    Tenant,
    /// An organization key, `oak_{slug}_…`.
    Organization,
    /// A platform operator key, `opk_{slug}_…`.
    Operator,
}

impl KeyFamily {
    /// The leading token this family's keys carry.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Tenant => "ik_live",
            Self::Organization => "oak",
            Self::Operator => "opk",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// A bearer token carries no other hint of its store, so two families
    /// sharing a leading token would send one family's keys to the other's.
    #[test]
    fn no_two_key_families_share_a_leading_token() {
        let prefixes = [
            KeyFamily::Tenant.prefix(),
            KeyFamily::Organization.prefix(),
            KeyFamily::Operator.prefix(),
        ];

        let distinct: HashSet<_> = prefixes.iter().collect();

        assert_eq!(distinct.len(), prefixes.len());
    }
}
