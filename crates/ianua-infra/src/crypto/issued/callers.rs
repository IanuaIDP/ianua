//! A presented bearer, turned into the caller behind it.
//!
//! The bearer's shape says what it is, so a request pays for one lookup,
//! never all of them: a tenant key leads with `ik_live_`, an organization
//! key with `oak_`, an operator key with `opk_`, and a session's refresh
//! token with `rt_`. Each is digested under the key of its own use, exactly
//! as it was when handed out, and the digest is looked up. A bearer of no
//! known shape, or longer than any the platform hands out, is refused
//! before anything is read, so a guess costs no database work. The bearer
//! itself is never logged.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::shared::{KeyFamily, ResolvedCaller, TokenLookup, TokenResolver};
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator as _;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::crypto::issued::HmacRefreshTokenGenerator;
use crate::crypto::keys::{Purpose, RootSecret};
use crate::crypto::seals::digests::KeyedDigest;

/// What a refresh token leads with, as [`HmacRefreshTokenGenerator`]
/// writes it.
const SESSION_PREFIX: &str = "rt_";

/// The longest bearer looked up: past every key and token the platform
/// hands out, which are a short prefix and 52 characters of base32 behind
/// a key prefix of at most 64.
const LONGEST_BEARER: usize = 256;

/// What a presented bearer is, by its shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bearer {
    /// A tenant's API key.
    TenantKey,
    /// An organization's API key.
    OrgKey,
    /// An operator's own key.
    OperatorKey,
    /// The refresh token of a tenant or organization session.
    Session,
    /// Nothing the platform hands out.
    Unknown,
}

impl Bearer {
    /// What `presented` is, by what it leads with and how long it is.
    fn of(presented: &str) -> Self {
        if presented.len() > LONGEST_BEARER {
            return Self::Unknown;
        }
        let leads = |family: KeyFamily| {
            presented
                .strip_prefix(family.prefix())
                .is_some_and(|rest| rest.starts_with('_'))
        };
        [
            (leads(KeyFamily::Tenant), Self::TenantKey),
            (leads(KeyFamily::Organization), Self::OrgKey),
            (leads(KeyFamily::Operator), Self::OperatorKey),
            (presented.starts_with(SESSION_PREFIX), Self::Session),
        ]
        .into_iter()
        .find_map(|(matches, bearer)| matches.then_some(bearer))
        .unwrap_or(Self::Unknown)
    }
}

/// Bearers resolved by their HMAC digests through a lookup of the stored
/// credentials.
pub struct HmacTokenResolver {
    lookup: Arc<dyn TokenLookup>,
    api_keys: KeyedDigest,
    refresh_tokens: HmacRefreshTokenGenerator,
}

impl HmacTokenResolver {
    /// A resolver digesting bearers under the keys `root` derives, as the
    /// key and token makers do, and finding them through `lookup`.
    #[must_use]
    pub fn new(root: &RootSecret, lookup: Arc<dyn TokenLookup>) -> Self {
        Self {
            lookup,
            api_keys: KeyedDigest::of(root, Purpose::ApiKeys),
            refresh_tokens: HmacRefreshTokenGenerator::new(root),
        }
    }

    /// The tenant or organization session whose refresh token `token` is.
    async fn session(&self, token: &Secret) -> Result<Option<ResolvedCaller>, DomainError> {
        let hash = self.refresh_tokens.hash_raw(token.expose());
        if let Some(caller) = self.lookup.find_session_by_token_hash(&hash).await? {
            return Ok(Some(caller));
        }
        self.lookup.find_org_session_by_token_hash(&hash).await
    }
}

impl std::fmt::Debug for HmacTokenResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacTokenResolver(<keys redacted>)")
    }
}

#[async_trait]
impl TokenResolver for HmacTokenResolver {
    async fn resolve(&self, token: &Secret) -> Result<Option<ResolvedCaller>, DomainError> {
        match Bearer::of(token.expose()) {
            Bearer::TenantKey => {
                let hash = self.api_keys.digest(token);
                self.lookup.find_api_key_by_key_hash(&hash).await
            }
            Bearer::OrgKey => {
                let hash = self.api_keys.digest(token);
                self.lookup.find_org_api_key_by_hash(&hash).await
            }
            Bearer::OperatorKey => {
                let hash = self.api_keys.digest(token);
                self.lookup.find_operator_key_by_hash(&hash).await
            }
            Bearer::Session => self.session(token).await,
            Bearer::Unknown => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ianua_app::context::{CallerIdentity, Credential};
    use ianua_app::ports::shared::ApiKeyGenerator as _;
    use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::types::{Expiry, OperatorId, SessionId, TenantSlug, TokenHash};

    use super::*;
    use crate::crypto::HmacApiKeyGenerator;
    use crate::crypto::keys::tests::test_root;

    /// Which of the lookup's questions was asked.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Asked {
        Session,
        OrgSession,
        ApiKey,
        OrgApiKey,
        OperatorKey,
    }

    /// A lookup that knows one digest, answered to one question, and notes
    /// every question it is asked.
    struct OneCredential {
        known: (Asked, TokenHash),
        asked: Mutex<Vec<Asked>>,
    }

    impl OneCredential {
        fn knowing(asked: Asked, hash: TokenHash) -> Arc<Self> {
            Arc::new(Self {
                known: (asked, hash),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn answer(&self, asked: Asked, hash: &TokenHash) -> Option<ResolvedCaller> {
            self.asked.lock().unwrap().push(asked);
            (self.known == (asked, hash.clone())).then(|| ResolvedCaller {
                identity: CallerIdentity::Operator(OperatorId::new()),
                credential: Credential::TenantSession(SessionId::new()),
                organization_id: None,
                tenant_id: None,
                kept_until: Expiry::Never,
            })
        }

        fn questions(&self) -> Vec<Asked> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TokenLookup for OneCredential {
        async fn find_session_by_token_hash(
            &self,
            token_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.answer(Asked::Session, token_hash))
        }

        async fn find_org_session_by_token_hash(
            &self,
            token_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.answer(Asked::OrgSession, token_hash))
        }

        async fn find_api_key_by_key_hash(
            &self,
            key_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.answer(Asked::ApiKey, key_hash))
        }

        async fn find_org_api_key_by_hash(
            &self,
            key_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.answer(Asked::OrgApiKey, key_hash))
        }

        async fn find_operator_key_by_hash(
            &self,
            key_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.answer(Asked::OperatorKey, key_hash))
        }
    }

    fn slug() -> TenantSlug {
        TenantSlug::new("acme", &SlugLimits::default()).unwrap()
    }

    async fn key_of(family: KeyFamily) -> (Secret, TokenHash) {
        let key = HmacApiKeyGenerator::new(&test_root())
            .generate(family, &slug())
            .await
            .unwrap();
        (key.raw_key, key.key_hash)
    }

    /// Each kind of key is digested as it was made and asked of its own
    /// table alone.
    #[tokio::test]
    async fn each_key_is_looked_up_where_its_family_lives() {
        let families = [
            (KeyFamily::Tenant, Asked::ApiKey),
            (KeyFamily::Organization, Asked::OrgApiKey),
            (KeyFamily::Operator, Asked::OperatorKey),
        ];
        for (family, asked) in families {
            let (raw, hash) = key_of(family).await;
            let lookup = OneCredential::knowing(asked, hash);
            let resolver = HmacTokenResolver::new(&test_root(), lookup.clone());

            let caller = resolver.resolve(&raw).await.unwrap();

            assert!(caller.is_some(), "{family:?}");
            assert_eq!(lookup.questions(), vec![asked]);
        }
    }

    /// A refresh token is asked of the tenant sessions first, then of the
    /// organization's.
    #[tokio::test]
    async fn a_refresh_token_is_looked_up_as_a_session() {
        let token = HmacRefreshTokenGenerator::new(&test_root())
            .generate()
            .unwrap();
        let lookup = OneCredential::knowing(Asked::OrgSession, token.hash().clone());
        let resolver = HmacTokenResolver::new(&test_root(), lookup.clone());

        let caller = resolver.resolve(token.raw()).await.unwrap();

        assert!(caller.is_some());
        assert_eq!(lookup.questions(), vec![Asked::Session, Asked::OrgSession]);
    }

    /// A generated refresh token has the session shape recognized by the resolver.
    #[test]
    fn a_refresh_token_has_the_shape_of_a_session() {
        let token = HmacRefreshTokenGenerator::new(&test_root())
            .generate()
            .unwrap();

        assert_eq!(Bearer::of(token.raw().expose()), Bearer::Session);
    }

    /// Unknown and oversized bearer forms resolve no caller and make no store lookup.
    #[tokio::test]
    async fn an_unknown_bearer_asks_nothing() {
        let lookup = OneCredential::knowing(Asked::Session, TokenHash::from_stored("x".into()));
        let resolver = HmacTokenResolver::new(&test_root(), lookup.clone());
        let long = format!("rt_{}", "a".repeat(LONGEST_BEARER));

        for bearer in [
            "",
            "Bearer",
            "eyJhbGciOiJub25lIn0.e30.",
            "ik_",
            "oakley",
            long.as_str(),
        ] {
            let caller = resolver.resolve(&Secret::new(bearer)).await.unwrap();

            assert!(caller.is_none(), "{bearer}");
        }
        assert!(lookup.questions().is_empty());
    }

    /// An API key digest stored as a session cannot resolve a caller;
    /// resolution asks only the API-key lookup.
    #[tokio::test]
    async fn a_key_digest_matches_only_as_a_key() {
        let (raw, hash) = key_of(KeyFamily::Tenant).await;
        let lookup = OneCredential::knowing(Asked::Session, hash);
        let resolver = HmacTokenResolver::new(&test_root(), lookup.clone());

        let caller = resolver.resolve(&raw).await.unwrap();

        assert!(caller.is_none());
        assert_eq!(lookup.questions(), vec![Asked::ApiKey]);
    }

    /// Resolver debug output is limited to its redacted representation.
    #[test]
    fn the_resolver_shows_no_key() {
        let lookup = OneCredential::knowing(Asked::Session, TokenHash::from_stored("x".into()));
        let resolver = HmacTokenResolver::new(&test_root(), lookup);

        assert_eq!(
            format!("{resolver:?}"),
            "HmacTokenResolver(<keys redacted>)"
        );
    }
}
