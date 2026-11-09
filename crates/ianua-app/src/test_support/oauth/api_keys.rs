//! Fakes for API keys: the store `acting` reads them from, and the
//! generator that makes them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::api_key::{ApiKey, ApiKeyRow, KeyStanding};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActorRef, ApiKeyId, CountryCode, Expiry, KeyPrefix, Label, Scope, TenantId, TenantSlug,
};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::oauth::{ApiKeySortField, ApiKeyStore, CrossTenantApiKeyStore, UseRecorded};
use crate::ports::shared::{ApiKeyGenerator, GeneratedApiKey, KeyFamily};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::oauth::codes::hash_of;
use crate::test_support::{Fake, ReadBeforeWrite};

/// In-memory API key store, each key kept under its tenant.
#[derive(Default)]
pub struct FakeApiKeyStore {
    keys: Mutex<Vec<(TenantId, ApiKey<ResolvedTenant>)>>,
}

impl TenantScoped for FakeApiKeyStore {}

impl FakeApiKeyStore {
    /// A store holding no key.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `key` in `tenant`.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, key: ApiKey<ResolvedTenant>) -> Self {
        Self {
            keys: Mutex::new(vec![(**tenant, key)]),
        }
    }

    /// How many keys are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    fn matching(
        &self,
        keeps: impl Fn(&TenantId, &ApiKey<ResolvedTenant>) -> bool,
    ) -> Result<Vec<ApiKey<ResolvedTenant>>, DomainError> {
        self.keys
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, key)| keeps(tenant, key))
            .map(|(_, key)| copy_key(key))
            .collect()
    }

    /// Replaces `tenant`'s key `id` with what `change` makes of it, and
    /// says whether there was one: a key gone is never written back.
    fn rewrite(
        &self,
        tenant: &ScopedTenant,
        id: &ApiKeyId,
        change: impl Fn(&ApiKey<ResolvedTenant>) -> Result<ApiKey<ResolvedTenant>, DomainError>,
    ) -> Result<bool, DomainError> {
        let mut keys = self.keys.lock().unwrap();
        let Some((_, kept)) = keys
            .iter_mut()
            .find(|(owner, kept)| owner == &**tenant && kept.id() == id)
        else {
            return Ok(false);
        };
        *kept = change(kept)?;
        Ok(true)
    }
}

#[async_trait]
impl ApiKeyStore for FakeApiKeyStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApiKeyId,
    ) -> Result<Option<ApiKey<ResolvedTenant>>, DomainError> {
        let found = self.matching(|tenant, key| tenant == &**tenant_id && key.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ApiKeySortField>,
        request: &PageRequest,
    ) -> Result<Page<ApiKey<ResolvedTenant>>, DomainError> {
        let found = self.matching(|tenant, _| tenant == &**tenant_id)?;
        page(found, sort, request)
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_key(key)?;
        self.keys.lock().unwrap().push((**tenant_id, copy));
        Ok(())
    }

    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        self.rewrite(tenant_id, key.id(), |kept| {
            ApiKey::reconstitute(ApiKeyRow {
                name: key.name().clone(),
                scopes: key.scopes().to_vec(),
                standing: key.standing(),
                ..row_of(kept)
            })
        })
    }

    async fn record_use(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
        read_countries: &[CountryCode],
    ) -> Result<UseRecorded, DomainError> {
        let mut keys = self.keys.lock().unwrap();
        let Some((_, kept)) = keys
            .iter_mut()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id() == key.id())
        else {
            return Ok(UseRecorded::Gone);
        };
        if kept.seen_countries() != read_countries {
            return Ok(UseRecorded::Overtaken);
        }
        let written = ApiKey::reconstitute(ApiKeyRow {
            last_used_at: key.last_used_at(),
            last_used_ip: key.last_used_ip().cloned(),
            seen_countries: key.seen_countries().to_vec(),
            ..row_of(kept)
        })?;
        *kept = written;
        Ok(UseRecorded::Written)
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ApiKeyId) -> Result<(), DomainError> {
        self.keys
            .lock()
            .unwrap()
            .retain(|(tenant, key)| !(tenant == &**tenant_id && key.id() == id));
        Ok(())
    }
}

#[async_trait]
impl CrossTenantApiKeyStore for FakeApiKeyStore {
    async fn delete_expired(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<(TenantId, ApiKeyId, Label)>, DomainError> {
        let mut keys = self.keys.lock().unwrap();
        let expired = keys
            .iter()
            .filter(|(_, key)| key.expires_at().has_passed(now))
            .map(|(tenant, key)| (*tenant, *key.id(), key.name().clone()))
            .collect();
        keys.retain(|(_, key)| !key.expires_at().has_passed(now));
        Ok(expired)
    }
}

impl Fake for Arc<dyn ApiKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeApiKeyStore::empty())
    }
}

impl Fake for Arc<dyn CrossTenantApiKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeApiKeyStore::empty())
    }
}

#[async_trait]
impl ApiKeyStore for ReadBeforeWrite<FakeApiKeyStore> {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApiKeyId,
    ) -> Result<Option<ApiKey<ResolvedTenant>>, DomainError> {
        self.seen.find_by_id(tenant_id, id).await
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ApiKeySortField>,
        request: &PageRequest,
    ) -> Result<Page<ApiKey<ResolvedTenant>>, DomainError> {
        self.seen.list_all(tenant_id, sort, request).await
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.live.insert(tenant_id, key).await
    }

    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        self.live.update(tenant_id, key).await
    }

    async fn record_use(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
        read_countries: &[CountryCode],
    ) -> Result<UseRecorded, DomainError> {
        self.live.record_use(tenant_id, key, read_countries).await
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ApiKeyId) -> Result<(), DomainError> {
        self.live.delete(tenant_id, id).await
    }
}

/// The key [`api_key_row`] describes.
#[must_use]
pub fn stored_api_key(name: &str, maker: ActorRef) -> ApiKey<ResolvedTenant> {
    ApiKey::reconstitute(api_key_row(name, maker)).expect("a fresh key is a consistent row")
}

/// A key named `name`, made by `maker`, created now, that reads routes and
/// never expires, as storage keeps it.
#[must_use]
pub fn api_key_row(name: &str, maker: ActorRef) -> ApiKeyRow {
    let id = ApiKeyId::new();
    let prefix = format!("ik_live_acme_{}", id.as_uuid().simple());
    ApiKeyRow {
        id,
        name: Label::new("name", name).expect("a valid name"),
        key_hash: hash_of(&format!("{prefix}_secret")),
        key_prefix: KeyPrefix::new(prefix).expect("a valid prefix"),
        scopes: vec![Scope::new("idp:routing:view").expect("a valid scope")],
        created_by: maker,
        expires_at: Expiry::Never,
        last_used_at: None,
        last_used_ip: None,
        seen_countries: Vec::new(),
        created_at: ianua_domain::shared::clock::now(),
        standing: KeyStanding::Working,
    }
}

/// `key` written out and read back, as storage would return it.
fn copy_key(key: &ApiKey<ResolvedTenant>) -> Result<ApiKey<ResolvedTenant>, DomainError> {
    ApiKey::reconstitute(row_of(key))
}

/// The stored row of `key`.
fn row_of(key: &ApiKey<ResolvedTenant>) -> ApiKeyRow {
    ApiKeyRow {
        id: *key.id(),
        name: key.name().clone(),
        key_prefix: key.key_prefix().clone(),
        key_hash: key.key_hash().clone(),
        scopes: key.scopes().to_vec(),
        created_by: key.created_by().clone(),
        expires_at: key.expires_at(),
        last_used_at: key.last_used_at(),
        last_used_ip: key.last_used_ip().cloned(),
        seen_countries: key.seen_countries().to_vec(),
        created_at: key.created_at(),
        standing: key.standing(),
    }
}

/// API key generator that counts the keys it makes: the first tenant key for
/// `acme` is `ik_live_acme_1_secret`, found by prefix `ik_live_acme_1` and
/// hashed with [`hash_of`].
#[derive(Default)]
pub struct FakeApiKeyGenerator {
    made: Mutex<u32>,
}

impl FakeApiKeyGenerator {
    /// A generator that has made no key yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ApiKeyGenerator for FakeApiKeyGenerator {
    async fn generate(
        &self,
        family: KeyFamily,
        slug: &TenantSlug,
    ) -> Result<GeneratedApiKey, DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let prefix = format!("{}_{}_{made}", family.prefix(), slug.as_str());
        let raw_key = format!("{prefix}_secret");
        Ok(GeneratedApiKey {
            key_prefix: KeyPrefix::new(prefix)?,
            key_hash: hash_of(&raw_key),
            raw_key: Secret::new(raw_key),
        })
    }
}

impl Fake for Arc<dyn ApiKeyGenerator> {
    fn fake() -> Self {
        Arc::new(FakeApiKeyGenerator::new())
    }
}
