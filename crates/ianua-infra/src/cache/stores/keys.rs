//! The keys the gateway reads on every request, kept in this process for a
//! short while: the public halves of a tenant's signing keys, which every
//! token it is shown is checked against, and the assertion key it signs
//! upstream identities and message signatures with, its private half
//! opened, which costs a store read and an unsealing each time.
//!
//! The signing keys are kept under the tenant's version of them, which
//! every key made, rotated, revoked or promoted raises, so a revoked key is
//! not believed on any node a moment after. The assertion key is kept
//! under the tenant's version of its assertion keys, which every key made,
//! rotated or retired raises, and an entry lives a minute at the most: a
//! rotated assertion key stays published for the overlap, a day, so an
//! upstream still believes whatever an entry signed before its version
//! moved. A tenant's deletion drops both. A tenant with no key is
//! never kept, so its first key is used the moment it is made; and when
//! the versions cannot be read, the store is asked and nothing is kept.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::crypto::{AssertionSigningKeys, VerifyingKeyStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::assertion_key::AssertionSigningKey;
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::cache::stores::entries::{Entries, EntryKeeping};
use crate::cache::stores::invalidation::StoreCaches;
use crate::cache::stores::owners::{Owner, Owners};
use crate::cache::stores::versions::{Cached, Version};

/// How long a tenant's signing keys are served from here at the most.
const SIGNING_KEYS_KEPT_FOR: Duration = Duration::from_secs(30);

/// How long a tenant's opened assertion key is served from here at the
/// most. Far shorter than the overlap a rotated assertion key stays
/// published for.
const ASSERTION_KEY_KEPT_FOR: Duration = Duration::from_secs(60);

/// What was read, and the version it was read at.
#[derive(Clone)]
struct Kept<T> {
    version: Version,
    value: T,
}

/// The public halves of tenants' signing keys, kept in this process.
pub struct CacheVerifyingKeyStore {
    inner: Arc<dyn VerifyingKeyStore>,
    caches: Arc<StoreCaches>,
    entries: Arc<Entries<TenantId, Kept<Vec<VerifyingKey>>>>,
}

impl std::fmt::Debug for CacheVerifyingKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheVerifyingKeyStore")
            .finish_non_exhaustive()
    }
}

impl CacheVerifyingKeyStore {
    /// `inner`, the keys of at most `capacity` tenants kept for a few
    /// seconds, among `caches`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn VerifyingKeyStore>,
        caches: Arc<StoreCaches>,
        capacity: usize,
    ) -> Self {
        let keeping = EntryKeeping {
            lifetime: SIGNING_KEYS_KEPT_FOR,
            capacity,
        };
        let entries = caches.entries(Cached::SigningKeys, keeping);
        Self {
            inner,
            caches,
            entries,
        }
    }
}

impl TenantScoped for CacheVerifyingKeyStore {}

#[async_trait]
impl VerifyingKeyStore for CacheVerifyingKeyStore {
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Vec<VerifyingKey>, DomainError> {
        let owner = Owner::Tenant(*tenant_id.as_uuid());
        let versions = self.caches.versions();
        let Ok(version) = versions.current(Cached::SigningKeys, owner).await else {
            return self.inner.find(tenant_id).await;
        };
        if let Some(kept) = live(&self.entries, **tenant_id, &version) {
            return Ok(kept);
        }
        let keys = self.inner.find(tenant_id).await?;
        if keys.is_empty() {
            return Ok(keys);
        }
        let kept = Kept {
            version,
            value: keys.clone(),
        };
        self.entries.put(**tenant_id, kept, Owners::only(owner));
        Ok(keys)
    }
}

/// The key that signs each tenant's assertions, opened, kept in this
/// process.
pub struct CacheAssertionSigningKeys {
    inner: Arc<dyn AssertionSigningKeys>,
    caches: Arc<StoreCaches>,
    entries: Arc<Entries<TenantId, Kept<AssertionSigningKey>>>,
}

impl std::fmt::Debug for CacheAssertionSigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheAssertionSigningKeys")
            .finish_non_exhaustive()
    }
}

impl CacheAssertionSigningKeys {
    /// `inner`, the opened keys of at most `capacity` tenants kept for a
    /// minute, among `caches`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn AssertionSigningKeys>,
        caches: Arc<StoreCaches>,
        capacity: usize,
    ) -> Self {
        let keeping = EntryKeeping {
            lifetime: ASSERTION_KEY_KEPT_FOR,
            capacity,
        };
        let entries = caches.entries(Cached::AssertionKeys, keeping);
        Self {
            inner,
            caches,
            entries,
        }
    }
}

impl TenantScoped for CacheAssertionSigningKeys {}

#[async_trait]
impl AssertionSigningKeys for CacheAssertionSigningKeys {
    async fn signing(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionSigningKey>, DomainError> {
        let owner = Owner::Tenant(*tenant_id.as_uuid());
        let versions = self.caches.versions();
        let Ok(version) = versions.current(Cached::AssertionKeys, owner).await else {
            return self.inner.signing(tenant_id).await;
        };
        if let Some(kept) = live(&self.entries, **tenant_id, &version) {
            return Ok(Some(kept));
        }
        let Some(key) = self.inner.signing(tenant_id).await? else {
            return Ok(None);
        };
        let kept = Kept {
            version,
            value: key.clone(),
        };
        self.entries.put(**tenant_id, kept, Owners::only(owner));
        Ok(Some(key))
    }
}

/// What `entries` keeps for `tenant`, when it was kept at `version`.
fn live<T: Clone>(
    entries: &Entries<TenantId, Kept<T>>,
    tenant: TenantId,
    version: &Version,
) -> Option<T> {
    entries
        .get(&tenant)
        .map(|seen| seen.value)
        .filter(|kept| &kept.version == version)
        .map(|kept| kept.value)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, NewAssertionKey,
    };
    use ianua_domain::domains::crypto::key_status::KeyState;
    use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::domains::crypto::verifying_key::VerifyingKeyRow;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{EventType, Expiry, KeyId, PublicKeyPem};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::state::SharedState;
    use crate::cache::stores::invalidation::Change;
    use crate::cache::stores::versions::RefusingState;

    const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----";

    fn caches_on(state: Arc<dyn SharedState>) -> Arc<StoreCaches> {
        Arc::new(StoreCaches::new(state, Duration::from_secs(600)))
    }

    fn caches() -> Arc<StoreCaches> {
        caches_on(Arc::new(MemoryState::new(100)))
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_background(TenantId::new())
    }

    fn signing_key(kid: &str) -> AssertionSigningKey {
        let key = AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(PUBLIC).unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        });
        let set = AssertionKeySet::<ResolvedTenant>::new(key);
        AssertionSigningKey::of(&set, Secret::new(format!("private-{kid}"))).unwrap()
    }

    /// A store of signing keys holding as many keys as it is told, counting
    /// every read.
    struct Keys {
        held: AtomicUsize,
        reads: AtomicUsize,
    }

    impl Keys {
        fn holding(held: usize) -> Arc<Self> {
            Arc::new(Self {
                held: AtomicUsize::new(held),
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TenantScoped for Keys {}

    #[async_trait]
    impl VerifyingKeyStore for Keys {
        async fn find(&self, _: &ScopedTenant) -> Result<Vec<VerifyingKey>, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let held = self.held.load(Ordering::SeqCst);
            Ok(std::iter::repeat_with(verifying_key).take(held).collect())
        }
    }

    fn verifying_key() -> VerifyingKey {
        VerifyingKey::reconstitute(VerifyingKeyRow {
            kid: KeyId::new("k1").unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(PUBLIC).unwrap(),
            state: KeyState::Active,
            created_at: clock::now(),
            expires_at: Expiry::Never,
        })
        .unwrap()
    }

    /// A tenant's signing keys asked for again are served from here.
    #[tokio::test]
    async fn signing_keys_are_served_from_here() {
        let store = Keys::holding(1);
        let cached = CacheVerifyingKeyStore::new(store.clone(), caches(), 100);
        let acme = tenant();

        cached.find(&acme).await.unwrap();
        let again = cached.find(&acme).await.unwrap();

        assert_eq!(again.len(), 1);
        assert_eq!(store.reads(), 1);
    }

    /// A key-revocation event invalidates the cached key list and forces another store read.
    #[tokio::test]
    async fn a_revoked_key_is_read_again() {
        let store = Keys::holding(1);
        let caches = caches();
        let cached = CacheVerifyingKeyStore::new(store.clone(), Arc::clone(&caches), 100);
        let acme = tenant();
        cached.find(&acme).await.unwrap();

        let revoked = EventType::parse("crypto.key_revoked").unwrap();
        caches
            .apply(Change::of(revoked, Owner::Tenant(*acme.as_uuid())))
            .await;
        cached.find(&acme).await.unwrap();

        assert_eq!(store.reads(), 2);
    }

    /// An empty key list is not cached, so the next lookup discovers the tenant's first stored key.
    #[tokio::test]
    async fn a_tenant_without_keys_is_asked_again() {
        let store = Keys::holding(0);
        let cached = CacheVerifyingKeyStore::new(store.clone(), caches(), 100);
        let acme = tenant();

        cached.find(&acme).await.unwrap();
        store.held.store(1, Ordering::SeqCst);
        let after = cached.find(&acme).await.unwrap();

        assert_eq!(after.len(), 1);
        assert_eq!(store.reads(), 2);
    }

    /// An unavailable version store makes each signing-key lookup consult the underlying store.
    #[tokio::test]
    async fn without_the_versions_the_store_is_asked_every_time() {
        let store = Keys::holding(1);
        let cached =
            CacheVerifyingKeyStore::new(store.clone(), caches_on(Arc::new(RefusingState)), 100);
        let acme = tenant();

        cached.find(&acme).await.unwrap();
        cached.find(&acme).await.unwrap();

        assert_eq!(store.reads(), 2);
    }

    /// One tenant's keys are never served for another.
    #[tokio::test]
    async fn an_entry_answers_for_its_tenant_only() {
        let store = Keys::holding(1);
        let cached = CacheVerifyingKeyStore::new(store.clone(), caches(), 100);

        cached.find(&tenant()).await.unwrap();
        cached.find(&tenant()).await.unwrap();

        assert_eq!(store.reads(), 2);
    }

    /// A store of opened assertion keys, signing with `kid` or with none,
    /// counting every read.
    struct Opened {
        kid: std::sync::Mutex<Option<&'static str>>,
        reads: AtomicUsize,
    }

    impl Opened {
        fn with(kid: Option<&'static str>) -> Arc<Self> {
            Arc::new(Self {
                kid: std::sync::Mutex::new(kid),
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TenantScoped for Opened {}

    #[async_trait]
    impl AssertionSigningKeys for Opened {
        async fn signing(
            &self,
            _: &ScopedTenant,
        ) -> Result<Option<AssertionSigningKey>, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.kid.lock().unwrap().map(signing_key))
        }
    }

    /// The gateway signs Ann's next request with the key it opened for her
    /// last one, without reading and unsealing it again.
    #[tokio::test]
    async fn an_opened_assertion_key_is_served_from_here() {
        let store = Opened::with(Some("a1"));
        let cached = CacheAssertionSigningKeys::new(store.clone(), caches(), 100);
        let acme = tenant();

        cached.signing(&acme).await.unwrap();
        let again = cached.signing(&acme).await.unwrap().unwrap();

        assert_eq!(again.kid().as_str(), "a1");
        assert_eq!(store.reads(), 1);
    }

    /// A missing assertion key is not cached; a later lookup finds the newly stored key.
    #[tokio::test]
    async fn a_tenant_without_an_assertion_key_is_asked_again() {
        let store = Opened::with(None);
        let cached = CacheAssertionSigningKeys::new(store.clone(), caches(), 100);
        let acme = tenant();

        cached.signing(&acme).await.unwrap();
        *store.kid.lock().unwrap() = Some("a1");
        let after = cached.signing(&acme).await.unwrap();

        assert!(after.is_some());
        assert_eq!(store.reads(), 2);
    }

    /// A tenant-deletion event invalidates the cached assertion key and causes a fresh store read.
    #[tokio::test]
    async fn a_deleted_tenants_assertion_key_goes() {
        let store = Opened::with(Some("a1"));
        let caches = caches();
        let cached = CacheAssertionSigningKeys::new(store.clone(), Arc::clone(&caches), 100);
        let acme = tenant();
        cached.signing(&acme).await.unwrap();

        let deleted = EventType::parse("tenant.deleted").unwrap();
        caches
            .apply(Change::of(deleted, Owner::Tenant(*acme.as_uuid())))
            .await;
        cached.signing(&acme).await.unwrap();

        assert_eq!(store.reads(), 2);
    }

    /// The assertion-key cache lifetime is at most one sixtieth of the rotation overlap.
    #[test]
    fn an_assertion_key_is_kept_far_shorter_than_its_overlap() {
        let overlap = KeyRotationSchedule::FOR_ASSERTION_KEYS
            .overlap()
            .whole_seconds();

        let kept = i64::try_from(ASSERTION_KEY_KEPT_FOR.as_secs()).unwrap();

        assert!(
            kept.saturating_mul(60) <= overlap,
            "{kept}s against {overlap}s"
        );
    }
}
