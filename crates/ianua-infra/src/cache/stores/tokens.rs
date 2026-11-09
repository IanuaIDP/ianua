//! The callers bearers resolve to, kept in this process: the hottest read
//! of the API, since every authenticated request asks it, and a tenant's
//! session or key is looked for in the platform database and in every
//! database of a tenant living apart at once.
//!
//! A bearer's digest names one credential for ever, so the first lookup
//! keeps only whose it is, which grants nothing. From the second on, the
//! owner's version is read first, then the store, and the caller found is
//! kept under that version; once the version moves, it is not read again.
//! So no answer read before a revocation is ever kept under the version
//! raised after it. A bearer that stopped answering is dropped, never kept
//! as an answer: only a caller found is served from here, and only until
//! its owner's version moves or its lifetime ends, and never past the end
//! its credential was read with: a key's end, or a session's absolute end.
//! Reaching that end only asks the store again, so a credential whose end
//! has moved keeps answering.
//!
//! A tenant's credential is kept under the tenant's version, and its
//! organization's events drop it on this node too; an organization's under
//! the organization's; an operator's under the platform's. When the
//! versions cannot be read, the store is asked and nothing is kept.

use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::shared::{ResolvedCaller, TokenLookup};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;
use time::OffsetDateTime;

use crate::cache::stores::entries::{Entries, EntryKeeping};
use crate::cache::stores::invalidation::StoreCaches;
use crate::cache::stores::owners::{Owner, Owners};
use crate::cache::stores::versions::{Cached, Version};

/// Which of the lookup's questions a digest was asked under.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Asked {
    TenantSession,
    OrgSession,
    TenantKey,
    OrgKey,
    OperatorKey,
}

/// A digest asked about under one question. It holds a keyed digest of a
/// bearer, so it has no `Debug` and is never logged.
#[derive(Clone, PartialEq, Eq, Hash)]
struct TokenKey {
    asked: Asked,
    digest: String,
}

/// What is known of a digest.
#[derive(Clone)]
enum Known {
    /// Whose credential it names, and nothing more.
    Owner,
    /// The caller it resolved to under `version`.
    Caller {
        caller: ResolvedCaller,
        version: Version,
    },
}

impl Known {
    /// The caller kept, when it was kept under `version` and its credential
    /// has not reached its end by `now`.
    fn caller_at(&self, version: &Version, now: OffsetDateTime) -> Option<ResolvedCaller> {
        match self {
            Self::Caller {
                caller,
                version: kept,
            } if kept == version && !caller.kept_until.has_passed(now) => Some(caller.clone()),
            Self::Caller { .. } | Self::Owner => None,
        }
    }
}

/// Whose credential `caller`, found under `asked`, is.
fn owners_of(asked: Asked, caller: &ResolvedCaller) -> Option<Owners> {
    let organization = caller
        .organization_id
        .map(|organization| Owner::Organization(*organization.as_uuid()));
    match asked {
        Asked::TenantSession | Asked::TenantKey => Some(Owners {
            owner: Owner::Tenant(*caller.tenant_id?.as_uuid()),
            within: organization,
        }),
        Asked::OrgSession | Asked::OrgKey => organization.map(Owners::only),
        Asked::OperatorKey => Some(Owners::only(Owner::Platform)),
    }
}

/// The bearer lookup, its callers kept in this process.
pub struct CacheTokenLookup {
    inner: Arc<dyn TokenLookup>,
    caches: Arc<StoreCaches>,
    entries: Arc<Entries<TokenKey, Known>>,
}

impl std::fmt::Debug for CacheTokenLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheTokenLookup").finish_non_exhaustive()
    }
}

impl CacheTokenLookup {
    /// `inner`, its callers kept as `keeping` says, among `caches`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn TokenLookup>,
        caches: Arc<StoreCaches>,
        keeping: EntryKeeping,
    ) -> Self {
        let entries = caches.entries(Cached::Callers, keeping);
        Self {
            inner,
            caches,
            entries,
        }
    }

    /// The caller `hash` resolves to under `asked`, from here when it is
    /// kept under its owner's version now, else from `read`.
    async fn through<R>(
        &self,
        asked: Asked,
        hash: &TokenHash,
        read: impl FnOnce() -> R + Send,
    ) -> Result<Option<ResolvedCaller>, DomainError>
    where
        R: Future<Output = Result<Option<ResolvedCaller>, DomainError>> + Send,
    {
        let key = TokenKey {
            asked,
            digest: hash.as_str().to_owned(),
        };
        let Some(seen) = self.entries.get(&key) else {
            let found = read().await?;
            self.note_owner(key, found.as_ref());
            return Ok(found);
        };
        let Ok(version) = self
            .caches
            .versions()
            .current(Cached::Callers, seen.owners.owner)
            .await
        else {
            return read().await;
        };
        if let Some(caller) = seen.value.caller_at(&version, clock::now()) {
            return Ok(Some(caller));
        }
        let found = read().await?;
        self.keep(key, found.as_ref(), version);
        Ok(found)
    }

    /// Keeps whose credential `found` is, when it was found.
    fn note_owner(&self, key: TokenKey, found: Option<&ResolvedCaller>) {
        let Some(owners) = found.and_then(|caller| owners_of(key.asked, caller)) else {
            return;
        };
        self.entries.put(key, Known::Owner, owners);
    }

    /// Keeps `found` under `version`, or drops the digest when it no longer
    /// answers.
    fn keep(&self, key: TokenKey, found: Option<&ResolvedCaller>, version: Version) {
        let Some((caller, owners)) =
            found.and_then(|caller| Some((caller, owners_of(key.asked, caller)?)))
        else {
            self.entries.remove(&key);
            return;
        };
        let known = Known::Caller {
            caller: caller.clone(),
            version,
        };
        self.entries.put(key, known, owners);
    }
}

#[async_trait]
impl TokenLookup for CacheTokenLookup {
    async fn find_session_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        self.through(Asked::TenantSession, token_hash, || {
            self.inner.find_session_by_token_hash(token_hash)
        })
        .await
    }

    async fn find_org_session_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        self.through(Asked::OrgSession, token_hash, || {
            self.inner.find_org_session_by_token_hash(token_hash)
        })
        .await
    }

    async fn find_api_key_by_key_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        self.through(Asked::TenantKey, key_hash, || {
            self.inner.find_api_key_by_key_hash(key_hash)
        })
        .await
    }

    async fn find_org_api_key_by_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        self.through(Asked::OrgKey, key_hash, || {
            self.inner.find_org_api_key_by_hash(key_hash)
        })
        .await
    }

    async fn find_operator_key_by_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        self.through(Asked::OperatorKey, key_hash, || {
            self.inner.find_operator_key_by_hash(key_hash)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ianua_app::context::{CallerIdentity, Credential};
    use ianua_domain::types::{EventType, Expiry, OrganizationId, SessionId, TenantId, UserId};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::state::SharedState;
    use crate::cache::stores::invalidation::Change;
    use crate::cache::stores::versions::RefusingState;

    /// A store that knows the sessions it holds, counts every read, and
    /// forgets a session when it is revoked.
    #[derive(Default)]
    struct Sessions {
        live: Mutex<Vec<(TokenHash, ResolvedCaller)>>,
        reads: AtomicUsize,
    }

    impl Sessions {
        fn holding(hash: &TokenHash, caller: ResolvedCaller) -> Arc<Self> {
            let sessions = Self::default();
            sessions.live.lock().unwrap().push((hash.clone(), caller));
            Arc::new(sessions)
        }

        fn revoke(&self, hash: &TokenHash) {
            self.live.lock().unwrap().retain(|(held, _)| held != hash);
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }

        fn find(&self, hash: &TokenHash) -> Option<ResolvedCaller> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.live
                .lock()
                .unwrap()
                .iter()
                .find(|(held, _)| held == hash)
                .map(|(_, caller)| caller.clone())
        }
    }

    #[async_trait]
    impl TokenLookup for Sessions {
        async fn find_session_by_token_hash(
            &self,
            token_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.find(token_hash))
        }

        async fn find_org_session_by_token_hash(
            &self,
            token_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.find(token_hash))
        }

        async fn find_api_key_by_key_hash(
            &self,
            key_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.find(key_hash))
        }

        async fn find_org_api_key_by_hash(
            &self,
            key_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.find(key_hash))
        }

        async fn find_operator_key_by_hash(
            &self,
            key_hash: &TokenHash,
        ) -> Result<Option<ResolvedCaller>, DomainError> {
            Ok(self.find(key_hash))
        }
    }

    fn ann_in(tenant: TenantId) -> ResolvedCaller {
        ResolvedCaller {
            identity: CallerIdentity::TenantUser(UserId::new()),
            credential: Credential::TenantSession(SessionId::new()),
            organization_id: Some(OrganizationId::new()),
            tenant_id: Some(tenant),
            kept_until: Expiry::Never,
        }
    }

    fn keeping(lifetime: Duration) -> EntryKeeping {
        EntryKeeping {
            lifetime,
            capacity: 100,
        }
    }

    fn caches_on(state: Arc<dyn SharedState>) -> Arc<StoreCaches> {
        Arc::new(StoreCaches::new(state, Duration::from_secs(60)))
    }

    fn revoked_in(tenant: TenantId) -> Change {
        Change::of(
            EventType::parse("authentication.session_revoked").expect("a known event type"),
            Owner::Tenant(*tenant.as_uuid()),
        )
    }

    fn token() -> TokenHash {
        TokenHash::from_stored(format!("digest-{}", uuid::Uuid::now_v7()))
    }

    /// What `lookup` answers to the question `asked` names about `hash`.
    async fn ask(
        lookup: &CacheTokenLookup,
        asked: Asked,
        hash: &TokenHash,
    ) -> Option<ResolvedCaller> {
        let answer = match asked {
            Asked::TenantSession => lookup.find_session_by_token_hash(hash).await,
            Asked::OrgSession => lookup.find_org_session_by_token_hash(hash).await,
            Asked::TenantKey => lookup.find_api_key_by_key_hash(hash).await,
            Asked::OrgKey => lookup.find_org_api_key_by_hash(hash).await,
            Asked::OperatorKey => lookup.find_operator_key_by_hash(hash).await,
        };
        answer.unwrap()
    }

    /// A credential ending in a second is served from the cache until the
    /// second before its end. From the very instant of its end the store
    /// is asked again, and answers no one, however long the entry had left.
    async fn check_served_up_to_its_end_only(asked: Asked) {
        let end = clock::now() + time::Duration::hours(1);
        let frozen = clock::freeze(end - time::Duration::seconds(1));
        let hash = token();
        let holder = ResolvedCaller {
            kept_until: Expiry::At(end),
            ..ann_in(TenantId::new())
        };
        let store = Sessions::holding(&hash, holder);
        let lookup = CacheTokenLookup::new(
            store.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            keeping(Duration::from_secs(60)),
        );
        for _ in 0..3 {
            assert!(ask(&lookup, asked, &hash).await.is_some());
        }
        assert_eq!(store.reads(), 2, "the third use is served from the cache");

        store.revoke(&hash);
        frozen.advance_to(end);

        assert!(ask(&lookup, asked, &hash).await.is_none());
    }

    /// The contractor's key stops at its end, cached or not.
    #[tokio::test]
    async fn a_tenant_key_is_not_served_from_the_cache_from_its_end_on() {
        check_served_up_to_its_end_only(Asked::TenantKey).await;
    }

    /// A company key made for the winter stops at its end, cached or not.
    #[tokio::test]
    async fn an_organization_key_is_not_served_from_the_cache_from_its_end_on() {
        check_served_up_to_its_end_only(Asked::OrgKey).await;
    }

    /// Sam's operator key stops at its end, cached or not.
    #[tokio::test]
    async fn an_operator_key_is_not_served_from_the_cache_from_its_end_on() {
        check_served_up_to_its_end_only(Asked::OperatorKey).await;
    }

    /// Ann's session stops at its end, cached or not.
    #[tokio::test]
    async fn a_tenant_session_is_not_served_from_the_cache_from_its_end_on() {
        check_served_up_to_its_end_only(Asked::TenantSession).await;
    }

    /// A member's session stops at its end, cached or not.
    #[tokio::test]
    async fn an_organization_session_is_not_served_from_the_cache_from_its_end_on() {
        check_served_up_to_its_end_only(Asked::OrgSession).await;
    }

    /// A session asked about again is served from the cache: after the
    /// first read keeps whose it is and the second keeps the caller, the
    /// store is not read again.
    #[tokio::test]
    async fn a_caller_is_served_from_the_cache() {
        let hash = token();
        let store = Sessions::holding(&hash, ann_in(TenantId::new()));
        let lookup = CacheTokenLookup::new(
            store.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            keeping(Duration::from_secs(60)),
        );

        for _ in 0..5 {
            assert!(
                lookup
                    .find_session_by_token_hash(&hash)
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        assert_eq!(store.reads(), 2);
    }

    /// After session revocation and its event, the local cache no longer resolves the bearer.
    #[tokio::test]
    async fn a_revoke_is_seen_at_once_on_the_node_that_made_it() {
        let (hash, acme) = (token(), TenantId::new());
        let store = Sessions::holding(&hash, ann_in(acme));
        let caches = caches_on(Arc::new(MemoryState::new(100)));
        let lookup = CacheTokenLookup::new(
            store.clone(),
            Arc::clone(&caches),
            keeping(Duration::from_secs(60)),
        );
        lookup.find_session_by_token_hash(&hash).await.unwrap();
        lookup.find_session_by_token_hash(&hash).await.unwrap();

        store.revoke(&hash);
        caches.apply(revoked_in(acme)).await;

        assert!(
            lookup
                .find_session_by_token_hash(&hash)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A node sharing versions sees revocation immediately; a node with independent versions
    /// stops resolving the bearer after its cached entry expires.
    #[tokio::test]
    async fn a_revoke_is_seen_elsewhere_within_the_lifetime() {
        let (hash, acme) = (token(), TenantId::new());
        let store = Sessions::holding(&hash, ann_in(acme));
        let shared: Arc<dyn SharedState> = Arc::new(MemoryState::new(100));
        let here = caches_on(Arc::clone(&shared));
        let sharing = CacheTokenLookup::new(
            store.clone(),
            caches_on(shared),
            keeping(Duration::from_secs(60)),
        );
        let apart = CacheTokenLookup::new(
            store.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            keeping(Duration::from_millis(50)),
        );
        for lookup in [&sharing, &apart] {
            lookup.find_session_by_token_hash(&hash).await.unwrap();
            lookup.find_session_by_token_hash(&hash).await.unwrap();
        }

        store.revoke(&hash);
        here.apply(revoked_in(acme)).await;
        let shared_sees = sharing.find_session_by_token_hash(&hash).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let apart_sees = apart.find_session_by_token_hash(&hash).await.unwrap();

        assert!(shared_sees.is_none());
        assert!(apart_sees.is_none());
    }

    /// During a version-store outage, every lookup reaches the credential store
    /// and the revoked session resolves to no caller.
    #[tokio::test]
    async fn a_cache_outage_falls_back_to_the_store() {
        let hash = token();
        let store = Sessions::holding(&hash, ann_in(TenantId::new()));
        let lookup = CacheTokenLookup::new(
            store.clone(),
            caches_on(Arc::new(RefusingState)),
            keeping(Duration::from_secs(60)),
        );
        lookup.find_session_by_token_hash(&hash).await.unwrap();
        lookup.find_session_by_token_hash(&hash).await.unwrap();

        store.revoke(&hash);
        let after = lookup.find_session_by_token_hash(&hash).await.unwrap();

        assert!(after.is_none());
        assert_eq!(store.reads(), 3);
    }

    /// An organization membership-removal event invalidates its tenant credential cache,
    /// causing the next lookup to read the store again.
    #[tokio::test]
    async fn an_organizations_event_drops_its_tenants_credentials_here() {
        let hash = token();
        let ann = ann_in(TenantId::new());
        let organization = *ann.organization_id.unwrap().as_uuid();
        let store = Sessions::holding(&hash, ann);
        let caches = caches_on(Arc::new(MemoryState::new(100)));
        let lookup = CacheTokenLookup::new(
            store.clone(),
            Arc::clone(&caches),
            keeping(Duration::from_secs(60)),
        );
        lookup.find_session_by_token_hash(&hash).await.unwrap();
        lookup.find_session_by_token_hash(&hash).await.unwrap();

        caches
            .apply(Change::of(
                EventType::parse("organization.org_user_deleted").expect("a known event type"),
                Owner::Organization(organization),
            ))
            .await;
        lookup.find_session_by_token_hash(&hash).await.unwrap();

        assert_eq!(store.reads(), 3);
    }
}
