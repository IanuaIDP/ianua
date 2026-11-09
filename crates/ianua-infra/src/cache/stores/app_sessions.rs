//! Whether an app session is live, kept in this process for a few seconds:
//! the gateway asks on every request carrying an app session cookie, and
//! the store's answer is a read and, now and then, a write.
//!
//! Only a live answer is kept, under the tenant's version of the callers
//! it was read at; a session that is not live is never kept, so a session
//! ended a moment ago is asked about again on every request. An entry is
//! served only while the tenant's version still is the one it was kept
//! under, so the events that end a session (signing out, an
//! administrator's revoke, a password change) drop it on every node at
//! once, and it lapses after its lifetime, [`KEPT_FOR`] unless the
//! deployment sets another, whatever happens. An entry is never served at
//! or past the moment the session was read to stop counting, its absolute
//! end or the end of its idle time, so a session ending is not kept alive
//! by a copy. Reaching that moment only asks the store again, which sees
//! what use has since moved. When the versions cannot be read, the store
//! is asked and nothing is kept.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{AppSessionCheck, AppSessionClaim};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ServiceId, SessionId, TenantId, UserId};
use time::OffsetDateTime;

use crate::cache::stores::entries::{Entries, EntryKeeping};
use crate::cache::stores::invalidation::StoreCaches;
use crate::cache::stores::owners::{Owner, Owners};
use crate::cache::stores::versions::{Cached, Version};

/// How long a live answer is served from here at the most.
const KEPT_FOR: Duration = Duration::from_secs(5);

/// A claim on one tenant's session, as it was asked about.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    tenant: TenantId,
    session: SessionId,
    user: UserId,
    service: ServiceId,
    idle_timeout: Option<Duration>,
}

impl SessionKey {
    fn of(tenant_id: &ScopedTenant, claim: &AppSessionClaim) -> Self {
        Self {
            tenant: **tenant_id,
            session: claim.session_id,
            user: claim.user_id,
            service: claim.service_id,
            idle_timeout: claim.idle_timeout,
        }
    }
}

/// A live answer kept, with the version it was read at and the moment the
/// store said the session stops counting.
#[derive(Clone)]
struct KeptAnswer {
    version: Version,
    until: OffsetDateTime,
}

/// The check of app sessions, its live answers kept in this process.
pub struct CacheAppSessionCheck {
    inner: Arc<dyn AppSessionCheck>,
    caches: Arc<StoreCaches>,
    entries: Arc<Entries<SessionKey, KeptAnswer>>,
}

impl std::fmt::Debug for CacheAppSessionCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheAppSessionCheck")
            .finish_non_exhaustive()
    }
}

impl CacheAppSessionCheck {
    /// `inner`, at most `capacity` of its live answers kept for a few
    /// seconds, among `caches`.
    #[must_use]
    pub fn new(inner: Arc<dyn AppSessionCheck>, caches: Arc<StoreCaches>, capacity: usize) -> Self {
        let keeping = EntryKeeping {
            lifetime: KEPT_FOR,
            capacity,
        };
        Self::keeping(inner, caches, keeping)
    }

    /// `inner`, its live answers kept as `keeping` says, among `caches`:
    /// for a deployment that sets how long a signed-out session may still
    /// be served.
    #[must_use]
    pub fn keeping(
        inner: Arc<dyn AppSessionCheck>,
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
}

impl TenantScoped for CacheAppSessionCheck {}

#[async_trait]
impl AppSessionCheck for CacheAppSessionCheck {
    async fn live_until(
        &self,
        tenant_id: &ScopedTenant,
        claim: &AppSessionClaim,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let owner = Owner::Tenant(*tenant_id.as_uuid());
        let Ok(version) = self.caches.versions().current(Cached::Callers, owner).await else {
            return self.inner.live_until(tenant_id, claim).await;
        };
        let key = SessionKey::of(tenant_id, claim);
        let kept = self.entries.get(&key);
        if let Some(seen) =
            kept.filter(|seen| seen.value.version == version && clock::now() < seen.value.until)
        {
            return Ok(Some(seen.value.until));
        }
        let Some(until) = self.inner.live_until(tenant_id, claim).await? else {
            self.entries.remove(&key);
            return Ok(None);
        };
        let kept = KeptAnswer { version, until };
        self.entries.put(key, kept, Owners::only(owner));
        Ok(Some(until))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ianua_domain::types::{EventType, Fact};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::state::SharedState;
    use crate::cache::stores::invalidation::Change;
    use crate::cache::stores::versions::RefusingState;

    /// A check answering whether the one session it knows is live, counting
    /// every read.
    struct Sessions {
        live: AtomicBool,
        until: OffsetDateTime,
        reads: AtomicUsize,
    }

    impl Sessions {
        fn answering(live: bool) -> Arc<Self> {
            Self::ending_at(live, clock::now() + time::Duration::hours(1))
        }

        fn ending_at(live: bool, until: OffsetDateTime) -> Arc<Self> {
            Arc::new(Self {
                live: AtomicBool::new(live),
                until,
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TenantScoped for Sessions {}

    #[async_trait]
    impl AppSessionCheck for Sessions {
        async fn live_until(
            &self,
            _: &ScopedTenant,
            _: &AppSessionClaim,
        ) -> Result<Option<OffsetDateTime>, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.live.load(Ordering::SeqCst).then_some(self.until))
        }
    }

    fn caches_on(state: Arc<dyn SharedState>) -> Arc<StoreCaches> {
        Arc::new(StoreCaches::new(state, Duration::from_secs(60)))
    }

    fn claim() -> AppSessionClaim {
        AppSessionClaim {
            session_id: SessionId::new(),
            user_id: UserId::new(),
            service_id: ServiceId::new(),
            idle_timeout: Some(Duration::from_secs(900)),
            signed_in_from: Fact::Unknown,
        }
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_background(TenantId::new())
    }

    /// A live session asked about again within its few seconds is answered
    /// from here, without the store.
    #[tokio::test]
    async fn a_live_session_is_answered_from_here() {
        let sessions = Sessions::answering(true);
        let check = CacheAppSessionCheck::new(
            sessions.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            100,
        );
        let (tenant, claim) = (tenant(), claim());

        let first = check.is_live(&tenant, &claim).await.unwrap();
        let second = check.is_live(&tenant, &claim).await.unwrap();

        assert!(first && second);
        assert_eq!(sessions.reads(), 1);
    }

    /// Pat's session is read to stop counting at an instant, well inside the
    /// entry's lifetime. Up to the second before it, the kept answer is
    /// served. At that very instant the store is asked again and answers
    /// that it ended, though the entry had time left.
    #[tokio::test]
    async fn a_live_answer_is_not_served_from_the_sessions_end_on() {
        let end = clock::now() + time::Duration::hours(1);
        let frozen = clock::freeze(end - time::Duration::seconds(1));
        let sessions = Sessions::ending_at(true, end);
        let check = CacheAppSessionCheck::new(
            sessions.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            100,
        );
        let (tenant, claim) = (tenant(), claim());
        for _ in 0..3 {
            assert_eq!(check.live_until(&tenant, &claim).await.unwrap(), Some(end));
        }
        assert_eq!(sessions.reads(), 1, "only the first check reads the store");

        sessions.live.store(false, Ordering::SeqCst);
        frozen.advance_to(end);

        assert_eq!(check.live_until(&tenant, &claim).await.unwrap(), None);
    }

    /// An ended session is not cached: two checks both return false and each reads the store.
    #[tokio::test]
    async fn an_ended_session_is_never_kept() {
        let sessions = Sessions::answering(false);
        let check = CacheAppSessionCheck::new(
            sessions.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            100,
        );
        let (tenant, claim) = (tenant(), claim());

        let first = check.is_live(&tenant, &claim).await.unwrap();
        let second = check.is_live(&tenant, &claim).await.unwrap();

        assert!(!first && !second);
        assert_eq!(sessions.reads(), 2);
    }

    /// Applying a revocation event forces another store read, which observes that the session has ended.
    #[tokio::test]
    async fn a_revoked_session_is_asked_about_again() {
        let sessions = Sessions::answering(true);
        let caches = caches_on(Arc::new(MemoryState::new(100)));
        let check = CacheAppSessionCheck::new(sessions.clone(), Arc::clone(&caches), 100);
        let (tenant, claim) = (tenant(), claim());
        check.is_live(&tenant, &claim).await.unwrap();

        sessions.live.store(false, Ordering::SeqCst);
        let revoked = EventType::parse("authentication.session_revoked").unwrap();
        caches
            .apply(Change::of(revoked, Owner::Tenant(*tenant.as_uuid())))
            .await;
        let after = check.is_live(&tenant, &claim).await.unwrap();

        assert!(!after);
        assert_eq!(sessions.reads(), 2);
    }

    /// When shared versions are unavailable, repeated session checks each consult the store.
    #[tokio::test]
    async fn without_the_versions_the_store_is_asked_every_time() {
        let sessions = Sessions::answering(true);
        let caches = caches_on(Arc::new(RefusingState));
        let check = CacheAppSessionCheck::new(sessions.clone(), caches, 100);
        let (tenant, claim) = (tenant(), claim());

        check.is_live(&tenant, &claim).await.unwrap();
        check.is_live(&tenant, &claim).await.unwrap();

        assert_eq!(sessions.reads(), 2);
    }

    /// Another tenant's session of the same ids is not answered from this
    /// tenant's entry.
    #[tokio::test]
    async fn an_entry_answers_for_its_tenant_only() {
        let sessions = Sessions::answering(true);
        let check = CacheAppSessionCheck::new(
            sessions.clone(),
            caches_on(Arc::new(MemoryState::new(100))),
            100,
        );
        let claim = claim();

        check.is_live(&tenant(), &claim).await.unwrap();
        check.is_live(&tenant(), &claim).await.unwrap();

        assert_eq!(sessions.reads(), 2);
    }
}
