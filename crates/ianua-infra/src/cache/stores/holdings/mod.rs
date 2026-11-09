//! What decides a holder's holdings, kept in this process: read on every
//! request a tenant's caller makes, as a handful of queries in one
//! transaction.
//!
//! Every entry is worked out from links, so it is kept under the tenant's
//! holdings version: the version is read before the store, and any event
//! that changes a link raises it, so every entry worked out from the old
//! links stops being read on every node at once. Each read hands out a
//! fresh copy, rebuilt through the records' own checks. Only a holder's
//! read is kept: the whole tenant's records, several holders' at once and
//! the administrator counts decide changes, and are always read from the
//! store.
//!
//! A read inside a unit of work that holds the tenant's grants, or that
//! changed its links, decides a write: it goes to the store, so it sees
//! every change committed before the hold and the unit's own. When the
//! versions cannot be read, the store is asked and nothing is kept.

mod copies;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    AccessRecordStore, AccessRecords, HeldRecords, Holder, Holders,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::stewardship::AdministratorCount;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, UserId};
use uuid::Uuid;

use self::copies::copied;
use crate::cache::stores::entries::{Entries, EntryKeeping};
use crate::cache::stores::invalidation::StoreCaches;
use crate::cache::stores::owners::{Owner, Owners};
use crate::cache::stores::versions::{Cached, Version};
use crate::cache::stores::writes::{note_held, settling_holdings_of};

/// Whose holdings a read is for: the tenant, the principal, and the roles
/// granted beside their own records, in one order.
#[derive(Clone, PartialEq, Eq, Hash)]
struct HolderKey {
    tenant: Uuid,
    principal: PrincipalRef,
    roles: Vec<Uuid>,
}

impl HolderKey {
    /// The key of `holder`'s read in `tenant`.
    fn of(tenant: Uuid, holder: &Holder<'_>) -> Self {
        let mut roles: Vec<Uuid> = holder
            .granted_roles
            .iter()
            .map(|role| *role.as_uuid())
            .collect();
        roles.sort_unstable();
        roles.dedup();
        Self {
            tenant,
            principal: holder.principal,
            roles,
        }
    }
}

/// One holder's records, as read under a version.
#[derive(Clone)]
struct Held {
    records: Arc<AccessRecords>,
    version: Version,
}

/// The access record store, each holder's records kept in this process.
pub struct CacheAccessRecordStore {
    inner: Arc<dyn AccessRecordStore>,
    caches: Arc<StoreCaches>,
    entries: Arc<Entries<HolderKey, Held>>,
}

impl std::fmt::Debug for CacheAccessRecordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheAccessRecordStore")
            .finish_non_exhaustive()
    }
}

impl CacheAccessRecordStore {
    /// `inner`, each holder's records kept as `keeping` says, among
    /// `caches`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn AccessRecordStore>,
        caches: Arc<StoreCaches>,
        keeping: EntryKeeping,
    ) -> Self {
        let entries = caches.entries(Cached::Holdings, keeping);
        Self {
            inner,
            caches,
            entries,
        }
    }

    /// A copy of the records kept at `key`, when they were kept under
    /// `version`.
    fn served(&self, key: &HolderKey, version: &Version) -> Option<AccessRecords> {
        let seen = self.entries.get(key)?;
        if seen.value.version != *version {
            return None;
        }
        copied(&seen.value.records).ok()
    }

    /// Keeps a copy of `records` at `key` under `version`.
    fn keep(&self, key: HolderKey, records: &AccessRecords, version: Version) {
        let Ok(copy) = copied(records) else {
            return;
        };
        let held = Held {
            records: Arc::new(copy),
            version,
        };
        let owner = Owner::Tenant(key.tenant);
        self.entries.put(key, held, Owners::only(owner));
    }
}

impl TenantScoped for CacheAccessRecordStore {}

#[async_trait]
impl AccessRecordStore for CacheAccessRecordStore {
    async fn load(&self, tenant_id: &ScopedTenant) -> Result<AccessRecords, DomainError> {
        self.inner.load(tenant_id).await
    }

    async fn load_held_by(
        &self,
        tenant_id: &ScopedTenant,
        holder: Holder<'_>,
    ) -> Result<HeldRecords, DomainError> {
        let tenant = *tenant_id.as_uuid();
        let owner = Owner::Tenant(tenant);
        if settling_holdings_of(owner) {
            return self.inner.load_held_by(tenant_id, holder).await;
        }
        let Ok(version) = self
            .caches
            .versions()
            .current(Cached::Holdings, owner)
            .await
        else {
            return self.inner.load_held_by(tenant_id, holder).await;
        };
        let key = HolderKey::of(tenant, &holder);
        if let Some(records) = self.served(&key, &version) {
            return Ok(HeldRecords::new(records));
        }
        let held = self.inner.load_held_by(tenant_id, holder).await?;
        self.keep(key, held.records(), version);
        Ok(held)
    }

    async fn load_held_by_all(
        &self,
        tenant_id: &ScopedTenant,
        holders: Holders<'_>,
    ) -> Result<HeldRecords, DomainError> {
        self.inner.load_held_by_all(tenant_id, holders).await
    }

    async fn count_administrators(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<AdministratorCount, DomainError> {
        self.inner.count_administrators(tenant_id).await
    }

    async fn list_administrators(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<UserId>, DomainError> {
        self.inner.list_administrators(tenant_id, page).await
    }

    async fn list_holders_of(
        &self,
        tenant_id: &ScopedTenant,
        right: SystemPermission,
        page: &PageRequest,
    ) -> Result<Page<UserId>, DomainError> {
        self.inner.list_holders_of(tenant_id, right, page).await
    }

    /// Holds the tenant's grants, and reads its holdings from the store for
    /// the rest of the running unit.
    async fn hold_grants(&self, tenant_id: &ScopedTenant) -> Result<(), DomainError> {
        note_held(Owner::Tenant(*tenant_id.as_uuid()));
        self.inner.hold_grants(tenant_id).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ianua_app::ports::runtime::{Settlement, UnitOfWork, UnitWork};
    use ianua_app::test_support::authorization::{stored_assignment, stored_role};
    use ianua_domain::domains::authorization::permission::RoleAction;
    use ianua_domain::types::{EventType, TenantId};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::state::SharedState;
    use crate::cache::stores::invalidation::Change;
    use crate::cache::stores::versions::RefusingState;
    use crate::cache::stores::writes::CacheUnitOfWork;

    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    /// A store whose holders hold the managing role until it is taken
    /// away, counting every holder's read.
    #[derive(Default)]
    struct Grants {
        taken_away: Mutex<bool>,
        reads: AtomicUsize,
    }

    impl Grants {
        fn take_away(&self) {
            *self.taken_away.lock().unwrap() = true;
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TenantScoped for Grants {}

    #[async_trait]
    impl AccessRecordStore for Grants {
        async fn load(&self, _: &ScopedTenant) -> Result<AccessRecords, DomainError> {
            Ok(AccessRecords::default())
        }

        async fn load_held_by(
            &self,
            _: &ScopedTenant,
            holder: Holder<'_>,
        ) -> Result<HeldRecords, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if *self.taken_away.lock().unwrap() {
                return Ok(HeldRecords::default());
            }
            let manager = stored_role("manager", vec![MANAGE_ROLES], Vec::new());
            Ok(HeldRecords::new(AccessRecords {
                assignments: vec![stored_assignment(holder.principal, *manager.id())],
                roles: vec![manager],
                ..AccessRecords::default()
            }))
        }

        async fn load_held_by_all(
            &self,
            _: &ScopedTenant,
            _: Holders<'_>,
        ) -> Result<HeldRecords, DomainError> {
            Ok(HeldRecords::default())
        }

        async fn count_administrators(
            &self,
            _: &ScopedTenant,
        ) -> Result<AdministratorCount, DomainError> {
            Err(DomainError::infra_msg("not counted in these tests"))
        }

        async fn list_administrators(
            &self,
            _: &ScopedTenant,
            _: &PageRequest,
        ) -> Result<Page<UserId>, DomainError> {
            Err(DomainError::infra_msg("not listed in these tests"))
        }

        async fn list_holders_of(
            &self,
            _: &ScopedTenant,
            _: SystemPermission,
            _: &PageRequest,
        ) -> Result<Page<UserId>, DomainError> {
            Err(DomainError::infra_msg("not listed in these tests"))
        }

        async fn hold_grants(&self, _: &ScopedTenant) -> Result<(), DomainError> {
            Ok(())
        }
    }

    /// A unit of work that runs its work and settles nothing.
    struct Running;

    #[async_trait]
    impl UnitOfWork for Running {
        async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            self.run(work).await
        }

        async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            let _: Settlement = work.await;
            Ok(())
        }
    }

    fn caches_on(state: Arc<dyn SharedState>) -> Arc<StoreCaches> {
        Arc::new(StoreCaches::new(state, Duration::from_secs(60)))
    }

    fn store_over(grants: &Arc<Grants>, caches: &Arc<StoreCaches>) -> CacheAccessRecordStore {
        CacheAccessRecordStore::new(
            Arc::clone(grants) as Arc<dyn AccessRecordStore>,
            Arc::clone(caches),
            EntryKeeping {
                lifetime: Duration::from_secs(60),
                capacity: 100,
            },
        )
    }

    fn acme() -> ScopedTenant {
        ScopedTenant::from_verified_credential(TenantId::new())
    }

    fn holds_manage_roles(records: &HeldRecords) -> bool {
        records
            .records()
            .roles
            .iter()
            .any(|role| role.system_permissions().contains(&MANAGE_ROLES))
    }

    fn revoked_in(tenant: &ScopedTenant) -> Change {
        Change::of(
            EventType::parse("authorization.role_revoked").expect("a known event type"),
            Owner::Tenant(*tenant.as_uuid()),
        )
    }

    /// A holder's records read again are served from the cache, a fresh
    /// copy each time, and the store is read once.
    #[tokio::test]
    async fn a_holders_records_are_served_from_the_cache() {
        let grants = Arc::new(Grants::default());
        let store = store_over(&grants, &caches_on(Arc::new(MemoryState::new(100))));
        let (acme, ann) = (acme(), Holder::user(UserId::new()));

        for _ in 0..3 {
            let records = store.load_held_by(&acme, ann).await.unwrap();
            assert!(holds_manage_roles(&records));
        }

        assert_eq!(grants.reads(), 1);
    }

    /// A role change advances the shared version, so subsequent holdings reads on both nodes
    /// lose the removed role-management right.
    #[tokio::test]
    async fn a_link_change_leaves_every_old_entry_unread() {
        let grants = Arc::new(Grants::default());
        let shared: Arc<dyn SharedState> = Arc::new(MemoryState::new(100));
        let elsewhere = store_over(&grants, &caches_on(Arc::clone(&shared)));
        let here = caches_on(shared);
        let (acme, ann, bob) = (
            acme(),
            Holder::user(UserId::new()),
            Holder::user(UserId::new()),
        );
        elsewhere.load_held_by(&acme, ann).await.unwrap();
        elsewhere.load_held_by(&acme, bob).await.unwrap();

        grants.take_away();
        here.apply(revoked_in(&acme)).await;
        let ann_now = elsewhere.load_held_by(&acme, ann).await.unwrap();
        let bob_now = elsewhere.load_held_by(&acme, bob).await.unwrap();

        assert!(!holds_manage_roles(&ann_now));
        assert!(!holds_manage_roles(&bob_now));
        assert_eq!(grants.reads(), 4);
    }

    /// Holdings reads inside a unit holding the tenant's grants bypass the cached result
    /// and consult the store each time.
    #[tokio::test]
    async fn a_read_after_the_hold_goes_to_the_store() {
        let grants = Arc::new(Grants::default());
        let caches = caches_on(Arc::new(MemoryState::new(100)));
        let store = store_over(&grants, &caches);
        let unit = CacheUnitOfWork::new(Arc::new(Running), Arc::clone(&caches));
        let (acme, ann) = (acme(), Holder::user(UserId::new()));
        store.load_held_by(&acme, ann).await.unwrap();

        let (store, tenant) = (&store, &acme);
        unit.run(Box::pin(async move {
            store.hold_grants(tenant).await.unwrap();
            store.load_held_by(tenant, ann).await.unwrap();
            store.load_held_by(tenant, ann).await.unwrap();
            Settlement::Commit
        }))
        .await
        .unwrap();

        assert_eq!(grants.reads(), 3);
    }

    /// A version-store outage forces fresh holdings reads, making the removed role visible immediately.
    #[tokio::test]
    async fn a_cache_outage_falls_back_to_the_store() {
        let grants = Arc::new(Grants::default());
        let store = store_over(&grants, &caches_on(Arc::new(RefusingState)));
        let (acme, ann) = (acme(), Holder::user(UserId::new()));
        store.load_held_by(&acme, ann).await.unwrap();

        grants.take_away();
        let after = store.load_held_by(&acme, ann).await.unwrap();

        assert!(!holds_manage_roles(&after));
        assert_eq!(grants.reads(), 2);
    }
}
