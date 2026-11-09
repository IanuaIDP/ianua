//! A tenant's classification rule set, kept in this process for a short
//! while: the gateway reads it for every answer its Data classify and
//! Redact stages run on.
//!
//! It is kept under the tenant's version of its rules, which every rule
//! added, changed or removed raises, so a field marked restricted a moment
//! ago is redacted on every node at once. A tenant with no rule set is kept
//! too: the first rule raises the version. When the versions cannot be
//! read, the store is asked and nothing is kept. Saving passes straight to
//! the store; its events drop what is kept.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::data_classification::ClassificationStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSet, ClassificationRuleSetRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ClassificationRuleSetId, TenantId};
use time::OffsetDateTime;

use crate::cache::stores::entries::{Entries, EntryKeeping};
use crate::cache::stores::invalidation::StoreCaches;
use crate::cache::stores::owners::{Owner, Owners};
use crate::cache::stores::versions::{Cached, Version};

/// How long a rule set is served from here at the most.
const KEPT_FOR: Duration = Duration::from_secs(30);

/// A rule set as it was read: the set itself is rebuilt from it on every
/// hit, so nothing it raises is ever shared between two readers.
#[derive(Clone)]
struct KeptRules {
    id: ClassificationRuleSetId,
    rules: Vec<ClassificationRule>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl KeptRules {
    fn of(set: &ClassificationRuleSet<ResolvedTenant>) -> Self {
        Self {
            id: *set.id(),
            rules: set.rules().to_vec(),
            created_at: set.created_at(),
            updated_at: set.updated_at(),
        }
    }

    fn rebuilt(self) -> Result<ClassificationRuleSet<ResolvedTenant>, DomainError> {
        ClassificationRuleSet::reconstitute(ClassificationRuleSetRow {
            id: self.id,
            rules: self.rules,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// What was read, and the version it was read at.
#[derive(Clone)]
struct Kept {
    version: Version,
    rules: Option<KeptRules>,
}

/// Tenants' classification rule sets, kept in this process.
pub struct CacheClassificationStore {
    inner: Arc<dyn ClassificationStore>,
    caches: Arc<StoreCaches>,
    entries: Arc<Entries<TenantId, Kept>>,
}

impl std::fmt::Debug for CacheClassificationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheClassificationStore")
            .finish_non_exhaustive()
    }
}

impl CacheClassificationStore {
    /// `inner`, the rule sets of at most `capacity` tenants kept for a few
    /// seconds, among `caches`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn ClassificationStore>,
        caches: Arc<StoreCaches>,
        capacity: usize,
    ) -> Self {
        let keeping = EntryKeeping {
            lifetime: KEPT_FOR,
            capacity,
        };
        let entries = caches.entries(Cached::Classifications, keeping);
        Self {
            inner,
            caches,
            entries,
        }
    }

    /// What is kept for `tenant` at `version`, when anything is.
    fn kept(&self, tenant: TenantId, version: &Version) -> Option<Kept> {
        self.entries
            .get(&tenant)
            .map(|seen| seen.value)
            .filter(|kept| &kept.version == version)
    }
}

impl TenantScoped for CacheClassificationStore {}

#[async_trait]
impl ClassificationStore for CacheClassificationStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, DomainError> {
        let owner = Owner::Tenant(*tenant_id.as_uuid());
        let versions = self.caches.versions();
        let Ok(version) = versions.current(Cached::Classifications, owner).await else {
            return self.inner.find(tenant_id).await;
        };
        if let Some(kept) = self.kept(**tenant_id, &version) {
            return kept.rules.map(KeptRules::rebuilt).transpose();
        }
        let found = self.inner.find(tenant_id).await?;
        let kept = Kept {
            version,
            rules: found.as_ref().map(KeptRules::of),
        };
        self.entries.put(**tenant_id, kept, Owners::only(owner));
        Ok(found)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule_set: &ClassificationRuleSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.inner.save(tenant_id, rule_set).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ianua_domain::domains::data_classification::classification::RedactionStrategy;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{EventType, FieldPath};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::state::SharedState;
    use crate::cache::stores::invalidation::Change;
    use crate::cache::stores::versions::RefusingState;

    /// A store holding one rule set made of the paths it is told, counting
    /// every read.
    struct Rules {
        id: ClassificationRuleSetId,
        paths: Mutex<Vec<&'static str>>,
        reads: AtomicUsize,
    }

    impl Rules {
        fn holding(paths: &[&'static str]) -> Arc<Self> {
            Arc::new(Self {
                id: ClassificationRuleSetId::new(),
                paths: Mutex::new(paths.to_vec()),
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TenantScoped for Rules {}

    #[async_trait]
    impl ClassificationStore for Rules {
        async fn find(
            &self,
            _: &ScopedTenant,
        ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let paths = self.paths.lock().unwrap().clone();
            if paths.is_empty() {
                return Ok(None);
            }
            let now = clock::now();
            ClassificationRuleSet::reconstitute(ClassificationRuleSetRow {
                id: self.id,
                rules: paths.into_iter().map(rule).collect(),
                created_at: now,
                updated_at: now,
            })
            .map(Some)
        }

        async fn save(
            &self,
            _: &ScopedTenant,
            _: &ClassificationRuleSet<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    fn rule(path: &str) -> ClassificationRule {
        ClassificationRule::new(
            FieldPath::new(path).unwrap(),
            DataClassLevel::Restricted,
            RedactionStrategy::Hash,
        )
    }

    fn caches_on(state: Arc<dyn SharedState>) -> Arc<StoreCaches> {
        Arc::new(StoreCaches::new(state, Duration::from_secs(600)))
    }

    fn caches() -> Arc<StoreCaches> {
        caches_on(Arc::new(MemoryState::new(100)))
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_background(TenantId::new())
    }

    fn paths(set: &ClassificationRuleSet<ResolvedTenant>) -> Vec<&str> {
        set.rules()
            .iter()
            .map(|rule| rule.field_path().as_str())
            .collect()
    }

    /// A rule set asked for again is served from here, whole.
    #[tokio::test]
    async fn a_rule_set_is_served_from_here() {
        let store = Rules::holding(&["user.ssn"]);
        let cached = CacheClassificationStore::new(store.clone(), caches(), 100);
        let acme = tenant();

        cached.find(&acme).await.unwrap();
        let again = cached.find(&acme).await.unwrap().unwrap();

        assert_eq!(paths(&again), ["user.ssn"]);
        assert_eq!(again.id(), &store.id);
        assert_eq!(store.reads(), 1);
    }

    /// A classification-change event triggers a new store read that includes the newly restricted email path.
    #[tokio::test]
    async fn a_changed_rule_is_read_again() {
        let store = Rules::holding(&["user.ssn"]);
        let caches = caches();
        let cached = CacheClassificationStore::new(store.clone(), Arc::clone(&caches), 100);
        let acme = tenant();
        cached.find(&acme).await.unwrap();

        store.paths.lock().unwrap().push("user.email");
        let added = EventType::parse("proxy.classification_rule_added").unwrap();
        caches
            .apply(Change::of(added, Owner::Tenant(*acme.as_uuid())))
            .await;
        let after = cached.find(&acme).await.unwrap().unwrap();

        assert_eq!(paths(&after), ["user.ssn", "user.email"]);
        assert_eq!(store.reads(), 2);
    }

    /// A tenant with no rules is kept as having none until its first rule
    /// raises the version.
    #[tokio::test]
    async fn no_rule_set_is_kept_until_the_first_rule() {
        let store = Rules::holding(&[]);
        let caches = caches();
        let cached = CacheClassificationStore::new(store.clone(), Arc::clone(&caches), 100);
        let acme = tenant();

        let first = cached.find(&acme).await.unwrap();
        let again = cached.find(&acme).await.unwrap();
        store.paths.lock().unwrap().push("user.ssn");
        let added = EventType::parse("proxy.classification_rule_added").unwrap();
        caches
            .apply(Change::of(added, Owner::Tenant(*acme.as_uuid())))
            .await;
        let after = cached.find(&acme).await.unwrap();

        assert!(first.is_none() && again.is_none());
        assert!(after.is_some());
        assert_eq!(store.reads(), 2);
    }

    /// Without shared versions, each classification lookup reads the store again.
    #[tokio::test]
    async fn without_the_versions_the_store_is_asked_every_time() {
        let store = Rules::holding(&["user.ssn"]);
        let cached =
            CacheClassificationStore::new(store.clone(), caches_on(Arc::new(RefusingState)), 100);
        let acme = tenant();

        cached.find(&acme).await.unwrap();
        cached.find(&acme).await.unwrap();

        assert_eq!(store.reads(), 2);
    }
}
