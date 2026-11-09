//! Fakes for the data classification port: a store that keeps each tenant's
//! rule set in memory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSet, ClassificationRuleSetRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ClassificationRuleSetId, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::data_classification::{ClassificationStore, RedactionDigest};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// A digest for tests: the value's length and first character, enough to
/// tell a digested field from its value.
pub struct FakeRedactionDigest;

impl RedactionDigest for FakeRedactionDigest {
    fn digest(&self, _tenant_id: &TenantId, value: &[u8]) -> String {
        format!("digest-{}", value.len())
    }
}

impl Fake for Arc<dyn RedactionDigest> {
    fn fake() -> Self {
        Arc::new(FakeRedactionDigest)
    }
}

/// In-memory classification store: keeps the last rule set saved for each
/// tenant and hands it back to that tenant only.
#[derive(Default)]
pub struct FakeClassificationStore {
    rule_sets: Mutex<HashMap<TenantId, StoredRuleSet>>,
}

impl TenantScoped for FakeClassificationStore {}

impl FakeClassificationStore {
    /// A store holding no rule set for any tenant.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `rule_set` for `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, rule_set: &ClassificationRuleSet<ResolvedTenant>) -> Self {
        let store = Self::empty();
        store
            .rule_sets
            .lock()
            .unwrap()
            .insert(tenant, StoredRuleSet::of(rule_set));
        store
    }

    /// A store holding a rule set of `rules` for `tenant`, as it was saved
    /// earlier.
    #[must_use]
    pub fn with_rules(tenant: TenantId, rules: Vec<ClassificationRule>) -> Self {
        let now = clock::now();
        let stored = StoredRuleSet {
            id: ClassificationRuleSetId::new(),
            rules,
            created_at: now,
            updated_at: now,
        };
        let store = Self::empty();
        store.rule_sets.lock().unwrap().insert(tenant, stored);
        store
    }

    /// The rules last saved for `tenant`, in evaluation order, or none.
    #[must_use]
    pub fn rules_of(&self, tenant: &TenantId) -> Vec<ClassificationRule> {
        self.rule_sets
            .lock()
            .unwrap()
            .get(tenant)
            .map(|stored| stored.rules.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl ClassificationStore for FakeClassificationStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, DomainError> {
        self.rule_sets
            .lock()
            .unwrap()
            .get(&**tenant_id)
            .map(StoredRuleSet::rule_set)
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule_set: &ClassificationRuleSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.rule_sets
            .lock()
            .unwrap()
            .insert(**tenant_id, StoredRuleSet::of(rule_set));
        Ok(())
    }
}

impl Fake for Arc<dyn ClassificationStore> {
    fn fake() -> Self {
        Arc::new(FakeClassificationStore::empty())
    }
}

/// A rule set as the fake keeps it, read back through the domain's
/// `reconstitute` as a real store would.
struct StoredRuleSet {
    id: ClassificationRuleSetId,
    rules: Vec<ClassificationRule>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl StoredRuleSet {
    fn of(rule_set: &ClassificationRuleSet<ResolvedTenant>) -> Self {
        Self {
            id: *rule_set.id(),
            rules: rule_set.rules().to_vec(),
            created_at: rule_set.created_at(),
            updated_at: rule_set.updated_at(),
        }
    }

    fn rule_set(&self) -> Result<ClassificationRuleSet<ResolvedTenant>, DomainError> {
        ClassificationRuleSet::reconstitute(ClassificationRuleSetRow {
            id: self.id,
            rules: self.rules.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}
