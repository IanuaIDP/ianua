//! In-memory separation-of-duties rules and clearance rules.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::separation::SeparationRule;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{Label, SeparationRuleId, TenantId};

use crate::ports::TenantScoped;
use crate::ports::authorization::{ClearanceRuleStore, SeparationRuleStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authorization::copies::{copy_clearance, copy_separation_rule};

/// A rule named `name` keeping `first` and `second` apart, declared by
/// someone a test does not name.
#[must_use]
pub fn separation_between(
    name: &str,
    first: &Role<ResolvedTenant>,
    second: &Role<ResolvedTenant>,
) -> SeparationRule<ResolvedTenant> {
    let by = anyone_holding(SystemPermission::all());
    SeparationRule::declare(
        Label::new("rule_name", name).expect("a valid rule name"),
        first,
        second,
        by,
    )
    .expect("two roles are kept apart")
}

/// In-memory separation rule store, tenant by tenant.
#[derive(Default)]
pub struct FakeSeparationRuleStore {
    rules: Mutex<Vec<(TenantId, SeparationRule<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSeparationRuleStore {}

impl FakeSeparationRuleStore {
    /// A store holding no rule.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `rules` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        rules: impl IntoIterator<Item = SeparationRule<ResolvedTenant>>,
    ) -> Self {
        Self {
            rules: Mutex::new(rules.into_iter().map(|rule| (tenant_id, rule)).collect()),
        }
    }

    /// How many rules are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rules.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&SeparationRule<ResolvedTenant>) -> bool,
    ) -> Result<Vec<SeparationRule<ResolvedTenant>>, DomainError> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, rule)| *tenant == tenant_id && keep(rule))
            .map(|(_, rule)| copy_separation_rule(rule))
            .collect()
    }
}

#[async_trait]
impl SeparationRuleStore for FakeSeparationRuleStore {
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SeparationRule<ResolvedTenant>>, DomainError> {
        self.matching(**tenant_id, |_| true)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SeparationRuleId,
    ) -> Result<Option<SeparationRule<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |rule| rule.id() == id)?.pop())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule: &SeparationRule<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_separation_rule(rule)?;
        self.rules.lock().unwrap().push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SeparationRuleId,
    ) -> Result<(), DomainError> {
        self.rules
            .lock()
            .unwrap()
            .retain(|(tenant, rule)| !(*tenant == **tenant_id && rule.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn SeparationRuleStore> {
    fn fake() -> Self {
        Arc::new(FakeSeparationRuleStore::empty())
    }
}

/// In-memory clearance rules, one record per tenant.
#[derive(Default)]
pub struct FakeClearanceRuleStore {
    rules: Mutex<Vec<(TenantId, ClearanceRules<ResolvedTenant>)>>,
}

impl TenantScoped for FakeClearanceRuleStore {}

impl FakeClearanceRuleStore {
    /// A store holding no tenant's rules.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// `tenant_id`'s rules as stored, if any were.
    #[must_use]
    pub fn stored(&self, tenant_id: TenantId) -> Option<ClearanceRules<ResolvedTenant>> {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, _)| *tenant == tenant_id)
            .and_then(|(_, rules)| copy_clearance(rules).ok())
    }
}

#[async_trait]
impl ClearanceRuleStore for FakeClearanceRuleStore {
    async fn load(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClearanceRules<ResolvedTenant>>, DomainError> {
        let rules = self.rules.lock().unwrap();
        let Some((_, held)) = rules.iter().find(|(tenant, _)| *tenant == **tenant_id) else {
            return Ok(None);
        };
        copy_clearance(held).map(Some)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rules: &ClearanceRules<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_clearance(rules)?;
        let mut held = self.rules.lock().unwrap();
        held.retain(|(tenant, _)| *tenant != **tenant_id);
        held.push((**tenant_id, copy));
        Ok(())
    }
}

impl Fake for Arc<dyn ClearanceRuleStore> {
    fn fake() -> Self {
        Arc::new(FakeClearanceRuleStore::empty())
    }
}
