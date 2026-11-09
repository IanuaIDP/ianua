//! In-memory access policies, every version of each tenant's.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::condition::PolicyCondition;
use ianua_domain::domains::authorization::policy::review::{OtherApprovers, PolicyApprover};
use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::status::PolicyStatus;
use ianua_domain::domains::authorization::policy::version::{
    DraftStart, PolicyHistory, PolicyVersion, Replacing,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{Label, PathPrefix, TenantId, Text};

use crate::ports::TenantScoped;
use crate::ports::authorization::PolicyStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// The rule `block-admin`, which denies every path under `/admin`.
#[must_use]
pub fn block_admin_rule() -> PolicyRule {
    PolicyRule::new(
        Label::new("rule_name", "block-admin").expect("a valid rule name"),
        vec![PolicyCondition::PathPrefix(
            PathPrefix::new("/admin").expect("a valid prefix"),
        )],
        PolicyAction::Deny {
            reason: Text::new("reason", "admin blocked").expect("a valid reason"),
        },
        10,
    )
    .expect("a valid rule")
}

/// A first version holding `rules` that allows what they do not match,
/// moved to `status` the way people move it, by someone a test does not
/// name.
#[must_use]
pub fn policy_in(status: PolicyStatus, rules: Vec<PolicyRule>) -> PolicySet {
    let by = anyone_holding(&[SystemPermission::ManagePolicy]);
    let mut policy = PolicySet::permissive();
    for rule in rules {
        policy.add_rule(rule, by).expect("a draft takes rules");
    }
    let moved = match status {
        PolicyStatus::Draft => Ok(()),
        PolicyStatus::Review => policy.submit_for_review(by),
        PolicyStatus::Active => policy.submit_for_review(by).and_then(|()| {
            policy.activate(
                Replacing::NothingLive,
                &PolicyApprover::assumed(by, OtherApprovers::NoneInTenant),
            )
        }),
        PolicyStatus::Archived => policy.archive(by),
    };
    moved.expect("a draft moves to any state");
    policy
}

/// A draft copied from the live version `live`, opened beside it by
/// someone a test does not name.
#[must_use]
pub fn draft_beside(live: &PolicySet) -> PolicySet {
    let by = anyone_holding(&[SystemPermission::ManagePolicy]);
    let versions = [live.clone()];
    let history = PolicyHistory::of(&versions).expect("one version is a consistent history");
    PolicySet::start_draft(&history, DraftStart::FromLive, by).expect("a live version is copied")
}

/// In-memory policy store holding every version of each tenant's policy,
/// keyed by its number, as the real store does.
#[derive(Default)]
pub struct FakePolicyStore {
    versions: Mutex<Vec<(TenantId, PolicySet)>>,
}

impl TenantScoped for FakePolicyStore {}

impl FakePolicyStore {
    /// A store holding no policy.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `policy` as `tenant_id`'s only version.
    #[must_use]
    pub fn holding(tenant_id: TenantId, policy: PolicySet) -> Self {
        Self::holding_versions(tenant_id, [policy])
    }

    /// A store already holding `versions` as `tenant_id`'s.
    #[must_use]
    pub fn holding_versions(
        tenant_id: TenantId,
        versions: impl IntoIterator<Item = PolicySet>,
    ) -> Self {
        Self {
            versions: Mutex::new(
                versions
                    .into_iter()
                    .map(|policy| (tenant_id, policy))
                    .collect(),
            ),
        }
    }

    /// `tenant_id`'s newest version, whatever state it is in.
    #[must_use]
    pub fn stored(&self, tenant_id: TenantId) -> Option<PolicySet> {
        self.versions_of(tenant_id)
            .into_iter()
            .max_by_key(PolicySet::version)
    }

    /// `tenant_id`'s version numbered `version`.
    #[must_use]
    pub fn version(&self, tenant_id: TenantId, version: PolicyVersion) -> Option<PolicySet> {
        self.versions_of(tenant_id)
            .into_iter()
            .find(|policy| policy.version() == version)
    }

    /// Every version held for `tenant_id`.
    #[must_use]
    pub fn versions_of(&self, tenant_id: TenantId) -> Vec<PolicySet> {
        self.versions
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, _)| *tenant == tenant_id)
            .map(|(_, policy)| policy.clone())
            .collect()
    }

    fn put(&self, tenant_id: TenantId, policy: &PolicySet) {
        let mut versions = self.versions.lock().unwrap();
        versions
            .retain(|(tenant, held)| !(*tenant == tenant_id && held.version() == policy.version()));
        versions.push((tenant_id, policy.clone()));
    }
}

#[async_trait]
impl PolicyStore for FakePolicyStore {
    async fn find_versions(&self, tenant_id: &ScopedTenant) -> Result<Vec<PolicySet>, DomainError> {
        Ok(self.versions_of(**tenant_id))
    }

    async fn find_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<PolicySet>, DomainError> {
        Ok(self
            .versions_of(**tenant_id)
            .into_iter()
            .find(|policy| policy.status() == PolicyStatus::Active))
    }

    async fn save(&self, tenant_id: &ScopedTenant, policy: &PolicySet) -> Result<(), DomainError> {
        self.put(**tenant_id, policy);
        Ok(())
    }

    async fn save_activation(
        &self,
        tenant_id: &ScopedTenant,
        activated: &PolicySet,
        replaced: Option<&PolicySet>,
    ) -> Result<(), DomainError> {
        if let Some(replaced) = replaced {
            self.put(**tenant_id, replaced);
        }
        self.put(**tenant_id, activated);
        Ok(())
    }
}

impl Fake for Arc<dyn PolicyStore> {
    fn fake() -> Self {
        Arc::new(FakePolicyStore::empty())
    }
}
