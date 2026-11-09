//! Describe delegations: what an administrator reads beside each one.
//!
//! A delegation names its delegator by id and its budget by limit. A listing
//! shows the delegator's name and how much of the budget is spent, and both
//! live elsewhere: the name with the principal, the usage in the counter the
//! proxy keeps. Both are best effort: a principal that no longer exists, or a
//! counter that cannot be reached, leaves the field empty and never fails the
//! listing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::PrincipalRef;

use crate::ports::agents::{AgentStore, BudgetUsageReader};
use crate::ports::identity::UserStore;
use crate::ports::organization::OrgUserStore;
use crate::tenancy::ScopedTenant;

/// A delegation with what an administrator reads beside it.
pub struct DescribedDelegation {
    /// The stored grant, including its capabilities and constraints.
    pub delegation: Delegation<ResolvedTenant>,
    /// The delegator's display name, or `None` when the principal no longer
    /// exists or is a kind nothing names yet.
    pub delegator_name: Option<String>,
    /// Requests counted against its budget in the current window, for a
    /// budgeted delegation whose counter answered.
    pub used_requests: Option<u32>,
}

/// Ports needed to describe delegations.
#[derive(ianua_macros::Fakes)]
pub struct DescribeDelegationsPorts {
    /// Port for naming tenant users.
    pub user_store: Arc<dyn UserStore>,
    /// Port for naming the organization's own people.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Port for naming agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// Port for reading how much of a budget is spent.
    pub budget_usage: Arc<dyn BudgetUsageReader>,
}

/// Describes delegations for listings.
pub struct DescribeDelegations {
    ports: DescribeDelegationsPorts,
}

impl DescribeDelegations {
    /// Creates a describer.
    #[must_use]
    pub fn new(ports: DescribeDelegationsPorts) -> Self {
        Self { ports }
    }

    /// Each delegation with its delegator's name and its budget usage.
    ///
    /// Delegators are named in one batch per principal kind.
    /// Neither a missing name nor an unreachable counter fails it.
    pub async fn describe(
        &self,
        tenant: &ScopedTenant,
        delegations: Vec<Delegation<ResolvedTenant>>,
    ) -> Vec<DescribedDelegation> {
        let names = self.names_of(tenant, &delegations).await;
        let mut described = Vec::with_capacity(delegations.len());

        for delegation in delegations {
            let delegator = *delegation.delegator();
            let delegator_name = names.get(&delegator).cloned();
            let used_requests = self.used_requests(&delegation).await;
            described.push(DescribedDelegation {
                delegator_name,
                used_requests,
                delegation,
            });
        }

        described
    }

    /// Names distinct delegators without letting a failed source hide names
    /// supplied by another kind of principal.
    async fn names_of(
        &self,
        tenant: &ScopedTenant,
        delegations: &[Delegation<ResolvedTenant>],
    ) -> HashMap<PrincipalRef, String> {
        let principals: HashSet<_> = delegations
            .iter()
            .map(|delegation| *delegation.delegator())
            .collect();
        let mut names = self.user_names(tenant, &principals).await;
        names.extend(self.member_names(&principals).await);
        names.extend(self.agent_names(tenant, &principals).await);
        names
    }

    /// Names tenant users in one read, leaving absent or unreadable names empty.
    async fn user_names(
        &self,
        tenant: &ScopedTenant,
        principals: &HashSet<PrincipalRef>,
    ) -> HashMap<PrincipalRef, String> {
        let ids: Vec<_> = principals
            .iter()
            .filter_map(|principal| match principal {
                PrincipalRef::User(id) => Some(*id),
                _ => None,
            })
            .collect();
        if ids.is_empty() {
            return HashMap::new();
        }
        self.ports
            .user_store
            .find_by_ids(tenant, &ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|user| {
                (
                    PrincipalRef::User(*user.id()),
                    user.display_name().as_str().to_owned(),
                )
            })
            .collect()
    }

    /// Names organization members already present in the authorized delegations.
    async fn member_names(
        &self,
        principals: &HashSet<PrincipalRef>,
    ) -> HashMap<PrincipalRef, String> {
        let ids: Vec<_> = principals
            .iter()
            .filter_map(|principal| match principal {
                PrincipalRef::OrgUser(id) => Some(*id),
                _ => None,
            })
            .collect();
        if ids.is_empty() {
            return HashMap::new();
        }
        self.ports
            .org_user_store
            .find_by_ids(&ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|user| {
                (
                    PrincipalRef::OrgUser(*user.id()),
                    user.display_name().as_str().to_owned(),
                )
            })
            .collect()
    }

    /// Names agents within the tenant in one read, preserving best-effort output.
    async fn agent_names(
        &self,
        tenant: &ScopedTenant,
        principals: &HashSet<PrincipalRef>,
    ) -> HashMap<PrincipalRef, String> {
        let ids: Vec<_> = principals
            .iter()
            .filter_map(|principal| match principal {
                PrincipalRef::Agent(id) => Some(*id),
                _ => None,
            })
            .collect();
        if ids.is_empty() {
            return HashMap::new();
        }
        self.ports
            .agent_store
            .find_by_ids(tenant, &ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|agent| {
                (
                    PrincipalRef::Agent(*agent.id()),
                    agent.name().as_str().to_owned(),
                )
            })
            .collect()
    }

    /// Requests spent against the delegation's budget, if it has one.
    async fn used_requests(&self, delegation: &Delegation<ResolvedTenant>) -> Option<u32> {
        delegation.constraints().budget().limit()?;
        self.ports.budget_usage.current_usage(delegation.id()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{AgentId, OrganizationId, UserId};

    use super::*;
    use crate::test_support::agents::{FakeAgentStore, child_delegation, root_delegation};
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::organization::{org_user_store_with, test_org_user};
    use crate::test_support::{block_on, test_ctx};

    fn describer(users: FakeUserStore) -> DescribeDelegations {
        DescribeDelegations::new(DescribeDelegationsPorts {
            user_store: Arc::new(users),
            ..DescribeDelegationsPorts::fakes()
        })
    }

    fn delegation_from(delegator: PrincipalRef) -> Delegation<ResolvedTenant> {
        root_delegation(delegator, AgentId::new(), CapabilitySet::empty())
    }

    /// Sam gave a delegation. The listing shows his name beside it.
    #[test]
    fn a_delegation_carries_its_delegators_name() {
        let tenant = test_ctx().tenant();
        let sam = UserId::new();
        let users = FakeUserStore::empty();
        block_on(users.save(
            &tenant,
            &stored_user(sam, "sam@acme.com", UserStatus::Active),
        ))
        .unwrap();
        let named = block_on(users.find_by_id(&tenant, &sam))
            .unwrap()
            .unwrap()
            .display_name()
            .as_str()
            .to_owned();

        let described = block_on(
            describer(users).describe(&tenant, vec![delegation_from(PrincipalRef::User(sam))]),
        );

        assert_eq!(described[0].delegator_name.as_deref(), Some(named.as_str()));
    }

    /// Two distinct users and a repeated delegator are named in one read,
    /// keeping the original delegation order and each person's displayed name.
    #[test]
    fn distinct_delegators_share_one_name_read() {
        let tenant = test_ctx().tenant();
        let sam = stored_user(UserId::new(), "sam@acme.com", UserStatus::Active);
        let ann = stored_user(UserId::new(), "ann@acme.com", UserStatus::Active);
        let users = Arc::new(FakeUserStore::empty());
        for user in [&sam, &ann] {
            block_on(users.save(&tenant, user)).unwrap();
        }
        let describe = DescribeDelegations::new(DescribeDelegationsPorts {
            user_store: users.clone(),
            ..DescribeDelegationsPorts::fakes()
        });
        let delegations = vec![
            delegation_from(PrincipalRef::User(*sam.id())),
            delegation_from(PrincipalRef::User(*ann.id())),
            delegation_from(PrincipalRef::User(*sam.id())),
        ];

        let found = block_on(describe.describe(&tenant, delegations));

        assert_eq!(found.len(), 3);
        assert_eq!(
            found[0].delegator_name.as_deref(),
            Some(sam.display_name().as_str())
        );
        assert_eq!(
            found[1].delegator_name.as_deref(),
            Some(ann.display_name().as_str())
        );
        assert_eq!(found[2].delegator_name, found[0].delegator_name);
        assert_eq!(users.id_reads().len(), 1);
    }

    /// The person who gave a delegation was deleted since. The listing
    /// leaves the name empty rather than failing.
    #[test]
    fn a_delegator_that_no_longer_exists_leaves_the_name_empty() {
        let tenant = test_ctx().tenant();

        let described = block_on(describer(FakeUserStore::empty()).describe(
            &tenant,
            vec![delegation_from(PrincipalRef::User(UserId::new()))],
        ));

        assert!(described[0].delegator_name.is_none());
    }

    /// Names from each principal kind stay attached to their delegations.
    /// Losing the agent store clears only agent names; user and member names,
    /// missing-principal output and delegation order remain usable.
    #[test]
    fn one_unreachable_name_source_leaves_the_other_principals_named() {
        let tenant = test_ctx().tenant();
        let sam = stored_user(UserId::new(), "sam@acme.com", UserStatus::Active);
        let member = test_org_user(OrganizationId::new(), "ann@example.com", OrgRole::Member);
        let member_id = *member.id();
        let member_name = member.display_name().as_str().to_owned();
        let users = Arc::new(FakeUserStore::empty());
        block_on(users.save(&tenant, &sam)).unwrap();
        let agent = AgentId::new();
        let agents = Arc::new(FakeAgentStore::with_active(agent));
        let root = root_delegation(PrincipalRef::User(*sam.id()), agent, CapabilitySet::empty());
        let child = child_delegation(&root, AgentId::new(), CapabilitySet::empty());
        let delegations = vec![
            root,
            child,
            delegation_from(PrincipalRef::OrgUser(member_id)),
            delegation_from(PrincipalRef::User(UserId::new())),
        ];
        let describe = DescribeDelegations::new(DescribeDelegationsPorts {
            user_store: users,
            org_user_store: Arc::new(org_user_store_with([member])),
            agent_store: agents.clone(),
            ..DescribeDelegationsPorts::fakes()
        });

        let available = block_on(describe.describe(&tenant, delegations.clone()));
        agents.fail_identity_reads();
        let unavailable = block_on(describe.describe(&tenant, delegations));

        assert_names(&available, sam.display_name().as_str(), &member_name);
        assert_unavailable_names(&available, &unavailable);
    }

    /// Each principal kind keeps its name in the original delegation order.
    fn assert_names(available: &[DescribedDelegation], user: &str, member: &str) {
        assert_eq!(available[0].delegator_name.as_deref(), Some(user));
        assert_eq!(available[1].delegator_name.as_deref(), Some("fake-agent"));
        assert_eq!(available[2].delegator_name.as_deref(), Some(member));
        assert!(available[3].delegator_name.is_none());
    }

    /// A failed agent lookup clears only its name and preserves delegation order.
    fn assert_unavailable_names(
        available: &[DescribedDelegation],
        unavailable: &[DescribedDelegation],
    ) {
        assert!(unavailable[1].delegator_name.is_none());
        for index in [0, 2, 3] {
            assert_eq!(
                unavailable[index].delegator_name,
                available[index].delegator_name
            );
        }
        assert_eq!(
            unavailable
                .iter()
                .map(|item| item.delegation.id())
                .collect::<Vec<_>>(),
            available
                .iter()
                .map(|item| item.delegation.id())
                .collect::<Vec<_>>()
        );
    }

    /// A delegation with no budget shows no usage.
    #[test]
    fn a_delegation_without_a_budget_reports_no_usage() {
        let tenant = test_ctx().tenant();

        let described = block_on(describer(FakeUserStore::empty()).describe(
            &tenant,
            vec![delegation_from(PrincipalRef::User(UserId::new()))],
        ));

        assert!(described[0].used_requests.is_none());
    }
}
