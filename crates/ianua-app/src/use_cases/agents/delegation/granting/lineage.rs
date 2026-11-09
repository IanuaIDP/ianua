//! Delegation lineage: the principals an authority descends from.
//!
//! A delegation records only its own delegator. That is enough to keep a
//! child inside its parent, and not enough to answer what every audit asks:
//! on whose authority, in the end? One hop down a chain the delegator is
//! another agent, and naming it alone hides the person at the root.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::{Delegation, Lineage};
use ianua_domain::domains::agents::oversight::review::ReviewLineage;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{AgentId, DelegationId, Initiator, PrincipalRef};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::ports::identity::UserStore;
use crate::ports::organization::OrgUserStore;
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::lookup::live_delegations;
use crate::use_cases::agents::people::{PeopleSources, person_behind};

/// The most links a walk up a chain follows, so stored data that loops
/// ends instead of spinning.
const MAX_HOPS: usize = 64;

/// The principals `delegation` descends from, nearest first.
///
/// A root yields the one principal that granted it. A child yields the
/// agent that passed it on, then each agent above, then the principal at
/// the root. A delegation an agent minted for itself yields the agent, then
/// whoever granted what it was minted from, and on up.
///
/// # Errors
///
/// - `AppError::Internal` when a delegation above cannot be loaded.
pub(crate) async fn principal_chain(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<Vec<PrincipalRef>, AppError> {
    Ok(ancestry(store, tenant, delegation).await?.principals)
}

/// A delegation's ancestry: itself and every delegation above it, and the
/// principal that granted each, nearest first and each once.
pub(crate) struct Ancestry {
    /// The delegation and those above it.
    pub delegations: Vec<DelegationId>,
    /// The principal that granted each.
    pub principals: Vec<PrincipalRef>,
}

impl Ancestry {
    fn of(delegation: &Delegation<ResolvedTenant>) -> Self {
        Self {
            delegations: vec![*delegation.id()],
            principals: vec![*delegation.delegator()],
        }
    }

    fn add(&mut self, delegation: DelegationId, principal: PrincipalRef) {
        push_once(&mut self.delegations, delegation);
        push_once(&mut self.principals, principal);
    }
}

/// Walks `delegation` up to its root, through the parent it was cut from
/// or the delegations it was minted from. A delegation above that is gone
/// ends the walk there.
///
/// # Errors
///
/// - `AppError::Internal` when a delegation above cannot be loaded.
pub(crate) async fn ancestry(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    delegation: &Delegation<ResolvedTenant>,
) -> Result<Ancestry, AppError> {
    let mut found = Ancestry::of(delegation);
    let mut next = above(delegation, &mut found);
    for _ in 0..MAX_HOPS {
        let Some(id) = next else {
            break;
        };
        let Some(parent) = store.find_by_id(tenant, &id).await.or_internal()? else {
            break;
        };
        found.add(id, *parent.delegator());
        next = above(&parent, &mut found);
    }
    Ok(found)
}

/// The delegation to walk to from `delegation`. A minted one adds every
/// delegation it was minted from and the person who granted them, and is
/// walked on through the first.
fn above(delegation: &Delegation<ResolvedTenant>, found: &mut Ancestry) -> Option<DelegationId> {
    match delegation.lineage() {
        Lineage::Root => None,
        Lineage::Under(parent) => Some(*parent),
        Lineage::Minted {
            from, delegator, ..
        } => {
            for source in from {
                found.add(*source, *delegator);
            }
            from.first().copied()
        }
    }
}

/// Where an agent's lineage is read from.
#[derive(Clone, ianua_macros::Fakes)]
pub struct LineagePorts {
    /// The agents, for the owner.
    pub agent_store: Arc<dyn AgentStore>,
    /// The delegations, for the chains.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The tenant's users, for the person behind an account.
    pub user_store: Arc<dyn UserStore>,
    /// The organization's members, for the person behind an account.
    pub org_user_store: Arc<dyn OrgUserStore>,
}

/// Where `agent`'s authority comes from: its owner and every party at the
/// root of its live delegations, each person read back from their account,
/// and every delegation in those chains, each once. Agents in a chain pass
/// their authority through and are not roots.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such agent.
/// - `AppError::Forbidden` when the account of a person behind the agent
///   can no longer be read, so independence cannot be shown.
/// - `AppError::Internal` when a store fails.
pub(crate) async fn agent_lineage(
    ports: &LineagePorts,
    tenant: &ScopedTenant,
    agent: &AgentId,
) -> Result<ReviewLineage, AppError> {
    let owner = existing_agent(ports.agent_store.as_ref(), tenant, agent)
        .await?
        .owner()
        .clone();
    let mut roots = vec![Initiator::Human(owner)];
    let mut delegations = Vec::new();
    for delegation in live_delegations(ports.delegation_store.as_ref(), tenant, agent).await? {
        let found = ancestry(ports.delegation_store.as_ref(), tenant, &delegation).await?;
        for principal in &found.principals {
            add_root(ports, tenant, &mut roots, principal).await?;
        }
        for id in found.delegations {
            push_once(&mut delegations, id);
        }
    }
    ReviewLineage::new(roots, delegations).map_err(AppError::from_domain)
}

/// Adds the party `principal` names to `roots`, once. Agents pass through.
async fn add_root(
    ports: &LineagePorts,
    tenant: &ScopedTenant,
    roots: &mut Vec<Initiator>,
    principal: &PrincipalRef,
) -> Result<(), AppError> {
    let Some(root) = root_party(ports, tenant, principal).await? else {
        return Ok(());
    };
    if !roots.iter().any(|known| known.is_same_party_as(&root)) {
        roots.push(root);
    }
    Ok(())
}

/// The party at a root `principal` names: the person behind a person's
/// account, or the consumer. `None` for an agent.
async fn root_party(
    ports: &LineagePorts,
    tenant: &ScopedTenant,
    principal: &PrincipalRef,
) -> Result<Option<Initiator>, AppError> {
    let person = match principal {
        PrincipalRef::Agent(_) => return Ok(None),
        PrincipalRef::Consumer(id) => return Ok(Some(Initiator::Consumer(*id))),
        PrincipalRef::User(_) | PrincipalRef::OrgUser(_) => {
            let sources = PeopleSources {
                users: ports.user_store.as_ref(),
                members: ports.org_user_store.as_ref(),
            };
            person_behind(sources, tenant, principal).await?
        }
    };
    let Some(person) = person else {
        return Err(AppError::Forbidden(message!(
            "agents-a-person-behind-this-agent-s",
            "a person behind this agent's authority can no longer be read"
        )));
    };
    Ok(Some(Initiator::Human(person)))
}

fn push_once<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{HumanAccount, UserId};

    use super::*;
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, caller_person, callers_agent, child_delegation,
        root_delegation,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::{block_on, test_ctx};

    fn caps() -> CapabilitySet {
        CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![],
        )
    }

    fn saved(store: &FakeDelegationStore, delegation: &Delegation<ResolvedTenant>) {
        block_on(store.save(&test_ctx().tenant(), delegation)).unwrap();
    }

    fn chain_of(
        store: &FakeDelegationStore,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Vec<PrincipalRef> {
        block_on(principal_chain(store, &test_ctx().tenant(), delegation)).unwrap()
    }

    /// Ann grants her agent a delegation. Its chain names Ann alone.
    #[test]
    fn a_root_names_the_principal_that_granted_it() {
        let ann = PrincipalRef::User(UserId::new());
        let root = root_delegation(ann, AgentId::new(), caps());

        assert_eq!(chain_of(&FakeDelegationStore::empty(), &root), vec![ann]);
    }

    /// Ann's planner passes part of her delegation to a fetcher. The
    /// fetcher's chain runs from the planner back to Ann.
    #[test]
    fn a_child_reaches_back_to_the_person_at_the_root() {
        let store = FakeDelegationStore::empty();
        let ann = PrincipalRef::User(UserId::new());
        let planner = AgentId::new();
        let root = root_delegation(ann, planner, caps());
        let child = child_delegation(&root, AgentId::new(), caps());
        saved(&store, &root);

        assert_eq!(
            chain_of(&store, &child),
            vec![PrincipalRef::Agent(planner), ann]
        );
    }

    /// The planner's own delegation was deleted. The fetcher's chain stops
    /// at the planner instead of failing.
    #[test]
    fn a_missing_parent_ends_the_chain_instead_of_failing() {
        let planner = AgentId::new();
        let root = root_delegation(PrincipalRef::User(UserId::new()), planner, caps());
        let child = child_delegation(&root, AgentId::new(), caps());

        assert_eq!(
            chain_of(&FakeDelegationStore::empty(), &child),
            vec![PrincipalRef::Agent(planner)]
        );
    }

    /// Ann gives her agent two delegations. Its lineage names Ann once and
    /// each delegation once.
    #[test]
    fn an_agent_lineage_names_each_party_and_delegation_once() {
        let agent = AgentId::new();
        let delegations = FakeDelegationStore::empty();
        let ann = caller_person();
        let first = root_delegation(ann.principal(), agent, caps());
        let second = root_delegation(ann.principal(), agent, caps());
        saved(&delegations, &first);
        saved(&delegations, &second);
        let ports = LineagePorts {
            user_store: Arc::new(users_with(caller_id(), "caller@example.test")),
            ..lineage_ports(callers_agent(agent), delegations)
        };

        let lineage = block_on(agent_lineage(&ports, &test_ctx().tenant(), &agent)).unwrap();

        assert_eq!(lineage.roots().len(), 1);
        assert_eq!(lineage.delegations(), [*first.id(), *second.id()]);
    }

    /// An unreadable person behind a delegation prevents resolving the
    /// agent's review lineage.
    #[test]
    fn a_person_who_can_no_longer_be_read_is_refused() {
        let agent = AgentId::new();
        let delegations = FakeDelegationStore::empty();
        saved(
            &delegations,
            &root_delegation(PrincipalRef::User(UserId::new()), agent, caps()),
        );
        let ports = lineage_ports(callers_agent(agent), delegations);

        let result = block_on(agent_lineage(&ports, &test_ctx().tenant(), &agent));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Bob grants Ann's agent a delegation. The lineage names both Ann, the
    /// owner, and Bob.
    #[test]
    fn an_agent_lineage_names_its_owner_and_its_delegators() {
        let agent = AgentId::new();
        let bob = UserId::new();
        let users = users_with(bob, "bob@example.test");
        let delegations = FakeDelegationStore::empty();
        saved(
            &delegations,
            &root_delegation(PrincipalRef::User(bob), agent, caps()),
        );
        let ports = LineagePorts {
            user_store: Arc::new(users),
            ..lineage_ports(callers_agent(agent), delegations)
        };

        let lineage = block_on(agent_lineage(&ports, &test_ctx().tenant(), &agent)).unwrap();

        assert_eq!(lineage.roots().len(), 2);
    }

    /// Resolving lineage for an unknown agent reports it as missing.
    #[test]
    fn an_unknown_agent_has_no_lineage() {
        let ports = lineage_ports(FakeAgentStore::empty(), FakeDelegationStore::empty());

        let result = block_on(agent_lineage(&ports, &test_ctx().tenant(), &AgentId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    fn users_with(user: UserId, address: &str) -> FakeUserStore {
        let users = FakeUserStore::empty();
        block_on(users.save(
            &test_ctx().tenant(),
            &stored_user(user, address, UserStatus::Active),
        ))
        .unwrap();
        users
    }

    fn caller_id() -> UserId {
        match caller_person().account() {
            HumanAccount::User(id) => id,
            HumanAccount::OrgUser(_) => panic!("the test caller is a tenant user"),
        }
    }

    fn lineage_ports(agents: FakeAgentStore, delegations: FakeDelegationStore) -> LineagePorts {
        LineagePorts {
            agent_store: Arc::new(agents),
            delegation_store: Arc::new(delegations),
            ..LineagePorts::fakes()
        }
    }
}
