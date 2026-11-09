//! Blast radius: what containing an agent would cut.
//!
//! Before pulling the kill switch, someone needs to see what it severs:
//! every delegation the agent holds and every delegation cut or minted from
//! those, the set [`ContainAgentUseCase`](crate::use_cases::agents::lifecycle::ContainAgentUseCase)
//! revokes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{AgentId, DelegationId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::agents::delegation::reading::viewing::viewed_agent;
use crate::use_cases::agents::delegation::{DescribeDelegations, DescribedDelegation};

/// The ports [`GetBlastRadiusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetBlastRadiusPorts {
    /// Loads the agent.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads and walks delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Adds the delegator's name and budget use to each delegation.
    pub describer: Arc<DescribeDelegations>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Previews what containing an agent would cut.
pub struct GetBlastRadiusUseCase {
    ports: GetBlastRadiusPorts,
}

impl GetBlastRadiusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetBlastRadiusPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetBlastRadiusUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<Vec<DescribedDelegation>, AppError>;

    /// Every delegation in `agent_id`'s blast radius, each once: each
    /// delegation it holds, followed by everything cut or minted from it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        agent_id: AgentId,
    ) -> Result<Vec<DescribedDelegation>, AppError> {
        let tenant = ctx.tenant();
        let agent = viewed_agent(
            self.ports.agent_store.as_ref(),
            self.ports.tenant_authorities.as_ref(),
            ctx,
            &agent_id,
        )
        .await?;
        let store = self.ports.delegation_store.as_ref();
        let held = store
            .list_for_agent(&tenant, agent.id())
            .await
            .or_internal()?;
        let radius = radius_of(store, &tenant, held).await?;
        Ok(self.ports.describer.describe(&tenant, radius).await)
    }
}

/// Walks all held roots together and hydrates each new descendant once.
/// A missing descendant is omitted, while held records keep their read value.
async fn radius_of(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    held: Vec<Delegation<ResolvedTenant>>,
) -> Result<Vec<Delegation<ResolvedTenant>>, AppError> {
    if held.is_empty() {
        return Ok(Vec::new());
    }
    let roots: Vec<_> = held.iter().map(|root| *root.id()).collect();
    let mut closures = store
        .find_revocation_closures(tenant, &roots)
        .await
        .or_internal()?;
    let mut records: HashMap<_, _> = held.into_iter().map(|root| (*root.id(), root)).collect();
    hydrate_descendants(store, tenant, &closures, &mut records).await?;
    Ok(roots
        .into_iter()
        .flat_map(|root| std::iter::once(root).chain(closures.remove(&root).unwrap_or_default()))
        .filter_map(|id| records.remove(&id))
        .collect())
}

/// Reads each reached descendant not already held once, leaving deleted rows absent.
async fn hydrate_descendants(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    closures: &HashMap<DelegationId, Vec<DelegationId>>,
    records: &mut HashMap<DelegationId, Delegation<ResolvedTenant>>,
) -> Result<(), AppError> {
    let missing: HashSet<_> = closures
        .values()
        .flatten()
        .filter(|id| !records.contains_key(*id))
        .copied()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let ids: Vec<_> = missing.into_iter().collect();
    records.extend(
        store
            .find_by_ids(tenant, &ids)
            .await
            .or_internal()?
            .into_iter()
            .map(|delegation| (*delegation.id(), delegation)),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, callers_agent, child_delegation, root_delegation,
    };
    use crate::test_support::{block_on, test_ctx};

    fn caps() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    fn ports_over(agents: FakeAgentStore, delegations: FakeDelegationStore) -> GetBlastRadiusPorts {
        GetBlastRadiusPorts {
            agent_store: Arc::new(agents),
            delegation_store: Arc::new(delegations),
            ..GetBlastRadiusPorts::fakes()
        }
    }

    fn saved(delegations: &FakeDelegationStore, delegation: &Delegation<ResolvedTenant>) {
        block_on(delegations.save(&test_ctx().tenant(), delegation)).unwrap();
    }

    fn radius(
        ports: GetBlastRadiusPorts,
        agent: AgentId,
    ) -> Result<Vec<DescribedDelegation>, AppError> {
        block_on(GetBlastRadiusUseCase::new(ports).execute(&test_ctx(), agent))
    }

    /// Ann's agent holds a delegation it passed on, and the sub-agent passed
    /// it on again. Containing Ann's agent cuts all three, its own first.
    #[test]
    fn the_radius_spans_everything_passed_on_below() {
        let agent = AgentId::new();
        let delegations = FakeDelegationStore::empty();
        let root = root_delegation(PrincipalRef::User(UserId::new()), agent, caps());
        let child = child_delegation(&root, AgentId::new(), caps());
        let grandchild = child_delegation(&child, AgentId::new(), caps());
        for delegation in [&root, &child, &grandchild] {
            saved(&delegations, delegation);
        }

        let found = radius(ports_over(callers_agent(agent), delegations), agent).unwrap();

        assert_eq!(found.len(), 3);
        assert_eq!(found[0].delegation.id(), root.id());
    }

    /// Overlapping roots reach the same grandchild. The preview keeps every
    /// delegation once in root-first order, using one walk and one hydration read.
    #[test]
    fn overlapping_roots_share_one_walk_and_one_hydration_read() {
        let agent = AgentId::new();
        let delegations = Arc::new(FakeDelegationStore::empty());
        let root = root_delegation(PrincipalRef::User(UserId::new()), agent, caps());
        let child = child_delegation(&root, agent, caps());
        let grandchild = child_delegation(&child, AgentId::new(), caps());
        for delegation in [&root, &child, &grandchild] {
            saved(&delegations, delegation);
        }
        let ports = GetBlastRadiusPorts {
            agent_store: Arc::new(callers_agent(agent)),
            delegation_store: delegations.clone(),
            ..GetBlastRadiusPorts::fakes()
        };

        let found = radius(ports, agent).unwrap();

        assert_eq!(
            found
                .iter()
                .map(|item| *item.delegation.id())
                .collect::<Vec<_>>(),
            [*root.id(), *child.id(), *grandchild.id()]
        );
        assert_eq!(delegations.closure_reads().len(), 1);
        assert_eq!(delegations.id_reads(), vec![vec![*grandchild.id()]]);
    }

    /// Bob's agent holds a delegation Ann's does not. Ann's agent holds
    /// nothing, so containing it cuts nothing.
    #[test]
    fn the_radius_leaves_out_what_the_agent_does_not_hold() {
        let agent = AgentId::new();
        let delegations = FakeDelegationStore::empty();
        saved(
            &delegations,
            &root_delegation(PrincipalRef::User(UserId::new()), AgentId::new(), caps()),
        );

        let found = radius(ports_over(callers_agent(agent), delegations), agent).unwrap();

        assert!(found.is_empty());
    }

    /// A provenance edge still names a deleted descendant. The preview
    /// keeps its held root and skips the missing row after one hydration read.
    #[test]
    fn a_missing_descendant_does_not_remove_the_held_root() {
        let agent = AgentId::new();
        let delegations = Arc::new(FakeDelegationStore::empty());
        let root = root_delegation(PrincipalRef::User(UserId::new()), agent, caps());
        let missing = DelegationId::new();
        saved(&delegations, &root);
        block_on(delegations.record_provenance(&test_ctx().tenant(), &missing, &[*root.id()]))
            .unwrap();
        let ports = GetBlastRadiusPorts {
            agent_store: Arc::new(callers_agent(agent)),
            delegation_store: delegations.clone(),
            ..GetBlastRadiusPorts::fakes()
        };

        let found = radius(ports, agent).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].delegation.id(), root.id());
        assert_eq!(delegations.id_reads(), vec![vec![missing]]);
    }

    /// An agent holding no delegations needs no graph walk or hydration read.
    #[test]
    fn an_empty_radius_needs_no_extra_reads() {
        let agent = AgentId::new();
        let delegations = Arc::new(FakeDelegationStore::empty());
        let ports = GetBlastRadiusPorts {
            agent_store: Arc::new(callers_agent(agent)),
            delegation_store: delegations.clone(),
            ..GetBlastRadiusPorts::fakes()
        };

        let found = radius(ports, agent).unwrap();

        assert!(found.is_empty());
        assert!(delegations.closure_reads().is_empty());
        assert!(delegations.id_reads().is_empty());
    }

    /// Previewing containment for another owner's agent without view
    /// permission reports the agent as missing.
    #[test]
    fn a_caller_who_may_not_view_another_persons_agent_is_refused() {
        let agent = AgentId::new();
        let ports = GetBlastRadiusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(
                FakeAgentStore::with_active(agent),
                FakeDelegationStore::empty(),
            )
        };

        let result = radius(ports, agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot preview an agent's containment impact.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();
        let ports = GetBlastRadiusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(callers_agent(agent), FakeDelegationStore::empty())
        };

        let result = radius(ports, agent);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
