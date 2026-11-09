//! Effective capabilities: everything an agent may do now, the union of
//! its live delegations.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::use_case::Query;
use crate::use_cases::agents::delegation::reading::viewing::viewed_agent;

/// An agent's effective capabilities and the delegations they come from.
pub struct AgentEffectiveCapabilities {
    /// The union of what its live delegations grant.
    pub capabilities: CapabilitySet,
    /// Its live delegations.
    pub active_delegations: Vec<Delegation<ResolvedTenant>>,
}

/// The ports [`GetEffectiveCapabilitiesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetEffectiveCapabilitiesPorts {
    /// Loads the agent.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads its delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Works out what an agent may do now.
pub struct GetEffectiveCapabilitiesUseCase {
    ports: GetEffectiveCapabilitiesPorts,
}

impl GetEffectiveCapabilitiesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetEffectiveCapabilitiesPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetEffectiveCapabilitiesUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<AgentEffectiveCapabilities, AppError>;

    /// The union of what `agent_id`'s live delegations grant. A revoked or
    /// expired delegation adds nothing.
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
    ) -> Result<AgentEffectiveCapabilities, AppError> {
        let agent = viewed_agent(
            self.ports.agent_store.as_ref(),
            self.ports.tenant_authorities.as_ref(),
            ctx,
            &agent_id,
        )
        .await?;
        let now = clock::now();
        let active_delegations: Vec<_> = self
            .ports
            .delegation_store
            .list_for_agent(&ctx.tenant(), agent.id())
            .await
            .or_internal()?
            .into_iter()
            .filter(|delegation| delegation.is_valid(now))
            .collect();
        let capabilities = active_delegations
            .iter()
            .fold(CapabilitySet::empty(), |held, delegation| {
                held.union(delegation.granted())
            });
        Ok(AgentEffectiveCapabilities {
            capabilities,
            active_delegations,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::Revoker;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, callers_agent, root_delegation,
    };
    use crate::test_support::{block_on, test_ctx};

    const VIEW_ROUTES: SystemPermission = SystemPermission::Routing(RoutingAction::View);
    const MANAGE_ROUTES: SystemPermission = SystemPermission::Routing(RoutingAction::Manage);

    fn granting(agent: AgentId, permission: SystemPermission) -> Delegation<ResolvedTenant> {
        root_delegation(
            PrincipalRef::User(UserId::new()),
            agent,
            CapabilitySet::new(vec![permission], vec![]),
        )
    }

    fn ports_over(
        agents: FakeAgentStore,
        delegations: &[Delegation<ResolvedTenant>],
    ) -> GetEffectiveCapabilitiesPorts {
        let store = FakeDelegationStore::empty();
        for delegation in delegations {
            block_on(store.save(&test_ctx().tenant(), delegation)).unwrap();
        }
        GetEffectiveCapabilitiesPorts {
            agent_store: Arc::new(agents),
            delegation_store: Arc::new(store),
            ..GetEffectiveCapabilitiesPorts::fakes()
        }
    }

    fn effective(
        ports: GetEffectiveCapabilitiesPorts,
        agent: AgentId,
    ) -> Result<AgentEffectiveCapabilities, AppError> {
        block_on(GetEffectiveCapabilitiesUseCase::new(ports).execute(&test_ctx(), agent))
    }

    /// Ann's agent holds a delegation to view routes. It may view routes.
    #[test]
    fn an_agent_may_do_what_its_live_delegations_grant() {
        let agent = AgentId::new();
        let ports = ports_over(callers_agent(agent), &[granting(agent, VIEW_ROUTES)]);

        let found = effective(ports, agent).unwrap();

        assert!(found.capabilities.permits(&VIEW_ROUTES));
        assert_eq!(found.active_delegations.len(), 1);
    }

    /// Ann revoked the delegation letting her agent manage routes. It no
    /// longer may.
    #[test]
    fn a_revoked_delegation_adds_nothing() {
        let agent = AgentId::new();
        let mut revoked = granting(agent, MANAGE_ROUTES);
        revoked.revoke(Revoker::Platform).unwrap();
        let ports = ports_over(
            callers_agent(agent),
            &[granting(agent, VIEW_ROUTES), revoked],
        );

        let found = effective(ports, agent).unwrap();

        assert!(!found.capabilities.permits(&MANAGE_ROUTES));
        assert_eq!(found.active_delegations.len(), 1);
    }

    /// Reading another owner's effective capabilities without agent-view
    /// permission reports the agent as missing.
    #[test]
    fn a_caller_who_may_not_view_another_persons_agent_is_refused() {
        let agent = AgentId::new();
        let ports = GetEffectiveCapabilitiesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(FakeAgentStore::with_active(agent), &[])
        };

        assert!(matches!(
            effective(ports, agent),
            Err(AppError::NotFound(_))
        ));
    }

    /// A signed-out caller cannot read an agent's effective capabilities.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();
        let ports = GetEffectiveCapabilitiesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(callers_agent(agent), &[])
        };

        assert!(matches!(
            effective(ports, agent),
            Err(AppError::Unauthenticated)
        ));
    }

    /// Ann asks about an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let agent = AgentId::new();

        let result = effective(ports_over(FakeAgentStore::empty(), &[]), agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
