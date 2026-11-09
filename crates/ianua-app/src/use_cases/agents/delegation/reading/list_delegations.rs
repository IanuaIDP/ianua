//! List delegations: the delegations an agent holds, each with who gave it
//! and how much of its budget is spent.

use std::sync::Arc;

use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::use_case::Query;
use crate::use_cases::agents::delegation::reading::viewing::viewed_agent;
use crate::use_cases::agents::delegation::{DescribeDelegations, DescribedDelegation};

/// The ports [`ListDelegationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListDelegationsPorts {
    /// Loads the agent.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads its delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Adds the delegator's name and budget use to each delegation.
    pub describer: Arc<DescribeDelegations>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the delegations an agent holds.
pub struct ListDelegationsUseCase {
    ports: ListDelegationsPorts,
}

impl ListDelegationsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListDelegationsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListDelegationsUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<Vec<DescribedDelegation>, AppError>;

    /// The delegations `agent_id` holds, each described with its delegator's
    /// name and budget use.
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
        let delegations = self
            .ports
            .delegation_store
            .list_for_agent(&tenant, agent.id())
            .await
            .or_internal()?;
        Ok(self.ports.describer.describe(&tenant, delegations).await)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, callers_agent, root_delegation,
    };
    use crate::test_support::{block_on, test_ctx};

    fn holding_one(agents: FakeAgentStore, agent: AgentId) -> ListDelegationsPorts {
        let delegations = FakeDelegationStore::empty();
        let delegation = root_delegation(
            PrincipalRef::User(UserId::new()),
            agent,
            CapabilitySet::empty(),
        );
        block_on(delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
        ListDelegationsPorts {
            agent_store: Arc::new(agents),
            delegation_store: Arc::new(delegations),
            ..ListDelegationsPorts::fakes()
        }
    }

    fn list(ports: ListDelegationsPorts, agent: AgentId) -> Result<usize, AppError> {
        block_on(ListDelegationsUseCase::new(ports).execute(&test_ctx(), agent)).map(|d| d.len())
    }

    /// Ann lists her agent's delegations. She sees the one it holds.
    #[test]
    fn an_owner_lists_the_delegations_their_agent_holds() {
        let agent = AgentId::new();

        let listed = list(holding_one(callers_agent(agent), agent), agent);

        assert_eq!(listed.unwrap(), 1);
    }

    /// Ann lists the delegations of an agent the tenant does not have. It
    /// is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let agent = AgentId::new();

        let result = list(holding_one(FakeAgentStore::empty(), agent), agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Listing another owner's delegations without agent-view permission
    /// reports the agent as missing.
    #[test]
    fn a_caller_who_may_not_view_another_persons_agent_is_refused() {
        let agent = AgentId::new();
        let ports = ListDelegationsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..holding_one(FakeAgentStore::with_active(agent), agent)
        };

        let result = list(ports, agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot list an agent's delegations.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();
        let ports = ListDelegationsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..holding_one(callers_agent(agent), agent)
        };

        let result = list(ports, agent);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
