//! Get agent: one agent of the caller's tenant, by id.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::agents::AgentStore;
use crate::use_case::Query;
use crate::use_cases::agents::delegation::reading::viewing::viewed_agent;

/// The ports [`GetAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetAgentPorts {
    /// Loads agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one agent of the caller's tenant.
pub struct GetAgentUseCase {
    ports: GetAgentPorts,
}

impl GetAgentUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetAgentPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<AgentIdentity<ResolvedTenant>, AppError>;

    /// The agent with `id`, once the caller owns it or may view agents.
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
        id: AgentId,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        viewed_agent(
            self.ports.agent_store.as_ref(),
            self.ports.tenant_authorities.as_ref(),
            ctx,
            &id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, agent_row, caller_person, someone_else};
    use crate::test_support::{block_on, test_ctx};

    fn use_case(store: FakeAgentStore, authorities: FakeTenantAuthorities) -> GetAgentUseCase {
        GetAgentUseCase::new(GetAgentPorts {
            agent_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)])
    }

    fn store_with(id: AgentId, owner: Human) -> FakeAgentStore {
        let store = FakeAgentStore::empty();
        let agent = AgentIdentity::reconstitute(agent_row(id, owner)).unwrap();
        block_on(store.save(&test_ctx().tenant(), &agent)).unwrap();
        store
    }

    /// Ann, who may view agents, reads the tenant's nightly agent. She gets
    /// it.
    #[test]
    fn a_viewer_reads_an_agent() {
        let id = AgentId::new();

        let agent =
            block_on(use_case(FakeAgentStore::with_active(id), viewer()).execute(&test_ctx(), id))
                .unwrap();

        assert_eq!(agent.id(), &id);
    }

    /// Ann, who holds no agent rights, reads the agent she owns. She gets
    /// it, as she gets its keys and its delegations.
    #[test]
    fn the_owner_reads_their_agent_without_the_view_right() {
        let id = AgentId::new();
        let store = store_with(id, caller_person());

        let agent =
            block_on(use_case(store, FakeTenantAuthorities::holding(&[])).execute(&test_ctx(), id))
                .unwrap();

        assert_eq!(agent.id(), &id);
    }

    /// Ann asks for an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = block_on(
            use_case(FakeAgentStore::empty(), viewer()).execute(&test_ctx(), AgentId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Without ownership or the view right, a real agent and an unknown id
    /// produce the same missing-agent response.
    #[test]
    fn someone_elses_agent_reads_as_missing_to_a_caller_who_may_not_view_agents() {
        let id = AgentId::new();
        let mallory = || FakeTenantAuthorities::holding(&[]);

        let real =
            block_on(use_case(store_with(id, someone_else()), mallory()).execute(&test_ctx(), id));
        let made_up = block_on(
            use_case(store_with(id, someone_else()), mallory())
                .execute(&test_ctx(), AgentId::new()),
        );

        let refusal = |read: Result<_, AppError>| read.err().map(|error| error.to_string());
        assert!(matches!(real, Err(AppError::NotFound(_))));
        assert_eq!(refusal(real), refusal(made_up));
    }

    /// A signed-out caller is refused access to the agent record.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = AgentId::new();

        let result = block_on(
            use_case(
                FakeAgentStore::with_active(id),
                FakeTenantAuthorities::refusing(Refusal::SignedOut),
            )
            .execute(&test_ctx(), id),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
