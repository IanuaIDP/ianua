//! Take over agent: a person allowed to manage agents becomes an agent's
//! owner.
//!
//! An agent's owner answers for it and steers it. When that person moves
//! to other work, someone allowed to manage agents takes the agent over,
//! so it never stays with somebody who no longer looks after it. The new
//! owner is the person asking: the domain checks they may own an agent,
//! which only someone allowed to create agents may, and works that out
//! from what they hold now, which only their own sign-in shows. The agent
//! keeps its status, proof and delegations; a delegation its old owner
//! granted still names them.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::{AgentIdentity, Handover};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::services::lookup::existing_agent;
use crate::use_case::Command;

/// The ports [`TakeOverAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TakeOverAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes the caller the owner of an agent of their tenant.
pub struct TakeOverAgentUseCase {
    ports: TakeOverAgentPorts,
}

impl TakeOverAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: TakeOverAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for TakeOverAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<AgentIdentity<ResolvedTenant>, AppError>;

    /// Makes the caller the owner of `agent_id`, records
    /// `agents.agent_ownership_transferred` naming both owners, and returns
    /// the agent as it stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any agent is read, or may not create them and so may not own one.
    /// - `AppError::NotFound` when the tenant has no such agent.
    /// - `AppError::Conflict` when the agent is the caller's already, or
    ///   changed since it was read.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut agent = existing_agent(self.ports.agent_store.as_ref(), &tenant, &agent_id).await?;
        let read = AgentVersion::of(&agent);
        let taker = AgentControl::new(&authority);
        agent
            .transfer_ownership(&taker, &taker, Handover::Given)
            .map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(agent)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, caller_person, callers_agent, someone};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An agent Owen owns, and the store keeping it.
    struct OwensAgent {
        agents: Arc<FakeAgentStore>,
        id: AgentId,
        owen: Human,
    }

    fn owens_agent() -> OwensAgent {
        let (id, owen) = (AgentId::new(), someone("owen@example.test"));
        let agents = FakeAgentStore::empty();
        agents.add_owned_by(id, owen.clone());
        OwensAgent {
            agents: Arc::new(agents),
            id,
            owen,
        }
    }

    impl OwensAgent {
        fn owner(&self) -> Human {
            self.agents
                .find_by_id_direct(&self.id)
                .unwrap()
                .owner()
                .clone()
        }
    }

    fn take_over(
        ports: TakeOverAgentPorts,
        sink: &Arc<FakeEventDispatcher>,
        agent_id: AgentId,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        block_on(TakeOverAgentUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            agent_id,
        ))
    }

    fn holding(agents: &Arc<FakeAgentStore>, held: &[SystemPermission]) -> TakeOverAgentPorts {
        TakeOverAgentPorts {
            agent_store: agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
        }
    }

    /// Owen moved teams. Ann, who manages agents, takes over his agent. She
    /// owns it now, and the move is recorded.
    #[test]
    fn a_manager_takes_over_an_agent() {
        let owens = owens_agent();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = TakeOverAgentPorts {
            agent_store: owens.agents.clone(),
            ..TakeOverAgentPorts::fakes()
        };

        let agent = take_over(ports, &sink, owens.id).unwrap();

        assert_eq!(agent.owner().account(), caller_person().account());
        assert_eq!(owens.owner().account(), caller_person().account());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_ownership_transferred"]
        );
    }

    /// The create right alone cannot take over an agent; the original
    /// owner remains and no transfer is recorded.
    #[test]
    fn taking_over_needs_the_right_to_manage_agents() {
        let owens = owens_agent();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = take_over(
            holding(
                &owens.agents,
                &[SystemPermission::Agents(AgentAction::Create)],
            ),
            &sink,
            owens.id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(owens.owner(), owens.owen);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Without management rights, takeover requests for a real agent and
    /// an unknown id return identical forbidden responses.
    #[test]
    fn a_caller_who_may_not_manage_agents_learns_nothing_of_an_id() {
        let owens = owens_agent();
        let creates = [SystemPermission::Agents(AgentAction::Create)];
        let sink = Arc::new(FakeEventDispatcher::new());

        let real = take_over(holding(&owens.agents, &creates), &sink, owens.id);
        let unknown = take_over(holding(&owens.agents, &creates), &sink, AgentId::new());

        assert!(
            matches!(unknown, Err(AppError::Forbidden(_))),
            "{unknown:?}"
        );
        assert_eq!(format!("{real:?}"), format!("{unknown:?}"));
    }

    /// Ann takes over an agent that is hers already. It is a conflict.
    #[test]
    fn an_agent_already_the_callers_is_a_conflict() {
        let id = AgentId::new();
        let agents = Arc::new(callers_agent(id));
        let ports = TakeOverAgentPorts {
            agent_store: agents,
            ..TakeOverAgentPorts::fakes()
        };

        let result = take_over(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
    }

    /// Ann takes over an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = take_over(
            TakeOverAgentPorts::fakes(),
            &Arc::new(FakeEventDispatcher::new()),
            AgentId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// A signed-out caller cannot take over an agent, whose owner stays unchanged.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let owens = owens_agent();
        let ports = TakeOverAgentPorts {
            agent_store: owens.agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        };

        let result = take_over(ports, &Arc::new(FakeEventDispatcher::new()), owens.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(owens.owner(), owens.owen);
    }
}
