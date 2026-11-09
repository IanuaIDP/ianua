//! Get run: one run of an agent, with its steps.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{AgentId, AgentRunId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::agents::{AgentStore, RunStore};
use crate::use_case::Query;
use crate::use_cases::agents::lookup::owned_run;
use crate::use_cases::agents::runs::reading::readers::{RunReader, ensure_may_read_runs};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, for whose runs they are.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which run to read, addressed under the agent it belongs to.
pub struct GetRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The run to read.
    pub run_id: AgentRunId,
}

/// Reads one run.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = GetRequest;
    type Output = Result<AgentRun<ResolvedTenant>, AppError>;

    /// The run `request.run_id` of `request.agent_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the agent or the run does not exist, the
    ///   run is another agent's, or the caller neither owns the agent nor
    ///   may view agents, so that an agent of someone else's answers as one
    ///   that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetRequest,
    ) -> Result<AgentRun<ResolvedTenant>, AppError> {
        let reader = RunReader {
            authorities: self.ports.tenant_authorities.as_ref(),
            agents: self.ports.agent_store.as_ref(),
        };
        ensure_may_read_runs(&reader, ctx, &request.agent_id).await?;
        owned_run(
            self.ports.run_store.as_ref(),
            &ctx.tenant(),
            &request.agent_id,
            &request.run_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeRunStore, agent_owned_by, caller_person, delegation_from,
        run_started_by, someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Ann's agent and one run she started of it, with ports reading them.
    struct Stored {
        agent: AgentId,
        run: AgentRunId,
        ports: GetPorts,
    }

    fn stored_run_of(owner: &ianua_domain::types::Human) -> Stored {
        let agent = agent_owned_by(AgentId::new(), owner.clone());
        let run = run_started_by(owner, &agent, &delegation_from(owner, *agent.id()));
        let agents = Arc::new(FakeAgentStore::empty());
        block_on(agents.save(&test_ctx().tenant(), &agent)).unwrap();
        let runs = Arc::new(FakeRunStore::empty());
        block_on(runs.save(&test_ctx().tenant(), &run)).unwrap();
        Stored {
            agent: *agent.id(),
            run: *run.id(),
            ports: GetPorts {
                run_store: runs,
                agent_store: agents,
                ..GetPorts::fakes()
            },
        }
    }

    fn read(
        ports: GetPorts,
        agent_id: AgentId,
        run_id: AgentRunId,
    ) -> Result<AgentRun<ResolvedTenant>, AppError> {
        block_on(GetUseCase::new(ports).execute(&test_ctx(), GetRequest { agent_id, run_id }))
    }

    /// Ann reads a run of her own agent. It comes back.
    #[test]
    fn the_owner_reads_a_run_of_their_agent() {
        let s = stored_run_of(&caller_person());
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..s.ports
        };

        let run = read(ports, s.agent, s.run).unwrap();

        assert_eq!(run.id(), &s.run);
    }

    /// Bob may view agents and reads a run of Ann's agent. It comes back.
    #[test]
    fn someone_allowed_to_view_agents_reads_anyones_run() {
        let s = stored_run_of(&someone("ann@example.test"));
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..s.ports
        };

        assert!(read(ports, s.agent, s.run).is_ok());
    }

    /// A caller without agent view rights receives not found for another
    /// person's agent run.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let s = stored_run_of(&someone("ann@example.test"));
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..s.ports
        };

        let result = read(ports, s.agent, s.run);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a run under a different agent returns not found, even when the
    /// caller owns both agents.
    #[test]
    fn a_run_addressed_under_another_agent_is_not_found() {
        let s = stored_run_of(&caller_person());
        let mine = agent_owned_by(AgentId::new(), caller_person());
        block_on(s.ports.agent_store.save(&test_ctx().tenant(), &mine)).unwrap();

        let result = read(s.ports, *mine.id(), s.run);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot read an agent run.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let s = stored_run_of(&caller_person());
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..s.ports
        };

        let result = read(ports, s.agent, s.run);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
