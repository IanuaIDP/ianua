//! List runs: an agent's runs, newest first.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::RunStatus;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::agents::{AgentStore, RunStore, RunSummary};
use crate::use_case::Query;
use crate::use_cases::agents::runs::reading::readers::{RunReader, ensure_may_read_runs};

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, for whose runs they are.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Whose runs to list, and which of them.
pub struct ListRequest {
    /// The agent whose runs to list.
    pub agent_id: AgentId,
    /// Narrows to one lifecycle state; `None` includes every state.
    pub status: Option<RunStatus>,
    /// The requested page in newest-first order.
    pub page: PageRequest,
}

/// Lists an agent's runs.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<RunSummary>, AppError>;

    /// The runs of `request.agent_id`, newest first.
    ///
    /// Asking for [`RunStatus::AwaitingApproval`] finds the runs paused on
    /// a tool call a person must sign off.
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
        request: ListRequest,
    ) -> Result<Page<RunSummary>, AppError> {
        let reader = RunReader {
            authorities: self.ports.tenant_authorities.as_ref(),
            agents: self.ports.agent_store.as_ref(),
        };
        ensure_may_read_runs(&reader, ctx, &request.agent_id).await?;
        self.ports
            .run_store
            .list_for_agent(
                &ctx.tenant(),
                &request.agent_id,
                request.status,
                &request.page,
            )
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::AgentRun;
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeRunStore, agent_owned_by, caller_person, delegation_from,
        run_started_by, someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Agents and their runs, kept in memory.
    struct Fleet {
        runs: Arc<FakeRunStore>,
        agents: Arc<FakeAgentStore>,
    }

    impl Fleet {
        fn new() -> Self {
            Self {
                runs: Arc::new(FakeRunStore::empty()),
                agents: Arc::new(FakeAgentStore::empty()),
            }
        }

        fn agent_of(&self, owner: &ianua_domain::types::Human) -> AgentIdentity<ResolvedTenant> {
            let agent = agent_owned_by(AgentId::new(), owner.clone());
            block_on(self.agents.save(&test_ctx().tenant(), &agent)).unwrap();
            agent
        }

        fn run_of(
            &self,
            owner: &ianua_domain::types::Human,
            agent: &AgentIdentity<ResolvedTenant>,
        ) -> AgentRun<ResolvedTenant> {
            let run = run_started_by(owner, agent, &delegation_from(owner, *agent.id()));
            block_on(self.runs.save(&test_ctx().tenant(), &run)).unwrap();
            run
        }

        fn ports(&self) -> ListPorts {
            ListPorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                ..ListPorts::fakes()
            }
        }
    }

    fn list(
        ports: ListPorts,
        agent_id: AgentId,
        status: Option<RunStatus>,
    ) -> Result<Vec<RunSummary>, AppError> {
        block_on(ListUseCase::new(ports).execute(
            &test_ctx(),
            ListRequest {
                agent_id,
                status,
                page: PageRequest::default(),
            },
        ))
        .map(|page| page.items)
    }

    /// Twenty-one runs exist for Ann's agent. Its first listing returns only
    /// the usual twenty, so older history cannot grow one response forever.
    #[test]
    fn an_agents_run_listing_stops_at_the_default_page_size() {
        let fleet = Fleet::new();
        let owner = caller_person();
        let agent = fleet.agent_of(&owner);
        for _ in 0..21 {
            fleet.run_of(&owner, &agent);
        }

        let found = list(fleet.ports(), *agent.id(), None).unwrap();

        assert_eq!(found.len(), 20);
    }

    /// Ann's agent has a running run and a finished one, and another agent
    /// has a run too. She sees her agent's two, and asking for running ones
    /// only the one still running.
    #[test]
    fn lists_only_the_named_agents_runs_in_the_state_asked_for() {
        let fleet = Fleet::new();
        let ann = caller_person();
        let agent = fleet.agent_of(&ann);
        let running = fleet.run_of(&ann, &agent);
        let mut finished = fleet.run_of(&ann, &agent);
        finished.complete("done").unwrap();
        block_on(fleet.runs.save(&test_ctx().tenant(), &finished)).unwrap();
        let other = fleet.agent_of(&ann);
        fleet.run_of(&ann, &other);

        let all = list(fleet.ports(), *agent.id(), None).unwrap();
        let still_running = list(fleet.ports(), *agent.id(), Some(RunStatus::Running)).unwrap();

        assert_eq!(all.len(), 2);
        assert_eq!(still_running.len(), 1);
        assert_eq!(&still_running[0].id, running.id());
    }

    /// A caller without agent view rights receives not found when listing
    /// another person's agent runs.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let fleet = Fleet::new();
        let ann = someone("ann@example.test");
        let agent = fleet.agent_of(&ann);
        fleet.run_of(&ann, &agent);
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..fleet.ports()
        };

        let result = list(ports, *agent.id(), None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Listing runs for an unknown agent returns not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = list(Fleet::new().ports(), AgentId::new(), None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot list an agent's runs.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fleet = Fleet::new();
        let agent = fleet.agent_of(&caller_person());
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..fleet.ports()
        };

        let result = list(ports, *agent.id(), None);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
