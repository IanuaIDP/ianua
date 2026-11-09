//! Pause run: a person holds a run between its steps.
//!
//! The domain decides who may: the person who started the run, the agent's
//! owner, or someone allowed to change agents. The pause is saved over the
//! version of the run the person read, so it never overwrites a step the
//! worker kept meanwhile, and the worker never writes a step over it: it
//! reads the run again before each step and stops at a pause, giving the
//! run back. A paused run stays paused until a person resumes it.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, AgentRunId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, RunStore};
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::steering::{
    SteeringStores, save_steered, steered_run,
};

/// Which run to pause, addressed under the agent it belongs to.
pub struct PauseRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The run to pause.
    pub run_id: AgentRunId,
}

/// The ports [`PauseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PausePorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, whose owners may pause their runs.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Pauses runs between their steps.
pub struct PauseUseCase {
    ports: PausePorts,
}

impl PauseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PausePorts) -> Self {
        Self { ports }
    }
}

impl Command for PauseUseCase {
    type Caller = CallerContext;
    type Input = PauseRequest;
    type Output = Result<AgentRun<ResolvedTenant>, AppError>;

    /// Pauses `request.run_id`, saves it over the version read, records
    /// `agents.run_paused`, and returns the run as it stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing run under this agent.
    /// - `AppError::Forbidden` unless the caller started the run, owns the agent or may change agents.
    /// - `AppError::Domain` when the run is waiting, paused or ended.
    /// - `AppError::Conflict` when the worker saved a step concurrently; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: PauseRequest,
    ) -> Result<AgentRun<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let stores = SteeringStores {
            runs: self.ports.run_store.as_ref(),
            agents: self.ports.agent_store.as_ref(),
        };
        let mut steered = steered_run(stores, &tenant, &request.agent_id, &request.run_id).await?;
        steered
            .run
            .pause(&AgentControl::new(&authority), &steered.agent)
            .map_err(AppError::from_domain)?;
        save_steered(self.ports.run_store.as_ref(), &tenant, &steered).await?;
        auditor
            .dispatch_by(&ctx.actor(), steered.run.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(steered.run)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeRunStore, agent_owned_by, caller_person, delegation_from, order_tool,
        paused_run, run_started_by, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An agent owned by `owner`, a run of it, and the stores they are kept
    /// in.
    struct Scene {
        agent: AgentIdentity<ResolvedTenant>,
        run: AgentRunId,
        runs: Arc<FakeRunStore>,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        /// A running run of an agent `owner` owns, started by `starter`.
        fn running(owner: Human, starter: &Human) -> Self {
            let agent = agent_owned_by(AgentId::new(), owner);
            let delegation = delegation_from(starter, *agent.id());
            let run = run_started_by(starter, &agent, &delegation);
            Self::keeping(agent, &run)
        }

        /// A run of the caller's agent, waiting for approval of a delete.
        fn awaiting_approval() -> Self {
            let agent = agent_owned_by(AgentId::new(), caller_person());
            let delegation = delegation_from(&caller_person(), *agent.id());
            let run = paused_run(
                &caller_person(),
                &agent,
                &delegation,
                &order_tool("delete_order"),
            );
            Self::keeping(agent, &run)
        }

        fn keeping(agent: AgentIdentity<ResolvedTenant>, run: &AgentRun<ResolvedTenant>) -> Self {
            let (runs, agents) = (
                Arc::new(FakeRunStore::empty()),
                Arc::new(FakeAgentStore::empty()),
            );
            block_on(runs.save(&test_ctx().tenant(), run)).unwrap();
            block_on(agents.save(&test_ctx().tenant(), &agent)).unwrap();
            Self {
                agent,
                run: *run.id(),
                runs,
                agents,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> PausePorts {
            PausePorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                ..PausePorts::fakes()
            }
        }

        fn pause_with(
            &self,
            ports: PausePorts,
            agent_id: AgentId,
        ) -> Result<AgentRun<ResolvedTenant>, AppError> {
            block_on(PauseUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                PauseRequest {
                    agent_id,
                    run_id: self.run,
                },
            ))
        }

        fn pause(&self) -> Result<AgentRun<ResolvedTenant>, AppError> {
            self.pause_with(self.ports(), *self.agent.id())
        }

        fn pause_holding(
            &self,
            held: &[SystemPermission],
        ) -> Result<AgentRun<ResolvedTenant>, AppError> {
            let ports = PausePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
                ..self.ports()
            };
            self.pause_with(ports, *self.agent.id())
        }

        fn stored_status(&self) -> RunStatus {
            block_on(self.runs.find_by_id(&test_ctx().tenant(), &self.run))
                .unwrap()
                .unwrap()
                .status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann pauses a run she started. It is kept paused and the pause is
    /// recorded.
    #[test]
    fn a_person_pauses_a_run_they_started() {
        let scene = Scene::running(someone("owen@example.test"), &caller_person());

        let run = scene.pause_holding(&[]).unwrap();

        assert_eq!(run.status(), RunStatus::Paused);
        assert_eq!(scene.stored_status(), RunStatus::Paused);
        assert_eq!(scene.records(), ["agents.run_paused"]);
    }

    /// Bob started a run of Ann's agent. Ann owns the agent and pauses it.
    /// She may.
    #[test]
    fn the_agents_owner_pauses_a_run_someone_else_started() {
        let scene = Scene::running(caller_person(), &someone("bob@example.test"));

        scene.pause_holding(&[]).unwrap();

        assert_eq!(scene.stored_status(), RunStatus::Paused);
    }

    /// An agent viewer who neither started the run nor owns its agent cannot
    /// pause it. The run stays running and no audit event is recorded.
    #[test]
    fn a_stranger_to_the_run_may_not_pause_it() {
        let scene = Scene::running(someone("owen@example.test"), &someone("bob@example.test"));

        let result = scene.pause_holding(&[SystemPermission::Agents(AgentAction::View)]);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.stored_status(), RunStatus::Running);
        assert!(scene.records().is_empty());
    }

    /// The worker kept a step after Ann read her run. Her pause is refused
    /// as a conflict, the worker's step stands and nothing is recorded.
    #[test]
    fn a_pause_over_a_run_that_moved_on_is_refused() {
        let scene = Scene::running(caller_person(), &caller_person());
        scene.runs.moves_on_before_each_save();

        let result = scene.pause();

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(scene.stored_status(), RunStatus::Running);
        assert!(scene.records().is_empty());
    }

    /// A run waiting for a person to approve its call is not paused again.
    #[test]
    fn a_run_waiting_for_approval_is_not_paused() {
        let scene = Scene::awaiting_approval();

        let result = scene.pause();

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(scene.stored_status(), RunStatus::AwaitingApproval);
    }

    /// Pausing a run under a different agent ID returns not found and leaves
    /// the run running.
    #[test]
    fn a_run_under_another_agents_address_is_not_found() {
        let scene = Scene::running(caller_person(), &caller_person());

        let result = scene.pause_with(scene.ports(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.stored_status(), RunStatus::Running);
    }

    /// A signed-out session cannot pause a run, which remains running.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::running(caller_person(), &caller_person());
        let ports = PausePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.pause_with(ports, *scene.agent.id());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.stored_status(), RunStatus::Running);
    }
}
