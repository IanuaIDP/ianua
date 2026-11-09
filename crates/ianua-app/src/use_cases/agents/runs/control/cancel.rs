//! Cancel run: a person stops a run.
//!
//! Their say is checked once, when they ask: the domain gives back a
//! [`CancelOrder`] for the person who started the run, the agent's owner or
//! someone allowed to change agents. Stopping a running run is cooperative.
//! The request goes on the run's kill switch, and the worker driving it
//! stops between steps. A run paused for approval has no worker to notice,
//! so it is cancelled here, announced as finished, and the approvals it
//! waited on are withdrawn. A run that already ended is left as it ended.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::{AgentRun, CancelOrder};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, AgentId, AgentRunId, EventLabel};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, ApprovalStore, RunCancellation, RunStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{RunAddress, RunOfAgent, owned_run_to_stop};
use crate::use_cases::agents::runs::control::stopping::{RunStopping, SettledStop};

/// Which run to stop, addressed under the agent it belongs to.
pub struct CancelRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The run to stop.
    pub run_id: AgentRunId,
}

/// The ports [`CancelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, whose owners may stop their runs.
    pub agent_store: Arc<dyn AgentStore>,
    /// The run kill switch.
    pub run_cancellation: Arc<dyn RunCancellation>,
    /// Withdraws the approvals a paused run waited on.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops runs.
pub struct CancelUseCase {
    ports: CancelPorts,
}

impl CancelUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelUseCase {
    type Caller = CallerContext;
    type Input = CancelRequest;
    type Output = Result<AgentRun<ResolvedTenant>, AppError>;

    /// Stops `request.run_id`, returning the run as it stands.
    ///
    /// Stopping a run is recorded when the person asks, not when the worker
    /// notices, since that is when they acted.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the run does not exist under this agent,
    ///   or the caller neither started it, owns the agent, nor may change
    ///   agents, so that it answers as a run that does not exist.
    /// - `AppError::Internal` when the stop cannot be recorded, or on
    ///   persistence or dispatch failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CancelRequest,
    ) -> Result<AgentRun<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let address = RunAddress {
            agent_id: request.agent_id,
            run_id: request.run_id,
        };
        let RunOfAgent { run, agent } = owned_run_to_stop(
            self.ports.run_store.as_ref(),
            self.ports.agent_store.as_ref(),
            &tenant,
            address,
            &control,
        )
        .await?;
        let order = run
            .order_cancel(&control, &agent)
            .map_err(AppError::from_domain)?;
        if run.status().is_terminal() {
            return Ok(run);
        }
        let stop = Stop {
            tenant: &tenant,
            actor: ctx.actor(),
            order: &order,
            agent: &agent,
        };
        recorded_stop(&self.ports, auditor, &stop, run).await
    }
}

/// A stop a person ordered, and the agent whose run it stops.
struct Stop<'a> {
    /// The scope in which the stop and its audit record are saved.
    tenant: &'a ScopedTenant,
    /// Who ordered it.
    actor: ActorRef,
    /// The order, checked when they gave it.
    order: &'a CancelOrder,
    /// The run's agent, named in the audit trail by its own name.
    agent: &'a AgentIdentity<ResolvedTenant>,
}

/// The run once its stop is on the kill switch and recorded: settled at
/// once when it is paused for approval, left to its worker otherwise.
async fn recorded_stop(
    ports: &CancelPorts,
    auditor: &RequestAuditor,
    stop: &Stop<'_>,
    mut run: AgentRun<ResolvedTenant>,
) -> Result<AgentRun<ResolvedTenant>, AppError> {
    run.announce_cancel_request(stop.order, stop.agent)
        .map_err(AppError::from_domain)?;
    let stopping = RunStopping {
        cancellation: ports.run_cancellation.as_ref(),
        runs: ports.run_store.as_ref(),
        approvals: ports.approval_store.as_ref(),
    };
    let Some(mut settled) = stopping.stop(stop.tenant, stop.order).await? else {
        auditor
            .dispatch_by(&stop.actor, run.take_events(stop.tenant))
            .await
            .or_internal()?;
        return Ok(run);
    };
    auditor
        .dispatch(&settled_record(stop, &mut run, &mut settled))
        .await
        .or_internal()?;
    Ok(settled.run)
}

/// What settling a paused run records: the stop asked for, the run's end,
/// and each approval withdrawn.
fn settled_record(
    stop: &Stop<'_>,
    asked: &mut AgentRun<ResolvedTenant>,
    settled: &mut SettledStop,
) -> Vec<DomainEvent> {
    let label = EventLabel::of(stop.agent.name().as_str());
    asked
        .take_events(stop.tenant)
        .into_iter()
        .map(|event| event.with_actor(stop.actor.clone()))
        .chain(settled.recorded(stop.tenant, &label, &stop.actor))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::{ApprovalId, Human};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeApprovalStore, FakeRunControl, FakeRunStore, agent_owned_by,
        caller_person, delegation_from, order_tool, paused_run, raised_approval, run_started_by,
        someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A run of an agent, kept with the agent and its approvals, and the
    /// switch a stop is recorded on.
    struct Scene {
        agent: AgentIdentity<ResolvedTenant>,
        run: AgentRunId,
        approval: Option<ApprovalId>,
        runs: Arc<FakeRunStore>,
        agents: Arc<FakeAgentStore>,
        approvals: Arc<FakeApprovalStore>,
        control: Arc<FakeRunControl>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn of(owner: Human) -> Self {
            let agents = Arc::new(FakeAgentStore::empty());
            let agent = agent_owned_by(AgentId::new(), owner);
            block_on(agents.save(&test_ctx().tenant(), &agent)).unwrap();
            Self {
                agent,
                run: AgentRunId::new(),
                approval: None,
                runs: Arc::new(FakeRunStore::empty()),
                agents,
                approvals: Arc::new(FakeApprovalStore::empty()),
                control: Arc::new(FakeRunControl::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// A running run of the scene's agent, started by `starter`.
        fn running(mut self, starter: &Human) -> Self {
            let delegation = delegation_from(starter, *self.agent.id());
            self.keep(&run_started_by(starter, &self.agent, &delegation));
            self
        }

        /// A run of the scene's agent started by `starter`, paused on a
        /// delete, with the approval request it raised.
        fn paused(mut self, starter: &Human) -> Self {
            let delegation = delegation_from(starter, *self.agent.id());
            let tool = order_tool("delete_order");
            let run = paused_run(starter, &self.agent, &delegation, &tool);
            let approval = raised_approval(&run, &self.agent, starter, &tool);
            block_on(self.approvals.save(&test_ctx().tenant(), &approval)).unwrap();
            self.approval = Some(*approval.id());
            self.keep(&run);
            self
        }

        fn keep(&mut self, run: &AgentRun<ResolvedTenant>) {
            block_on(self.runs.save(&test_ctx().tenant(), run)).unwrap();
            self.run = *run.id();
        }

        fn ports(&self) -> CancelPorts {
            CancelPorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                run_cancellation: self.control.clone(),
                approval_store: self.approvals.clone(),
                ..CancelPorts::fakes()
            }
        }

        fn cancel_with(
            &self,
            ports: CancelPorts,
            agent_id: AgentId,
        ) -> Result<AgentRun<ResolvedTenant>, AppError> {
            block_on(CancelUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                CancelRequest {
                    agent_id,
                    run_id: self.run,
                },
            ))
        }

        fn cancel(&self) -> Result<AgentRun<ResolvedTenant>, AppError> {
            self.cancel_with(self.ports(), *self.agent.id())
        }

        fn cancel_as(
            &self,
            held: &[SystemPermission],
        ) -> Result<AgentRun<ResolvedTenant>, AppError> {
            let ports = CancelPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
                ..self.ports()
            };
            self.cancel_with(ports, *self.agent.id())
        }

        fn stop_requested(&self) -> bool {
            self.control.has_order_for(&self.run)
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

    /// Ann stops a run she started of her agent. The stop goes on the kill
    /// switch for its worker, and is recorded naming the agent.
    #[test]
    fn cancelling_a_running_run_records_the_request() {
        let scene = Scene::of(caller_person()).running(&caller_person());

        scene.cancel().unwrap();

        assert!(scene.stop_requested());
        assert_eq!(scene.records(), ["agents.run_cancel_requested"]);
        assert_eq!(
            scene.sink.label_of("agents.run_cancel_requested", "agent"),
            Some(scene.agent.name().as_str().to_owned())
        );
    }

    /// Bob started a run of Ann's agent. Ann owns the agent, holds no agent
    /// permission, and stops it. She may.
    #[test]
    fn the_agents_owner_stops_a_run_someone_else_started() {
        let scene = Scene::of(caller_person()).running(&someone("bob@example.test"));

        scene.cancel_as(&[]).unwrap();

        assert!(scene.stop_requested());
    }

    /// Carol may change agents and stops a run Ann started of her own
    /// agent. She may.
    #[test]
    fn someone_allowed_to_change_agents_stops_any_run() {
        let ann = someone("ann@example.test");
        let scene = Scene::of(ann.clone()).running(&ann);

        scene
            .cancel_as(&[SystemPermission::Agents(AgentAction::Update)])
            .unwrap();

        assert!(scene.stop_requested());
    }

    /// An agent viewer who neither started the run nor owns its agent receives
    /// not found when cancelling it. No stop is requested and no audit event is recorded.
    #[test]
    fn a_caller_with_no_say_over_the_run_is_refused() {
        let ann = someone("ann@example.test");
        let scene = Scene::of(ann.clone()).running(&ann);

        let result = scene.cancel_as(&[SystemPermission::Agents(AgentAction::View)]);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert!(!scene.stop_requested());
        assert!(scene.records().is_empty());
    }

    /// Cancelling a run under a different agent ID returns not found without
    /// requesting a stop or recording an audit event.
    #[test]
    fn a_run_addressed_under_another_agent_is_not_found_and_keeps_running() {
        let scene = Scene::of(caller_person()).running(&caller_person());

        let result = scene.cancel_with(scene.ports(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!scene.stop_requested());
        assert!(scene.records().is_empty());
    }

    /// Ann stops a run that already completed. There is nothing to stop, so
    /// nothing goes on the switch and nothing is recorded.
    #[test]
    fn cancelling_a_finished_run_is_a_no_op() {
        let mut scene = Scene::of(caller_person());
        let ann = caller_person();
        let mut run = run_started_by(
            &ann,
            &scene.agent,
            &delegation_from(&ann, *scene.agent.id()),
        );
        run.complete("done").unwrap();
        scene.keep(&run);

        let returned = scene.cancel().unwrap();

        assert_eq!(returned.status(), RunStatus::Completed);
        assert!(!scene.stop_requested());
        assert!(scene.records().is_empty());
    }

    /// Ann stops a run paused on a delete. No worker drives a paused run,
    /// so it is cancelled here, or an approval would wake it to make the
    /// very call it was held on.
    #[test]
    fn cancelling_a_paused_run_settles_it_at_once() {
        let scene = Scene::of(caller_person()).paused(&caller_person());

        let returned = scene.cancel().unwrap();

        assert_eq!(returned.status(), RunStatus::Cancelled);
        assert_eq!(scene.stored_status(), RunStatus::Cancelled);
    }

    /// Ann stops a paused run. Whatever waits on it hears it finished, and
    /// the approval it waited on is withdrawn, not left for Bob to approve
    /// a call that will never be made.
    #[test]
    fn cancelling_a_paused_run_announces_it_and_withdraws_its_approval() {
        let scene = Scene::of(caller_person()).paused(&caller_person());

        scene.cancel().unwrap();

        let withdrawn = block_on(
            scene
                .approvals
                .find_by_id(&test_ctx().tenant(), &scene.approval.unwrap()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(withdrawn.status(), ApprovalStatus::Withdrawn);
        assert_eq!(
            scene.records(),
            [
                "agents.run_cancel_requested",
                "agents.run_finished",
                "agents.approval_withdrawn"
            ]
        );
    }

    /// The kill switch cannot be reached. A stop that was not recorded is
    /// not answered as done, and nothing is recorded.
    #[test]
    fn a_cancel_that_cannot_be_recorded_fails() {
        let scene = Scene::of(caller_person()).running(&caller_person());
        scene.control.unreadable.store(true, Ordering::SeqCst);

        let result = scene.cancel();

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(scene.records().is_empty());
    }

    /// Ann stops a run the tenant does not have. It is not found.
    #[test]
    fn cancelling_an_unknown_run_is_not_found() {
        let scene = Scene::of(caller_person());

        let result = scene.cancel();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot cancel a run; no stop is requested.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::of(caller_person()).running(&caller_person());
        let ports = CancelPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.cancel_with(ports, *scene.agent.id());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!scene.stop_requested());
    }
}
