//! Resume run: a person lets a paused run go on.
//!
//! The same people who may pause a run may resume it, and only while its
//! agent may still act: an agent suspended while its run was paused does
//! not get its authority back through the run. The run is saved over the
//! version the person read and handed back to a worker, which drives it on
//! from the step it paused at.

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
use crate::ports::shared::AuditLabelResolver;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::steering::{
    SteeringStores, save_steered, steered_run,
};
use crate::use_cases::agents::runs::driving::RunDrives;
use crate::use_cases::agents::runs::reading::names::run_names;

/// Which run to resume, addressed under the agent it belongs to.
pub struct ResumeRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The paused run.
    pub run_id: AgentRunId,
}

/// The ports [`ResumeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumePorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, whose standing a resumed run needs.
    pub agent_store: Arc<dyn AgentStore>,
    /// Names the agent and provider in the record that hands the run back.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Where the job driving the resumed run is queued.
    pub run_drives: RunDrives,
}

/// Resumes paused runs.
pub struct ResumeUseCase {
    ports: ResumePorts,
}

impl ResumeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResumePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeUseCase {
    type Caller = CallerContext;
    type Input = ResumeRequest;
    type Output = Result<AgentRun<ResolvedTenant>, AppError>;

    /// Resumes `request.run_id`, saves it over the version read, queues the
    /// job that hands it to a worker, and records `agents.run_resumed` and
    /// `agents.run_started`. Returns the run as it stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing run under this agent.
    /// - `AppError::Forbidden` when the agent cannot act or the caller has none of the rights conferred by starting the run, owning the agent or permission to change agents.
    /// - `AppError::Domain` when the run is not paused.
    /// - `AppError::Conflict` for a concurrent run change; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ResumeRequest,
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
            .resume(&AgentControl::new(&authority), &steered.agent)
            .map_err(AppError::from_domain)?;
        let names = run_names(
            self.ports.audit_label_resolver.as_ref(),
            &tenant,
            &steered.run,
        )
        .await;
        steered.run.announce_start(names);
        save_steered(self.ports.run_store.as_ref(), &tenant, &steered).await?;
        self.ports
            .run_drives
            .hand_over(&tenant, &steered.run)
            .await?;
        auditor
            .dispatch_by(&ctx.actor(), steered.run.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(steered.run)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::agents::identity::agent::{AgentIdentity, SuspendedBy};
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeRunStore, agent_owned_by, caller_person, delegation_from,
        run_started_by, someone,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::agents::runs::DRIVE_RUN_JOB;

    /// An agent owned by `owner`, a run of it its starter paused, and the
    /// stores they are kept in.
    struct Scene {
        agent: AgentIdentity<ResolvedTenant>,
        run: AgentRunId,
        runs: Arc<FakeRunStore>,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
        queue: Arc<FakeJobQueue>,
    }

    impl Scene {
        /// A run of an agent `owner` owns, started and paused by `starter`.
        fn paused(owner: Human, starter: &Human) -> Self {
            let agent = agent_owned_by(AgentId::new(), owner);
            let delegation = delegation_from(starter, *agent.id());
            let mut run = run_started_by(starter, &agent, &delegation);
            let authority =
                TenantAuthority::assumed(starter.clone(), test_ctx().tenant_id(), &[], &[]);
            run.pause(&AgentControl::new(&authority), &agent).unwrap();
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
                queue: Arc::new(FakeJobQueue::new()),
            }
        }

        fn ports(&self) -> ResumePorts {
            ResumePorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                run_drives: RunDrives {
                    queue: self.queue.clone(),
                    attempts: NonZeroU32::MIN,
                },
                ..ResumePorts::fakes()
            }
        }

        fn drive_jobs(&self) -> usize {
            self.queue.jobs_of(DRIVE_RUN_JOB).len()
        }

        fn resume_with(&self, ports: ResumePorts) -> Result<AgentRun<ResolvedTenant>, AppError> {
            block_on(ResumeUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ResumeRequest {
                    agent_id: *self.agent.id(),
                    run_id: self.run,
                },
            ))
        }

        fn resume_holding(
            &self,
            held: &[SystemPermission],
        ) -> Result<AgentRun<ResolvedTenant>, AppError> {
            let ports = ResumePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
                ..self.ports()
            };
            self.resume_with(ports)
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

    /// Ann resumes the run she paused. It runs again, the resume is
    /// recorded, and the job that drives it is queued for a worker.
    #[test]
    fn a_paused_run_resumes_and_goes_back_to_a_worker() {
        let scene = Scene::paused(someone("owen@example.test"), &caller_person());

        let run = scene.resume_holding(&[]).unwrap();

        assert_eq!(run.status(), RunStatus::Running);
        assert_eq!(scene.stored_status(), RunStatus::Running);
        assert_eq!(
            scene.records(),
            ["agents.run_resumed", "agents.run_started"]
        );
        assert_eq!(scene.drive_jobs(), 1);
    }

    /// A suspended agent's run cannot resume. It stays paused, queues no drive
    /// job and records no audit event.
    #[test]
    fn a_run_whose_agent_was_suspended_is_not_resumed() {
        let scene = Scene::paused(caller_person(), &caller_person());
        let mut agent = scene.agent.clone();
        agent.suspend(SuspendedBy::Monitor).unwrap();
        block_on(scene.agents.save(&test_ctx().tenant(), &agent)).unwrap();

        let result = scene.resume_with(scene.ports());

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.stored_status(), RunStatus::Paused);
        assert!(scene.records().is_empty());
        assert_eq!(scene.drive_jobs(), 0);
    }

    /// An agent viewer who neither started the run nor owns its agent cannot
    /// resume it; the run stays paused.
    #[test]
    fn a_stranger_to_the_run_may_not_resume_it() {
        let scene = Scene::paused(someone("owen@example.test"), &someone("bob@example.test"));

        let result = scene.resume_holding(&[SystemPermission::Agents(AgentAction::View)]);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.stored_status(), RunStatus::Paused);
    }

    /// A run that is not paused is not resumed.
    #[test]
    fn a_running_run_is_not_resumed() {
        let agent = agent_owned_by(AgentId::new(), caller_person());
        let delegation = delegation_from(&caller_person(), *agent.id());
        let run = run_started_by(&caller_person(), &agent, &delegation);
        let scene = Scene::keeping(agent, &run);

        let result = scene.resume_with(scene.ports());

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(scene.records().is_empty());
    }

    /// Someone stopped the run after Ann read it. Her resume is refused as
    /// a conflict, and nothing is recorded.
    #[test]
    fn a_resume_over_a_run_that_changed_is_refused() {
        let scene = Scene::paused(caller_person(), &caller_person());
        scene.runs.moves_on_before_each_save();

        let result = scene.resume_with(scene.ports());

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert!(scene.records().is_empty());
    }

    /// A signed-out session cannot resume a run, which stays paused.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::paused(caller_person(), &caller_person());
        let ports = ResumePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.resume_with(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.stored_status(), RunStatus::Paused);
    }
}
