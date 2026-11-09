//! Reply to run call: a person answers the call a run holds in words
//! instead of letting it run.
//!
//! Ann's run holds a payment to the live ledger, and she would rather tell
//! the agent "use the staging ledger instead". Replying takes the same
//! right and clearance as denying: the request the run raised is denied,
//! the call is never made, and what she wrote is recorded as the run's step
//! for its model to read next. The run is then handed back to a worker.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::{CallReply, DeniedCall};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{ApprovalRequest, Approver};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, AgentRunId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::agents::{AgentStore, ApprovalStore, RunStore};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::AuditLabelResolver;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::audit_labels::agent_label;
use crate::use_cases::agents::runs::answers::decided::RunDecided;
use crate::use_cases::agents::runs::control::steering::{
    SteeredRun, SteeringStores, open_request_of, save_steered, steered_run,
};
use crate::use_cases::agents::runs::driving::RunDrives;
use crate::use_cases::agents::runs::reading::names::run_names;

/// The reply to the call a run holds, addressed under the run and agent it
/// belongs to.
pub struct ReplyToCallRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The run holding the call.
    pub run_id: AgentRunId,
    /// What the person writes back to the agent.
    pub reply: CallReply,
}

/// The ports [`ReplyToCallUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReplyToCallPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, whose runs are replied to.
    pub agent_store: Arc<dyn AgentStore>,
    /// The request the run raised, denied by the reply.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// Names the agent and provider in the audit trail.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Keeps the run, the request and the record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Where the job driving the run on is queued.
    pub run_drives: RunDrives,
}

/// Answers the calls paused runs hold in words.
pub struct ReplyToCallUseCase {
    ports: ReplyToCallPorts,
}

impl ReplyToCallUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReplyToCallPorts) -> Self {
        Self { ports }
    }

    /// The run's agent and provider named as the audit trail knows them,
    /// for the decision and the run handed back.
    async fn announce(
        &self,
        tenant: &ScopedTenant,
        steered: &mut SteeredRun,
        approval: &mut ApprovalRequest<ResolvedTenant>,
    ) {
        let resolver = self.ports.audit_label_resolver.as_ref();
        approval.announce_decision(agent_label(resolver, tenant, steered.run.agent_id()).await);
        let names = run_names(resolver, tenant, &steered.run).await;
        steered.run.announce_start(names);
    }

    /// Keeps the denied request and the run, and records both, together:
    /// a request decided, or a run moved on, since they were read is
    /// answered as a conflict, and nothing of the reply is kept.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        steered: &mut SteeredRun,
        approval: &mut ApprovalRequest<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let work = async {
            self.ports
                .approval_store
                .save(&tenant, approval)
                .await
                .or_conflict(message!(
                    "agents-the-request-was-decided-by-someone",
                    "the request was decided by someone else meanwhile"
                ))?;
            save_steered(self.ports.run_store.as_ref(), &tenant, steered).await?;
            self.ports
                .run_drives
                .hand_over(&tenant, &steered.run)
                .await?;
            auditor
                .dispatch_by(&ctx.actor(), replied_record(&tenant, steered, approval))
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), work).await
    }
}

impl Command for ReplyToCallUseCase {
    type Caller = CallerContext;
    type Input = ReplyToCallRequest;
    type Output = Result<RunDecided, AppError>;

    /// Denies the request `request.run_id` raised, records the reply as the
    /// run's step, hands the run back to a worker, and records
    /// `agents.approval_denied` and `agents.run_started`. Returns where the
    /// run stands: only that, since replying takes the right to decide and
    /// not the right to read the run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing agent run or open request.
    /// - `AppError::Forbidden` for missing approval rights or insufficient clearance.
    /// - `AppError::Conflict` for another call or a concurrent decision/run change; no reply is kept.
    /// - `AppError::Domain` when the request or run is not awaiting approval.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ReplyToCallRequest,
    ) -> Result<RunDecided, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let stores = SteeringStores {
            runs: self.ports.run_store.as_ref(),
            agents: self.ports.agent_store.as_ref(),
        };
        let mut steered = steered_run(stores, &tenant, &request.agent_id, &request.run_id).await?;
        let mut approval =
            open_request_of(self.ports.approval_store.as_ref(), &tenant, &steered.run).await?;
        let denied = approval
            .deny(&Approver::of(AgentControl::new(&authority)))
            .map_err(AppError::from_domain)?;
        let denied = denied_call(denied)?;
        steered
            .run
            .reply_to_pending(&denied, request.reply)
            .map_err(AppError::from_domain)?;
        self.announce(&tenant, &mut steered, &mut approval).await;
        self.keep(ctx, auditor, &mut steered, &mut approval).await?;
        Ok(RunDecided::of(&steered.run))
    }
}

/// The proof the run drops its held call on. A request a run raised always
/// gives one.
fn denied_call(denied: Option<DeniedCall>) -> Result<DeniedCall, AppError> {
    denied.ok_or_else(|| {
        AppError::Conflict(message!(
            "agents-the-request-is-not-about-a",
            "the request is not about a run's call"
        ))
    })
}

/// What the reply records: the request denied, then the run handed back.
fn replied_record(
    tenant: &ScopedTenant,
    steered: &mut SteeredRun,
    approval: &mut ApprovalRequest<ResolvedTenant>,
) -> Vec<DomainEvent> {
    let mut recorded = approval.take_events(tenant);
    recorded.extend(steered.run.take_events(tenant));
    recorded
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::domains::agents::execution::run::{AgentRun, RunStatus, StepOutcome};
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::ApprovalId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeApprovalStore, FakeRunStore, agent_owned_by, delegation_row,
        order_tool, paused_run, raised_approval, someone,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FakeEventDispatcher, Rewind, RewindingUnitOfWork, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::agents::runs::DRIVE_RUN_JOB;

    /// Ann's run of Owen's agent, paused on deleting order 1, with the
    /// request it raised, and the stores they are kept in.
    struct Scene {
        agent: AgentIdentity<ResolvedTenant>,
        run: AgentRunId,
        approval: ApprovalId,
        runs: Arc<FakeRunStore>,
        agents: Arc<FakeAgentStore>,
        approvals: Arc<FakeApprovalStore>,
        sink: Arc<FakeEventDispatcher>,
        queue: Arc<FakeJobQueue>,
    }

    impl Scene {
        fn new() -> Self {
            Self::keeping_approvals_in(FakeApprovalStore::empty())
        }

        /// The same, its request kept in `approvals`.
        fn keeping_approvals_in(approvals: FakeApprovalStore) -> Self {
            let ann = someone("ann@corp.test");
            let agent = agent_owned_by(AgentId::new(), someone("owen@corp.test"));
            let delegation =
                Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
            let tool = order_tool("delete_order");
            let run = paused_run(&ann, &agent, &delegation, &tool);
            let approval = raised_approval(&run, &agent, &ann, &tool);
            let tenant = test_ctx().tenant();
            let scene = Self {
                agent: agent.clone(),
                run: *run.id(),
                approval: *approval.id(),
                runs: Arc::new(FakeRunStore::empty()),
                agents: Arc::new(FakeAgentStore::empty()),
                approvals: Arc::new(approvals),
                sink: Arc::new(FakeEventDispatcher::new()),
                queue: Arc::new(FakeJobQueue::new()),
            };
            block_on(scene.runs.save(&tenant, &run)).unwrap();
            block_on(scene.agents.save(&tenant, &agent)).unwrap();
            block_on(scene.approvals.save(&tenant, &approval)).unwrap();
            scene
        }

        fn ports(&self) -> ReplyToCallPorts {
            ReplyToCallPorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                approval_store: self.approvals.clone(),
                run_drives: RunDrives {
                    queue: self.queue.clone(),
                    attempts: NonZeroU32::MIN,
                },
                unit_of_work: Arc::new(RewindingUnitOfWork::over(vec![
                    self.runs.clone() as Arc<dyn Rewind>,
                    self.approvals.clone(),
                ])),
                ..ReplyToCallPorts::fakes()
            }
        }

        fn reply_with(&self, ports: ReplyToCallPorts) -> Result<RunDecided, AppError> {
            block_on(ReplyToCallUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ReplyToCallRequest {
                    agent_id: *self.agent.id(),
                    run_id: self.run,
                    reply: CallReply::new("archive order 1 instead").unwrap(),
                },
            ))
        }

        fn reply(&self) -> Result<RunDecided, AppError> {
            self.reply_with(self.ports())
        }

        fn stored_run(&self) -> AgentRun<ResolvedTenant> {
            block_on(self.runs.find_by_id(&test_ctx().tenant(), &self.run))
                .unwrap()
                .unwrap()
        }

        fn approval_status(&self) -> ApprovalStatus {
            block_on(
                self.approvals
                    .find_by_id(&test_ctx().tenant(), &self.approval),
            )
            .unwrap()
            .unwrap()
            .status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Bob answers Ann's held delete with "archive order 1 instead". The
    /// call never runs: the request is denied, the reply is the run's step
    /// for its model to read, and the run goes back to a worker.
    #[test]
    fn a_reply_is_the_runs_next_step_and_the_run_goes_on() {
        let scene = Scene::new();

        let decided = scene.reply().unwrap();

        assert_eq!(decided.status, RunStatus::Running);
        let run = scene.stored_run();
        assert!(run.pending().is_none());
        assert!(matches!(
            run.steps()[0].outcome(),
            StepOutcome::Replied(reply) if reply == "archive order 1 instead"
        ));
        assert_eq!(scene.approval_status(), ApprovalStatus::Denied);
        assert_eq!(
            scene.records(),
            ["agents.approval_denied", "agents.run_started"]
        );
        assert_eq!(scene.queue.jobs_of(DRIVE_RUN_JOB).len(), 1);
    }

    /// An agent viewer cannot reply to a held call. The call stays pending,
    /// its approval request stays open and no audit event is recorded.
    #[test]
    fn only_someone_allowed_to_approve_replies() {
        let scene = Scene::new();
        let ports = ReplyToCallPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..scene.ports()
        };

        let result = scene.reply_with(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert!(scene.stored_run().pending().is_some());
        assert_eq!(scene.approval_status(), ApprovalStatus::Pending);
        assert!(scene.records().is_empty());
    }

    /// A concurrent run change makes the reply conflict and rolls back its
    /// denial. The approval stays pending, no drive job is queued and no audit
    /// event is recorded.
    #[test]
    fn a_reply_over_a_run_that_changed_is_refused() {
        let scene = Scene::new();
        scene.runs.moves_on_before_each_save();

        let result = scene.reply();

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(scene.approval_status(), ApprovalStatus::Pending);
        assert!(scene.records().is_empty());
        assert!(scene.queue.jobs_of(DRIVE_RUN_JOB).is_empty());
    }

    /// An approval expiring during a reply makes it conflict. The run keeps its
    /// pending call, the approval is not denied and no audit event is recorded.
    #[test]
    fn a_reply_to_a_request_decided_meanwhile_is_a_conflict() {
        let scene = Scene::keeping_approvals_in(FakeApprovalStore::lapsing_while_decided());

        let result = scene.reply();

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert!(scene.stored_run().pending().is_some());
        assert_ne!(scene.approval_status(), ApprovalStatus::Denied);
        assert!(scene.records().is_empty());
    }

    /// Replying to a run under a different agent ID returns not found and leaves
    /// its approval pending.
    #[test]
    fn a_run_under_another_agents_address_is_not_found() {
        let scene = Scene::new();

        let result = block_on(ReplyToCallUseCase::new(scene.ports()).execute(
            &test_ctx(),
            &test_auditor(scene.sink.clone()),
            ReplyToCallRequest {
                agent_id: AgentId::new(),
                run_id: scene.run,
                reply: CallReply::new("no").unwrap(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.approval_status(), ApprovalStatus::Pending);
    }

    /// A signed-out session cannot reply to a held call; its approval stays pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::new();
        let ports = ReplyToCallPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.reply_with(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.approval_status(), ApprovalStatus::Pending);
    }
}
