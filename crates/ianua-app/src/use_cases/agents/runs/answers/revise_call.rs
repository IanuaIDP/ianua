//! Revise run call: a person changes the arguments of the call a run holds
//! for approval.
//!
//! Ann's run holds `delete_order(id=1)` and she means order 2. Rather than
//! deny and wait for the model to ask again, someone allowed to approve
//! agent actions, and cleared for what the run read, edits the call. The
//! domain keeps it to the same tool and the same class of action, and
//! checks it as it checks any call. An edit approves nothing: the request
//! opened for the old call is withdrawn and a new one is opened for the
//! revised call, with the same people barred from deciding it, so a
//! high-risk call still needs two others.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::{
    AgentRun, ResolvedCall, RevisedCall, ToolArguments, ToolCall,
};
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{
    ApprovalAction, ApprovalOrigin, ApprovalRequest, MAX_APPROVAL_SECONDS, RequestApprovalParams,
    RunOrigin,
};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    ActorRef, AgentId, AgentRunId, ApprovalId, DeclaredAction, EventLabel, Seconds,
};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, ApprovalStore, RunStore, ToolStore};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::AuditLabelResolver;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::audit_labels::agent_label;
use crate::use_cases::agents::runs::control::steering::{
    SteeredRun, SteeringStores, held_tool, open_request_of, save_steered, steered_run,
};
use crate::use_cases::agents::runs::driving::step::path_values;

/// The call to revise, addressed under the run and agent it belongs to.
pub struct ReviseCallRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The run holding the call.
    pub run_id: AgentRunId,
    /// The arguments the call is to be made with instead.
    pub arguments: ToolArguments,
}

/// What a revision left: the request now open for the revised call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisedRunCall {
    /// The execution now waiting on the replacement approval.
    pub run_id: AgentRunId,
    /// The approval request opened for the revised call.
    pub approval_id: ApprovalId,
}

/// The ports [`ReviseCallUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReviseCallPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// The agents, whose standing the run needs.
    pub agent_store: Arc<dyn AgentStore>,
    /// The tenant's tools, for the one the held call is for.
    pub tool_store: Arc<dyn ToolStore>,
    /// Withdraws the old request and keeps the new one.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// Names the agent in the audit trail.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Keeps the run, both requests and the record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revises the calls paused runs hold.
pub struct ReviseCallUseCase {
    ports: ReviseCallPorts,
    approval_ttl: Seconds,
}

impl ReviseCallUseCase {
    /// A use case working through `ports`, opening requests that stay
    /// decidable for `approval_ttl`, at most the domain's seven days, as
    /// the worker's own requests do.
    #[must_use]
    pub fn new(ports: ReviseCallPorts, approval_ttl: time::Duration) -> Self {
        let seconds = u32::try_from(approval_ttl.whole_seconds())
            .unwrap_or(MAX_APPROVAL_SECONDS)
            .clamp(1, MAX_APPROVAL_SECONDS);
        Self {
            ports,
            approval_ttl: Seconds::new(seconds),
        }
    }

    /// The run `request` addresses, with the agent it runs for.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the run does not exist under the agent.
    /// - `AppError::Internal` when the run or agent cannot be read.
    async fn steered(
        &self,
        tenant: &ScopedTenant,
        request: &ReviseCallRequest,
    ) -> Result<SteeredRun, AppError> {
        let stores = SteeringStores {
            runs: self.ports.run_store.as_ref(),
            agents: self.ports.agent_store.as_ref(),
        };
        steered_run(stores, tenant, &request.agent_id, &request.run_id).await
    }

    /// Revises the call `steered`'s run holds as `edit` says, withdraws
    /// `withdrawn` for it, and opens the request for the revised call.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden`, `AppError::Conflict` or `AppError::Domain`
    ///   when the domain refuses the revision or the withdrawal.
    /// - `AppError::Conflict` when the run is not paused on a call.
    fn opened_for_revision(
        &self,
        steered: &mut SteeredRun,
        withdrawn: &mut ApprovalRequest<ResolvedTenant>,
        edit: &Edit<'_>,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        let (revised, action) = revised_call(steered, edit)?;
        withdrawn
            .supersede(&revised)
            .map_err(AppError::from_domain)?;
        reopened(&steered.run, withdrawn, action, self.approval_ttl)
    }

    /// Keeps the revised run, the withdrawn request and the new one, and
    /// records all three, together.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        revision: &mut Revision,
        actor: &ActorRef,
    ) -> Result<(), AppError> {
        let approvals = self.ports.approval_store.as_ref();
        let work = async {
            save_steered(self.ports.run_store.as_ref(), tenant, &revision.steered).await?;
            approvals
                .save(tenant, &revision.withdrawn)
                .await
                .or_internal()?;
            approvals
                .save(tenant, &revision.opened)
                .await
                .or_internal()?;
            auditor
                .dispatch_by(actor, revision.recorded(tenant))
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), work).await
    }
}

impl Command for ReviseCallUseCase {
    type Caller = CallerContext;
    type Input = ReviseCallRequest;
    type Output = Result<RevisedRunCall, AppError>;

    /// Revises the call `request.run_id` holds, withdraws the request
    /// opened for it, opens one for the revised call, and records
    /// `agents.held_call_revised`, `agents.approval_withdrawn` and
    /// `agents.run_awaiting_approval`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing agent run, open request or registered tool.
    /// - `AppError::Forbidden` for missing approval rights/clearance, an agent unable to act, or a refused revised call.
    /// - `AppError::Conflict` for another tool/action class, an unchanged revision, or a concurrent run change.
    /// - `AppError::Domain` when the run is not awaiting approval or arguments cannot fill the tool's path.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ReviseCallRequest,
    ) -> Result<RevisedRunCall, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut steered = self.steered(&tenant, &request).await?;
        let mut withdrawn =
            open_request_of(self.ports.approval_store.as_ref(), &tenant, &steered.run).await?;
        let tool = held_tool(self.ports.tool_store.as_ref(), &tenant, &steered.run).await?;
        let edit = Edit {
            authority: &authority,
            tool: &tool,
            arguments: &request.arguments,
        };
        let opened = self.opened_for_revision(&mut steered, &mut withdrawn, &edit)?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let label = agent_label(resolver, &tenant, &request.agent_id).await;
        let mut revision = Revision {
            steered,
            withdrawn,
            opened,
            label,
        };
        self.keep(&tenant, auditor, &mut revision, &ctx.actor())
            .await?;
        Ok(RevisedRunCall {
            run_id: *revision.steered.run.id(),
            approval_id: *revision.opened.id(),
        })
    }
}

/// Who edits the held call, of which tool, to what arguments.
struct Edit<'a> {
    /// The person editing, with what they hold.
    authority: &'a TenantAuthority,
    /// The tool the held call is for.
    tool: &'a AgentTool<ResolvedTenant>,
    /// The arguments it is to be made with.
    arguments: &'a ToolArguments,
}

/// A revised run with the request withdrawn for its old call, the one
/// opened for its new call, and its agent's name in the record.
struct Revision {
    /// The run, holding the revised call.
    steered: SteeredRun,
    /// The request opened for the old call, withdrawn.
    withdrawn: ApprovalRequest<ResolvedTenant>,
    /// The request opened for the revised call.
    opened: ApprovalRequest<ResolvedTenant>,
    /// The run's agent, as the audit trail names it.
    label: EventLabel,
}

impl Revision {
    /// What the revision records: the edit, the old request withdrawn, and
    /// the run waiting on the new one.
    fn recorded(&mut self, tenant: &ScopedTenant) -> Vec<DomainEvent> {
        self.withdrawn.announce_decision(self.label.clone());
        self.steered.run.announce_pause(self.label.clone());
        let mut recorded = self.steered.run.take_events(tenant);
        recorded.extend(self.withdrawn.take_events(tenant));
        recorded
    }
}

/// Revises the call `steered`'s run holds as `edit` says, and gives back
/// the proof the old request is withdrawn on with the action the revised
/// call takes.
fn revised_call(
    steered: &mut SteeredRun,
    edit: &Edit<'_>,
) -> Result<(RevisedCall, ApprovalAction), AppError> {
    let call = ToolCall::new(edit.tool.name().as_str(), edit.arguments.as_str())
        .map_err(|e| AppError::from_domain(DomainError::from(e)))?;
    let values = path_values(edit.tool, call.arguments()).ok_or_else(|| {
        AppError::from_domain(DomainError::invalid(message!(
            "agents-the-arguments-do-not-fill-every",
            "the arguments do not fill every part of the tool's path"
        )))
    })?;
    let resolved = ResolvedCall::resolve(call, edit.tool, &values)
        .map_err(|refusal| AppError::from_domain(refusal.into()))?;
    let action = ApprovalAction::for_call(edit.tool.method().into(), resolved.target().as_str())
        .map_err(AppError::from_domain)?;
    let revised = steered
        .run
        .revise_pending(&AgentControl::new(edit.authority), resolved, &steered.agent)
        .map_err(AppError::from_domain)?;
    Ok((revised, action))
}

/// The request opened for the call `run` now holds, barring the same
/// people `withdrawn` barred, open for `ttl`.
fn reopened(
    run: &AgentRun<ResolvedTenant>,
    withdrawn: &ApprovalRequest<ResolvedTenant>,
    action: ApprovalAction,
    ttl: Seconds,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    let origin = RunOrigin::of(run).ok_or_else(|| {
        AppError::Conflict(message!(
            "agents-the-run-is-not-paused-on",
            "the run is not paused on a call"
        ))
    })?;
    ApprovalRequest::request(RequestApprovalParams {
        agent_id: *run.agent_id(),
        delegation_id: *run.delegation_id(),
        action_class: DeclaredAction::Declared(origin.class()),
        origin: ApprovalOrigin::Run(origin),
        parties: withdrawn.parties().clone(),
        action,
        ttl_seconds: ttl,
    })
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeApprovalStore, FakeRunStore, FakeToolStore, agent_owned_by,
        delegation_row, order_tool, paused_run, raised_approval, someone, tools_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann's run of Owen's agent, paused on deleting order 1, with the
    /// request it raised, and the stores they are kept in.
    struct Scene {
        agent: AgentIdentity<ResolvedTenant>,
        run: AgentRunId,
        approval: ApprovalId,
        runs: Arc<FakeRunStore>,
        agents: Arc<FakeAgentStore>,
        approvals: Arc<FakeApprovalStore>,
        tools: Arc<FakeToolStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn new() -> Self {
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
                approvals: Arc::new(FakeApprovalStore::empty()),
                tools: Arc::new(tools_holding([tool])),
                sink: Arc::new(FakeEventDispatcher::new()),
            };
            block_on(scene.runs.save(&tenant, &run)).unwrap();
            block_on(scene.agents.save(&tenant, &agent)).unwrap();
            block_on(scene.approvals.save(&tenant, &approval)).unwrap();
            scene
        }

        fn ports(&self) -> ReviseCallPorts {
            ReviseCallPorts {
                run_store: self.runs.clone(),
                agent_store: self.agents.clone(),
                tool_store: self.tools.clone(),
                approval_store: self.approvals.clone(),
                ..ReviseCallPorts::fakes()
            }
        }

        fn revise_with(
            &self,
            ports: ReviseCallPorts,
            arguments: &str,
        ) -> Result<RevisedRunCall, AppError> {
            let use_case = ReviseCallUseCase::new(ports, time::Duration::hours(1));
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ReviseCallRequest {
                    agent_id: *self.agent.id(),
                    run_id: self.run,
                    arguments: ToolArguments::new(arguments).unwrap(),
                },
            ))
        }

        fn revise(&self, arguments: &str) -> Result<RevisedRunCall, AppError> {
            self.revise_with(self.ports(), arguments)
        }

        fn revise_holding(
            &self,
            held: &[SystemPermission],
            arguments: &str,
        ) -> Result<RevisedRunCall, AppError> {
            let ports = ReviseCallPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
                ..self.ports()
            };
            self.revise_with(ports, arguments)
        }

        fn stored_run(&self) -> AgentRun<ResolvedTenant> {
            block_on(self.runs.find_by_id(&test_ctx().tenant(), &self.run))
                .unwrap()
                .unwrap()
        }

        fn status_of(&self, id: &ApprovalId) -> ApprovalStatus {
            block_on(self.approvals.find_by_id(&test_ctx().tenant(), id))
                .unwrap()
                .unwrap()
                .status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Bob changes Ann's held delete to order 2. The run holds the revised
    /// call, still waiting; the old request is withdrawn and a new one is
    /// open for the revised call; all three are recorded.
    #[test]
    fn a_revised_call_waits_on_a_new_request() {
        let scene = Scene::new();

        let revised = scene.revise("{\"id\":2}").unwrap();

        let run = scene.stored_run();
        assert_eq!(run.status(), RunStatus::AwaitingApproval);
        assert_eq!(run.pending().unwrap().arguments(), "{\"id\":2}");
        assert_eq!(scene.status_of(&scene.approval), ApprovalStatus::Withdrawn);
        assert_eq!(
            scene.status_of(&revised.approval_id),
            ApprovalStatus::Pending
        );
        assert_eq!(
            scene.records(),
            [
                "agents.held_call_revised",
                "agents.run_awaiting_approval",
                "agents.approval_withdrawn"
            ]
        );
    }

    /// An agent viewer cannot revise a held call. Its arguments stay unchanged,
    /// its approval stays pending and no audit event is recorded.
    #[test]
    fn only_someone_allowed_to_approve_revises_a_call() {
        let scene = Scene::new();

        let viewer = [SystemPermission::Agents(AgentAction::View)];

        let result = scene.revise_holding(&viewer, "{\"id\":9}");

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        let held = scene.stored_run();
        assert_eq!(held.pending().unwrap().arguments(), "{\"id\":1}");
        assert_eq!(scene.status_of(&scene.approval), ApprovalStatus::Pending);
        assert!(scene.records().is_empty());
    }

    /// A revision that changes nothing is refused as a conflict, and the
    /// request stays open.
    #[test]
    fn a_revision_that_changes_nothing_is_refused() {
        let scene = Scene::new();

        let result = scene.revise("{\"id\":1}");

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(scene.status_of(&scene.approval), ApprovalStatus::Pending);
    }

    /// Revised arguments missing the required path ID are refused, leaving the
    /// approval pending.
    #[test]
    fn a_revision_that_does_not_fill_the_path_is_refused() {
        let scene = Scene::new();

        let result = scene.revise("{}");

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(scene.status_of(&scene.approval), ApprovalStatus::Pending);
    }

    /// The worker or a person changed the run after Bob read it. His
    /// revision is refused as a conflict.
    #[test]
    fn a_revision_over_a_run_that_changed_is_refused() {
        let scene = Scene::new();
        scene.runs.moves_on_before_each_save();

        let result = scene.revise("{\"id\":2}");

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert!(scene.records().is_empty());
    }

    /// A signed-out session cannot revise a held call; its approval stays pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::new();
        let ports = ReviseCallPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.revise_with(ports, "{\"id\":2}");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.status_of(&scene.approval), ApprovalStatus::Pending);
    }
}
