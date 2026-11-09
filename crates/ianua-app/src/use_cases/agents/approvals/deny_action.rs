//! Deny action: a person refuses an agent's paused action.
//!
//! Denying takes the same right and clearance as approving, so nobody keeps
//! refusing other people's requests to stall them. A request a run raised
//! hands the run the proof it drops its held call on, and the run carries
//! on without it. The run is changed before anything is saved, so the
//! denial and the run move together or not at all.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::{AgentRun, DeniedCall};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{ApprovalRequest, Approver};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, ApprovalId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::RunVersion;
use crate::ports::shared::AuditLabelResolver;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::decided::{
    DecisionPorts, Resumed, ensure_may_approve, save_decision, save_if_lapsed,
};
use crate::use_cases::agents::audit_labels::agent_label;
use crate::use_cases::agents::lookup::owned_approval;
use crate::use_cases::agents::runs::reading::names::run_names;

/// Why a run records the call a person denied.
const DENIED_REASON: &str = "denied by a person";

/// Which approval request to deny, addressed under the agent it was raised
/// for.
pub struct DenyActionRequest {
    /// The agent the address named. The request must be one of its own.
    pub agent_id: AgentId,
    /// The request being denied.
    pub approval_id: ApprovalId,
}

/// The ports [`DenyActionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DenyActionPorts {
    /// Where the request, the run that drops the denied call, and the job
    /// driving it on are kept.
    pub decisions: DecisionPorts,
    /// Names the agent in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Denies an agent's paused action.
pub struct DenyActionUseCase {
    ports: DenyActionPorts,
}

impl DenyActionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DenyActionPorts) -> Self {
        Self { ports }
    }
}

impl Command for DenyActionUseCase {
    type Caller = CallerContext;
    type Input = DenyActionRequest;
    type Output = Result<ApprovalRequest<ResolvedTenant>, AppError>;

    /// Denies the paused action for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing approval rights or clearance.
    /// - `AppError::NotFound` for a missing agent request or originating run.
    /// - `AppError::Domain` when the request or run is not awaiting a decision.
    /// - `AppError::Conflict` for another call, a concurrent decision, or a stopped/changed run.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DenyActionRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_may_approve(&authority)?;
        let mut approval = owned_approval(
            self.ports.decisions.approval_store.as_ref(),
            &tenant,
            &request.agent_id,
            &request.approval_id,
        )
        .await?;
        let denied = denied(&self.ports, &tenant, &mut approval, &authority).await?;
        let mut resumed = run_without_call(&self.ports, &tenant, denied).await?;
        let keeping = self.ports.decisions.keeping();
        save_decision(keeping, &tenant, &approval, resumed.as_ref()).await?;

        auditor
            .dispatch_by(
                &ctx.actor(),
                denial_record(
                    &tenant,
                    &mut approval,
                    resumed.as_mut().map(|kept| &mut kept.run),
                ),
            )
            .await
            .or_internal()?;
        Ok(approval)
    }
}

/// The call `authority`'s denial of `approval` drops, announced with the
/// agent named as the audit trail knows it. A request opened by hand drops
/// none. A request whose time ran out is expired by the attempt, and saved
/// so before the refusal goes back.
///
/// # Errors
///
/// Returns `AppError::Forbidden` or `AppError::Domain` when the caller may
/// not deny the request, it is no longer pending or its time ran out.
async fn denied(
    ports: &DenyActionPorts,
    tenant: &ScopedTenant,
    approval: &mut ApprovalRequest<ResolvedTenant>,
    authority: &TenantAuthority,
) -> Result<Option<DeniedCall>, AppError> {
    let label = agent_label(
        ports.audit_label_resolver.as_ref(),
        tenant,
        approval.agent_id(),
    )
    .await;
    let refused = match approval.deny(&Approver::of(AgentControl::new(authority))) {
        Ok(denied) => {
            approval.announce_decision(label);
            return Ok(denied);
        }
        Err(refused) => refused,
    };
    save_if_lapsed(ports.decisions.approval_store.as_ref(), tenant, approval).await?;
    Err(AppError::from_domain(refused))
}

/// What the denial records: the request denied, then the run it handed
/// back to a worker, when a run raised it.
fn denial_record(
    tenant: &ScopedTenant,
    approval: &mut ApprovalRequest<ResolvedTenant>,
    resumed: Option<&mut AgentRun<ResolvedTenant>>,
) -> Vec<DomainEvent> {
    let mut recorded = approval.take_events(tenant);
    recorded.extend(
        resumed
            .map(|run| run.take_events(tenant))
            .unwrap_or_default(),
    );
    recorded
}

/// The run `denied` names, carrying on without the call it held and handed
/// back to a worker, which drives it on. A request opened by hand has no
/// run.
async fn run_without_call(
    ports: &DenyActionPorts,
    tenant: &ScopedTenant,
    denied: Option<DeniedCall>,
) -> Result<Option<Resumed>, AppError> {
    let Some(denied) = denied else {
        return Ok(None);
    };
    let mut run = ports
        .decisions
        .run_store
        .find_by_id(tenant, denied.run_id())
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-the-denied-run-no-longer-exists",
            "the denied run no longer exists"
        ))?;
    let read = RunVersion::of(&run);
    run.deny_pending(&denied, DENIED_REASON)
        .map_err(AppError::from_domain)?;
    let names = run_names(ports.audit_label_resolver.as_ref(), tenant, &run).await;
    run.announce_start(names);
    Ok(Some(Resumed { run, read }))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::agents::oversight::approval::{
        ApprovalRequestRow, ApprovalState, FirstOfTwo, StoredApprovalOrigin,
    };
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::Initiator;
    use time::Duration;

    use super::*;
    use crate::ports::agents::{ApprovalStore, RunStore};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeApprovalStore, FakeRunStore, agent_owned_by, delegation_row, opened_request,
        order_tool, paused_run, raised_approval, someone,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::agents::runs::{DRIVE_RUN_JOB, RunDrives};

    /// A request Olga opened by hand for Ann's agent.
    fn opened() -> (Arc<FakeApprovalStore>, DenyActionRequest) {
        let agent = agent_owned_by(AgentId::new(), someone("ann@corp.test"));
        let approval = opened_request(&agent, someone("olga@corp.test"));
        let store = Arc::new(FakeApprovalStore::empty());
        block_on(store.save(&test_ctx().tenant(), &approval)).unwrap();
        let request = DenyActionRequest {
            agent_id: *agent.id(),
            approval_id: *approval.id(),
        };
        (store, request)
    }

    fn deny(
        ports: DenyActionPorts,
        sink: &Arc<FakeEventDispatcher>,
        request: DenyActionRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        block_on(DenyActionUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn quietly(
        ports: DenyActionPorts,
        request: DenyActionRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        deny(ports, &Arc::new(FakeEventDispatcher::new()), request)
    }

    fn ports_over(store: &Arc<FakeApprovalStore>) -> DenyActionPorts {
        DenyActionPorts {
            decisions: DecisionPorts {
                approval_store: store.clone(),
                ..DecisionPorts::fakes()
            },
            ..DenyActionPorts::fakes()
        }
    }

    /// Bob denies the note Olga asked Ann's agent to write. It is denied and
    /// the denial is recorded.
    #[test]
    fn a_person_denies_a_paused_action_and_it_is_recorded() {
        let (store, request) = opened();
        let sink = Arc::new(FakeEventDispatcher::new());

        let approval = deny(ports_over(&store), &sink, request).unwrap();

        assert_eq!(approval.status(), ApprovalStatus::Denied);
        assert_eq!(store.all()[0].status(), ApprovalStatus::Denied);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.approval_denied"]
        );
    }

    /// Bob denies the delete Ann's run paused on. The run drops the call and
    /// carries on, recording the denial, and the request is denied with it.
    #[test]
    fn denying_a_runs_request_lets_the_run_carry_on_without_the_call() {
        let ann = someone("ann@corp.test");
        let agent = agent_owned_by(AgentId::new(), someone("owner@corp.test"));
        let delegation =
            Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
        let tool = order_tool("delete_order");
        let run = paused_run(&ann, &agent, &delegation, &tool);
        let approval = raised_approval(&run, &agent, &ann, &tool);
        let tenant = test_ctx().tenant();
        let (runs, approvals) = (
            Arc::new(FakeRunStore::empty()),
            Arc::new(FakeApprovalStore::empty()),
        );
        block_on(runs.save(&tenant, &run)).unwrap();
        block_on(approvals.save(&tenant, &approval)).unwrap();
        let mut ports = ports_over(&approvals);
        ports.decisions.run_store = runs.clone();

        quietly(
            ports,
            DenyActionRequest {
                agent_id: *agent.id(),
                approval_id: *approval.id(),
            },
        )
        .unwrap();

        assert_eq!(approvals.all()[0].status(), ApprovalStatus::Denied);
        let stored = runs.all().remove(0);
        assert_eq!(stored.status(), RunStatus::Running);
        assert!(stored.pending().is_none());
    }

    /// Bob denies the delete Ann's run paused on. The denial is recorded and
    /// the run is handed back to a worker, so it goes on without the call
    /// instead of waiting for nobody.
    #[test]
    fn denying_a_runs_request_hands_the_run_back_to_a_worker() {
        let runs = Arc::new(FakeRunStore::empty());
        let approvals = Arc::new(FakeApprovalStore::empty());
        let request = paused_request(&runs, &approvals);
        let sink = Arc::new(FakeEventDispatcher::new());
        let queue = Arc::new(FakeJobQueue::new());
        let mut ports = ports_over(&approvals);
        ports.decisions.run_store = runs;
        ports.decisions.run_drives = RunDrives {
            queue: queue.clone(),
            attempts: NonZeroU32::MIN,
        };

        deny(ports, &sink, request).unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.approval_denied", "agents.run_started"]
        );
        assert_eq!(queue.jobs_of(DRIVE_RUN_JOB).len(), 1);
    }

    /// Stores the approval raised by Ann's paused delete and addresses it for denial.
    fn paused_request(runs: &FakeRunStore, approvals: &FakeApprovalStore) -> DenyActionRequest {
        let ann = someone("ann@corp.test");
        let agent = agent_owned_by(AgentId::new(), someone("owner@corp.test"));
        let delegation =
            Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
        let tool = order_tool("delete_order");
        let run = paused_run(&ann, &agent, &delegation, &tool);
        let approval = raised_approval(&run, &agent, &ann, &tool);
        let tenant = test_ctx().tenant();
        block_on(runs.save(&tenant, &run)).unwrap();
        block_on(approvals.save(&tenant, &approval)).unwrap();
        DenyActionRequest {
            agent_id: *agent.id(),
            approval_id: *approval.id(),
        }
    }

    /// Bob denies a note Olga opened by hand. No run stands behind it, so
    /// no drive job is queued.
    #[test]
    fn denying_a_hand_opened_request_queues_no_drive_job() {
        let (store, request) = opened();
        let queue = Arc::new(FakeJobQueue::new());
        let mut ports = ports_over(&store);
        ports.decisions.run_drives = RunDrives {
            queue: queue.clone(),
            attempts: NonZeroU32::MIN,
        };

        quietly(ports, request).unwrap();

        assert!(queue.jobs_of(DRIVE_RUN_JOB).is_empty());
    }

    /// A missing originating run prevents denial and leaves its approval
    /// request pending.
    #[test]
    fn a_request_whose_run_is_gone_stays_pending() {
        let ann = someone("ann@corp.test");
        let agent = agent_owned_by(AgentId::new(), someone("owner@corp.test"));
        let delegation =
            Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
        let tool = order_tool("delete_order");
        let run = paused_run(&ann, &agent, &delegation, &tool);
        let approval = raised_approval(&run, &agent, &ann, &tool);
        let approvals = Arc::new(FakeApprovalStore::empty());
        block_on(approvals.save(&test_ctx().tenant(), &approval)).unwrap();

        let result = quietly(
            ports_over(&approvals),
            DenyActionRequest {
                agent_id: *agent.id(),
                approval_id: *approval.id(),
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(approvals.all()[0].status(), ApprovalStatus::Pending);
    }

    /// A request expiring during denial returns a conflict, remains expired,
    /// and records no denial event.
    #[test]
    fn a_denial_of_a_request_that_lapsed_meanwhile_is_a_conflict() {
        let agent = agent_owned_by(AgentId::new(), someone("ann@corp.test"));
        let approval = opened_request(&agent, someone("olga@corp.test"));
        let store = Arc::new(FakeApprovalStore::lapsing_while_decided());
        block_on(store.save(&test_ctx().tenant(), &approval)).unwrap();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = deny(
            ports_over(&store),
            &sink,
            DenyActionRequest {
                agent_id: *agent.id(),
                approval_id: *approval.id(),
            },
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.all()[0].status(), ApprovalStatus::Expired);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Denying a lapsed request fails and saves it as expired without a
    /// decider or a denial event.
    #[test]
    fn a_lapsed_request_is_refused_and_saved_as_expired() {
        let (store, request) = opened();
        let stored = store.all().remove(0);
        let now = clock::now();
        let lapsed = ApprovalRequest::reconstitute(ApprovalRequestRow {
            id: *stored.id(),
            agent_id: *stored.agent_id(),
            delegation_id: *stored.delegation_id(),
            origin: StoredApprovalOrigin::Opened(Initiator::Human(someone("olga@corp.test"))),
            parties: stored.parties().clone(),
            action_class: stored.action_class(),
            action: stored.action().clone(),
            state: ApprovalState::Pending(FirstOfTwo::NotGiven),
            created_at: now - Duration::hours(2),
            expires_at: now - Duration::hours(1),
            updated_at: now - Duration::hours(2),
        })
        .unwrap();
        block_on(store.save(&test_ctx().tenant(), &lapsed)).unwrap();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = deny(ports_over(&store), &sink, request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        let kept = store.all().remove(0);
        assert_eq!(kept.state().status(), ApprovalStatus::Expired);
        assert!(kept.decided_by().is_none());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Denying a request through another agent's address reports it as
    /// missing and leaves it pending.
    #[test]
    fn a_request_under_another_agents_address_is_not_found() {
        let (store, request) = opened();
        let request = DenyActionRequest {
            agent_id: AgentId::new(),
            ..request
        };

        let result = quietly(ports_over(&store), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(store.all()[0].status(), ApprovalStatus::Pending);
    }

    /// Bob denies a request that does not exist. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let (store, request) = opened();
        let request = DenyActionRequest {
            approval_id: ApprovalId::new(),
            ..request
        };

        let result = quietly(ports_over(&store), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without approval permission cannot deny a request, which
    /// remains pending.
    #[test]
    fn a_caller_who_may_not_approve_cannot_deny() {
        let (store, request) = opened();
        let ports = DenyActionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&store)
        };

        let result = quietly(ports, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.all()[0].status(), ApprovalStatus::Pending);
    }

    /// A signed-out caller cannot deny an approval request.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, request) = opened();
        let ports = DenyActionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = quietly(ports, request);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Bob denies a request already denied. It is no longer pending and is
    /// refused.
    #[test]
    fn a_request_is_denied_once() {
        let (store, request) = opened();
        let again = DenyActionRequest {
            agent_id: request.agent_id,
            approval_id: request.approval_id,
        };
        quietly(ports_over(&store), request).unwrap();

        let result = quietly(ports_over(&store), again);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }
}
