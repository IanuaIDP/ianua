//! Approve action: a person authorizes an agent's paused action.
//!
//! The domain decides who may approve: someone allowed to approve agent
//! actions, cleared for what the request shows, who neither put the action
//! there, owns the agent nor stands behind its delegation. A high-risk
//! action needs two different people, each present with a fresh second
//! factor. The app adds the hourly cap on approvals one person gives.
//!
//! The approval that grants a run's call is spent on it at once, on the
//! delegation as it stands now, and the run resumes on exactly that call.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{
    ApprovalRequest, ApprovalStep, Approver, PresenceProof,
};
use ianua_domain::domains::authentication::mfa::enrollment::AnsweredCode;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, ApprovalId};
use time::Duration;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{DelegationStore, RunVersion};
use crate::ports::shared::AuditLabelResolver;
use crate::services::authentication::approver_presence::ApproverPresence;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::ApprovalLimits;
use crate::use_cases::agents::approvals::action_authority::loaded_authority;
use crate::use_cases::agents::approvals::decided::{
    DecisionPorts, Resumed, ensure_may_approve, save_decision, save_if_lapsed,
};
use crate::use_cases::agents::audit_labels::agent_label;
use crate::use_cases::agents::lookup::owned_approval;
use crate::use_cases::agents::runs::reading::names::run_names;

/// The ports [`ApproveActionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApproveActionPorts {
    /// Where the request, the run it resumes, and the job driving that run
    /// are kept, so deciding in the inbox and deciding on the run are the
    /// same act.
    pub decisions: DecisionPorts,
    /// The delegation the approved action uses, and the chain above it.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Names the agent in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Requires a fresh second factor from the approver of a high-risk action.
    pub presence: Arc<ApproverPresence>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// One person's approval of a paused action.
pub struct ApproveActionRequest {
    /// The agent the address named. The request must be one of its own.
    pub agent_id: AgentId,
    /// The request being approved.
    pub approval_id: ApprovalId,
    /// A fresh second-factor code, needed for a high-risk action.
    pub mfa_code: Option<String>,
}

/// Approves an agent's paused action.
pub struct ApproveActionUseCase {
    limits: ApprovalLimits,
    ports: ApproveActionPorts,
}

impl ApproveActionUseCase {
    /// A use case working through `ports`, holding approvers to `limits`.
    #[must_use]
    pub fn new(limits: ApprovalLimits, ports: ApproveActionPorts) -> Self {
        Self { limits, ports }
    }
}

impl Command for ApproveActionUseCase {
    type Caller = CallerContext;
    type Input = ApproveActionRequest;
    type Output = Result<ApprovalRequest<ResolvedTenant>, AppError>;

    /// Approves the paused action for the person `ctx` names.
    ///
    /// The first of two approvals is recorded and the action keeps
    /// waiting; the approval that grants a run's call resumes the run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing approval rights, checked before reading.
    /// - `AppError::TooManyRequests` for the hourly approval cap; `NotFound` for a missing request, run or delegation.
    /// - `AppError::Forbidden` for insufficient clearance, approval by the action author, agent owner, delegator or first approver, or a wrong/spent code; `StepUpRequired` or `AccountLocked` for failed presence checks.
    /// - `AppError::Domain` for a decided/expired request (expiry is saved), inactive delegation or missing approved call; `Conflict` for concurrent decisions or run changes.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ApproveActionRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_may_approve(&authority)?;
        ensure_under_hourly_cap(&self.ports, self.limits, &tenant, &authority).await?;
        let mut approval = owned_approval(
            self.ports.decisions.approval_store.as_ref(),
            &tenant,
            &request.agent_id,
            &request.approval_id,
        )
        .await?;
        let answered = presence(&self.ports, ctx, &approval, request.mfa_code.as_deref()).await?;
        let approver = approver_of(&authority, answered.as_ref())?;
        let step = decided(&self.ports, &tenant, &mut approval, &approver).await?;
        let mut resumed = released_run(&self.ports, &tenant, &mut approval, step).await?;
        let keeping = self.ports.decisions.keeping();
        save_decision(keeping, &tenant, &approval, resumed.as_ref()).await?;
        let events = recorded(
            ctx,
            &mut approval,
            resumed.as_mut().map(|kept| &mut kept.run),
        );
        auditor.dispatch(&events).await.or_internal()?;
        Ok(approval)
    }
}

/// Refuses a person who already gave as many approvals in the last hour as
/// one person may. Approving faster than anyone could read is
/// rubber-stamping.
async fn ensure_under_hourly_cap(
    ports: &ApproveActionPorts,
    limits: ApprovalLimits,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
) -> Result<(), AppError> {
    let since = clock::now() - Duration::hours(1);
    let signed = ports
        .decisions
        .approval_store
        .count_signed_by(tenant, &authority.who().principal(), since)
        .await
        .or_internal()?;
    let most = limits.per_person_per_hour;
    if signed < most {
        return Ok(());
    }
    Err(AppError::TooManyRequests(message!(
        "agents-at-most-approvals-per-person-per",
        format!("at most {most} approvals per person per hour")
    )))
}

/// The caller's fresh second-factor answer, when the request needs the
/// approver present.
async fn presence(
    ports: &ApproveActionPorts,
    ctx: &CallerContext,
    approval: &ApprovalRequest<ResolvedTenant>,
    code: Option<&str>,
) -> Result<Option<AnsweredCode>, AppError> {
    if !approval.needs_presence() {
        return Ok(None);
    }
    Ok(Some(ports.presence.require(ctx, code).await?))
}

/// The person `authority` names as an approver, present when `answered`
/// proves it.
fn approver_of<'a>(
    authority: &'a TenantAuthority,
    answered: Option<&AnsweredCode>,
) -> Result<Approver<'a>, AppError> {
    let control = AgentControl::new(authority);
    match answered {
        None => Ok(Approver::of(control)),
        Some(code) => {
            Approver::present(control, PresenceProof::Code(code)).map_err(AppError::from_domain)
        }
    }
}

/// The step `approver`'s approval takes, announced with the agent named as
/// the audit trail knows it. A request whose time ran out is expired by the
/// attempt, and saved so before the refusal goes back.
async fn decided(
    ports: &ApproveActionPorts,
    tenant: &ScopedTenant,
    approval: &mut ApprovalRequest<ResolvedTenant>,
    approver: &Approver<'_>,
) -> Result<ApprovalStep, AppError> {
    let label = agent_label(
        ports.audit_label_resolver.as_ref(),
        tenant,
        approval.agent_id(),
    )
    .await;
    let refused = match approval.approve(approver) {
        Ok(step) => {
            approval.announce_decision(label);
            return Ok(step);
        }
        Err(refused) => refused,
    };
    save_if_lapsed(ports.decisions.approval_store.as_ref(), tenant, approval).await?;
    Err(AppError::from_domain(refused))
}

/// The run behind `approval`, resumed on the call it holds, once `step`
/// granted it. The approval is spent on that call, on the delegation as it
/// stands now. A request opened by hand has no run to resume.
async fn released_run(
    ports: &ApproveActionPorts,
    tenant: &ScopedTenant,
    approval: &mut ApprovalRequest<ResolvedTenant>,
    step: ApprovalStep,
) -> Result<Option<Resumed>, AppError> {
    let (ApprovalStep::Granted, Some(run_id)) = (step, approval.run_id().copied()) else {
        return Ok(None);
    };
    let mut run = ports
        .decisions
        .run_store
        .find_by_id(tenant, &run_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "agents-the-approved-run-no-longer-exists",
            "the approved run no longer exists"
        ))?;
    let read = RunVersion::of(&run);
    let loaded = loaded_authority(
        ports.delegation_store.as_ref(),
        tenant,
        approval.delegation_id(),
    )
    .await?;
    let released = approval
        .release(&loaded.authority())
        .map_err(AppError::from_domain)?;
    run.approve_pending(&released)
        .map_err(AppError::from_domain)?;
    let names = run_names(ports.audit_label_resolver.as_ref(), tenant, &run).await;
    run.announce_start(names);
    Ok(Some(Resumed { run, read }))
}

/// What the approval records: a grant or a first signature by the person
/// `ctx` names, then the run it resumed.
fn recorded(
    ctx: &CallerContext,
    approval: &mut ApprovalRequest<ResolvedTenant>,
    resumed: Option<&mut AgentRun<ResolvedTenant>>,
) -> Vec<DomainEvent> {
    let tenant = ctx.tenant();
    let actor = ctx.actor();
    let decision = approval
        .take_events(&tenant)
        .into_iter()
        .map(|event| event.with_actor(actor.clone()));
    let handed_on = resumed
        .map(|run| run.take_events(&tenant))
        .unwrap_or_default();
    decision.chain(handed_on).collect()
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::agents::authority::delegation::{Delegation, DelegationStatus};
    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::oversight::approval::{
        ApprovalRequestRow, ApprovalState, FirstOfTwo, StoredApprovalOrigin,
    };
    use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{Human, HumanAccount, Initiator, PersonKey, SessionId, UserId};

    use super::*;
    use crate::acting::tenant::{AccountHolder, SignedInAccount};
    use crate::context::CallerIdentity;
    use crate::ports::agents::{ApprovalStore, RunStore};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        DistinctPeople, FakeApprovalStore, FakeDelegationStore, FakeRunStore, OPENED_TARGET,
        PRESENT_CODE, agent_owned_by, approval_limits, delegation_row, enrolled_presence,
        opened_request, order_tool, paused_run, person_of, raised_approval, someone,
    };
    use crate::test_support::authentication::FakeMfaEnrollmentStore;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FakeAuditLabelResolver, FakeEventDispatcher, block_on, reference_label, test_auditor,
        test_ctx, test_ctx_with,
    };
    use crate::use_cases::agents::runs::{DRIVE_RUN_JOB, RunDrives};

    /// Ann's agent, with a request Olga opened by hand for it.
    struct Opened {
        agent: AgentIdentity<ResolvedTenant>,
        approvals: Arc<FakeApprovalStore>,
        approval_id: ApprovalId,
    }

    fn opened() -> Opened {
        let agent = agent_owned_by(AgentId::new(), someone("ann@corp.test"));
        opened_by(agent, someone("olga@corp.test"))
    }

    fn opened_by(agent: AgentIdentity<ResolvedTenant>, opener: Human) -> Opened {
        let approvals = Arc::new(FakeApprovalStore::empty());
        let approval = opened_request(&agent, opener);
        let approval_id = *approval.id();
        block_on(approvals.save(&test_ctx().tenant(), &approval)).unwrap();
        Opened {
            agent,
            approvals,
            approval_id,
        }
    }

    impl Opened {
        fn ports(&self) -> ApproveActionPorts {
            ApproveActionPorts {
                decisions: DecisionPorts {
                    approval_store: self.approvals.clone(),
                    ..DecisionPorts::fakes()
                },
                ..ApproveActionPorts::fakes()
            }
        }

        fn request(&self) -> ApproveActionRequest {
            ApproveActionRequest {
                agent_id: *self.agent.id(),
                approval_id: self.approval_id,
                mfa_code: None,
            }
        }

        fn status(&self) -> ApprovalStatus {
            self.approvals.all()[0].status()
        }
    }

    fn approve(
        ports: ApproveActionPorts,
        ctx: &CallerContext,
        sink: &Arc<FakeEventDispatcher>,
        request: ApproveActionRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        let use_case = ApproveActionUseCase::new(approval_limits(), ports);
        block_on(use_case.execute(ctx, &test_auditor(sink.clone()), request))
    }

    fn quietly(
        ports: ApproveActionPorts,
        request: ApproveActionRequest,
    ) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
        approve(
            ports,
            &test_ctx(),
            &Arc::new(FakeEventDispatcher::new()),
            request,
        )
    }

    /// Ann's agent paused on deleting order 1 in a run she started under
    /// her own delegation, with the request the pause raised.
    struct Paused {
        runs: Arc<FakeRunStore>,
        approvals: Arc<FakeApprovalStore>,
        delegations: Arc<FakeDelegationStore>,
        agent_id: AgentId,
        approval_id: ApprovalId,
        delegation: Delegation<ResolvedTenant>,
        queue: Arc<FakeJobQueue>,
    }

    fn paused() -> Paused {
        let ann = someone("ann@corp.test");
        let agent = agent_owned_by(AgentId::new(), someone("owner@corp.test"));
        let delegation =
            Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
        let tool = order_tool("delete_order");
        let run = paused_run(&ann, &agent, &delegation, &tool);
        let approval = raised_approval(&run, &agent, &ann, &tool);
        let tenant = test_ctx().tenant();
        let (runs, approvals, delegations) = (
            Arc::new(FakeRunStore::empty()),
            Arc::new(FakeApprovalStore::empty()),
            Arc::new(FakeDelegationStore::empty()),
        );
        block_on(runs.save(&tenant, &run)).unwrap();
        block_on(approvals.save(&tenant, &approval)).unwrap();
        block_on(delegations.save(&tenant, &delegation)).unwrap();
        Paused {
            runs,
            approvals,
            delegations,
            agent_id: *agent.id(),
            approval_id: *approval.id(),
            delegation,
            queue: Arc::new(FakeJobQueue::new()),
        }
    }

    impl Paused {
        fn ports(&self, mfa: Arc<FakeMfaEnrollmentStore>) -> ApproveActionPorts {
            ApproveActionPorts {
                decisions: DecisionPorts {
                    approval_store: self.approvals.clone(),
                    run_store: self.runs.clone(),
                    run_drives: RunDrives {
                        queue: self.queue.clone(),
                        attempts: NonZeroU32::MIN,
                    },
                },
                delegation_store: self.delegations.clone(),
                presence: Arc::new(enrolled_presence(mfa)),
                tenant_authorities: Arc::new(DistinctPeople::holding_everything()),
                ..ApproveActionPorts::fakes()
            }
        }

        fn drive_jobs(&self) -> usize {
            self.queue.jobs_of(DRIVE_RUN_JOB).len()
        }

        fn request(&self, code: Option<&str>) -> ApproveActionRequest {
            ApproveActionRequest {
                agent_id: self.agent_id,
                approval_id: self.approval_id,
                mfa_code: code.map(str::to_owned),
            }
        }

        fn run_status(&self) -> RunStatus {
            self.runs.all()[0].status()
        }

        fn status(&self) -> ApprovalStatus {
            self.approvals.all()[0].status()
        }

        fn revoke_delegation(&self) {
            let mut row = delegation_row(self.agent_id, *self.delegation.delegator());
            row.id = *self.delegation.id();
            row.status = DelegationStatus::Revoked;
            let revoked = Delegation::reconstitute(row).unwrap();
            block_on(self.delegations.save(&test_ctx().tenant(), &revoked)).unwrap();
        }
    }

    /// Bob and Carol, two people each enrolled in a second factor.
    fn two_present_approvers() -> (CallerContext, CallerContext, Arc<FakeMfaEnrollmentStore>) {
        let tenant = test_ctx();
        let bob = UserId::new();
        let carol = UserId::new();
        let mfa = Arc::new(FakeMfaEnrollmentStore::empty());
        mfa.enroll(bob);
        mfa.enroll(carol);
        let ctx = |user| test_ctx_with(tenant.organization_id(), tenant.tenant_id(), user);
        (ctx(bob), ctx(carol), mfa)
    }

    /// Bob approves the note Olga asked Ann's agent to write. It is approved
    /// and the grant is recorded.
    #[test]
    fn a_person_approves_a_paused_action_and_it_is_recorded() {
        let opened = opened();
        let sink = Arc::new(FakeEventDispatcher::new());

        let approval = approve(opened.ports(), &test_ctx(), &sink, opened.request()).unwrap();

        assert_eq!(approval.status(), ApprovalStatus::Approved);
        assert_eq!(opened.status(), ApprovalStatus::Approved);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.approval_granted"]
        );
    }

    /// The record of Bob's approval names the agent and the exact call.
    #[test]
    fn the_record_names_the_agent_and_the_call() {
        let opened = opened();
        let sink = Arc::new(FakeEventDispatcher::new());

        approve(opened.ports(), &test_ctx(), &sink, opened.request()).unwrap();

        let payloads = sink.all_payloads();
        assert_eq!(reference_label(&payloads[0], "agent"), Some("test agent"));
        let action = format!("POST {OPENED_TARGET}");
        assert_eq!(
            reference_label(&payloads[0], "approval"),
            Some(action.as_str())
        );
    }

    /// Ann's agent is deleted while Bob approves. The record names it by its
    /// id, and the approval still goes through.
    #[test]
    fn a_vanished_agent_is_named_by_its_id() {
        let opened = opened();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ApproveActionPorts {
            audit_label_resolver: Arc::new(FakeAuditLabelResolver::missing()),
            ..opened.ports()
        };

        approve(ports, &test_ctx(), &sink, opened.request()).unwrap();

        let id = opened.agent.id().to_string();
        assert_eq!(
            reference_label(&sink.all_payloads()[0], "agent"),
            Some(id.as_str())
        );
    }

    /// Bob approves a request that does not exist. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let opened = opened();
        let request = ApproveActionRequest {
            approval_id: ApprovalId::new(),
            ..opened.request()
        };

        let result = quietly(opened.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Approving through another agent's address reports the request as
    /// missing and leaves it pending.
    #[test]
    fn a_request_under_another_agents_address_is_not_found() {
        let opened = opened();
        let request = ApproveActionRequest {
            agent_id: AgentId::new(),
            ..opened.request()
        };

        let result = quietly(opened.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(opened.status(), ApprovalStatus::Pending);
    }

    /// Bob approves the same request twice. The second time it is no longer
    /// pending and is refused.
    #[test]
    fn a_request_is_approved_once() {
        let opened = opened();
        quietly(opened.ports(), opened.request()).unwrap();

        let again = quietly(opened.ports(), opened.request());

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// The person who opened a request cannot approve it; it remains pending.
    #[test]
    fn the_person_who_opened_a_request_cannot_approve_it() {
        let agent = agent_owned_by(AgentId::new(), someone("ann@corp.test"));
        let olga = test_ctx_with(
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            UserId::new(),
        );
        let opened = opened_by(agent, person_of(&olga));
        let ports = ApproveActionPorts {
            tenant_authorities: Arc::new(DistinctPeople::holding_everything()),
            ..opened.ports()
        };

        let result = approve(
            ports,
            &olga,
            &Arc::new(FakeEventDispatcher::new()),
            opened.request(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(opened.status(), ApprovalStatus::Pending);
    }

    /// The agent's owner cannot approve its requested action.
    #[test]
    fn the_agents_owner_cannot_approve_its_action() {
        let ann = test_ctx_with(
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            UserId::new(),
        );
        let agent = agent_owned_by(AgentId::new(), person_of(&ann));
        let opened = opened_by(agent, someone("olga@corp.test"));
        let ports = ApproveActionPorts {
            tenant_authorities: Arc::new(DistinctPeople::holding_everything()),
            ..opened.ports()
        };

        let result = approve(
            ports,
            &ann,
            &Arc::new(FakeEventDispatcher::new()),
            opened.request(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller without approval permission is refused and leaves the
    /// request pending.
    #[test]
    fn a_caller_who_may_not_approve_is_refused() {
        let opened = opened();
        let ports = ApproveActionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..opened.ports()
        };

        let result = quietly(ports, opened.request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(opened.status(), ApprovalStatus::Pending);
    }

    /// A signed-out caller cannot approve an action.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let opened = opened();
        let ports = ApproveActionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..opened.ports()
        };

        let result = quietly(ports, opened.request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A zero hourly approval allowance rate-limits the attempt and leaves
    /// the request pending.
    #[test]
    fn an_approver_past_the_hourly_cap_is_turned_away() {
        let opened = opened();
        let use_case = ApproveActionUseCase::new(
            ApprovalLimits {
                per_person_per_hour: 0,
                ..approval_limits()
            },
            opened.ports(),
        );

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            opened.request(),
        ));

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
        assert_eq!(opened.status(), ApprovalStatus::Pending);
    }

    /// Bob approves a request whose time ran out an hour ago. He is refused,
    /// and the request is saved as expired.
    #[test]
    fn a_lapsed_request_is_refused_and_saved_as_expired() {
        let opened = opened();
        let stored = opened.approvals.all().remove(0);
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
        block_on(opened.approvals.save(&test_ctx().tenant(), &lapsed)).unwrap();

        let result = quietly(opened.ports(), opened.request());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(
            opened.approvals.all()[0].state().status(),
            ApprovalStatus::Expired
        );
    }

    /// Bob and Carol each approve the delete Ann's run paused on, each with
    /// a fresh code. Bob's signature leaves the run paused; Carol's grants
    /// the call, spends the approval on it and resumes the run, queueing
    /// the job that drives it on.
    #[test]
    fn two_people_release_a_paused_run() {
        let paused = paused();
        let (bob, carol, mfa) = two_present_approvers();
        let sink = Arc::new(FakeEventDispatcher::new());

        approve(
            paused.ports(mfa.clone()),
            &bob,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        )
        .unwrap();
        assert_eq!(paused.run_status(), RunStatus::AwaitingApproval);
        assert_eq!(paused.drive_jobs(), 0);
        approve(
            paused.ports(mfa),
            &carol,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        )
        .unwrap();

        assert_eq!(paused.status(), ApprovalStatus::Consumed);
        assert_eq!(paused.run_status(), RunStatus::Running);
        assert_eq!(paused.drive_jobs(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "agents.approval_signed",
                "agents.approval_granted",
                "agents.run_started"
            ]
        );
    }

    /// A concurrent run change makes the second approval conflict; the run
    /// stays awaiting approval, no drive job is queued, and only the first
    /// signature remains in the audit trail.
    #[test]
    fn an_approval_over_a_run_stopped_meanwhile_resumes_nothing() {
        let paused = paused();
        let (bob, carol, mfa) = two_present_approvers();
        let sink = Arc::new(FakeEventDispatcher::new());
        approve(
            paused.ports(mfa.clone()),
            &bob,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        )
        .unwrap();
        paused.runs.moves_on_before_each_save();

        let result = approve(
            paused.ports(mfa),
            &carol,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(paused.run_status(), RunStatus::AwaitingApproval);
        assert_eq!(paused.drive_jobs(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.approval_signed"]
        );
    }

    /// Revoking the delegation before the second approval refuses release,
    /// leaving the request pending and its run awaiting approval.
    #[test]
    fn an_approval_on_a_revoked_delegation_releases_nothing() {
        let paused = paused();
        let (bob, carol, mfa) = two_present_approvers();
        let sink = Arc::new(FakeEventDispatcher::new());
        approve(
            paused.ports(mfa.clone()),
            &bob,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        )
        .unwrap();
        paused.revoke_delegation();

        let result = approve(
            paused.ports(mfa),
            &carol,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(paused.run_status(), RunStatus::AwaitingApproval);
        assert_eq!(paused.status(), ApprovalStatus::Pending);
    }

    /// Bob approves the delete without a code. He is asked to step up first.
    #[test]
    fn a_high_risk_approval_without_a_code_needs_a_step_up() {
        let paused = paused();
        let (bob, _, mfa) = two_present_approvers();

        let result = approve(
            paused.ports(mfa),
            &bob,
            &Arc::new(FakeEventDispatcher::new()),
            paused.request(None),
        );

        assert!(matches!(result, Err(AppError::StepUpRequired)));
        assert_eq!(paused.status(), ApprovalStatus::Pending);
    }

    /// An incorrect second-factor code refuses the high-risk approval and
    /// leaves the request pending.
    #[test]
    fn a_high_risk_approval_with_a_wrong_code_is_refused() {
        let paused = paused();
        let (bob, _, mfa) = two_present_approvers();

        let result = approve(
            paused.ports(mfa),
            &bob,
            &Arc::new(FakeEventDispatcher::new()),
            paused.request(Some("000000")),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(paused.status(), ApprovalStatus::Pending);
    }

    /// A caller without an enrolled second factor cannot approve a high-risk
    /// action even when supplying a code.
    #[test]
    fn an_approver_without_a_second_factor_cannot_approve_a_high_risk_action() {
        let paused = paused();
        let (bob, _, _) = two_present_approvers();

        let result = approve(
            paused.ports(Arc::new(FakeMfaEnrollmentStore::empty())),
            &bob,
            &Arc::new(FakeEventDispatcher::new()),
            paused.request(Some(PRESENT_CODE)),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reusing the first approver for the second approval is refused; the
    /// request stays pending and the run keeps awaiting approval.
    #[test]
    fn one_person_cannot_give_both_approvals() {
        let paused = paused();
        let (bob, _, mfa) = two_present_approvers();
        let sink = Arc::new(FakeEventDispatcher::new());
        approve(
            paused.ports(mfa.clone()),
            &bob,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        )
        .unwrap();

        let again = approve(
            paused.ports(mfa),
            &bob,
            &sink,
            paused.request(Some(PRESENT_CODE)),
        );

        assert!(matches!(again, Err(AppError::Forbidden(_))));
        assert_eq!(paused.status(), ApprovalStatus::Pending);
        assert_eq!(paused.run_status(), RunStatus::AwaitingApproval);
    }

    /// The person who started a run cannot approve its call through another
    /// account, even with a fresh code; the request stays pending.
    #[test]
    fn the_runs_starter_cannot_approve_its_call() {
        let paused = paused();
        let ctx = test_ctx();
        let CallerIdentity::TenantUser(account) = ctx.identity() else {
            panic!("the test caller is a tenant user");
        };
        let mfa = Arc::new(FakeMfaEnrollmentStore::empty());
        mfa.enroll(*account);
        let ann_elsewhere = Human::new(
            HumanAccount::User(*account),
            PersonKey::new("ann@corp.test").unwrap(),
        );
        let ports = ApproveActionPorts {
            tenant_authorities: Arc::new(ActingAs(ann_elsewhere)),
            ..paused.ports(mfa)
        };

        let result = approve(
            ports,
            &ctx,
            &Arc::new(FakeEventDispatcher::new()),
            paused.request(Some(PRESENT_CODE)),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(paused.status(), ApprovalStatus::Pending);
    }

    /// Answers every caller as the person it holds, holding every
    /// permission.
    struct ActingAs(Human);

    #[async_trait::async_trait]
    impl TenantAuthorities for ActingAs {
        async fn authority(&self, caller: &CallerContext) -> Result<TenantAuthority, AppError> {
            Ok(TenantAuthority::assumed(
                self.0.clone(),
                caller.tenant_id(),
                SystemPermission::all(),
                &[],
            ))
        }

        async fn signed_in(&self, _: &CallerContext) -> Result<SignedInAccount, AppError> {
            Err(AppError::Unauthenticated)
        }

        async fn holder(&self, _: &CallerContext) -> Result<AccountHolder, AppError> {
            Err(AppError::Unauthenticated)
        }

        async fn signed_in_on(
            &self,
            _: &ScopedTenant,
            _: &SessionId,
        ) -> Result<SignedInAccount, AppError> {
            Err(AppError::Unauthenticated)
        }
    }
}
