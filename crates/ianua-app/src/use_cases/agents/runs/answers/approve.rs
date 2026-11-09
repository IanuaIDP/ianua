//! Approve run: a person approves the call a paused run holds, and the run
//! resumes to make it.
//!
//! A run pauses when the model asks for a tool whose action class needs a
//! person's sign-off, and raises an approval request for the exact call it
//! holds. Approving from the run is the same act as approving that request
//! in the inbox, through [`ApproveActionUseCase`]: one decision path, so a
//! high-risk call needs two people and a fresh second factor whichever door
//! they come through.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::PendingCallRef;
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::message;
use ianua_domain::types::{AgentId, AgentRunId, ApprovalId};

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{ApprovalStore, RunStore};
use crate::use_case::Command;
use crate::use_cases::agents::approvals::{ApproveActionRequest, ApproveActionUseCase};
use crate::use_cases::agents::lookup::owned_run;
use crate::use_cases::agents::runs::answers::decided::RunDecided;

/// The ports [`ApproveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApprovePorts {
    /// Finds the approval request the run raised for its held call.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// Reads the run back after the decision.
    pub run_store: Arc<dyn RunStore>,
    /// The one place an approval is decided.
    pub approve_action: Arc<ApproveActionUseCase>,
}

/// One person's approval of a run's held call.
pub struct ApproveRequest {
    /// The agent the address names. The run must be one of its own.
    pub agent_id: AgentId,
    /// The paused run.
    pub run_id: AgentRunId,
    /// The exact call the approver looked at.
    pub approving: PendingCallRef,
    /// A fresh second-factor code, needed for a high-risk call.
    pub mfa_code: Option<String>,
}

/// Approves the calls paused runs hold.
pub struct ApproveUseCase {
    ports: ApprovePorts,
}

impl ApproveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApprovePorts) -> Self {
        Self { ports }
    }
}

impl Command for ApproveUseCase {
    type Caller = CallerContext;
    type Input = ApproveRequest;
    type Output = Result<RunDecided, AppError>;

    /// Approves the call `request.run_id` holds through the approval
    /// request it raised. The run resumes once the request is fully
    /// approved: at once for a low-risk call, on the second person for a
    /// high-risk one. Only where the run stands comes back, since
    /// approving takes the right to decide and not the right to read the
    /// run.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the run does not exist under this agent,
    ///   or holds no open approval for that call.
    /// - Everything [`ApproveActionUseCase`] returns.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ApproveRequest,
    ) -> Result<RunDecided, AppError> {
        let approval_id =
            open_request_for(self.ports.approval_store.as_ref(), ctx, &request).await?;
        self.ports
            .approve_action
            .execute(
                ctx,
                auditor,
                ApproveActionRequest {
                    agent_id: request.agent_id,
                    approval_id,
                    mfa_code: request.mfa_code,
                },
            )
            .await?;
        let run = owned_run(
            self.ports.run_store.as_ref(),
            &ctx.tenant(),
            &request.agent_id,
            &request.run_id,
        )
        .await?;
        Ok(RunDecided::of(&run))
    }
}

/// The open approval request the run raised for exactly the call the
/// approver looked at.
async fn open_request_for(
    store: &dyn ApprovalStore,
    ctx: &CallerContext,
    request: &ApproveRequest,
) -> Result<ApprovalId, AppError> {
    store
        .list_for_agent(
            &ctx.tenant(),
            &request.agent_id,
            Some(ApprovalStatus::Pending),
        )
        .await
        .or_internal()?
        .into_iter()
        .find(|approval| {
            approval.run_id() == Some(&request.run_id)
                && approval.pending_call() == Some(&request.approving)
        })
        .map(|approval| *approval.id())
        .or_not_found(message!(
            "agents-no-open-approval-for-that-call",
            "no open approval for that call"
        ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::{RunStatus, ToolCall};
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::ports::agents::DelegationStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeApprovalStore, FakeDelegationStore, FakeRunStore, agent_owned_by, approval_limits,
        delegation_from, order_tool, paused_run, raised_approval, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::agents::approvals::{ApproveActionPorts, DecisionPorts};

    /// Ann's run of Olga's agent, paused on updating order 1, with the
    /// request it raised and the delegation behind it.
    struct Paused {
        agent: AgentId,
        run: AgentRunId,
        call: PendingCallRef,
        runs: Arc<FakeRunStore>,
        approvals: Arc<FakeApprovalStore>,
        delegations: Arc<FakeDelegationStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    fn paused() -> Paused {
        let (ann, olga) = (someone("ann@example.test"), someone("olga@example.test"));
        let agent = agent_owned_by(AgentId::new(), olga);
        let delegation = delegation_from(&ann, *agent.id());
        let tool = order_tool("update_order");
        let run = paused_run(&ann, &agent, &delegation, &tool);
        let approval = raised_approval(&run, &agent, &ann, &tool);
        let p = Paused {
            agent: *agent.id(),
            run: *run.id(),
            call: PendingCallRef::of(run.pending().unwrap()),
            runs: Arc::new(FakeRunStore::empty()),
            approvals: Arc::new(FakeApprovalStore::empty()),
            delegations: Arc::new(FakeDelegationStore::empty()),
            sink: Arc::new(FakeEventDispatcher::new()),
        };
        block_on(p.runs.save(&test_ctx().tenant(), &run)).unwrap();
        block_on(p.approvals.save(&test_ctx().tenant(), &approval)).unwrap();
        block_on(p.delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
        p
    }

    impl Paused {
        fn ports_holding(&self, approver: FakeTenantAuthorities) -> ApprovePorts {
            let approve_action = ApproveActionUseCase::new(
                approval_limits(),
                ApproveActionPorts {
                    decisions: DecisionPorts {
                        approval_store: self.approvals.clone(),
                        run_store: self.runs.clone(),
                        ..DecisionPorts::fakes()
                    },
                    delegation_store: self.delegations.clone(),
                    tenant_authorities: Arc::new(approver),
                    ..ApproveActionPorts::fakes()
                },
            );
            ApprovePorts {
                approval_store: self.approvals.clone(),
                run_store: self.runs.clone(),
                approve_action: Arc::new(approve_action),
            }
        }

        fn approve(
            &self,
            ports: ApprovePorts,
            agent_id: AgentId,
            approving: PendingCallRef,
        ) -> Result<RunDecided, AppError> {
            block_on(ApproveUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ApproveRequest {
                    agent_id,
                    run_id: self.run,
                    approving,
                    mfa_code: None,
                },
            ))
        }

        fn approve_as_bob(&self) -> Result<RunDecided, AppError> {
            let ports = self.ports_holding(FakeTenantAuthorities::holding_everything());
            self.approve(ports, self.agent, self.call.clone())
        }

        fn stored_status(&self) -> RunStatus {
            block_on(self.runs.find_by_id(&test_ctx().tenant(), &self.run))
                .unwrap()
                .unwrap()
                .status()
        }
    }

    /// Bob approves the update Ann's run is paused on. It is a write, so
    /// one approval is enough: the run resumes to make the call.
    #[test]
    fn approving_a_low_risk_call_resumes_the_run() {
        let p = paused();

        let decided = p.approve_as_bob().unwrap();

        assert_eq!(decided.status, RunStatus::Running);
        assert_eq!(p.stored_status(), RunStatus::Running);
    }

    /// Bob may approve agent calls but not view agents. He approves the call
    /// Ann's run holds, and is told only that the run goes on, not what it
    /// read or called.
    #[test]
    fn an_approver_who_may_not_read_the_run_is_told_only_where_it_stands() {
        let p = paused();
        let decides_only = [SystemPermission::Agents(AgentAction::Approve)];
        let ports = p.ports_holding(FakeTenantAuthorities::holding(&decides_only));

        let decided = p.approve(ports, p.agent, p.call.clone()).unwrap();

        assert_eq!(
            decided,
            RunDecided {
                run_id: p.run,
                status: RunStatus::Running,
            }
        );
    }

    /// Approving a run under a different agent ID returns not found. The run
    /// stays awaiting approval and no audit event is recorded.
    #[test]
    fn a_run_addressed_under_another_agent_is_not_found_and_stays_paused() {
        let p = paused();
        let ports = p.ports_holding(FakeTenantAuthorities::holding_everything());

        let result = p.approve(ports, AgentId::new(), p.call.clone());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(p.stored_status(), RunStatus::AwaitingApproval);
        assert!(p.sink.records.lock().unwrap().is_empty());
    }

    /// A call differing from the open approval request returns not found and
    /// leaves the run awaiting approval.
    #[test]
    fn a_call_with_no_open_approval_is_not_found() {
        let p = paused();
        let ports = p.ports_holding(FakeTenantAuthorities::holding_everything());
        let other = PendingCallRef::new(
            ToolCall::new("update_order", "{\"id\":2}").unwrap(),
            p.call.at_step(),
        );

        let result = p.approve(ports, p.agent, other);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(p.stored_status(), RunStatus::AwaitingApproval);
    }

    /// A caller without approval rights cannot approve a held call; the run
    /// stays awaiting approval.
    #[test]
    fn a_caller_who_may_not_approve_is_refused() {
        let p = paused();
        let ports = p.ports_holding(FakeTenantAuthorities::holding(&[]));

        let result = p.approve(ports, p.agent, p.call.clone());

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(p.stored_status(), RunStatus::AwaitingApproval);
    }

    /// A signed-out session cannot approve a held call; the run stays awaiting approval.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let p = paused();
        let ports = p.ports_holding(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = p.approve(ports, p.agent, p.call.clone());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(p.stored_status(), RunStatus::AwaitingApproval);
    }
}
