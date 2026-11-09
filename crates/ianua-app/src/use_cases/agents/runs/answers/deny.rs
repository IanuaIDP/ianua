//! Deny run: a person refuses the call a paused run holds, and the run
//! goes on without it.
//!
//! A paused run raised an approval request for the exact call it holds.
//! Denying from the run is the same act as denying that request in the
//! inbox, through [`DenyActionUseCase`]: the request closes as denied, the
//! run records the refusal as a step and resumes, so its model sees the
//! denial and carries on without the call.

use std::sync::Arc;

use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::message;
use ianua_domain::types::{AgentId, AgentRunId, ApprovalId};

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{ApprovalStore, RunStore};
use crate::use_case::Command;
use crate::use_cases::agents::approvals::{DenyActionRequest, DenyActionUseCase};
use crate::use_cases::agents::lookup::owned_run;
use crate::use_cases::agents::runs::answers::decided::RunDecided;

/// Which paused run to deny, addressed under the agent it belongs to.
pub struct DenyRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The paused run.
    pub run_id: AgentRunId,
}

/// The ports [`DenyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DenyPorts {
    /// Finds the approval request the run raised for its held call.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// Reads the run back after the decision.
    pub run_store: Arc<dyn RunStore>,
    /// The one place a paused call is denied.
    pub deny_action: Arc<DenyActionUseCase>,
}

/// Denies the calls paused runs hold.
pub struct DenyUseCase {
    ports: DenyPorts,
}

impl DenyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DenyPorts) -> Self {
        Self { ports }
    }
}

impl Command for DenyUseCase {
    type Caller = CallerContext;
    type Input = DenyRequest;
    type Output = Result<RunDecided, AppError>;

    /// Denies the call `request.run_id` holds through the approval request
    /// it raised, and returns where the run stands after: only that, since
    /// denying takes the right to decide and not the right to read the
    /// run.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the run does not exist under this agent,
    ///   or holds no open approval request.
    /// - Everything [`DenyActionUseCase`] returns.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DenyRequest,
    ) -> Result<RunDecided, AppError> {
        let approval_id =
            open_request_of(self.ports.approval_store.as_ref(), ctx, &request).await?;
        self.ports
            .deny_action
            .execute(
                ctx,
                auditor,
                DenyActionRequest {
                    agent_id: request.agent_id,
                    approval_id,
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

/// The approval request the run raised and nobody has decided yet.
async fn open_request_of(
    store: &dyn ApprovalStore,
    ctx: &CallerContext,
    request: &DenyRequest,
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
        .find(|approval| approval.run_id() == Some(&request.run_id))
        .map(|approval| *approval.id())
        .or_not_found(message!(
            "agents-no-open-approval-for-that-run",
            "no open approval for that run"
        ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::RunStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeApprovalStore, FakeRunStore, agent_owned_by, delegation_from, order_tool, paused_run,
        raised_approval, run_started_by, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::agents::approvals::{DecisionPorts, DenyActionPorts};

    /// Ann's run of Olga's agent, paused on updating an order, with the
    /// request it raised, kept where the decision reads them.
    struct Paused {
        agent: AgentId,
        run: AgentRunId,
        approval: ApprovalId,
        runs: Arc<FakeRunStore>,
        approvals: Arc<FakeApprovalStore>,
    }

    fn paused() -> Paused {
        let (ann, olga) = (someone("ann@example.test"), someone("olga@example.test"));
        let agent = agent_owned_by(AgentId::new(), olga);
        let tool = order_tool("update_order");
        let run = paused_run(&ann, &agent, &delegation_from(&ann, *agent.id()), &tool);
        let approval = raised_approval(&run, &agent, &ann, &tool);
        let (runs, approvals) = stores();
        block_on(runs.save(&test_ctx().tenant(), &run)).unwrap();
        block_on(approvals.save(&test_ctx().tenant(), &approval)).unwrap();
        Paused {
            agent: *agent.id(),
            run: *run.id(),
            approval: *approval.id(),
            runs,
            approvals,
        }
    }

    fn stores() -> (Arc<FakeRunStore>, Arc<FakeApprovalStore>) {
        (
            Arc::new(FakeRunStore::empty()),
            Arc::new(FakeApprovalStore::empty()),
        )
    }

    impl Paused {
        fn ports_holding(&self, decider: Arc<FakeTenantAuthorities>) -> DenyPorts {
            let deny_action = DenyActionUseCase::new(DenyActionPorts {
                decisions: DecisionPorts {
                    approval_store: self.approvals.clone(),
                    run_store: self.runs.clone(),
                    ..DecisionPorts::fakes()
                },
                tenant_authorities: decider,
                ..DenyActionPorts::fakes()
            });
            DenyPorts {
                approval_store: self.approvals.clone(),
                run_store: self.runs.clone(),
                deny_action: Arc::new(deny_action),
            }
        }

        fn ports(&self) -> DenyPorts {
            self.ports_holding(Arc::new(FakeTenantAuthorities::holding_everything()))
        }

        fn deny_with(&self, ports: DenyPorts, agent_id: AgentId) -> Result<RunDecided, AppError> {
            block_on(DenyUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                DenyRequest {
                    agent_id,
                    run_id: self.run,
                },
            ))
        }

        fn stored_status(&self) -> RunStatus {
            block_on(self.runs.find_by_id(&test_ctx().tenant(), &self.run))
                .unwrap()
                .unwrap()
                .status()
        }

        fn request_status(&self) -> ApprovalStatus {
            block_on(
                self.approvals
                    .find_by_id(&test_ctx().tenant(), &self.approval),
            )
            .unwrap()
            .unwrap()
            .status()
        }
    }

    /// Bob denies the update Ann's run is paused on. The request closes as
    /// denied and the run goes on without the call.
    #[test]
    fn denying_closes_the_request_and_resumes_the_run_without_the_call() {
        let p = paused();

        let decided = p.deny_with(p.ports(), p.agent).unwrap();

        assert_eq!(decided.status, RunStatus::Running);
        assert_eq!(p.stored_status(), RunStatus::Running);
        assert_eq!(p.request_status(), ApprovalStatus::Denied);
    }

    /// Bob may approve agent calls but not view agents. He denies the call
    /// Ann's run holds, and is told only that the run goes on, not what it
    /// read or called.
    #[test]
    fn a_decider_who_may_not_read_the_run_is_told_only_where_it_stands() {
        let p = paused();
        let decides_only = [SystemPermission::Agents(AgentAction::Approve)];

        let decided = p
            .deny_with(
                p.ports_holding(Arc::new(FakeTenantAuthorities::holding(&decides_only))),
                p.agent,
            )
            .unwrap();

        assert_eq!(
            decided,
            RunDecided {
                run_id: p.run,
                status: RunStatus::Running,
            }
        );
    }

    /// Denying a run under a different agent ID returns not found and leaves
    /// the run awaiting approval.
    #[test]
    fn a_run_addressed_under_another_agent_is_not_found_and_stays_paused() {
        let p = paused();

        let result = p.deny_with(p.ports(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(p.stored_status(), RunStatus::AwaitingApproval);
    }

    /// Bob denies a run that is not paused. There is no open request to
    /// deny, so it is not found.
    #[test]
    fn a_run_holding_no_open_request_is_not_found() {
        let ann: Human = someone("ann@example.test");
        let agent = agent_owned_by(AgentId::new(), ann.clone());
        let run = run_started_by(&ann, &agent, &delegation_from(&ann, *agent.id()));
        let (runs, approvals) = stores();
        block_on(runs.save(&test_ctx().tenant(), &run)).unwrap();
        let ports = DenyPorts {
            approval_store: approvals,
            run_store: runs,
            ..DenyPorts::fakes()
        };

        let result = block_on(DenyUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            DenyRequest {
                agent_id: *agent.id(),
                run_id: *run.id(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without approval rights cannot deny a held call; the run stays
    /// awaiting approval.
    #[test]
    fn a_caller_who_may_not_decide_is_refused() {
        let p = paused();

        let result = p.deny_with(
            p.ports_holding(Arc::new(FakeTenantAuthorities::holding(&[]))),
            p.agent,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(p.stored_status(), RunStatus::AwaitingApproval);
    }

    /// A signed-out session cannot deny a held call; its approval request stays pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let p = paused();

        let result = p.deny_with(
            p.ports_holding(Arc::new(FakeTenantAuthorities::refusing(
                Refusal::SignedOut,
            ))),
            p.agent,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(p.request_status(), ApprovalStatus::Pending);
    }
}
