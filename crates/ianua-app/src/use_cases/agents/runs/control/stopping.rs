//! Stopping a run on an order: a person's, or the workflow engine's for a
//! run an ended execution gave up. Whoever applies the order, the one who
//! gives it while the run is paused or the worker between steps, withdraws
//! the approvals the run waited on with it, so none waits in an inbox on a
//! run that will never resume.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::{
    AgentRun, CancelOrder, RunCancelled, RunStatus,
};
use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, AgentRunId, EventLabel};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{ApprovalStore, RunCancellation, RunStore, RunVersion};
use crate::ports::shared::AuditLabelResolver;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::audit_labels::agent_label;

/// The ports stopping a run on an order goes through, for whoever orders
/// it outside the agents' own use cases.
#[derive(ianua_macros::Fakes)]
pub struct StopPorts {
    /// Carries the order to the worker driving the run.
    pub run_cancellation: Arc<dyn RunCancellation>,
    /// Keeps the runs, read again to settle a paused one.
    pub run_store: Arc<dyn RunStore>,
    /// Withdraws the approvals a paused run waited on.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// Names the run's agent in the audit trail.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
}

impl StopPorts {
    /// The stopping these ports carry out.
    pub(crate) fn stopping(&self) -> RunStopping<'_> {
        RunStopping {
            cancellation: self.run_cancellation.as_ref(),
            runs: self.run_store.as_ref(),
            approvals: self.approval_store.as_ref(),
        }
    }

    /// What settling `settled` records, its agent named as the audit trail
    /// knows it and the stop in the name of whoever gave `order`.
    pub(crate) async fn settled_events(
        &self,
        tenant: &ScopedTenant,
        settled: &mut SettledStop,
        order: &CancelOrder,
    ) -> Vec<DomainEvent> {
        let label = agent_label(
            self.audit_label_resolver.as_ref(),
            tenant,
            settled.run.agent_id(),
        )
        .await;
        settled.recorded(tenant, &label, &ActorRef::from(order.by().account()))
    }
}

/// Where a run is stopped on an order.
pub(crate) struct RunStopping<'a> {
    /// Carries the order to the worker driving the run.
    pub(crate) cancellation: &'a dyn RunCancellation,
    /// Keeps the runs.
    pub(crate) runs: &'a dyn RunStore,
    /// Keeps the approvals runs wait on.
    pub(crate) approvals: &'a dyn ApprovalStore,
}

/// A paused run stopped at once on an order, and the approvals withdrawn
/// with it.
pub(crate) struct SettledStop {
    /// The run, cancelled.
    pub(crate) run: AgentRun<ResolvedTenant>,
    /// The approvals it waited on, withdrawn.
    pub(crate) withdrawn: Vec<ApprovalRequest<ResolvedTenant>>,
}

impl RunStopping<'_> {
    /// Puts `order` on the kill switch, then settles its run at once when it
    /// is paused for approval or by a person, saving the run and the
    /// approvals withdrawn with it. A paused run has no worker to apply the
    /// order until it resumes. `None` when the run is not paused: its worker applies the
    /// order between steps, or it already ended. `None` too when the run
    /// changed between its reading and its saving, such as an approval
    /// that resumed it: the stop is not saved over the resume, and the
    /// order on the kill switch stops the run at its worker's next step.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the order cannot be kept, or on
    ///   persistence failure.
    /// - `AppError::Domain` when an approval cannot be withdrawn.
    pub(crate) async fn stop(
        &self,
        tenant: &ScopedTenant,
        order: &CancelOrder,
    ) -> Result<Option<SettledStop>, AppError> {
        self.cancellation
            .request_cancel(tenant, order)
            .await
            .or_internal()?;
        let Some(paused) = paused_now(self.runs, tenant, order.run_id()).await? else {
            return Ok(None);
        };
        let read = RunVersion::of(&paused);
        let settled = self.cancelled_with_approvals(tenant, order, paused).await?;
        self.saved(tenant, settled, read).await
    }

    /// The paused run cancelled on `order`, with its open approvals
    /// withdrawn.
    async fn cancelled_with_approvals(
        &self,
        tenant: &ScopedTenant,
        order: &CancelOrder,
        mut run: AgentRun<ResolvedTenant>,
    ) -> Result<SettledStop, AppError> {
        let Some(cancelled) = run.cancel(order).map_err(AppError::from_domain)? else {
            return Ok(SettledStop {
                run,
                withdrawn: Vec::new(),
            });
        };
        let withdrawn = withdrawn_approvals(self.approvals, tenant, &run, &cancelled).await?;
        Ok(SettledStop { run, withdrawn })
    }

    /// Saves the cancelled run, while it is as it was read at `read`, and
    /// every approval withdrawn with it. One decided or run out since it was
    /// read no longer waits on anybody, so it is left as its decision put
    /// it, and dropped from the withdrawals the stop records: the stop
    /// stands, and never records taking back a request it did not take
    /// back. `None` when the run changed since it was read: nothing is
    /// saved, and the stop records nothing.
    async fn saved(
        &self,
        tenant: &ScopedTenant,
        mut settled: SettledStop,
        read: RunVersion,
    ) -> Result<Option<SettledStop>, AppError> {
        let kept_run = self
            .runs
            .save_unchanged_since(tenant, &settled.run, read)
            .await;
        if matches!(kept_run, Err(DomainError::Conflict(_))) {
            return Ok(None);
        }
        kept_run.map_err(AppError::internal)?;
        let mut kept = Vec::with_capacity(settled.withdrawn.len());
        for approval in settled.withdrawn.drain(..) {
            match self.approvals.save(tenant, &approval).await {
                Ok(()) => kept.push(approval),
                Err(DomainError::Conflict(_)) => {}
                Err(failed) => return Err(AppError::internal(failed)),
            }
        }
        settled.withdrawn = kept;
        Ok(Some(settled))
    }
}

impl SettledStop {
    /// What settling the run records: its end, its agent named
    /// `agent_label`, and each approval withdrawn in the name of `actor`,
    /// who stopped it.
    pub(crate) fn recorded(
        &mut self,
        tenant: &ScopedTenant,
        agent_label: &EventLabel,
        actor: &ActorRef,
    ) -> Vec<DomainEvent> {
        self.run.announce_end(agent_label.clone());
        let mut recorded = self.run.take_events(tenant);
        recorded.extend(withdrawals_recorded(
            &mut self.withdrawn,
            tenant,
            agent_label,
            actor,
        ));
        recorded
    }
}

/// The approvals a worker withdrew when it stopped a run on an order, and
/// the person who gave the order.
pub(in crate::use_cases::agents::runs) struct Withdrawal {
    /// Who ordered the stop.
    pub(in crate::use_cases::agents::runs) by: ActorRef,
    /// The approvals withdrawn.
    pub(in crate::use_cases::agents::runs) approvals: Vec<ApprovalRequest<ResolvedTenant>>,
}

/// The run, read again now its stop is recorded, when it waits on a
/// person: paused for approval, or paused by someone. Neither has a worker
/// to apply the order. A run an approval woke and finished meanwhile keeps
/// how it ended.
async fn paused_now(
    store: &dyn RunStore,
    tenant: &ScopedTenant,
    run_id: &AgentRunId,
) -> Result<Option<AgentRun<ResolvedTenant>>, AppError> {
    let run = store.find_by_id(tenant, run_id).await.or_internal()?;
    Ok(run.filter(|run| {
        matches!(
            run.status(),
            RunStatus::AwaitingApproval | RunStatus::Paused
        )
    }))
}

/// The open approval requests `run` raised, each withdrawn on `cancelled`.
pub(in crate::use_cases::agents::runs) async fn withdrawn_approvals(
    store: &dyn ApprovalStore,
    tenant: &ScopedTenant,
    run: &AgentRun<ResolvedTenant>,
    cancelled: &RunCancelled,
) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError> {
    let pending = store
        .list_for_agent(tenant, run.agent_id(), Some(ApprovalStatus::Pending))
        .await
        .or_internal()?;
    pending
        .into_iter()
        .filter(|approval| approval.run_id() == Some(run.id()))
        .map(|mut approval| {
            approval
                .withdraw(cancelled)
                .map_err(AppError::from_domain)?;
            Ok(approval)
        })
        .collect()
}

/// The record of each of `approvals` withdrawn when `actor` stopped their
/// run, its agent named `agent_label`.
pub(in crate::use_cases::agents::runs) fn withdrawals_recorded(
    approvals: &mut [ApprovalRequest<ResolvedTenant>],
    tenant: &ScopedTenant,
    agent_label: &EventLabel,
    actor: &ActorRef,
) -> Vec<DomainEvent> {
    approvals
        .iter_mut()
        .flat_map(|approval| {
            approval.announce_decision(agent_label.clone());
            approval.take_events(tenant)
        })
        .map(|event| event.with_actor(actor.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::CancelOrderRow;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{AgentId, Human};

    use super::*;
    use crate::test_support::agents::{
        FakeApprovalStore, FakeRunControl, FakeRunStore, agent_owned_by, caller_person,
        delegation_from, order_tool, paused_run, raised_approval, run_started_by, someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// A run kept with its approval, and the stop ports over them.
    struct Scene {
        run: AgentRun<ResolvedTenant>,
        approval: Option<ApprovalRequest<ResolvedTenant>>,
        stops: StopPorts,
        control: Arc<FakeRunControl>,
        runs: Arc<FakeRunStore>,
        approvals: Arc<FakeApprovalStore>,
    }

    impl Scene {
        fn over(
            run: AgentRun<ResolvedTenant>,
            approval: Option<ApprovalRequest<ResolvedTenant>>,
        ) -> Self {
            Self::kept_in(run, approval, FakeApprovalStore::empty())
        }

        /// The same, the approval kept in `approvals`.
        fn kept_in(
            run: AgentRun<ResolvedTenant>,
            approval: Option<ApprovalRequest<ResolvedTenant>>,
            approvals: FakeApprovalStore,
        ) -> Self {
            let tenant = test_ctx().tenant();
            let runs = Arc::new(FakeRunStore::empty());
            block_on(runs.save(&tenant, &run)).unwrap();
            let approvals = Arc::new(approvals);
            if let Some(approval) = &approval {
                block_on(approvals.save(&tenant, approval)).unwrap();
            }
            let control = Arc::new(FakeRunControl::empty());
            Self {
                stops: StopPorts {
                    run_cancellation: control.clone(),
                    run_store: runs.clone(),
                    approval_store: approvals.clone(),
                    ..StopPorts::fakes()
                },
                run,
                approval,
                control,
                runs,
                approvals,
            }
        }

        /// Ann's run of her agent, paused on a delete, with the approval it
        /// raised.
        fn paused(ann: &Human) -> Self {
            let agent = agent_owned_by(AgentId::new(), ann.clone());
            let delegation = delegation_from(ann, *agent.id());
            let tool = order_tool("delete_order");
            let run = paused_run(ann, &agent, &delegation, &tool);
            let approval = raised_approval(&run, &agent, ann, &tool);
            Self::over(run, Some(approval))
        }

        fn order_by(&self, by: &Human) -> CancelOrder {
            CancelOrder::reconstitute(CancelOrderRow {
                run_id: *self.run.id(),
                by: by.clone(),
                at: clock::now(),
            })
            .unwrap()
        }

        fn approval_status(&self) -> ApprovalStatus {
            let id = self.approval.as_ref().unwrap().id();
            block_on(self.approvals.find_by_id(&test_ctx().tenant(), id))
                .unwrap()
                .unwrap()
                .status()
        }
    }

    /// A workflow Ann started ends while its agent run waits for approval of
    /// a delete. The run is stopped at once and the approval withdrawn, so
    /// nobody approves a call no run will make.
    #[test]
    fn a_paused_run_is_settled_at_once_and_its_approval_withdrawn() {
        let ann = caller_person();
        let scene = Scene::paused(&ann);
        let order = scene.order_by(&ann);

        let settled = block_on(scene.stops.stopping().stop(&test_ctx().tenant(), &order))
            .unwrap()
            .unwrap();

        assert_eq!(settled.run.status(), RunStatus::Cancelled);
        assert_eq!(scene.approval_status(), ApprovalStatus::Withdrawn);
        assert!(scene.control.has_order_for(scene.run.id()));
    }

    /// The settled stop records the run's end and the withdrawn approval,
    /// the withdrawal in the name of whoever gave the order.
    #[test]
    fn a_settled_stop_records_the_end_and_the_withdrawal() {
        let ann = caller_person();
        let scene = Scene::paused(&ann);
        let order = scene.order_by(&ann);
        let tenant = test_ctx().tenant();
        let mut settled = block_on(scene.stops.stopping().stop(&tenant, &order))
            .unwrap()
            .unwrap();

        let events = block_on(scene.stops.settled_events(&tenant, &mut settled, &order));

        let names: Vec<_> = events.iter().map(|e| e.event_type().as_str()).collect();
        assert_eq!(names, ["agents.run_finished", "agents.approval_withdrawn"]);
    }

    /// An approval expiring during cancellation retains its expired status. The
    /// run is cancelled and only its end is recorded.
    #[test]
    fn an_approval_decided_meanwhile_is_left_out_of_the_stop() {
        let ann = caller_person();
        let paused = Scene::paused(&ann);
        let scene = Scene::kept_in(
            paused.run,
            paused.approval,
            FakeApprovalStore::lapsing_while_decided(),
        );
        let order = scene.order_by(&ann);
        let tenant = test_ctx().tenant();

        let mut settled = block_on(scene.stops.stopping().stop(&tenant, &order))
            .unwrap()
            .unwrap();
        let events = block_on(scene.stops.settled_events(&tenant, &mut settled, &order));

        assert_eq!(settled.run.status(), RunStatus::Cancelled);
        assert_eq!(scene.approval_status(), ApprovalStatus::Expired);
        let names: Vec<_> = events.iter().map(|e| e.event_type().as_str()).collect();
        assert_eq!(names, ["agents.run_finished"]);
    }

    /// A concurrent run change prevents immediate cancellation settlement. Its
    /// approval stays pending and the kill switch retains the stop order.
    #[test]
    fn a_run_that_changed_meanwhile_is_left_to_its_worker() {
        let ann = caller_person();
        let scene = Scene::paused(&ann);
        let order = scene.order_by(&ann);
        scene.runs.moves_on_before_each_save();

        let settled = block_on(scene.stops.stopping().stop(&test_ctx().tenant(), &order)).unwrap();

        assert!(settled.is_none());
        assert_eq!(scene.approval_status(), ApprovalStatus::Pending);
        assert!(scene.control.has_order_for(scene.run.id()));
    }

    /// A running run is left to its worker: the order goes on the kill
    /// switch and nothing is settled here.
    #[test]
    fn a_running_run_is_left_to_its_worker() {
        let bob = someone("bob@example.test");
        let agent = agent_owned_by(AgentId::new(), bob.clone());
        let run = run_started_by(&bob, &agent, &delegation_from(&bob, *agent.id()));
        let scene = Scene::over(run, None);
        let order = scene.order_by(&bob);

        let settled = block_on(scene.stops.stopping().stop(&test_ctx().tenant(), &order)).unwrap();

        assert!(settled.is_none());
        assert!(scene.control.has_order_for(scene.run.id()));
    }
}
