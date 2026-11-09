//! An agent flow: stages of agent runs a person makes and starts at once.
//!
//! A flow is a workflow, not a new kind of thing.
//! [`WorkflowGraph::staged`] lays its stages out, and [`Workflow::flow`]
//! makes it as one version, published when it is made and started by hand.
//! It is never edited, redrafted or republished, and lists of designed
//! workflows leave it out. Its one run is the flow's progress, and every
//! rule a workflow run keeps holds for it. Once that run has ended, the
//! flow and its run are deleted together.

use std::marker::PhantomData;
use std::num::NonZeroU32;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::authors::Authors;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::{Node, NodeKind};
use crate::domains::workflows::design::publish_rules::ensure_paths_name_earlier_steps;
use crate::domains::workflows::design::workflow::{
    CanvasLayout, FailureAlert, Hold, Publication, RunLimit, Workflow, WorkflowStatus,
};
use crate::domains::workflows::events::{WorkflowFlowCreated, WorkflowFlowDeleted};
use crate::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::types::{Human, Label, Lifetime, WorkflowId};

/// How long a flow's run may go on before it is stopped: a week, so the
/// approvals its agents wait for have time.
pub(crate) const FLOW_RUN_TIME: Lifetime = Lifetime::from_secs(NonZeroU32::new(604_800).unwrap());

/// Where a workflow came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowOrigin {
    /// A person designed it, version by version.
    Designed,
    /// A person made it as an agent flow, with this description.
    Flow(FlowDescription),
}

/// What a flow's maker wrote about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDescription {
    /// They wrote nothing.
    Blank,
    /// They wrote this.
    Written(Label),
}

/// The values a person makes a flow from.
pub struct NewFlow {
    /// The display label people use to find and start this automation.
    pub name: Label,
    /// What its maker wrote about it.
    pub description: FlowDescription,
    /// Its stages, as [`WorkflowGraph::staged`] laid them out.
    pub graph: WorkflowGraph,
}

impl<T: TenantScope> Workflow<T> {
    /// `by` makes a flow: one version, published at once and started by
    /// hand, acting for `by`. Raises `workflows.flow_created`.
    ///
    /// It is published as it is made, so making one needs the right to
    /// run workflows as well as to create them. Its run then acts for `by`
    /// as any run started by hand does.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create workflows, or
    ///   may not run them.
    /// - [`DomainError::Validation`] when the graph holds no agent run, or
    ///   a step other than an agent run or a transform between stages.
    /// - [`DomainError::Validation`] when a step reads a step that cannot
    ///   come before it.
    pub fn flow(by: &WorkflowControl<'_>, flow: NewFlow) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Create)?;
        by.ensure_may(WorkflowAction::Run)?;
        ensure_flow_steps(&flow.graph)?;
        ensure_paths_name_earlier_steps(&flow.graph)?;
        let run_limit = RunLimit::new(FLOW_RUN_TIME)?;
        let mut workflow = Self::flow_published_by(by.by(), flow, run_limit);
        workflow.raised.raise(WorkflowFlowCreated {
            version: workflow.version_ref(),
            by: by.by().principal(),
            occurred_at: workflow.created_at,
        });
        Ok(workflow)
    }

    /// The one version of `flow`, published by its maker as it is made.
    fn flow_published_by(maker: &Human, flow: NewFlow, run_limit: RunLimit) -> Self {
        let now = crate::shared::clock::now();
        Self {
            id: WorkflowId::new(),
            version: 1,
            name: flow.name,
            description: None,
            graph: flow.graph,
            layout: CanvasLayout::default(),
            trigger: Trigger::Manual,
            run_limit,
            failure_alert: FailureAlert::default(),
            status: WorkflowStatus::Published,
            created_by: maker.clone(),
            edited_by: maker.clone(),
            authors: Authors::first(maker),
            publication: Publication::PublishedBy(maker.clone()),
            origin: WorkflowOrigin::Flow(flow.description),
            hold: Hold::Clear,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Refuses `by` unless they may delete this workflow: its maker, or
    /// someone who may delete workflows.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` neither made it nor may
    ///   delete workflows.
    pub fn ensure_deletable_by(&self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        if by.by().is_same_person_as(&self.created_by) {
            return Ok(());
        }
        by.ensure_may(WorkflowAction::Delete)
    }

    /// `by` deletes this flow, once `run`, its run, has ended. Raises
    /// `workflows.flow_deleted`; the caller deletes the flow and its run
    /// together.
    ///
    /// Its maker may delete it, and so may someone who may delete
    /// workflows. Sam may only view workflows. Without this, he deletes
    /// Ann's flows and their runs.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` neither made it nor may
    ///   delete workflows.
    /// - [`DomainError::Conflict`] when this is a designed workflow, which
    ///   is archived instead.
    /// - [`DomainError::Conflict`] when `run` is not this flow's run.
    /// - [`DomainError::Conflict`] while `run` is still running. It is
    ///   cancelled first.
    pub fn delete_flow(
        &mut self,
        by: &WorkflowControl<'_>,
        run: &WorkflowExecution<T>,
    ) -> Result<(), DomainError> {
        self.ensure_deletable_by(by)?;
        let WorkflowOrigin::Flow(_) = self.origin else {
            return Err(DomainError::conflict(message!(
                "workflows-only-a-flow-is-deleted-a",
                "only a flow is deleted; a designed workflow is archived"
            )));
        };
        if *run.workflow_id() != self.id || run.version() != self.version {
            return Err(DomainError::conflict(message!(
                "workflows-that-run-is-not-this-flow",
                "that run is not this flow's"
            )));
        }
        if run.status() == ExecutionStatus::Running {
            return Err(DomainError::conflict(message!(
                "workflows-a-flow-is-deleted-once-its",
                "a flow is deleted once its run ended; cancel it first"
            )));
        }
        self.raised.raise(WorkflowFlowDeleted {
            version: self.version_ref(),
            execution_id: *run.id(),
            by: by.by().principal(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Whether a person designed it or it is an agent flow.
    #[must_use]
    pub fn origin(&self) -> &WorkflowOrigin {
        &self.origin
    }
}

/// Whether `graph` is what a flow holds: at least one agent run, and
/// nothing but agent runs and the transforms that gather their answers.
pub(super) fn holds_only_flow_steps(graph: &WorkflowGraph) -> bool {
    let kinds = || graph.nodes().iter().map(Node::kind);
    let has_a_run = kinds().any(|kind| matches!(kind, NodeKind::AgentRun(_)));
    let only_flow_steps = kinds().all(|kind| match kind {
        NodeKind::AgentRun(_) | NodeKind::Transform(_) => true,
        NodeKind::Action(_)
        | NodeKind::Condition(_)
        | NodeKind::Approval(_)
        | NodeKind::Wait(_)
        | NodeKind::Loop(_)
        | NodeKind::Code(_)
        | NodeKind::Guardrail(_) => false,
    });
    has_a_run && only_flow_steps
}

/// Refuses a graph that is not what a flow holds.
fn ensure_flow_steps(graph: &WorkflowGraph) -> Result<(), DomainError> {
    if holds_only_flow_steps(graph) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "workflows-a-flow-holds-agent-runs-and",
        "a flow holds agent runs and the steps between its stages, nothing else"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::design::workflow::WorkflowRow;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, SeesAll, agent_step, ann, approval, bob, by_hand, holding_only, managing,
        publish_as, published, stage_run, start_as, transform, viewing,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::AgentId;

    /// A flow as these tests make it.
    type Flow = Workflow<ResolvedTenant>;

    /// Two runs side by side, then one that reads their answers.
    fn two_stages() -> WorkflowGraph {
        WorkflowGraph::staged(vec![vec![stage_run(), stage_run()], vec![stage_run()]]).unwrap()
    }

    /// The flow "Incident digest" made of `graph`.
    fn digest_of(graph: WorkflowGraph) -> NewFlow {
        NewFlow {
            name: Label::new("name", "Incident digest").unwrap(),
            description: FlowDescription::Blank,
            graph,
        }
    }

    /// `maker`'s two-stage flow.
    fn made_by(maker: &Human) -> Flow {
        Workflow::flow(&managing(maker), digest_of(two_stages())).unwrap()
    }

    /// The flow as storage would keep it.
    fn stored(flow: &Flow) -> WorkflowRow {
        WorkflowRow {
            id: flow.id,
            version: flow.version,
            name: flow.name.clone(),
            description: flow.description.clone(),
            graph: flow.graph.clone(),
            layout: flow.layout.clone(),
            trigger: flow.trigger.clone(),
            run_limit: flow.run_limit,
            failure_alert: flow.failure_alert,
            status: flow.status,
            created_by: flow.created_by.clone(),
            edited_by: flow.edited_by.clone(),
            authors: flow.authors.clone(),
            publication: flow.publication.clone(),
            origin: flow.origin.clone(),
            hold: flow.hold.clone(),
            created_at: flow.created_at,
            updated_at: flow.updated_at,
        }
    }

    /// `flow`'s run, started by its maker Ann, and cancelled by her.
    fn ended_run(flow: &Flow) -> Execution {
        let (mut run, _) = start_as(flow, &ann(), by_hand(DataClassLevel::Internal)).unwrap();
        run.cancel(&managing(&ann())).unwrap();
        run
    }

    /// Ann makes a flow. It is one version, published by her, started by
    /// hand, and its making is recorded as a flow's, not a publication.
    #[test]
    fn a_flow_is_made_published_and_started_by_hand() {
        let mut flow = made_by(&ann());

        assert_eq!(flow.version(), 1);
        assert_eq!(flow.status(), WorkflowStatus::Published);
        assert_eq!(flow.publication(), &Publication::PublishedBy(ann()));
        assert_eq!(flow.trigger(), &Trigger::Manual);
        assert_eq!(flow.origin(), &WorkflowOrigin::Flow(FlowDescription::Blank));
        assert_eq!(raised_names(&mut flow), ["workflows.flow_created"]);
    }

    /// Ann starts the flow she made. Its run acts for her, and its first
    /// stage's runs are ready.
    #[test]
    fn a_flow_runs_as_a_start_by_hand() {
        let flow = made_by(&ann());

        let (run, _) = start_as(&flow, &ann(), by_hand(DataClassLevel::Internal)).unwrap();

        assert_eq!(run.acting_for(), &ann());
        assert_eq!(run.ready().count(), 2);
    }

    /// Flow creation rejects both viewing rights alone and creation rights
    /// without run permission.
    #[test]
    fn making_a_flow_needs_the_rights_to_create_and_run() {
        let sam = bob();

        let viewing_only = Flow::flow(&viewing(&sam), digest_of(two_stages()));
        let creating_only = Flow::flow(
            &holding_only(&sam, WorkflowAction::Create),
            digest_of(two_stages()),
        );

        assert!(matches!(viewing_only, Err(DomainError::Forbidden(_))));
        assert!(matches!(creating_only, Err(DomainError::Forbidden(_))));
    }

    /// A flow rejects a graph containing an approval step and a graph of
    /// transforms without any agent run.
    #[test]
    fn a_flow_holds_only_agent_runs_and_the_steps_between_stages() {
        let with_approval = WorkflowGraph::new(
            vec![agent_step(AgentId::new(), &[]), approval("check")],
            Vec::new(),
        )
        .unwrap();
        let no_agents = WorkflowGraph::new(vec![transform("tidy", Join::All)], Vec::new()).unwrap();

        let approving = Flow::flow(&managing(&ann()), digest_of(with_approval));
        let idle = Flow::flow(&managing(&ann()), digest_of(no_agents));

        assert!(matches!(approving, Err(DomainError::Validation(_))));
        assert!(matches!(idle, Err(DomainError::Validation(_))));
    }

    /// Ann's flow cannot be renamed, given new steps, published again or
    /// followed by a new draft. Each is refused, so a flow stays what ran.
    #[test]
    fn a_flow_is_never_edited_or_redrafted() {
        let mut flow = made_by(&ann());

        let renamed = flow.rename(&managing(&ann()), Label::new("name", "Other").unwrap());
        let replaced = flow.replace_graph(&managing(&ann()), two_stages());
        let republished = publish_as(&mut flow, &ann(), &[], &SeesAll);
        let next = flow.next_draft(&managing(&ann()));

        assert!(matches!(renamed, Err(DomainError::Conflict(_))));
        assert!(matches!(replaced, Err(DomainError::Conflict(_))));
        assert!(republished.is_err());
        assert!(matches!(next, Err(DomainError::Conflict(_))));
    }

    /// Ann's flow is deleted once its run ended. While the run is still
    /// going, deleting it is refused.
    #[test]
    fn a_flow_is_deleted_only_once_its_run_ended() {
        let mut flow = made_by(&ann());
        raised_names(&mut flow);
        let (running, _) = start_as(&flow, &ann(), by_hand(DataClassLevel::Internal)).unwrap();
        let ended = ended_run(&flow);

        let while_running = flow.delete_flow(&managing(&ann()), &running);
        flow.delete_flow(&viewing(&ann()), &ended).unwrap();

        assert!(matches!(while_running, Err(DomainError::Conflict(_))));
        assert_eq!(raised_names(&mut flow), ["workflows.flow_deleted"]);
    }

    /// A viewer who did not make the flow cannot delete it after its run ends.
    /// The same person succeeds with workflow deletion rights.
    #[test]
    fn only_its_maker_or_a_deleter_deletes_a_flow() {
        let mut flow = made_by(&ann());
        let ended = ended_run(&flow);
        let sam = bob();

        let by_sam = flow.delete_flow(&viewing(&sam), &ended);
        let by_deleter = flow.delete_flow(&holding_only(&sam, WorkflowAction::Delete), &ended);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_deleter.is_ok());
    }

    /// A designed workflow is archived, not deleted as a flow. A flow is
    /// not deleted with another flow's run.
    #[test]
    fn delete_flow_takes_only_a_flow_and_its_own_run() {
        let mut designed = published(vec![transform("tidy", Join::All)], Vec::new());
        let (designed_run, _) =
            start_as(&designed, &ann(), by_hand(DataClassLevel::Internal)).unwrap();
        let mut flow = made_by(&ann());
        let other_run = ended_run(&made_by(&ann()));

        let as_flow = designed.delete_flow(&managing(&ann()), &designed_run);
        let with_other = flow.delete_flow(&managing(&ann()), &other_run);

        assert!(matches!(as_flow, Err(DomainError::Conflict(_))));
        assert!(matches!(with_other, Err(DomainError::Conflict(_))));
    }

    /// A stored flow reads back. One stored as version 2, still a draft,
    /// or started by its webhook is refused as corrupt.
    #[test]
    fn a_stored_flow_that_is_not_one_published_version_is_refused() {
        let flow = made_by(&ann());
        let corrupt = [
            WorkflowRow {
                version: 2,
                ..stored(&flow)
            },
            WorkflowRow {
                status: WorkflowStatus::Draft,
                publication: Publication::Unpublished,
                ..stored(&flow)
            },
            WorkflowRow {
                trigger: Trigger::Webhook,
                ..stored(&flow)
            },
        ];

        assert!(Flow::reconstitute(stored(&flow)).is_ok());
        for row in corrupt {
            assert!(refused_as_corrupt(&Flow::reconstitute(row)));
        }
    }
}
