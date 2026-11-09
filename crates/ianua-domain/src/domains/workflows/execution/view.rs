//! An execution as one person may read it: where each step stands, with
//! the data above their clearance withheld.
//!
//! The view right lets someone follow a workflow's runs. It does not clear
//! them for what the runs carry. Sam may view workflows and sees only
//! internal data. A payroll run's steps hold the salaries it moves. Read
//! whole, the run would hand them to him.

use std::fmt;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::authors::Authors;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::Node;
use crate::domains::workflows::execution::step::{StepPhase, StepState};
use crate::domains::workflows::execution::{
    Cause, ExecutionMode, ExecutionStatus, PassOf, WorkflowExecution,
};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::model::aggregate::Aggregate;
use crate::types::{Human, WorkflowExecutionId, WorkflowId};

/// Where one step stands, as the viewer may read it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StepView<'a> {
    /// The viewer is cleared for what reached the step: it as it stands.
    Shown(&'a StepState),
    /// The step holds data above the viewer's clearance. Only where it
    /// stands, and how sensitive its data is, are shown.
    Withheld {
        /// Where it stands.
        phase: StepPhase,
        /// How sensitive the data it holds is.
        exposure: DataClassLevel,
    },
}

/// One execution, read by a person who may view workflows, with what they
/// are not cleared for withheld.
///
/// Only [`WorkflowExecution::viewed_by`] makes one, with the clearance the
/// viewer's rights give them. The request never names it.
pub struct ExecutionView<T: TenantScope> {
    execution: WorkflowExecution<T>,
    clearance: DataClassLevel,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// This execution as `viewer` may read it.
    ///
    /// Every step whose data is above the viewer's clearance is withheld,
    /// and so is the trigger's data when it is. A failed step keeps no
    /// class of its own, and its reason may repeat what it was handed, so
    /// it is withheld when anything in the run is above the clearance.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `viewer` may not view workflows.
    pub fn viewed_by(self, viewer: WorkflowControl<'_>) -> Result<ExecutionView<T>, DomainError> {
        viewer.ensure_may(WorkflowAction::View)?;
        Ok(ExecutionView {
            clearance: viewer.authority().data_clearance(),
            execution: self,
        })
    }
}

impl<T: TenantScope> ExecutionView<T> {
    /// The run identity exposed through this viewer's authorized projection.
    #[must_use]
    pub fn id(&self) -> &WorkflowExecutionId {
        self.execution.id()
    }

    /// The workflow it runs.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        self.execution.workflow_id()
    }

    /// The version it runs.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.execution.version()
    }

    /// The steps and edges it runs.
    #[must_use]
    pub fn graph(&self) -> &WorkflowGraph {
        self.execution.graph()
    }

    /// The person it acts for.
    #[must_use]
    pub fn acting_for(&self) -> &Human {
        self.execution.acting_for()
    }

    /// The authors of the version it runs.
    #[must_use]
    pub fn authors(&self) -> &Authors {
        self.execution.authors()
    }

    /// What started it.
    #[must_use]
    pub fn cause(&self) -> Cause {
        self.execution.cause()
    }

    /// Whether it is a real run or a test of a draft.
    #[must_use]
    pub fn mode(&self) -> &ExecutionMode {
        self.execution.mode()
    }

    /// The loop it runs one pass of, if it is a pass.
    #[must_use]
    pub fn pass(&self) -> Option<&PassOf> {
        self.execution.pass()
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> ExecutionStatus {
        self.execution.status()
    }

    /// When it is stopped if it has not ended.
    #[must_use]
    pub fn deadline(&self) -> OffsetDateTime {
        self.execution.deadline()
    }

    /// When it started.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        Aggregate::created_at(&self.execution)
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        Aggregate::updated_at(&self.execution)
    }

    /// The most sensitive data in the trigger's data.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.execution.exposure()
    }

    /// The most sensitive data the viewer may read.
    #[must_use]
    pub fn clearance(&self) -> DataClassLevel {
        self.clearance
    }

    /// The trigger's data, or `None` when it is above the viewer's
    /// clearance.
    #[must_use]
    pub fn input(&self) -> Option<&FlowData> {
        (self.execution.exposure() <= self.clearance).then(|| self.execution.input())
    }

    /// Each step, with where it stands as the viewer may read it.
    pub fn steps(&self) -> impl Iterator<Item = (&Node, StepView<'_>)> {
        let peak = self.peak_exposure();
        self.execution
            .steps()
            .map(move |(node, state)| (node, self.step_view(state, peak)))
    }

    /// `state` as the viewer may read it, where `peak` is the most
    /// sensitive data anything in the run held.
    fn step_view<'s>(&self, state: &'s StepState, peak: DataClassLevel) -> StepView<'s> {
        let exposure = match state {
            StepState::Failed(_) => Some(peak),
            StepState::Waiting
            | StepState::Ready { .. }
            | StepState::Running { .. }
            | StepState::Succeeded { .. }
            | StepState::Skipped
            | StepState::Stopped
            | StepState::Abandoned { .. } => state.exposure(),
        };
        match exposure {
            Some(exposure) if exposure > self.clearance => StepView::Withheld {
                phase: state.phase(),
                exposure,
            },
            Some(_) | None => StepView::Shown(state),
        }
    }

    /// The most sensitive data the trigger or any step held.
    fn peak_exposure(&self) -> DataClassLevel {
        self.execution
            .steps()
            .filter_map(|(_, state)| state.exposure())
            .fold(self.execution.exposure(), DataClassLevel::max)
    }
}

impl<T: TenantScope> fmt::Debug for ExecutionView<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionView")
            .field("id", self.execution.id())
            .field("status", &self.execution.status())
            .field("clearance", &self.clearance)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{DataAccessAction, SystemPermission};
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, ann, bob, by_hand, copy, key, published, start_as, viewing,
    };
    use crate::test_support::authority::assumed_authority;
    use crate::types::TenantId;

    /// Ann's payroll run, started with confidential data, whose one step
    /// copied the salaries on.
    fn confidential_run() -> Execution {
        let workflow = published(vec![copy("salaries", &[("ok", "trigger.ok")])], Vec::new());
        start_as(&workflow, &ann(), by_hand(DataClassLevel::Confidential))
            .unwrap()
            .0
    }

    /// Bob may view workflows and is cleared for confidential data.
    fn cleared(by: &Human) -> WorkflowControl<'_> {
        WorkflowControl::new(assumed_authority(
            by,
            TenantId::new(),
            &[
                SystemPermission::Workflows(WorkflowAction::View),
                SystemPermission::Data(DataAccessAction::Confidential),
            ],
            &[],
        ))
    }

    /// Sam's workflow view right and internal clearance expose Ann's payroll
    /// run's successful step phase and its confidential classification, but
    /// withhold its step data and trigger input.
    #[test]
    fn a_viewer_below_the_runs_class_sees_where_it_stands_but_not_its_data() {
        let sam = bob();

        let view = confidential_run().viewed_by(viewing(&sam)).unwrap();

        assert_eq!(view.input(), None);
        let (_, step) = view.steps().next().unwrap();
        assert_eq!(
            step,
            StepView::Withheld {
                phase: StepPhase::Succeeded,
                exposure: DataClassLevel::Confidential,
            }
        );
    }

    /// Bob is cleared for confidential data. He reads Ann's payroll run
    /// whole.
    #[test]
    fn a_cleared_viewer_reads_the_run_whole() {
        let bob = bob();
        let run = confidential_run();
        let kept = run.step(&key("salaries")).cloned().unwrap();

        let view = run.viewed_by(cleared(&bob)).unwrap();

        assert!(view.input().is_some());
        let (_, step) = view.steps().next().unwrap();
        assert_eq!(step, StepView::Shown(&kept));
    }

    /// Mallory cannot open Ann's run without workflow view rights; reading
    /// it returns a forbidden error.
    #[test]
    fn reading_a_run_needs_the_view_right() {
        let mallory = bob();
        let nothing = WorkflowControl::new(assumed_authority(&mallory, TenantId::new(), &[], &[]));

        let result = confidential_run().viewed_by(nothing);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
