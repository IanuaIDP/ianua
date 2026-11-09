//! Sets and evaluations as one person may read them, with what is above
//! their clearance withheld.
//!
//! The view right lets someone follow a workflow's evaluations. It does not
//! clear them for what the cases carry. Ann writes a payroll case whose
//! input holds a salary and marks it confidential. Sam may view workflows
//! and sees only internal data. Read whole, the set would hand him the
//! salary, and a failed check would show him what the run found in the
//! payroll system.

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::design::workflow::Revision;
use crate::domains::workflows::evaluation::case::{CaseName, EvaluationCase};
use crate::domains::workflows::evaluation::outcome::CaseOutcome;
use crate::domains::workflows::evaluation::run::{Evaluation, EvaluationState};
use crate::domains::workflows::evaluation::set::{EvaluationSet, PublishGate};
use crate::isolation::scope::TenantScope;
use crate::shared::model::aggregate::Aggregate;
use crate::types::{EvaluationId, Human, WorkflowExecutionId, WorkflowId};

/// One case, as the viewer may read it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CaseView<'a> {
    /// The viewer is cleared for the case's input: all of it.
    Shown(&'a EvaluationCase),
    /// The input is above the viewer's clearance: only its name and how
    /// sensitive it is.
    Withheld {
        /// What the author calls it.
        name: &'a CaseName,
        /// How sensitive its input is.
        exposure: DataClassLevel,
    },
}

/// What one case came to, as the viewer may read it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutcomeView<'a> {
    /// All of it: it carries no data, or the viewer is cleared for what
    /// its run held.
    Shown(&'a CaseOutcome),
    /// It failed, and what differed may repeat data above the viewer's
    /// clearance, so only that it failed and its run are shown.
    Withheld {
        /// The test run.
        execution: &'a WorkflowExecutionId,
        /// How sensitive the data its run held is.
        exposure: DataClassLevel,
    },
}

/// A workflow's set, read by a person who may view workflows.
pub struct SetView<T: TenantScope> {
    pub(super) set: EvaluationSet<T>,
    pub(super) clearance: DataClassLevel,
}

/// An evaluation, read by a person who may view workflows.
pub struct EvaluationView<T: TenantScope> {
    pub(super) evaluation: Evaluation<T>,
    pub(super) clearance: DataClassLevel,
}

impl<T: TenantScope> SetView<T> {
    /// The workflow whose versions it tries.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        self.set.workflow_id()
    }

    /// Each case, as the viewer may read it.
    pub fn cases(&self) -> impl Iterator<Item = CaseView<'_>> {
        self.set
            .cases()
            .iter()
            .map(|case| case_view(case, self.clearance))
    }

    /// Whether publishing needs the draft's last evaluation to pass.
    #[must_use]
    pub fn gate(&self) -> PublishGate {
        self.set.gate()
    }

    /// The person who last saved it.
    #[must_use]
    pub fn edited_by(&self) -> &Human {
        self.set.edited_by()
    }

    /// When it was last saved.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.set.updated_at()
    }
}

impl<T: TenantScope> EvaluationView<T> {
    /// The evaluation shown.
    #[must_use]
    pub fn id(&self) -> &EvaluationId {
        self.evaluation.id()
    }

    /// The workflow it tries.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        self.evaluation.workflow_id()
    }

    /// The version it tries.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.evaluation.version()
    }

    /// The revision of that version it tries, as a publisher hands it back.
    #[must_use]
    pub fn revision(&self) -> Revision {
        self.evaluation.revision()
    }

    /// The person who started it.
    #[must_use]
    pub fn started_by(&self) -> &Human {
        self.evaluation.started_by()
    }

    /// Where it stands.
    #[must_use]
    pub fn state(&self) -> EvaluationState {
        self.evaluation.state()
    }

    /// When every case still open could not run.
    #[must_use]
    pub fn deadline(&self) -> OffsetDateTime {
        self.evaluation.deadline()
    }

    /// When it started.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        Aggregate::created_at(&self.evaluation)
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        Aggregate::updated_at(&self.evaluation)
    }

    /// Each case and what it came to, as the viewer may read them.
    pub fn cases(&self) -> impl Iterator<Item = (CaseView<'_>, OutcomeView<'_>)> {
        self.evaluation
            .cases()
            .iter()
            .zip(self.evaluation.outcomes())
            .map(|(case, outcome)| {
                (
                    case_view(case, self.clearance),
                    outcome_view(outcome, self.clearance),
                )
            })
    }
}

/// `case`, withheld when its input is above `clearance`.
fn case_view(case: &EvaluationCase, clearance: DataClassLevel) -> CaseView<'_> {
    if case.exposure() > clearance {
        return CaseView::Withheld {
            name: case.name(),
            exposure: case.exposure(),
        };
    }
    CaseView::Shown(case)
}

/// `outcome`, withheld when it failed on a run holding data above
/// `clearance`.
fn outcome_view(outcome: &CaseOutcome, clearance: DataClassLevel) -> OutcomeView<'_> {
    match outcome {
        CaseOutcome::Failed {
            execution,
            exposure,
            ..
        } if *exposure > clearance => OutcomeView::Withheld {
            execution,
            exposure: *exposure,
        },
        CaseOutcome::Waiting
        | CaseOutcome::Running { .. }
        | CaseOutcome::Passed { .. }
        | CaseOutcome::Failed { .. }
        | CaseOutcome::NotRun { .. } => OutcomeView::Shown(outcome),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::evaluation::set::PublishGate;
    use crate::domains::workflows::evaluation::tests::{
        confidential_case, evaluator, set_with, viewer, workflow,
    };

    /// Sam may view workflows and is cleared for internal data. A
    /// confidential case shows him its name only; Ann, who wrote it, sees
    /// it whole.
    #[test]
    fn a_case_above_the_clearance_shows_its_name_only() {
        let draft = workflow();
        let set = set_with(&draft, vec![confidential_case("payroll")]);

        let by_viewer = set.clone().viewed_by(viewer()).unwrap();
        let by_author = set.viewed_by(evaluator()).unwrap();

        assert!(matches!(
            by_viewer.cases().next(),
            Some(CaseView::Withheld { .. })
        ));
        assert!(matches!(by_author.cases().next(), Some(CaseView::Shown(_))));
        assert_eq!(by_author.gate(), PublishGate::Off);
    }
}
