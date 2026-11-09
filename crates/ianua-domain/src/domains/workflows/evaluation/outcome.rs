//! What one case of an evaluation came to: passed, failed with what
//! differed or how its run ended, or not run with why; and the verdict
//! over every case.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::evaluation::check::Found;
use crate::types::WorkflowExecutionId;

/// Why a case could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum NotRunReason {
    /// The test run was refused, such as for a step reading data no
    /// earlier step hands on.
    Refused,
    /// The person who started the evaluation may no longer test this
    /// workflow.
    EvaluatorMayNotAct,
    /// The draft changed while the case waited its turn, so it would have
    /// tried another revision than the others.
    DraftChanged,
    /// The evaluation ran out of time first.
    OutOfTime,
}

impl NotRunReason {
    /// The reason's stored and shown name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::EvaluatorMayNotAct => "evaluator_may_not_act",
            Self::DraftChanged => "draft_changed",
            Self::OutOfTime => "out_of_time",
        }
    }
}

/// How a case's test run ended, when it did not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RunEnd {
    /// A step failed.
    Failed,
    /// Someone stopped it.
    Cancelled,
    /// It ran past its workflow's run limit.
    TimedOut,
}

impl RunEnd {
    /// The end's stored and shown name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

/// One thing that differed in a failed case.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum Difference {
    /// The test run did not succeed, so there were no results to check.
    RunEnded {
        /// How it ended.
        end: RunEnd,
    },
    /// The check at `index` of the case did not hold.
    Check {
        /// Which of the case's checks, counted from zero.
        index: usize,
        /// What was at its path; `None` when nothing was.
        found: Option<Found>,
    },
}

/// What one case came to so far.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "state", rename_all = "snake_case"))]
pub enum CaseOutcome {
    /// It waits for a free place among the runs under way.
    Waiting,
    /// Its test run is under way.
    Running {
        /// The test run.
        execution: WorkflowExecutionId,
    },
    /// Every check held.
    Passed {
        /// The test run.
        execution: WorkflowExecutionId,
    },
    /// A check did not hold, or the run did not succeed.
    Failed {
        /// The test run.
        execution: WorkflowExecutionId,
        /// What differed.
        differences: Vec<Difference>,
        /// The most sensitive data the run held, which what it found may
        /// repeat.
        exposure: DataClassLevel,
    },
    /// It could not run.
    NotRun {
        /// Why.
        reason: NotRunReason,
    },
}

impl CaseOutcome {
    /// Whether it still waits or runs.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Waiting | Self::Running { .. })
    }
}

/// How an evaluation that ended went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every case passed.
    Passed,
    /// A case failed or could not run.
    Failed,
}

impl Verdict {
    /// The verdict's stored and audited name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}
