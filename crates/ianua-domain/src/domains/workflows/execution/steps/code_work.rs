//! A code step's run under way, and how its runner reports it went.

use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::execution::step::StepFailure;
use crate::types::{CodeRunId, UntrustedText};

/// A run of a code step's sandbox version under way, with what its code is
/// given, so a worker that picks the run up again hands it the same.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CodeWork {
    /// The run, which its outcome is reported under.
    pub run_id: CodeRunId,
    /// What the code is given.
    pub input: FlowData,
}

/// How a run of a code step's sandbox version went, as its runner reports
/// it.
#[derive(Debug, Clone, PartialEq)]
pub enum CodeOutcome {
    /// The code gave back this.
    Succeeded(FlowData),
    /// It did not. This is why.
    Failed(CodeFailure),
}

impl CodeOutcome {
    /// The outcome of code that could not be run at all, for `reason`.
    #[must_use]
    pub fn not_run(reason: &str) -> Self {
        Self::Failed(CodeFailure::NotRun(UntrustedText::record(reason)))
    }
}

/// Why a run of code gave nothing back.
#[derive(Debug, Clone, PartialEq)]
pub enum CodeFailure {
    /// It raised an error, or exited without giving anything back. This is
    /// the end of what it wrote about it.
    Raised(UntrustedText),
    /// It ran past its time limit.
    TimedOut,
    /// It used more memory than it is given.
    OutOfMemory,
    /// What it gave back was no JSON, or too large.
    Unreadable,
    /// It could not be run at all. This is why.
    NotRun(UntrustedText),
}

impl From<CodeFailure> for StepFailure {
    fn from(failure: CodeFailure) -> Self {
        match failure {
            CodeFailure::Raised(reason) => Self::CodeRaised(reason),
            CodeFailure::TimedOut => Self::CodeTimedOut,
            CodeFailure::OutOfMemory => Self::CodeOutOfMemory,
            CodeFailure::Unreadable => Self::CodeOutputUnreadable,
            CodeFailure::NotRun(reason) => Self::CodeNotRun(reason),
        }
    }
}
