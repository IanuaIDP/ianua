//! The records of evaluations: a workflow's sample cases saved, an
//! evaluation started, and how it ended.
//!
//! All three are a person working on their own draft, as a test is, so
//! they stay in the audit trail and out of colleagues' feeds. A failing
//! evaluation means the draft is not ready yet, not that anything broke.

use time::OffsetDateTime;

use crate::domains::workflows::evaluation::outcome::Verdict;
use crate::domains::workflows::evaluation::set::PublishGate;
use crate::domains::workflows::events::VersionRef;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{EvaluationId, WorkflowId};

/// The reference kind for one evaluation.
const EVALUATION: RefKind = RefKind::new("workflow_evaluation");

/// Which evaluation an event is about.
#[derive(Debug, Clone)]
pub(crate) struct EvaluationRef {
    /// The evaluation recorded.
    pub(crate) evaluation_id: EvaluationId,
    /// The workflow it tries.
    pub(crate) workflow_id: WorkflowId,
    /// The version of it tried.
    pub(crate) version: u32,
}

impl EvaluationRef {
    fn payload(&self) -> EventData {
        let named = format!("evaluation of version {}", self.version);
        EventData::new()
            .reference(
                "evaluation",
                Reference::new(EVALUATION, self.evaluation_id.to_string(), &named),
            )
            .field("workflow_id", self.workflow_id.to_string())
            .field("version", self.version.to_string())
    }
}

/// A workflow's sample cases were saved.
#[derive(Debug)]
pub(crate) struct EvaluationSetSaved {
    /// The workflow, as its latest version names it.
    pub(crate) version: VersionRef,
    /// How many cases the set holds now.
    pub(crate) cases: usize,
    /// Whether publishing needs the draft's last evaluation to pass.
    pub(crate) gate: PublishGate,
    /// When it was saved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    EvaluationSetSaved => WorkflowsEvent::EvaluationSetSaved,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("cases", self.cases.to_string())
            .field("publish_gate", self.gate.as_str())
    }
}

/// A person started an evaluation.
#[derive(Debug)]
pub(crate) struct EvaluationStarted {
    /// The evaluation started.
    pub(crate) evaluation: EvaluationRef,
    /// How many cases it runs.
    pub(crate) cases: usize,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    EvaluationStarted => WorkflowsEvent::EvaluationStarted,
    fn payload(&self) -> EventData {
        self.evaluation
            .payload()
            .field("cases", self.cases.to_string())
    }
}

/// An evaluation ended, with how many of its cases passed, failed or
/// could not run.
#[derive(Debug)]
pub(crate) struct EvaluationEnded {
    /// The evaluation that ended.
    pub(crate) evaluation: EvaluationRef,
    /// Whether every case passed.
    pub(crate) verdict: Verdict,
    /// Cases whose checks all held.
    pub(crate) passed: usize,
    /// Cases with a check that did not hold, or whose run did not succeed.
    pub(crate) failed: usize,
    /// Cases that could not run.
    pub(crate) not_run: usize,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    EvaluationEnded => WorkflowsEvent::EvaluationEnded,
    fn payload(&self) -> EventData {
        self.evaluation
            .payload()
            .field("verdict", self.verdict.as_str())
            .field("passed", self.passed.to_string())
            .field("failed", self.failed.to_string())
            .field("not_run", self.not_run.to_string())
    }
}
