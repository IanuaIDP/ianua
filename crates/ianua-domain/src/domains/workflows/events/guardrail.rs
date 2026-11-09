//! The record that a guardrail step found something in the text it checked.

use time::OffsetDateTime;

use crate::domains::workflows::events::StepRef;
use crate::domains::workflows::guardrail::finding::{GuardrailFinding, GuardrailFound};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;

/// A guardrail step found personal data, an attempt to trick a model or a
/// banned word, whatever it then did about it.
///
/// It names each finding by kind and place, never the text matched, so the
/// audit trail does not carry the card number the step kept out of the run.
/// It stays out of colleagues' feeds: a step that stops the run fails, and
/// that failure notifies.
#[derive(Debug)]
pub(crate) struct WorkflowGuardrailFound {
    /// The guardrail step.
    pub(crate) step: StepRef,
    /// What it found.
    pub(crate) found: GuardrailFound,
    /// When it checked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowGuardrailFound => WorkflowsEvent::GuardrailFound,
    fn payload(&self) -> EventData {
        let checks: Vec<&str> = self.found.checks().iter().map(|check| check.as_str()).collect();
        let findings: Vec<String> = self
            .found
            .findings()
            .iter()
            .map(GuardrailFinding::summary)
            .collect();
        self.step
            .payload()
            .field("found", self.found.total().to_string())
            .field("checks", checks.join(", "))
            .field("findings", findings.join("; "))
    }
}
