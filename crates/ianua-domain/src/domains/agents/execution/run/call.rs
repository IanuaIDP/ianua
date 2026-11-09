//! The tool calls a run makes: the one held for approval, and the steps it records.

use time::{Duration, OffsetDateTime};

use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::validation::{TextValue, ValidationError, Validator, text_value};
use crate::types::{ActionClass, AgentRunId, Human, UntrustedText};

/// The most a model may send as one call's arguments.
pub(crate) const MAX_TOOL_ARGUMENTS: usize = 64 * 1024;

/// How long an approved call may wait to be made. After that the approval
/// has lapsed and the call is not made.
pub(crate) const APPROVED_CALL_WINDOW: Duration = Duration::minutes(15);

text_value! {
    /// The arguments a model sent with a tool call, kept exactly as sent.
    ///
    /// They are replayed to the model and handed to the tool. So nothing is
    /// cut or rewritten. Only their size is limited.
    pub struct ToolArguments;
}

impl TextValue for ToolArguments {
    const FIELD: &'static str = "tool_arguments";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.max_bytes(MAX_TOOL_ARGUMENTS)
    }
}

text_value! {
    /// What a person writes back to the agent instead of letting the call
    /// it holds run, such as "use the staging ledger instead".
    pub struct CallReply;
}

impl TextValue for CallReply {
    const FIELD: &'static str = "reply";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .char_length(1..=4000)
            .no_control_chars_but_line_breaks()
            .no_invisible_chars()
    }
}

impl CallReply {
    /// Moves the validated reply into the run's recorded step without copying it.
    pub(super) fn into_text(self) -> String {
        self.0
    }
}

/// A tool call as the model made it: the tool it named and the arguments
/// it sent.
///
/// The name is kept as untrusted text, because the model may name a tool
/// that does not exist. It is compared with the registered names, never
/// trusted as one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ToolCall {
    tool: UntrustedText,
    arguments: ToolArguments,
}

impl ToolCall {
    /// The call to `tool` with `arguments`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the arguments are larger than
    ///   `MAX_TOOL_ARGUMENTS` bytes.
    pub fn new(tool: &str, arguments: &str) -> Result<Self, ValidationError> {
        Ok(Self {
            tool: UntrustedText::record(tool),
            arguments: ToolArguments::new(arguments)?,
        })
    }

    /// The tool the model named.
    #[must_use]
    pub fn tool(&self) -> &str {
        self.tool.as_str()
    }

    /// The arguments the model sent.
    #[must_use]
    pub fn arguments(&self) -> &str {
        self.arguments.as_str()
    }
}

/// A tool call a run holds until a person approves it.
///
/// It names the step it paused at. A run pauses at most once at each step,
/// so that names the pause, and an approval of one pause never releases
/// another.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PendingCall {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub(super) call: ToolCall,
    pub(super) class: ActionClass,
    pub(super) at_step: u32,
    pub(super) approved: CallApproval,
}

/// Whether a person has approved a held tool call, and when the run took
/// the approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum CallApproval {
    /// Waiting for a person to decide.
    Awaiting,
    /// A person approved it, and the run took the approval at this time.
    Approved(OffsetDateTime),
}

/// The exact call an approver decided on, at the pause they saw.
///
/// It travels from what the approver saw into the decision. The run then
/// checks it still holds that call at that pause. Tool, arguments and pause
/// are all compared. Ann approves `delete(id=1)`. That is not an approval of
/// `delete(id=everything)`, nor of a later pause on `delete(id=1)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCallRef {
    call: ToolCall,
    at_step: u32,
}

impl PendingCallRef {
    /// References `call`, held by the pause at step `at_step`.
    #[must_use]
    pub fn new(call: ToolCall, at_step: u32) -> Self {
        Self { call, at_step }
    }

    /// References the call a run holds now.
    #[must_use]
    pub fn of(pending: &PendingCall) -> Self {
        Self::new(pending.call.clone(), pending.at_step)
    }

    /// Whether the run still holds this call, with the same tool and
    /// arguments, at the same pause.
    #[must_use]
    pub fn matches(&self, pending: &PendingCall) -> bool {
        self.call == pending.call && self.at_step == pending.at_step
    }

    /// The step the referenced pause was at.
    #[must_use]
    pub fn at_step(&self) -> u32 {
        self.at_step
    }

    /// The referenced tool.
    #[must_use]
    pub fn tool(&self) -> &str {
        self.call.tool()
    }

    /// The arguments the referenced call was made with.
    #[must_use]
    pub fn arguments(&self) -> &str {
        self.call.arguments()
    }
}

/// Proof that an approval request granted the call a run holds. It names the
/// run that raised the request and the call that was decided on.
///
/// It is made only when a granted approval is used. So a run resumes its
/// held call on a granted approval, never on one person's word. The approval
/// request decides who may approve and how many must.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedCall {
    run_id: AgentRunId,
    call: PendingCallRef,
}

impl ReleasedCall {
    pub(crate) fn new(run_id: AgentRunId, call: PendingCallRef) -> Self {
        Self { run_id, call }
    }

    /// The run the approval was raised by.
    #[must_use]
    pub fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }

    /// The call it granted.
    #[must_use]
    pub fn call(&self) -> &PendingCallRef {
        &self.call
    }
}

/// Proof that a person allowed to decide denied the call a run holds.
///
/// It is made only when an approval request raised by that run is denied.
/// So a run drops its held call on a real decision, never on anyone's say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedCall {
    run_id: AgentRunId,
    call: PendingCallRef,
}

impl DeniedCall {
    pub(crate) fn new(run_id: AgentRunId, call: PendingCallRef) -> Self {
        Self { run_id, call }
    }

    /// The run the request was raised by.
    #[must_use]
    pub fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }

    /// The call it denied.
    #[must_use]
    pub fn call(&self) -> &PendingCallRef {
        &self.call
    }
}

/// Proof that a person allowed to decide changed the arguments of the call
/// a run held, so the request opened for the old call is withdrawn.
///
/// Only [`AgentRun::revise_pending`](crate::domains::agents::execution::run::AgentRun::revise_pending) makes
/// one. It names the run, the call as it was before, and who changed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisedCall {
    run_id: AgentRunId,
    previous: PendingCallRef,
    by: Human,
}

impl RevisedCall {
    pub(super) fn new(run_id: AgentRunId, previous: PendingCallRef, by: Human) -> Self {
        Self {
            run_id,
            previous,
            by,
        }
    }

    /// The run whose call changed.
    #[must_use]
    pub fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }

    /// The call as it was before the change.
    #[must_use]
    pub fn previous(&self) -> &PendingCallRef {
        &self.previous
    }

    /// The person who changed it.
    #[must_use]
    pub fn by(&self) -> &Human {
        &self.by
    }
}

impl PendingCall {
    /// The call held.
    #[must_use]
    pub fn call(&self) -> &ToolCall {
        &self.call
    }

    /// The tool the model asked to call.
    #[must_use]
    pub fn tool(&self) -> &str {
        self.call.tool()
    }

    /// The arguments the model supplied.
    #[must_use]
    pub fn arguments(&self) -> &str {
        self.call.arguments()
    }

    /// The class of action the paused tool takes. It is read from the tool
    /// when the run paused, and decides how many people must approve.
    #[must_use]
    pub fn class(&self) -> ActionClass {
        self.class
    }

    /// The step the run paused at. The held call fills it once it is made
    /// or refused.
    #[must_use]
    pub fn at_step(&self) -> u32 {
        self.at_step
    }

    /// Whether a person has approved this call.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self.approved, CallApproval::Approved(_))
    }

    /// When the run took the approval, once a person approved the call.
    #[must_use]
    pub fn approved_at(&self) -> Option<OffsetDateTime> {
        match self.approved {
            CallApproval::Awaiting => None,
            CallApproval::Approved(at) => Some(at),
        }
    }

    /// Whether the approval has lapsed by `now`, so the call may no longer
    /// be made. A call still awaiting a person has nothing to lapse.
    #[must_use]
    pub fn approval_lapsed_at(&self, now: OffsetDateTime) -> bool {
        self.approved_at()
            .is_some_and(|at| now >= at.saturating_add(APPROVED_CALL_WINDOW))
    }
}

/// What happened in one step of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StepOutcome {
    /// A tool call passed the call check and ran. Holds its result.
    Allowed(String),
    /// A tool call was refused. Holds the reason.
    Denied(String),
    /// The model gave its final answer. Holds the answer.
    Answered(String),
    /// A person answered the held call in words instead of letting it run.
    /// Holds what they wrote, which the model reads next.
    Replied(String),
    /// The check the run is held to turned its last answer back. Holds what
    /// the check said is wrong, which the model reads before it tries
    /// again, or why the check could not run.
    CheckFailed(String),
}

/// What a step of a run called: the model, or a tool with its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepCall {
    /// The model answered without calling a tool.
    Model,
    /// The model called a tool. The audit trail records the arguments too,
    /// not only the name.
    Tool(ToolCall),
}

/// One step of a run. Steps are only ever added, never changed.
///
/// Stored as JSON with separate `tool` and `arguments` fields, and read
/// through [`StepCall`]. So a stored step with arguments but no tool does
/// not load.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "RunStepWire", into = "RunStepWire")
)]
pub struct RunStep {
    pub(super) seq: u32,
    pub(super) call: StepCall,
    pub(super) outcome: StepOutcome,
    pub(super) read: DataClassLevel,
    pub(super) at: OffsetDateTime,
}

/// A [`RunStep`] as JSON spells it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct RunStepWire {
    seq: u32,
    tool: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
    outcome: StepOutcome,
    read: DataClassLevel,
    at: OffsetDateTime,
}

#[cfg(feature = "serde")]
impl TryFrom<RunStepWire> for RunStep {
    type Error = crate::shared::errors::DomainError;

    fn try_from(wire: RunStepWire) -> Result<Self, Self::Error> {
        let call = match (wire.tool, wire.arguments) {
            (None, None) => StepCall::Model,
            (Some(tool), arguments) => StepCall::Tool(
                ToolCall::new(&tool, &arguments.unwrap_or_default()).map_err(|broken_rule| {
                    crate::shared::errors::DomainError::corrupt_value(
                        "agent run",
                        "a step holds a tool call that is not valid",
                        broken_rule,
                    )
                })?,
            ),
            (None, Some(_)) => {
                return Err(crate::shared::errors::DomainError::infra_msg(
                    "a stored run step has arguments but names no tool",
                ));
            }
        };
        Ok(Self {
            seq: wire.seq,
            call,
            outcome: wire.outcome,
            read: wire.read,
            at: wire.at,
        })
    }
}

#[cfg(feature = "serde")]
impl From<RunStep> for RunStepWire {
    fn from(step: RunStep) -> Self {
        let (tool, arguments) = match step.call {
            StepCall::Model => (None, None),
            StepCall::Tool(call) => (
                Some(call.tool().to_owned()),
                Some(call.arguments().to_owned()),
            ),
        };
        Self {
            seq: step.seq,
            tool,
            arguments,
            outcome: step.outcome,
            read: step.read,
            at: step.at,
        }
    }
}

impl RunStep {
    /// The step's number, counting from 1.
    #[must_use]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// What the step called.
    #[must_use]
    pub fn call(&self) -> &StepCall {
        &self.call
    }

    /// The tool the model named, if this step was a tool call.
    #[must_use]
    pub fn tool(&self) -> Option<&str> {
        match &self.call {
            StepCall::Model => None,
            StepCall::Tool(call) => Some(call.tool()),
        }
    }

    /// The arguments the model sent, if this step was a tool call. The audit
    /// trail records them along with the tool's name.
    #[must_use]
    pub fn arguments(&self) -> Option<&str> {
        match &self.call {
            StepCall::Model => None,
            StepCall::Tool(call) => Some(call.arguments()),
        }
    }

    /// The step's outcome.
    #[must_use]
    pub fn outcome(&self) -> &StepOutcome {
        &self.outcome
    }

    /// The most sensitive data the step brought into the run. It is the
    /// tool's data class for a call that ran, and public for any other step.
    #[must_use]
    pub fn read(&self) -> DataClassLevel {
        self.read
    }

    /// When the step was recorded. The time between it and the step before,
    /// or the run's start, is how long the step took.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }

    /// Whether the step was a tool call, made or refused. Only these count
    /// against the run's step limit.
    #[must_use]
    pub fn is_tool_call(&self) -> bool {
        matches!(self.call, StepCall::Tool(_))
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    /// A held `Delete` call paused at step 3 is stored awaiting, another
    /// approved at a time. Each reads back in the matching state at step 3,
    /// and the approved one writes back the same JSON.
    #[cfg(feature = "serde")]
    #[test]
    fn a_held_call_keeps_its_stored_approval_and_pause() {
        let approved_at = OffsetDateTime::UNIX_EPOCH;
        let held = PendingCall {
            call: ToolCall::new("t", "{}").unwrap(),
            class: ActionClass::Delete,
            at_step: 3,
            approved: CallApproval::Approved(approved_at),
        };
        let awaiting = PendingCall {
            approved: CallApproval::Awaiting,
            ..held.clone()
        };

        let read: PendingCall =
            serde_json::from_str(&serde_json::to_string(&held).unwrap()).unwrap();
        let read_awaiting: PendingCall =
            serde_json::from_str(&serde_json::to_string(&awaiting).unwrap()).unwrap();

        assert_eq!(read, held);
        assert_eq!(read.approved_at(), Some(approved_at));
        assert_eq!(read.at_step(), 3);
        assert!(!read_awaiting.is_approved());
    }

    /// A stored step has arguments but a `null` tool. It fails to load,
    /// because arguments with no tool are corrupt data, not a step to replay.
    #[test]
    fn a_stored_step_with_arguments_and_no_tool_does_not_load() {
        let json = r#"{"seq":1,"tool":null,"arguments":"{}","outcome":{"Answered":"done"},"read":"Public"}"#;

        assert!(serde_json::from_str::<RunStep>(json).is_err());
    }

    /// A stored `lookup` step holds arguments one byte past the limit. It is
    /// refused as a corrupt run, and the causes name the size rule the
    /// arguments break rather than a guess at what went wrong.
    #[test]
    fn a_stored_step_past_the_argument_limit_names_the_broken_rule() {
        let wire = RunStepWire {
            seq: 1,
            tool: Some("lookup".to_owned()),
            arguments: Some("x".repeat(MAX_TOOL_ARGUMENTS + 1)),
            outcome: StepOutcome::Allowed("ok".to_owned()),
            read: DataClassLevel::Public,
            at: OffsetDateTime::UNIX_EPOCH,
        };

        let error = RunStep::try_from(wire).unwrap_err();

        let chain = crate::shared::errors::causes(&error);
        assert!(chain.contains("stored agent run is corrupt"), "{chain}");
        assert!(chain.contains("tool_arguments must be between"), "{chain}");
    }

    /// A `lookup` step with its arguments, recorded at a set time, is
    /// stored with separate `tool` and `arguments` fields. It reads back
    /// naming `lookup`, the internal data it read and the time it was
    /// recorded, equal to what was written.
    #[test]
    fn a_stored_tool_step_reads_back_as_written() {
        let step = RunStep {
            seq: 2,
            call: StepCall::Tool(ToolCall::new("lookup", "{\"id\":1}").unwrap()),
            outcome: StepOutcome::Allowed("ok".to_owned()),
            read: DataClassLevel::Internal,
            at: OffsetDateTime::UNIX_EPOCH,
        };

        let json = serde_json::to_string(&step).unwrap();
        let read: RunStep = serde_json::from_str(&json).unwrap();

        assert!(
            json.contains(r#""tool":"lookup","arguments":"{\"id\":1}""#),
            "{json}"
        );
        assert_eq!(read, step);
        assert_eq!(read.tool(), Some("lookup"));
        assert_eq!(read.at(), OffsetDateTime::UNIX_EPOCH);
    }

    /// A stored step with no time it was recorded fails to load. Its
    /// duration could not be told.
    #[test]
    fn a_stored_step_without_its_time_does_not_load() {
        let json = r#"{"seq":2,"tool":null,"arguments":null,"outcome":{"Answered":"done"},"read":"Public"}"#;

        assert!(serde_json::from_str::<RunStep>(json).is_err());
    }
}
