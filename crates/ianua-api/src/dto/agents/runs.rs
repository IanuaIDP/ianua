//! Run bodies: starting a governed run, reading it, deciding the call a
//! paused run holds, and steering it: changing that call or answering it in
//! words.

use ianua_app::listing::PageRequest;
use ianua_app::ports::agents::{RunAgentRequest, RunSummary};
use ianua_app::use_cases::agents::runs::{
    ApproveRequest, ListRequest, ReplyToCallRequest, ReviseCallRequest, RevisedRunCall, RunDecided,
};
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{
    AgentRun, CallReply, PendingCall, PendingCallRef, RunGoal, RunStatus, RunStep, SpendCheck,
    StepOutcome, ToolArguments, ToolCall,
};
use ianua_domain::domains::agents::execution::tool::ToolName;
use ianua_domain::domains::agents::execution::usage::Spend;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{ActionClass, AgentId, AgentRunId, DelegationId, ModelProviderId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::delegation::UnknownFields;
use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// The wire names an action class is accepted under, for error messages.
const ACTION_CLASSES: &str = "read, write, delete, configure, communicate, financial, admin";

/// The wire names a run status is accepted under, for error messages.
const RUN_STATUSES: &str =
    "running, awaiting_approval, paused, completed, failed, cancelled, halted, over_budget";

/// The action class a request names, in any case.
///
/// [`ActionClass::parse`] reads stored values and calls an unknown one a
/// corrupted row; a caller's typo is a validation error naming the value.
fn action_class_named(value: &str) -> Result<ActionClass, ApiError> {
    ActionClass::parse(&value.to_ascii_lowercase()).map_err(|_| {
        ApiError::validation(message!(
            "api-unknown-action-class-expected-one-of",
            format!("unknown action class: {value} (expected one of: {ACTION_CLASSES})")
        ))
    })
}

/// The action classes a request names.
fn action_classes(values: &[String]) -> Result<Vec<ActionClass>, ApiError> {
    values.iter().map(|v| action_class_named(v)).collect()
}

/// The wire names of `classes`.
fn class_names(classes: &[ActionClass]) -> Vec<String> {
    classes
        .iter()
        .map(|class| class.as_str().to_owned())
        .collect()
}

/// Query parameters for listing runs.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RunQueryParams {
    /// Narrows to one lifecycle state (`running`, `awaiting_approval`,
    /// `paused`, `completed`, `failed`, `cancelled`, `halted`,
    /// `over_budget`). Left out to include every state in the page.
    ///
    /// `awaiting_approval` is the run-approval inbox: each entry carries the
    /// run's id, its purpose, and the `pending_tool`, `pending_arguments`
    /// and `pending_at_step` held for sign-off.
    pub status: Option<String>,
}

impl RunQueryParams {
    /// The state to narrow to, if one was asked for.
    ///
    /// # Errors
    ///
    /// - A validation error when `status` names no state.
    pub(crate) fn status(&self) -> Result<Option<RunStatus>, ApiError> {
        self.status
            .as_deref()
            .map(|value| {
                RunStatus::parse(&value.to_ascii_lowercase()).map_err(|_| {
                    ApiError::validation(message!(
                        "api-unknown-run-status-expected-one-of",
                        format!("unknown run status: {value} (expected one of: {RUN_STATUSES})")
                    ))
                })
            })
            .transpose()
    }

    /// The runs of `agent_id` this query asks for.
    ///
    /// # Errors
    ///
    /// - A validation error when `status` names no state.
    pub(crate) fn listing(
        &self,
        agent_id: AgentId,
        page: PageRequest,
    ) -> Result<ListRequest, ApiError> {
        Ok(ListRequest {
            agent_id,
            status: self.status()?,
            page,
        })
    }
}

/// Request body for running an agent toward a goal.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RunAgentBody {
    /// The natural-language goal to pursue.
    pub goal: String,
    /// The model provider to reason with.
    pub provider_id: Uuid,
    /// The action classes the run may exercise (`read`, `write`, `delete`,
    /// `configure`, `communicate`, `financial`, `admin`).
    pub purpose: Vec<String>,
    /// Tools granted to this run by name. A run reaches only the tools
    /// named here; an empty list grants none.
    #[serde(default)]
    pub tool_names: Vec<String>,
    /// Further action classes whose tool calls wait for a person's approval
    /// before running. High-risk classes (`delete`, `configure`,
    /// `financial`, `admin`) always wait; this list can only add to them.
    #[serde(default)]
    pub approval_classes: Vec<String>,
    /// The delegation the run acts under. Tool calls go through the
    /// zero-trust proxy bearing a task token minted from it, and the
    /// proxy's policy pipeline authorizes every call. Left out, the
    /// delegation the caller granted the agent is used; with none at all,
    /// the run may not call tools.
    #[serde(default)]
    pub delegation_id: Option<Uuid>,
    /// Maximum loop iterations. Left out or zero takes the deployment's
    /// default; more than its maximum gets the maximum.
    #[serde(default)]
    pub max_steps: u32,
    /// The most the run may spend on its model, in millionths of the
    /// tenant's billing currency. Once spent, or once a model call's cost
    /// cannot be told, the run stops as `over_budget`. Left out for no
    /// limit.
    #[serde(default)]
    pub spend_limit_micros: Option<u64>,
    /// What the run may spend before it pauses for a person to let it go
    /// on, in the same millionths; below `spend_limit_micros` when both are
    /// set. Whoever may resume the run lets it spend on, once. A call whose
    /// cost cannot be told makes it pause too. Left out for no pause.
    #[serde(default)]
    pub ask_past_micros: Option<u64>,
    /// Fields the body does not know, refused.
    #[serde(flatten)]
    #[schema(ignore)]
    pub unknown: UnknownFields,
}

impl RunAgentBody {
    /// The run of `agent_id` this body starts.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown field, or a goal, tool name or
    ///   action class that is not valid.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<RunAgentRequest, ApiError> {
        self.unknown.ensure_none()?;
        let tool_names = self
            .tool_names
            .into_iter()
            .map(|name| ToolName::new(name).map_err(ApiError::validation))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RunAgentRequest {
            agent_id,
            provider_id: ModelProviderId::from_uuid(self.provider_id),
            goal: RunGoal::new(self.goal).map_err(ApiError::validation)?,
            purpose: IntentEnvelope::new(action_classes(&self.purpose)?),
            tool_names,
            approval_classes: action_classes(&self.approval_classes)?,
            delegation_id: self.delegation_id.map(DelegationId::from_uuid),
            max_steps: self.max_steps,
            spend_limit: amount(self.spend_limit_micros),
            ask_past: amount(self.ask_past_micros),
        })
    }
}

/// One recorded step of a run.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RunStepDto {
    /// 1-based step index.
    pub seq: u32,
    /// The tool named, if this step was a tool call.
    pub tool: Option<String>,
    /// The arguments the tool was called with, if this step was a tool
    /// call.
    pub arguments: Option<String>,
    /// The outcome kind (`allowed`, `denied`, `answered`, `replied`, a
    /// person's answer to a held call in place of running it, or
    /// `check_failed`, an answer the run's check turned back).
    pub outcome: String,
    /// The tool result, refusal reason, final answer, the person's reply,
    /// or what the check found.
    pub detail: String,
    /// When the step was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
}

impl From<&RunStep> for RunStepDto {
    fn from(step: &RunStep) -> Self {
        let (outcome, detail) = match step.outcome() {
            StepOutcome::Allowed(result) => ("allowed", result),
            StepOutcome::Denied(reason) => ("denied", reason),
            StepOutcome::Answered(answer) => ("answered", answer),
            StepOutcome::Replied(reply) => ("replied", reply),
            StepOutcome::CheckFailed(said) => ("check_failed", said),
        };
        Self {
            seq: step.seq(),
            tool: step.tool().map(str::to_owned),
            arguments: step.arguments().map(str::to_owned),
            outcome: outcome.to_owned(),
            detail: detail.clone(),
            at: step.at(),
        }
    }
}

/// The tokens a run's model calls used so far.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RunUsageDto {
    /// Tokens sent to the model.
    pub input_tokens: u64,
    /// Tokens the model wrote.
    pub output_tokens: u64,
}

/// A run summary; its steps and final answer are available on the detail endpoint.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RunSummaryResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The acting agent.
    pub agent_id: Uuid,
    /// The model provider used.
    pub provider_id: Uuid,
    /// The task the agent was asked to accomplish.
    pub goal: String,
    /// The purpose: the action classes the run may exercise.
    pub purpose: Vec<String>,
    /// Lifecycle status (`running`, `awaiting_approval`, `paused`,
    /// `completed`, `failed`, `cancelled`, `halted`, `over_budget`).
    pub status: String,
    /// The tool awaiting a person's approval, if the run is paused.
    pub pending_tool: Option<String>,
    /// The arguments that tool was called with, verbatim.
    ///
    /// An approver has to see what they approve, and echo it back when
    /// deciding, so the decision cannot land on a call that changed
    /// meanwhile.
    pub pending_arguments: Option<String>,
    /// The step the held call was made at, echoed back with the decision.
    pub pending_at_step: Option<u32>,
    /// The most sensitive data class the run has read (`public`,
    /// `internal`, `confidential`, `restricted`). The run may call only
    /// tools cleared for it, and its answer may carry it.
    pub exposure: String,
    /// Who started the run.
    pub started_by: OwnerDto,
    /// The delegation the run acts under, or `null` for a run that calls no
    /// tool.
    pub delegation_id: Option<Uuid>,
    /// The most steps the run may take.
    pub max_steps: u32,
    /// The action classes the starter listed as needing approval;
    /// high-risk classes need it too, listed or not.
    pub approval_classes: Vec<String>,
    /// The tokens its model calls used so far.
    pub usage: RunUsageDto,
    /// What its model calls cost so far, in millionths of the tenant's
    /// billing currency. Calls to a provider with no price are not counted.
    pub spent_micros: u64,
    /// The most the run may spend, or `null` for no limit.
    pub spend_limit_micros: Option<u64>,
    /// Where the run waits for a person before spending more, or `null`
    /// when it never does.
    pub spend_check: Option<SpendCheckDto>,
    /// When the run started.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the run last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<RunSummary> for RunSummaryResponse {
    fn from(run: RunSummary) -> Self {
        let pending = run.state.pending();
        Self {
            id: *run.id.as_uuid(),
            agent_id: *run.agent_id.as_uuid(),
            provider_id: *run.provider_id.as_uuid(),
            goal: run.goal.as_str().to_owned(),
            purpose: class_names(run.purpose.allowed()),
            status: run.state.status().as_str().to_owned(),
            pending_tool: pending.map(|call| call.tool().to_owned()),
            pending_arguments: pending.map(|call| call.arguments().to_owned()),
            pending_at_step: pending.map(PendingCall::at_step),
            exposure: run.exposure.as_str().to_owned(),
            started_by: OwnerDto::from_principal(&run.started_by.principal()),
            delegation_id: run.delegation_id.delegation().map(|id| *id.as_uuid()),
            max_steps: run.max_steps,
            approval_classes: class_names(&run.approval_classes),
            usage: RunUsageDto {
                input_tokens: run.usage.input(),
                output_tokens: run.usage.output(),
            },
            spent_micros: run.spent.micros(),
            spend_limit_micros: micros_of(run.spend_limit),
            spend_check: SpendCheckDto::of(run.spend_check),
            created_at: run.created_at,
            updated_at: run.updated_at,
        }
    }
}

/// Where a run waits for a person before spending more.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SpendCheckDto {
    /// What it may spend before it asks, in millionths of the tenant's
    /// billing currency.
    pub asks_at_micros: u64,
    /// `ahead` until it reaches that, `due` once it must ask before its
    /// next model call, `asked` once it paused for it.
    pub state: &'static str,
}

impl SpendCheckDto {
    /// `check` on the wire, or `None` for a run that never asks.
    fn of(check: SpendCheck) -> Option<Self> {
        let (asks_at, state) = match check {
            SpendCheck::Off => return None,
            SpendCheck::AskAt(mark) => (mark, "ahead"),
            SpendCheck::Due(mark) => (mark, "due"),
            SpendCheck::Asked(mark) => (mark, "asked"),
        };
        Some(Self {
            asks_at_micros: asks_at.micros(),
            state,
        })
    }
}

/// The amount `micros` names, or no amount when it is left out.
pub(crate) fn amount(micros: Option<u64>) -> Restriction<Spend> {
    micros.map_or(Restriction::Unrestricted, |micros| {
        Restriction::To(Spend::from_micros(micros))
    })
}

/// `amount` in millionths, or `None` when there is none.
pub(crate) fn micros_of(amount: Restriction<Spend>) -> Option<u64> {
    amount.limit().map(|amount| amount.micros())
}

/// An agent's task, current status and progress toward its goal.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RunResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The acting agent.
    pub agent_id: Uuid,
    /// The model provider used.
    pub provider_id: Uuid,
    /// The task the agent was asked to accomplish.
    pub goal: String,
    /// The purpose: the action classes the run may exercise.
    pub purpose: Vec<String>,
    /// Lifecycle status (`running`, `awaiting_approval`, `paused`,
    /// `completed`, `failed`, `cancelled`, `halted`, `over_budget`).
    pub status: String,
    /// The tool awaiting a person's approval, if the run is paused.
    pub pending_tool: Option<String>,
    /// The arguments that tool was called with, verbatim.
    ///
    /// An approver has to see what they approve, and echo it back when
    /// deciding, so the decision cannot land on a call that changed
    /// meanwhile.
    pub pending_arguments: Option<String>,
    /// The step the held call was made at, echoed back with the decision.
    pub pending_at_step: Option<u32>,
    /// The most sensitive data class the run has read (`public`,
    /// `internal`, `confidential`, `restricted`). The run may call only
    /// tools cleared for it, and its answer may carry it.
    pub exposure: String,
    /// Who started the run.
    pub started_by: OwnerDto,
    /// The delegation the run acts under, or `null` for a run that calls no
    /// tool.
    pub delegation_id: Option<Uuid>,
    /// The most steps the run may take.
    pub max_steps: u32,
    /// The action classes the starter listed as needing approval;
    /// high-risk classes need it too, listed or not.
    pub approval_classes: Vec<String>,
    /// The tokens its model calls used so far.
    pub usage: RunUsageDto,
    /// What its model calls cost so far, in millionths of the tenant's
    /// billing currency. Calls to a provider with no price are not counted.
    pub spent_micros: u64,
    /// The most the run may spend, or `null` for no limit.
    pub spend_limit_micros: Option<u64>,
    /// Where the run waits for a person before spending more, or `null`
    /// when it never does.
    pub spend_check: Option<SpendCheckDto>,
    /// The final answer, once the run completed.
    pub answer: Option<String>,
    /// The recorded steps.
    pub steps: Vec<RunStepDto>,
    /// When the run started.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the run last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<AgentRun<ResolvedTenant>> for RunResponse {
    fn from(run: AgentRun<ResolvedTenant>) -> Self {
        let pending = run.pending();
        let usage = run.usage();
        Self {
            id: *run.id().as_uuid(),
            agent_id: *run.agent_id().as_uuid(),
            provider_id: *run.provider_id().as_uuid(),
            goal: run.goal().as_str().to_owned(),
            purpose: class_names(run.purpose().allowed()),
            status: run.status().as_str().to_owned(),
            pending_tool: pending.map(|p| p.tool().to_owned()),
            pending_arguments: pending.map(|p| p.arguments().to_owned()),
            pending_at_step: pending.map(PendingCall::at_step),
            exposure: run.exposure().as_str().to_owned(),
            started_by: OwnerDto::from_principal(&run.started_by().principal()),
            delegation_id: run.delegation_id().delegation().map(|id| *id.as_uuid()),
            max_steps: run.max_steps(),
            approval_classes: class_names(run.approval_classes()),
            usage: RunUsageDto {
                input_tokens: usage.input(),
                output_tokens: usage.output(),
            },
            spent_micros: run.spent().micros(),
            spend_limit_micros: micros_of(run.spend_limit()),
            spend_check: SpendCheckDto::of(run.spend_check()),
            answer: run.answer().map(str::to_owned),
            steps: run.steps().iter().map(RunStepDto::from).collect(),
            created_at: run.created_at(),
            updated_at: run.updated_at(),
        }
    }
}

/// Names the held call an approver decides on.
///
/// Echoed back from the run's pending call, so the decision cannot land on
/// a different action than the one looked at.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ApproveRunBody {
    /// The tool the run is paused on.
    pub tool: String,
    /// The arguments it was called with, verbatim.
    pub arguments: String,
    /// The step the call was made at (`pending_at_step`).
    pub at_step: u32,
    /// A fresh second-factor code, needed when the call is high-risk.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

impl ApproveRunBody {
    /// The approval of the call run `run_id` of `agent_id` holds.
    ///
    /// # Errors
    ///
    /// - A validation error when the tool or the arguments are not valid.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
        run_id: AgentRunId,
    ) -> Result<ApproveRequest, ApiError> {
        let call = ToolCall::new(&self.tool, &self.arguments).map_err(ApiError::validation)?;
        Ok(ApproveRequest {
            agent_id,
            run_id,
            approving: PendingCallRef::new(call, self.at_step),
            mfa_code: self.mfa_code,
        })
    }
}

/// Where a run stands once a person decided the call it held. Read the run
/// for its steps.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RunDecidedResponse {
    /// Identifies the task whose pending call received the decision.
    pub run_id: Uuid,
    /// Its lifecycle status now.
    pub status: String,
}

impl From<RunDecided> for RunDecidedResponse {
    fn from(decided: RunDecided) -> Self {
        Self {
            run_id: *decided.run_id.as_uuid(),
            status: decided.status.as_str().to_owned(),
        }
    }
}

/// Request body for changing the arguments of the call a run holds.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReviseRunCallBody {
    /// The arguments the held call is to be made with instead, as the tool
    /// takes them.
    pub arguments: String,
}

impl ReviseRunCallBody {
    /// The change to the call run `run_id` of `agent_id` holds.
    ///
    /// # Errors
    ///
    /// - A validation error when the arguments are not valid.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
        run_id: AgentRunId,
    ) -> Result<ReviseCallRequest, ApiError> {
        Ok(ReviseCallRequest {
            agent_id,
            run_id,
            arguments: ToolArguments::new(self.arguments).map_err(ApiError::validation)?,
        })
    }
}

/// The run whose held call changed, and the approval request it now waits
/// on.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RevisedRunCallResponse {
    /// Identifies the task waiting for approval of the revised call.
    pub run_id: Uuid,
    /// The approval request raised for the changed call.
    pub approval_id: Uuid,
}

impl From<RevisedRunCall> for RevisedRunCallResponse {
    fn from(revised: RevisedRunCall) -> Self {
        Self {
            run_id: *revised.run_id.as_uuid(),
            approval_id: *revised.approval_id.as_uuid(),
        }
    }
}

/// Request body for answering the call a run holds in words.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReplyToRunCallBody {
    /// What the model reads instead of the call's result, such as `use the
    /// staging ledger instead`.
    pub reply: String,
}

impl ReplyToRunCallBody {
    /// The reply to the call run `run_id` of `agent_id` holds.
    ///
    /// # Errors
    ///
    /// - A validation error when the reply is blank, too long or carries
    ///   control or invisible characters.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
        run_id: AgentRunId,
    ) -> Result<ReplyToCallRequest, ApiError> {
        Ok(ReplyToCallRequest {
            agent_id,
            run_id,
            reply: CallReply::new(self.reply).map_err(ApiError::validation)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// The run `body` starts, for a new agent.
    fn started(body: Value) -> Result<RunAgentRequest, ApiError> {
        let body: RunAgentBody = serde_json::from_value(body).unwrap();
        body.into_request(AgentId::new())
    }

    /// Ann's run names the classes that wait for her, and they are kept.
    #[test]
    fn a_run_naming_known_fields_keeps_its_approval_classes() {
        let Ok(request) = started(json!({
            "goal": "tidy the support queue",
            "provider_id": Uuid::now_v7(),
            "purpose": ["read", "write"],
            "approval_classes": ["write"]
        })) else {
            panic!("a body naming only known fields is read");
        };

        assert_eq!(request.approval_classes, vec![ActionClass::Write]);
    }

    /// A misspelled approval-class field makes the run request invalid.
    #[test]
    fn a_run_with_a_misspelt_field_is_refused() {
        let result = started(json!({
            "goal": "tidy the support queue",
            "provider_id": Uuid::now_v7(),
            "purpose": ["read", "write"],
            "aproval_classes": ["write"]
        }));

        assert!(result.is_err());
    }
}
