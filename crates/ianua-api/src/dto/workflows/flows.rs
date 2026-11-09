//! Agent flows on the wire, in the shape the dashboard's flow pages read:
//! stages of agent runs, each run with where it stands.
//!
//! A flow is a workflow whose graph its stages were laid out as; its one
//! execution is its progress. The stages are read back from the run steps
//! of that graph, and each step's state says how far its run got.

use ianua_app::use_cases::workflows::flows::{
    CreateRequest, FlowProgress, FlowStanding, FlowStarted, RunShown,
};
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::GoalTemplate;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Checks, Mapping, NodeKind,
};
use ianua_domain::domains::workflows::design::stages::stage_of;
use ianua_domain::domains::workflows::design::workflow::{
    FlowDescription, Workflow, WorkflowOrigin,
};
use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
use ianua_domain::domains::workflows::execution::step::{
    StepFailure, StepPhase, StepState, Underway,
};
use ianua_domain::domains::workflows::execution::{
    ANSWER_FIELD, ExecutionStatus, ExecutionView, StepView,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, Label, ModelProviderId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::runs::{amount, micros_of};
use crate::dto::workflows::data::{data_class, flow_data, json_of};
use crate::dto::workflows::graph::{class_names, classes, tool_names};
use crate::error::ApiError;

/// The most steps a flow's run takes when its maker names none.
const DEFAULT_MAX_STEPS: u32 = 10;

/// Request body for making and starting an agent flow.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateFlowBody {
    /// Label people will use to find the staged automation.
    pub name: String,
    /// What its maker writes about it, or `null`.
    pub description: Option<String>,
    /// Its stages, in order: the runs of each start together, once every
    /// run of the stage before has answered.
    pub stages: Vec<Vec<FlowNodeBody>>,
    /// The data its run starts with: any JSON value; an empty object when
    /// left out.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub input: Option<Value>,
    /// The most sensitive data in that input, such as `internal`, which it
    /// is when left out.
    pub exposure: Option<String>,
}

/// One agent run of a flow, as its maker lays it out.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct FlowNodeBody {
    /// The acting agent.
    pub agent_id: Uuid,
    /// The model provider it reasons with.
    pub provider_id: Uuid,
    /// The instruction.
    pub goal: String,
    /// The action classes its tool calls may take, such as `read`.
    #[serde(default)]
    pub purpose: Vec<String>,
    /// The tools it may call. None when empty.
    #[serde(default)]
    pub tool_names: Vec<String>,
    /// Action classes whose tool calls wait for a person's approval.
    #[serde(default)]
    pub approval_classes: Vec<String>,
    /// The most steps the run may take; 10 when left out.
    pub max_steps: Option<u32>,
    /// The most the run may spend on its model, in millionths of the
    /// tenant's billing currency. Once spent, the run stops as over
    /// budget. Left out for no limit.
    pub spend_cap_micros: Option<u64>,
    /// What the run may spend before it pauses for a person to let it go
    /// on, in the same millionths; below the cap when both are set. Left
    /// out for no pause.
    pub ask_past_micros: Option<u64>,
}

impl FlowNodeBody {
    /// The run this body lays out.
    fn params(self) -> Result<AgentRunParams, ApiError> {
        Ok(AgentRunParams {
            agent_id: AgentId::from_uuid(self.agent_id),
            provider_id: ModelProviderId::from_uuid(self.provider_id),
            goal: GoalTemplate::new(self.goal).map_err(ApiError::validation)?,
            inputs: Mapping::new(Vec::new()).map_err(ApiError::validation)?,
            purpose: IntentEnvelope::new(classes(&self.purpose)?),
            tools: tool_names(self.tool_names)?,
            approval_classes: classes(&self.approval_classes)?,
            max_steps: self.max_steps.unwrap_or(DEFAULT_MAX_STEPS),
            spend_cap: amount(self.spend_cap_micros),
            ask_past: amount(self.ask_past_micros),
            checks: Checks::Nothing,
        })
    }
}

impl TryFrom<CreateFlowBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateFlowBody) -> Result<Self, Self::Error> {
        let input = body
            .input
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            description: description(body.description)?,
            stages: body
                .stages
                .into_iter()
                .map(|stage| {
                    stage
                        .into_iter()
                        .map(FlowNodeBody::params)
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<_, _>>()?,
            input: flow_data(&input)?,
            exposure: body
                .exposure
                .as_deref()
                .map_or(Ok(DataClassLevel::Internal), data_class)?,
        })
    }
}

/// What a maker wrote about a flow: `text`, or nothing.
fn description(text: Option<String>) -> Result<FlowDescription, ApiError> {
    let Some(text) = text.filter(|text| !text.is_empty()) else {
        return Ok(FlowDescription::Blank);
    };
    Label::new("description", text)
        .map(FlowDescription::Written)
        .map_err(ApiError::validation)
}

/// An agent flow and where it stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FlowResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Label shown beside the flow's progress in the dashboard.
    pub name: String,
    /// What its maker wrote about it.
    pub description: Option<String>,
    /// `Running`, `Completed`, `Failed` or `Canceled`. Left out only for a
    /// flow with no run kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    /// The first stage, counting from 0, with a run that has not finished.
    /// Left out when the reader is shown no run's steps: a flow with no run
    /// kept, or one stopped by a maker who may not view workflows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_stage: Option<usize>,
    /// Its stages, in order, each with its runs.
    pub stages: Vec<Vec<FlowNodeResponse>>,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// One agent run of a flow.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FlowNodeResponse {
    /// The acting agent.
    pub agent_id: Uuid,
    /// The model provider it reasons with.
    pub provider_id: Uuid,
    /// The instruction.
    pub goal: String,
    /// The action classes its tool calls may take.
    pub purpose: Vec<String>,
    /// The tools it may call.
    pub tool_names: Vec<String>,
    /// Action classes whose tool calls wait for a person's approval.
    pub approval_classes: Vec<String>,
    /// The most steps the run may take.
    pub max_steps: u32,
    /// The most the run may spend on its model, in millionths. Left out
    /// when it has no cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_cap_micros: Option<u64>,
    /// What the run may spend before it pauses for a person, in
    /// millionths. Left out when it never pauses over spend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_past_micros: Option<u64>,
    /// `Pending`, `Dispatched`, `Completed` or `Failed`. Left out when the
    /// reader is shown no run's steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    /// The agent run, once it was dispatched.
    pub run_id: Option<Uuid>,
    /// What the run answered, once it completed and the reader is cleared
    /// for it.
    pub output: Option<String>,
    /// How sensitive the data that reached the run is, once any has.
    pub output_exposure: Option<&'static str>,
    /// Why it failed, when it did.
    pub error_message: Option<String>,
}

impl FlowNodeResponse {
    /// The run `step` lays out, before anything of it is known.
    fn laid_out(step: &AgentRunStep) -> Self {
        Self {
            agent_id: *step.agent_id().as_uuid(),
            provider_id: *step.provider_id().as_uuid(),
            goal: step.goal().as_str().to_owned(),
            purpose: class_names(step.purpose().allowed()),
            tool_names: step
                .tools()
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
            approval_classes: class_names(step.approval_classes()),
            max_steps: step.max_steps(),
            spend_cap_micros: micros_of(step.spend_cap()),
            ask_past_micros: micros_of(step.ask_past()),
            status: None,
            run_id: None,
            output: None,
            output_exposure: None,
            error_message: None,
        }
    }

    /// The run `step` lays out, where `view` shows it stands.
    fn of(step: &AgentRunStep, view: StepView<'_>) -> Self {
        let laid_out = Self::laid_out(step);
        match view {
            StepView::Withheld { phase, exposure } => Self {
                status: Some(phase_status(phase)),
                output_exposure: Some(exposure.as_str()),
                ..laid_out
            },
            StepView::Shown(state) => laid_out.shown(state),
        }
    }

    /// This run, with what `state` holds.
    fn shown(mut self, state: &StepState) -> Self {
        self.status = Some(phase_status(state.phase()));
        match state {
            StepState::Ready { exposure, .. } => {
                self.output_exposure = Some(exposure.as_str());
            }
            StepState::Running {
                exposure, underway, ..
            }
            | StepState::Abandoned {
                exposure, underway, ..
            } => {
                self.run_id = run_of(underway);
                self.output_exposure = Some(exposure.as_str());
            }
            StepState::Succeeded {
                output, exposure, ..
            } => {
                self.output = answer_of(output);
                self.output_exposure = Some(exposure.as_str());
            }
            StepState::Failed(failure) => {
                self.error_message = Some(failure_message(failure));
            }
            StepState::Waiting | StepState::Skipped | StepState::Stopped => {}
        }
        self
    }
}

/// Why a run failed: what is known of it, or the kind of failure when
/// nothing more is.
fn failure_message(failure: &StepFailure) -> String {
    let detail = failure.detail();
    if detail.is_empty() {
        return failure.code().to_owned();
    }
    detail
}

/// The agent run `underway` names, when it is one.
fn run_of(underway: &Underway) -> Option<Uuid> {
    match underway {
        Underway::AgentRun(id) => Some(*id.as_uuid()),
        _ => None,
    }
}

/// What a run answered, as text: the answer itself when it is text, or
/// written out as JSON.
fn answer_of(output: &FlowData) -> Option<String> {
    let field = FieldName::new(ANSWER_FIELD).ok()?;
    let answer = json_of(output.field(&field)?);
    match answer {
        Value::String(text) => Some(text),
        other => Some(other.to_string()),
    }
}

/// A run step's phase, in the dashboard's words.
fn phase_status(phase: StepPhase) -> &'static str {
    match phase {
        StepPhase::Waiting | StepPhase::Ready | StepPhase::Skipped => "Pending",
        StepPhase::Running => "Dispatched",
        StepPhase::Succeeded => "Completed",
        StepPhase::Failed | StepPhase::Stopped | StepPhase::Abandoned => "Failed",
    }
}

/// A flow's status, from its run's: a run that ran out of time failed.
fn flow_status(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Running => "Running",
        ExecutionStatus::Ended(ExecutionEnd::Succeeded) => "Completed",
        ExecutionStatus::Ended(
            ExecutionEnd::Failed | ExecutionEnd::TimedOut | ExecutionEnd::LoopEnded,
        ) => "Failed",
        ExecutionStatus::Ended(ExecutionEnd::Cancelled(_)) => "Canceled",
    }
}

/// What the maker of `flow` wrote about it.
fn description_of(flow: &Workflow<ResolvedTenant>) -> Option<String> {
    match flow.origin() {
        WorkflowOrigin::Flow(FlowDescription::Written(text)) => Some(text.as_str().to_owned()),
        WorkflowOrigin::Flow(FlowDescription::Blank) | WorkflowOrigin::Designed => None,
    }
}

/// Puts `node` into stage `stage`, counting from one, of `stages`.
fn place(stages: &mut Vec<Vec<FlowNodeResponse>>, stage: usize, node: FlowNodeResponse) {
    if stages.len() < stage {
        stages.resize_with(stage, Vec::new);
    }
    if let Some(runs) = stage.checked_sub(1).and_then(|index| stages.get_mut(index)) {
        runs.push(node);
    }
}

/// The stages of `graph`, each run as laid out.
fn laid_out_stages(graph: &WorkflowGraph) -> Vec<Vec<FlowNodeResponse>> {
    let mut stages = Vec::new();
    for node in graph.nodes() {
        let (Some(stage), NodeKind::AgentRun(step)) = (stage_of(node.key()), node.kind()) else {
            continue;
        };
        place(&mut stages, stage, FlowNodeResponse::laid_out(step));
    }
    stages
}

/// The stages of `run`, each run where it stands.
fn running_stages(run: &ExecutionView<ResolvedTenant>) -> Vec<Vec<FlowNodeResponse>> {
    let mut stages = Vec::new();
    for (node, view) in run.steps() {
        let (Some(stage), NodeKind::AgentRun(step)) = (stage_of(node.key()), node.kind()) else {
            continue;
        };
        place(&mut stages, stage, FlowNodeResponse::of(step, view));
    }
    stages
}

/// The first stage, counting from 0, with a run that has not finished; the
/// last when every run has.
fn current_stage(stages: &[Vec<FlowNodeResponse>]) -> usize {
    stages
        .iter()
        .position(|runs| {
            runs.iter()
                .any(|run| matches!(run.status, Some("Pending" | "Dispatched")))
        })
        .unwrap_or_else(|| stages.len().saturating_sub(1))
}

impl From<FlowProgress> for FlowResponse {
    fn from(progress: FlowProgress) -> Self {
        let FlowProgress { flow, run } = progress;
        let stages = running_stages(&run);
        Self {
            id: *flow.id().as_uuid(),
            name: flow.name().as_str().to_owned(),
            description: description_of(&flow),
            status: Some(flow_status(run.status())),
            current_stage: Some(current_stage(&stages)),
            stages,
            created_at: flow.created_at(),
        }
    }
}

impl From<FlowStanding> for FlowResponse {
    fn from(standing: FlowStanding) -> Self {
        let FlowStanding { flow, run } = standing;
        match run {
            RunShown::Viewed(run) => Self::from(FlowProgress { flow, run: *run }),
            RunShown::StatusOnly(status) => Self {
                status: Some(flow_status(status)),
                ..laid_out_flow(&flow)
            },
            RunShown::Missing => laid_out_flow(&flow),
        }
    }
}

/// `flow` as laid out, with nothing of its run.
fn laid_out_flow(flow: &Workflow<ResolvedTenant>) -> FlowResponse {
    FlowResponse {
        id: *flow.id().as_uuid(),
        name: flow.name().as_str().to_owned(),
        description: description_of(flow),
        status: None,
        current_stage: None,
        stages: laid_out_stages(flow.graph()),
        created_at: flow.created_at(),
    }
}

/// A flow just made, and its run just started: every run still pending.
#[must_use]
pub(crate) fn started_flow(started: &FlowStarted) -> FlowResponse {
    let FlowStarted { flow, run } = started;
    let stages = laid_out_stages(flow.graph());
    FlowResponse {
        id: *flow.id().as_uuid(),
        name: flow.name().as_str().to_owned(),
        description: description_of(flow),
        status: Some(flow_status(run.status())),
        current_stage: Some(0),
        stages: stages
            .into_iter()
            .map(|runs| {
                runs.into_iter()
                    .map(|run| FlowNodeResponse {
                        status: Some("Pending"),
                        ..run
                    })
                    .collect()
            })
            .collect(),
        created_at: flow.created_at(),
    }
}
