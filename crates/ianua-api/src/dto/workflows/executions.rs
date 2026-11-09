//! Workflow executions on the wire: where one stands, as the caller may
//! read it, and the bodies that start one and decide its approvals.

use ianua_app::listing::PageRequest;
use ianua_app::ports::workflows::RunKind;
use ianua_app::use_cases::workflows::executions::{
    ApproveStepRequest, ExecutionDecided, ListAllRequest, ListPassesRequest, ListRequest,
    StartByHandRequest, StartOnWebhookRequest, StartTestRequest, TriggeredStart,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::node::{Node, NodeKey, Port};
use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
use ianua_domain::domains::workflows::execution::step::{
    ItemsApproval, StepFailure, StepPhase, StepState, Underway,
};
use ianua_domain::domains::workflows::execution::{
    ExecutionStatus, ExecutionView, PassOf, StepView, WorkflowExecution,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{WorkflowExecutionId, WorkflowId, WorkflowTriggerId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::{data_class, flow_data, json_of, person_label};
use crate::error::ApiError;

/// One execution, with what the caller is not cleared for withheld.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ExecutionResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The workflow it runs.
    pub workflow_id: Uuid,
    /// The version it runs.
    pub version: u32,
    /// The person it acts for, as `<kind>:<uuid>`.
    pub acting_for: String,
    /// What started it: `manual`, `schedule`, `webhook`, `service` or
    /// `event`. A pass of a loop carries the cause of the run it belongs
    /// to.
    pub cause: String,
    /// `live` for a real run, or `test` for a test of a draft, whose steps
    /// that would reach out answer with a stand-in saying what they would
    /// have used.
    pub mode: &'static str,
    /// The loop it runs one pass of; left out for a run that is no pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<PassResponse>,
    /// `running`, or how it ended: `succeeded`, `failed`, `cancelled`,
    /// `timed_out`, or, for a pass whose loop failed or ended first,
    /// `loop_ended`.
    pub status: String,
    /// The most sensitive data it was started with.
    pub exposure: String,
    /// The data it was started with; `null` when it is above the caller's
    /// clearance.
    #[schema(value_type = Object)]
    pub input: Value,
    /// Whether `input` was withheld.
    pub input_withheld: bool,
    /// Each step and where it stands.
    pub steps: Vec<StepStateResponse>,
    /// When it is stopped if it has not ended.
    #[serde(with = "time::serde::rfc3339")]
    pub deadline: OffsetDateTime,
    /// When it started.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Where one step stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StepStateResponse {
    /// The step's key.
    pub key: String,
    /// The step's name.
    pub name: String,
    /// `waiting`, `ready`, `running`, `succeeded`, `failed`, `skipped`,
    /// `stopped` or `abandoned`.
    pub phase: String,
    /// Whether what the step holds is above the caller's clearance. Only
    /// `phase` and `exposure` are shown then.
    pub withheld: bool,
    /// How sensitive the data that reached it is; left out while nothing
    /// has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<String>,
    /// The input a ready step starts with.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub input: Option<Value>,
    /// What a finished step produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub output: Option<Value>,
    /// The way out a finished step left by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Why a failed step failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<StepFailureResponse>,
    /// How far a loop step's passes got, while it runs or when its run
    /// ended under it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passes: Option<LoopProgressResponse>,
}

/// The loop a pass belongs to.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PassResponse {
    /// The execution whose loop step started it.
    pub execution_id: Uuid,
    /// That loop step's key.
    pub step: String,
    /// The item it is the pass for, counted from zero.
    pub index: u32,
}

/// How far a loop step's passes got.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LoopProgressResponse {
    /// How many items the list held, one pass each.
    pub items: usize,
    /// How many passes ended and gave back what they made.
    pub done: usize,
    /// The execution of each pass started so far, in the order of the
    /// items. Each is read like any execution.
    pub executions: Vec<Uuid>,
    /// For a loop whose first step asks one approval for every item:
    /// `waiting` while no pass may start, `given` once people approved;
    /// left out for a loop that asks nobody about every item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<&'static str>,
}

/// Why a step failed.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StepFailureResponse {
    /// A stable name for the kind of failure.
    pub code: String,
    /// What else is known about it; empty when nothing is.
    pub detail: String,
}

impl From<&StepFailure> for StepFailureResponse {
    fn from(failure: &StepFailure) -> Self {
        Self {
            code: failure.code().to_owned(),
            detail: failure.detail(),
        }
    }
}

impl From<ExecutionView<ResolvedTenant>> for ExecutionResponse {
    fn from(view: ExecutionView<ResolvedTenant>) -> Self {
        Self {
            id: *view.id().as_uuid(),
            workflow_id: *view.workflow_id().as_uuid(),
            version: view.version(),
            acting_for: person_label(view.acting_for()),
            cause: view.cause().as_str().to_owned(),
            mode: view.mode().as_str(),
            pass: view.pass().map(PassResponse::from),
            status: status_name(view.status()),
            exposure: view.exposure().as_str().to_owned(),
            input: view.input().map_or(Value::Null, json_of),
            input_withheld: view.input().is_none(),
            steps: view
                .steps()
                .map(|(node, step)| StepStateResponse::of(node, step))
                .collect(),
            deadline: view.deadline(),
            created_at: view.created_at(),
            updated_at: view.updated_at(),
        }
    }
}

impl StepStateResponse {
    /// Where `node` stands, as `step` lets the caller read it.
    fn of(node: &Node, step: StepView<'_>) -> Self {
        let named = Self {
            key: node.key().as_str().to_owned(),
            name: node.name().as_str().to_owned(),
            phase: String::new(),
            withheld: false,
            exposure: None,
            input: None,
            output: None,
            port: None,
            failure: None,
            passes: None,
        };
        match step {
            StepView::Withheld { phase, exposure } => Self {
                phase: phase_name(phase).to_owned(),
                withheld: true,
                exposure: Some(exposure.as_str().to_owned()),
                ..named
            },
            StepView::Shown(state) => named.shown(state),
        }
    }

    /// This step, with what `state` holds.
    fn shown(mut self, state: &StepState) -> Self {
        self.phase = phase_name(state.phase()).to_owned();
        match state {
            StepState::Ready {
                input, exposure, ..
            } => {
                self.exposure = Some(exposure.as_str().to_owned());
                self.input = Some(json_of(input));
            }
            StepState::Running {
                exposure, underway, ..
            }
            | StepState::Abandoned {
                exposure, underway, ..
            } => {
                self.exposure = Some(exposure.as_str().to_owned());
                self.passes = LoopProgressResponse::of(underway);
            }
            StepState::Succeeded {
                output,
                exposure,
                port,
                ..
            } => return self.with_output(output, port, *exposure),
            StepState::Failed(failure) => {
                self.failure = Some(StepFailureResponse::from(failure));
            }
            StepState::Waiting | StepState::Skipped | StepState::Stopped => {}
        }
        self
    }

    /// Adds a successful step's output and exit without changing its already selected phase.
    fn with_output(mut self, output: &FlowData, port: &Port, exposure: DataClassLevel) -> Self {
        self.exposure = Some(exposure.as_str().to_owned());
        self.output = Some(json_of(output));
        self.port = Some(port.as_str().to_owned());
        self
    }
}

impl From<&PassOf> for PassResponse {
    fn from(of: &PassOf) -> Self {
        Self {
            execution_id: *of.execution.as_uuid(),
            step: of.step.as_str().to_owned(),
            index: of.index,
        }
    }
}

impl LoopProgressResponse {
    /// How far the passes of a loop step waiting on `underway` got; `None`
    /// for a step that is no loop.
    fn of(underway: &Underway) -> Option<Self> {
        let Underway::Loop(progress) = underway else {
            return None;
        };
        Some(Self {
            items: progress.items().len(),
            done: progress.done(),
            executions: progress.executions().map(|id| *id.as_uuid()).collect(),
            approval: items_approval_name(progress.approval()),
        })
    }
}

/// How a loop's approval of every item stands on the wire; `None` when it
/// asks nobody.
fn items_approval_name(approval: &ItemsApproval) -> Option<&'static str> {
    match approval {
        ItemsApproval::NotAsked => None,
        ItemsApproval::Waiting(_) => Some("waiting"),
        ItemsApproval::Given(_) => Some("given"),
    }
}

/// The step phase's name on the wire, such as `running`.
fn phase_name(phase: StepPhase) -> &'static str {
    match phase {
        StepPhase::Waiting => "waiting",
        StepPhase::Ready => "ready",
        StepPhase::Running => "running",
        StepPhase::Succeeded => "succeeded",
        StepPhase::Failed => "failed",
        StepPhase::Skipped => "skipped",
        StepPhase::Stopped => "stopped",
        StepPhase::Abandoned => "abandoned",
    }
}

/// The execution's status on the wire: `running`, or how it ended.
fn status_name(status: ExecutionStatus) -> String {
    match status {
        ExecutionStatus::Running => "running",
        ExecutionStatus::Ended(end) => ExecutionEnd::as_str(end),
    }
    .to_owned()
}

/// Where an execution stands after a decision on it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ExecutionDecidedResponse {
    /// The run whose approval was decided or whose start just completed.
    pub execution_id: Uuid,
    /// `running`, or how it ended.
    pub status: String,
}

impl From<ExecutionDecided> for ExecutionDecidedResponse {
    fn from(decided: ExecutionDecided) -> Self {
        Self {
            execution_id: *decided.execution_id.as_uuid(),
            status: status_name(decided.status),
        }
    }
}

impl ExecutionDecidedResponse {
    /// Where `execution` stands once started. Its data is read through
    /// the execution endpoint, which withholds what the reader is not
    /// cleared for.
    #[must_use]
    pub(crate) fn started(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
        Self {
            execution_id: *execution.id().as_uuid(),
            status: status_name(execution.status()),
        }
    }
}

impl From<FlowData> for ApprovalDataResponse {
    fn from(shown: FlowData) -> Self {
        Self {
            shown: json_of(&shown),
        }
    }
}

/// Request body for starting a workflow by hand.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct StartExecutionBody {
    /// The data it starts with: any JSON value, usually an object.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub input: Value,
    /// The most sensitive data in it, such as `internal`.
    pub exposure: String,
}

impl StartExecutionBody {
    /// Starting `workflow_id`'s version in service with this data.
    ///
    /// # Errors
    ///
    /// - `422` when the data or the class is not valid.
    pub(crate) fn request(&self, workflow_id: WorkflowId) -> Result<StartByHandRequest, ApiError> {
        Ok(StartByHandRequest {
            workflow_id,
            input: flow_data(&self.input)?,
            exposure: data_class(&self.exposure)?,
        })
    }
}

/// The data an approval step lets through, to decide on.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalDataResponse {
    /// The data. An approval is for exactly this, so it is sent back as
    /// `shown` to approve.
    #[schema(value_type = Object)]
    pub shown: Value,
}

/// Request body for approving a step.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ApproveStepBody {
    /// The data the approver was shown, as it came.
    #[schema(value_type = Object)]
    pub shown: Value,
    /// A fresh second-factor code, needed for a high-risk step.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

impl ApproveStepBody {
    /// Approving `step` of `execution_id` for this data.
    ///
    /// # Errors
    ///
    /// - `422` when the data is not valid.
    pub(crate) fn request(
        self,
        execution_id: WorkflowExecutionId,
        step: NodeKey,
    ) -> Result<ApproveStepRequest, ApiError> {
        Ok(ApproveStepRequest {
            execution_id,
            step,
            shown: flow_data(&self.shown)?,
            mfa_code: self.mfa_code,
        })
    }
}

/// The listing asked for: `workflow_id`'s executions, the page
/// `pagination` names.
#[must_use]
pub(crate) fn execution_listing(
    workflow_id: WorkflowId,
    kind: RunKind,
    pagination: PageRequest,
) -> ListRequest {
    ListRequest {
        workflow_id,
        kind,
        page: pagination,
    }
}

/// The listing asked for: the tenant's runs of `kind` across workflows,
/// the page `pagination` names.
#[must_use]
pub(crate) fn all_execution_listing(kind: RunKind, pagination: PageRequest) -> ListAllRequest {
    ListAllRequest {
        kind,
        page: pagination,
    }
}

/// Query parameters choosing real runs or tests.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RunKindParams {
    /// `runs`, the default, for real runs, or `tests` for tests of drafts.
    #[serde(default)]
    pub kind: Option<String>,
}

impl RunKindParams {
    /// The kind of run asked for.
    ///
    /// # Errors
    ///
    /// - `422` when `kind` is neither `runs` nor `tests`.
    pub(crate) fn kind(&self) -> Result<RunKind, ApiError> {
        match self.kind.as_deref() {
            None | Some("runs") => Ok(RunKind::Real),
            Some("tests") => Ok(RunKind::Tests),
            Some(_) => Err(ApiError::validation(message!(
                "api-a-run-kind-is-runs-or-tests",
                "a run kind is runs or tests"
            ))),
        }
    }
}

/// Request body for testing a workflow's latest version.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct StartTestBody {
    /// The example data it starts with: any JSON value, usually an object.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub input: Value,
    /// The most sensitive data in it, such as `internal`.
    pub exposure: String,
}

impl StartTestBody {
    /// Testing `workflow_id`'s latest version with this data.
    ///
    /// # Errors
    ///
    /// - `422` when the data or the class is not valid.
    pub(crate) fn request(&self, workflow_id: WorkflowId) -> Result<StartTestRequest, ApiError> {
        Ok(StartTestRequest {
            workflow_id,
            input: flow_data(&self.input)?,
            exposure: data_class(&self.exposure)?,
        })
    }
}

/// The listing asked for: the passes `execution_id`'s loops started, the
/// page `pagination` names.
#[must_use]
pub(crate) fn pass_listing(
    execution_id: WorkflowExecutionId,
    pagination: PageRequest,
) -> ListPassesRequest {
    ListPassesRequest {
        execution_id,
        page: pagination,
    }
}

/// Query parameters of a webhook call.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct WebhookCallParams {
    /// The most sensitive data the call carries, such as `confidential`;
    /// `internal` when left out.
    pub exposure: Option<String>,
}

impl WebhookCallParams {
    /// The start a call of trigger `trigger_id` with `presented` and the
    /// JSON `input` asks for.
    ///
    /// # Errors
    ///
    /// - `422` when the data or the class is not valid.
    pub(crate) fn start(
        self,
        trigger_id: WorkflowTriggerId,
        presented: Secret,
        input: &Value,
    ) -> Result<StartOnWebhookRequest, ApiError> {
        Ok(StartOnWebhookRequest {
            trigger_id,
            presented,
            input: flow_data(input)?,
            exposure: self
                .exposure
                .as_deref()
                .map_or(Ok(DataClassLevel::Internal), data_class)?,
        })
    }
}

/// What a webhook call did.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct WebhookStartResponse {
    /// `started`; `refused` when the workflow may not start for its
    /// publisher now; or `chain_too_long` when workflows set each other off
    /// too many times over.
    pub status: &'static str,
    /// The execution started, when one was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<Uuid>,
    /// Why it was refused, such as `person_may_not_run`, when it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl From<TriggeredStart> for WebhookStartResponse {
    fn from(start: TriggeredStart) -> Self {
        let answer = Self {
            status: "started",
            execution_id: None,
            reason: None,
        };
        match start {
            TriggeredStart::Started(id) => Self {
                execution_id: Some(*id.as_uuid()),
                ..answer
            },
            TriggeredStart::Refused(why) => Self {
                status: "refused",
                reason: Some(why.as_str()),
                ..answer
            },
            TriggeredStart::ChainTooLong => Self {
                status: "chain_too_long",
                ..answer
            },
        }
    }
}
