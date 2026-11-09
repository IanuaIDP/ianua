//! What the workflow builder reads and asks on the wire: the data each step
//! may read, and steps a model proposes from a person's words.

use ianua_app::use_cases::workflows::definitions::{
    DataSource, DraftPlace, DraftRequest, EarlierData, Proposal, ProposedEdge, ProposedKind,
    ProposedStep, ProposedTrigger, ProposedValue, ReadableValue, StepData, ValueShape,
};
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::types::{ModelProviderId, Text, WorkflowId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// What one step may read.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StepDataResponse {
    /// The step's key.
    pub key: String,
    /// The trigger first, then each step that can come before it.
    pub earlier: Vec<EarlierDataResponse>,
}

impl From<StepData> for StepDataResponse {
    fn from(data: StepData) -> Self {
        Self {
            key: data.key.as_str().to_owned(),
            earlier: data
                .earlier
                .into_iter()
                .map(EarlierDataResponse::from)
                .collect(),
        }
    }
}

/// The values one source hands on.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EarlierDataResponse {
    /// `trigger`, or the key of the step before.
    pub source: String,
    /// Each value.
    pub values: Vec<ReadableValueResponse>,
}

impl From<EarlierData> for EarlierDataResponse {
    fn from(data: EarlierData) -> Self {
        Self {
            source: match data.source {
                DataSource::Trigger => "trigger".to_owned(),
                DataSource::Step(key) => key.as_str().to_owned(),
            },
            values: data
                .values
                .into_iter()
                .map(ReadableValueResponse::from)
                .collect(),
        }
    }
}

/// One value a step may read.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReadableValueResponse {
    /// Its full path, as a step's input names it, such as
    /// `trigger.issue.title`.
    pub path: String,
    /// What it is, when its integration describes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether it is everything at the path, whose shape only a run shows.
    pub whole: bool,
}

impl From<ReadableValue> for ReadableValueResponse {
    fn from(value: ReadableValue) -> Self {
        Self {
            path: value.path.to_string(),
            description: value.description.map(|text| text.as_str().to_owned()),
            whole: value.shape == ValueShape::Whole,
        }
    }
}

/// Request body for asking the tenant's model to draft steps.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DraftBody {
    /// The tenant's model provider the words are given to.
    pub provider_id: Uuid,
    /// What the person wants, in up to 500 characters.
    pub words: String,
    /// The step of a draft the steps come after; left out for a whole new
    /// workflow.
    #[serde(default)]
    pub after: Option<DraftAfterBody>,
}

/// The step of a draft proposed steps come after.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DraftAfterBody {
    /// Draft whose graph supplies the insertion point for proposed steps.
    pub workflow_id: Uuid,
    /// The step's key.
    pub step: String,
}

impl TryFrom<DraftBody> for DraftRequest {
    type Error = ApiError;

    fn try_from(body: DraftBody) -> Result<Self, ApiError> {
        let place = match body.after {
            None => DraftPlace::NewWorkflow,
            Some(after) => DraftPlace::After {
                workflow_id: WorkflowId::from_uuid(after.workflow_id),
                step: NodeKey::new(&after.step).map_err(ApiError::validation)?,
            },
        };
        Ok(Self {
            provider_id: ModelProviderId::from_uuid(body.provider_id),
            words: Text::new("words", body.words).map_err(ApiError::validation)?,
            place,
        })
    }
}

/// Steps a model proposed. Nothing is saved: the builder places them and
/// saves what it keeps as a draft.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ProposalResponse {
    /// What starts a new workflow; left out for steps after a step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<ProposedTriggerResponse>,
    /// Suggested nodes the person can accept into their draft.
    pub steps: Vec<ProposedStepResponse>,
    /// The arrows between them; `from` is left out for the step the
    /// proposal goes after.
    pub edges: Vec<ProposedEdgeResponse>,
    /// What the person should know, such as a step no operation fits.
    pub notes: Vec<String>,
}

impl From<Proposal> for ProposalResponse {
    fn from(proposal: Proposal) -> Self {
        Self {
            trigger: proposal.trigger.map(ProposedTriggerResponse::from),
            steps: proposal
                .steps
                .into_iter()
                .map(ProposedStepResponse::from)
                .collect(),
            edges: proposal
                .edges
                .into_iter()
                .map(ProposedEdgeResponse::from)
                .collect(),
            notes: proposal.notes,
        }
    }
}

/// A proposed trigger, named by `kind`.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProposedTriggerResponse {
    /// A person starts it.
    Manual,
    /// A call to its webhook.
    Webhook,
    /// Starts runs at the times described by a cron expression.
    Schedule {
        /// The cron expression, as proposed.
        cron: String,
    },
    /// An event a service sends.
    ServiceEvent {
        /// Installed provider whose event would start the workflow.
        integration: String,
        /// The event, as proposed.
        event: String,
    },
}

impl From<ProposedTrigger> for ProposedTriggerResponse {
    fn from(trigger: ProposedTrigger) -> Self {
        match trigger {
            ProposedTrigger::Manual => Self::Manual,
            ProposedTrigger::Webhook => Self::Webhook,
            ProposedTrigger::Schedule(cron) => Self::Schedule { cron },
            ProposedTrigger::ServiceEvent { integration, event } => Self::ServiceEvent {
                integration: integration.as_str().to_owned(),
                event,
            },
        }
    }
}

/// Unsaved node returned by the model for the builder to review.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ProposedStepResponse {
    /// Identifier used by the proposal's edges to connect this node.
    pub key: String,
    /// Its name for people.
    pub title: String,
    /// What it does.
    #[serde(flatten)]
    pub kind: ProposedKindResponse,
}

impl From<ProposedStep> for ProposedStepResponse {
    fn from(step: ProposedStep) -> Self {
        Self {
            key: step.key.as_str().to_owned(),
            title: step.title.as_str().to_owned(),
            kind: ProposedKindResponse::from(step.kind),
        }
    }
}

/// What a proposed step does, named by `kind`.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProposedKindResponse {
    /// Calls an operation.
    Action {
        /// Installed provider offering the proposed action.
        integration: String,
        /// Callable action key within the selected provider.
        operation: String,
        /// Its inputs, by name.
        inputs: Vec<ProposedInputResponse>,
    },
    /// Gives an agent a goal; the builder picks the agent.
    AgentRun {
        /// Task instructions proposed for the agent the builder selects.
        goal: String,
    },
    /// Checks one value.
    Condition {
        /// The value checked.
        path: String,
        /// What it should equal; left out to check it is there.
        #[serde(skip_serializing_if = "Option::is_none")]
        equals: Option<String>,
    },
    /// Waits for a person to approve.
    Approval {
        /// What they are asked.
        summary: String,
        /// The kind of action that follows, such as `delete`.
        class: &'static str,
    },
    /// Waits a while.
    Wait {
        /// How long, in seconds.
        seconds: u32,
    },
}

impl From<ProposedKind> for ProposedKindResponse {
    fn from(kind: ProposedKind) -> Self {
        match kind {
            ProposedKind::Action {
                integration,
                operation,
                inputs,
            } => Self::Action {
                integration: integration.as_str().to_owned(),
                operation: operation.as_str().to_owned(),
                inputs: inputs
                    .into_iter()
                    .map(|(name, value)| ProposedInputResponse::of(name.as_str(), value))
                    .collect(),
            },
            ProposedKind::AgentRun { goal } => Self::AgentRun {
                goal: goal.as_str().to_owned(),
            },
            ProposedKind::Condition { path, equals } => Self::Condition {
                path: path.to_string(),
                equals,
            },
            ProposedKind::Approval { summary, class } => Self::Approval {
                summary: summary.as_str().to_owned(),
                class: class.as_str(),
            },
            ProposedKind::Wait { seconds } => Self::Wait { seconds },
        }
    }
}

/// One proposed input: a value written out, or a path to earlier data.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ProposedInputResponse {
    /// The input.
    pub name: String,
    /// The value written out, when it is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The path read, when it reads earlier data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl ProposedInputResponse {
    /// The input `name`, set to `value`.
    fn of(name: &str, value: ProposedValue) -> Self {
        let (text, path) = match value {
            ProposedValue::Text(text) => (Some(text), None),
            ProposedValue::Path(path) => (None, Some(path.to_string())),
        };
        Self {
            name: name.to_owned(),
            text,
            path,
        }
    }
}

/// One proposed arrow.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ProposedEdgeResponse {
    /// The step it leaves; left out for the step the proposal goes after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// `next`, `when_true` or `when_false`.
    pub port: &'static str,
    /// The step it leads to.
    pub to: String,
}

impl From<ProposedEdge> for ProposedEdgeResponse {
    fn from(edge: ProposedEdge) -> Self {
        Self {
            from: edge.from.map(|key| key.as_str().to_owned()),
            port: edge.port.as_str(),
            to: edge.to.as_str().to_owned(),
        }
    }
}
