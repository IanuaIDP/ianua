//! Workflow definitions on the wire: a version, and the bodies that create,
//! edit and publish one.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::workflows::WorkflowSortField;
use ianua_app::use_cases::workflows::definitions::{
    CreateWorkflowRequest, DraftEdit, EditDraftRequest, ListWorkflowsRequest,
    PublishWorkflowRequest,
};
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::design::workflow::{
    CanvasLayout, FailureAlert, Hold, MissingAccount, Publication, Revision, RunLimit,
    StepPosition, Workflow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{Label, Lifetime, Text, WorkflowId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::person_label;
use crate::dto::workflows::graph::{GraphBody, TriggerBody};
use crate::error::ApiError;

/// One version of a workflow.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct WorkflowResponse {
    /// The workflow, the same for every version of it.
    pub id: Uuid,
    /// This version's number, counting from 1.
    pub version: u32,
    /// Label shown when people select or inspect this workflow version.
    pub name: String,
    /// What it does, as its authors describe it; left out when nobody did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `draft`, `published` or `archived`.
    pub status: String,
    /// What starts it.
    pub trigger: TriggerBody,
    /// How long one execution may run, in seconds.
    pub run_limit_seconds: i64,
    /// Who is told when one of its runs fails: `administrators`, or
    /// `also_authors`.
    pub failure_alert: &'static str,
    /// Its steps and edges.
    pub graph: GraphBody,
    /// Where its steps sit on the builder's canvas. A step it leaves out is
    /// placed wherever the builder chooses.
    pub layout: Vec<StepPositionBody>,
    /// When it last changed. A publisher hands it back to say what they
    /// reviewed.
    #[serde(with = "time::serde::rfc3339")]
    pub revision: OffsetDateTime,
    /// Who drafted this version, as `<kind>:<uuid>`.
    pub created_by: String,
    /// Who changed it last, as `<kind>:<uuid>`.
    pub edited_by: String,
    /// Who published it, as `<kind>:<uuid>`; left out while it never was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_by: Option<String>,
    /// The account this version in service needs, when it is held because
    /// an account it acts through can no longer be used for its publisher:
    /// nothing starts it until a next version is published. Left out while
    /// nothing holds it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_account: Option<NeedsAccountResponse>,
    /// When this version was drafted.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When this version last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The account a held version needs.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct NeedsAccountResponse {
    /// The account it can no longer use.
    pub account_id: Uuid,
    /// Where it uses it: `trigger`, or the key of the step.
    pub at: String,
    /// Why: `gone`, `disabled`, `owner_cannot_lend`, `not_lent` or
    /// `not_for_this_use`.
    pub reason: &'static str,
}

impl From<&MissingAccount> for NeedsAccountResponse {
    fn from(missing: &MissingAccount) -> Self {
        Self {
            account_id: *missing.account.as_uuid(),
            at: missing.at.as_str().to_owned(),
            reason: missing.why.as_str(),
        }
    }
}

impl From<Workflow<ResolvedTenant>> for WorkflowResponse {
    fn from(workflow: Workflow<ResolvedTenant>) -> Self {
        Self {
            id: *workflow.id().as_uuid(),
            version: workflow.version(),
            name: workflow.name().as_str().to_owned(),
            description: workflow.description().map(|text| text.as_str().to_owned()),
            status: workflow.status().as_str().to_owned(),
            trigger: TriggerBody::from(workflow.trigger()),
            run_limit_seconds: workflow.run_limit().lifetime().whole_seconds(),
            failure_alert: workflow.failure_alert().as_str(),
            graph: GraphBody::from(workflow.graph()),
            layout: workflow
                .layout()
                .iter()
                .map(StepPositionBody::from)
                .collect(),
            revision: workflow.revision().changed_at(),
            created_by: person_label(workflow.created_by()),
            edited_by: person_label(workflow.edited_by()),
            published_by: match workflow.publication() {
                Publication::Unpublished => None,
                Publication::PublishedBy(by) => Some(person_label(by)),
            },
            needs_account: match workflow.hold() {
                Hold::Clear => None,
                Hold::NeedsAccount(missing) => Some(NeedsAccountResponse::from(missing)),
            },
            created_at: Aggregate::created_at(&workflow),
            updated_at: Aggregate::updated_at(&workflow),
        }
    }
}

/// Where one step sits on the canvas.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct StepPositionBody {
    /// The step's key.
    pub key: String,
    /// Points from the left, at most 20000.
    pub x: u32,
    /// Points from the top, at most 20000.
    pub y: u32,
}

impl From<(&NodeKey, StepPosition)> for StepPositionBody {
    fn from((key, position): (&NodeKey, StepPosition)) -> Self {
        Self {
            key: key.as_str().to_owned(),
            x: position.x(),
            y: position.y(),
        }
    }
}

/// Request body for drafting a new workflow.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateWorkflowBody {
    /// Label people will use to find the new workflow.
    pub name: String,
    /// What it does, in up to 500 characters.
    #[serde(default)]
    pub description: Option<String>,
    /// Its steps and edges.
    pub graph: GraphBody,
    /// Where its steps sit on the canvas.
    #[serde(default)]
    pub layout: Vec<StepPositionBody>,
    /// What starts it.
    pub trigger: TriggerBody,
    /// How long one execution may run, in seconds, at most 31 days.
    pub run_limit_seconds: i64,
    /// Who is told when one of its runs fails: `administrators`, the
    /// default, or `also_authors`.
    #[serde(default)]
    pub failure_alert: Option<String>,
}

impl TryFrom<CreateWorkflowBody> for CreateWorkflowRequest {
    type Error = ApiError;

    fn try_from(body: CreateWorkflowBody) -> Result<Self, ApiError> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            description: description(body.description)?,
            graph: body.graph.try_into()?,
            layout: layout(body.layout)?,
            trigger: body.trigger.try_into()?,
            run_limit: run_limit(body.run_limit_seconds)?,
            failure_alert: body
                .failure_alert
                .as_deref()
                .map(failure_alert)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// One change to a workflow's draft, named by `edit`.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "edit", rename_all = "snake_case")]
pub(crate) enum EditDraftBody {
    /// Gives it a new name.
    Rename {
        /// Replacement label shown for the draft.
        name: String,
    },
    /// Replaces its steps and edges.
    ReplaceSteps {
        /// The steps and edges.
        graph: GraphBody,
    },
    /// Starts it on something else.
    ChangeTrigger {
        /// What starts it.
        trigger: TriggerBody,
    },
    /// Lets each execution run for another time.
    ChangeRunLimit {
        /// How long, in seconds.
        run_limit_seconds: i64,
    },
    /// Describes what it does, or takes the description away with `null`.
    Describe {
        /// The description, in up to 500 characters.
        description: Option<String>,
    },
    /// Chooses who is told when one of its runs fails.
    ChangeFailureAlert {
        /// `administrators` or `also_authors`.
        failure_alert: String,
    },
    /// Moves its steps on the canvas. This keeps the draft's revision and
    /// records nothing, since no run is changed by it.
    Arrange {
        /// Where each step sits.
        layout: Vec<StepPositionBody>,
    },
}

impl EditDraftBody {
    /// The edit to make to `workflow_id`'s draft.
    ///
    /// # Errors
    ///
    /// - `422` when a value in the body is not valid.
    pub(crate) fn request(self, workflow_id: WorkflowId) -> Result<EditDraftRequest, ApiError> {
        let edit = match self {
            Self::Rename { name } => {
                DraftEdit::Rename(Label::new("name", name).map_err(ApiError::validation)?)
            }
            Self::ReplaceSteps { graph } => DraftEdit::ReplaceSteps(graph.try_into()?),
            Self::ChangeTrigger { trigger } => DraftEdit::ChangeTrigger(trigger.try_into()?),
            Self::ChangeRunLimit { run_limit_seconds } => {
                DraftEdit::ChangeRunLimit(run_limit(run_limit_seconds)?)
            }
            Self::Describe { description: text } => DraftEdit::Describe(description(text)?),
            Self::ChangeFailureAlert {
                failure_alert: alert,
            } => DraftEdit::ChangeFailureAlert(failure_alert(&alert)?),
            Self::Arrange { layout: positions } => DraftEdit::Arrange(layout(positions)?),
        };
        Ok(EditDraftRequest { workflow_id, edit })
    }
}

/// Request body for publishing a workflow's draft.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PublishWorkflowBody {
    /// The draft's `revision` as the publisher was shown it.
    #[serde(with = "time::serde::rfc3339")]
    pub revision: OffsetDateTime,
}

impl PublishWorkflowBody {
    /// Publishing `workflow_id`'s draft as it stood at this revision.
    #[must_use]
    pub(crate) fn request(&self, workflow_id: WorkflowId) -> PublishWorkflowRequest {
        PublishWorkflowRequest {
            workflow_id,
            reviewed: Revision::reviewed(self.revision),
        }
    }
}

/// The listing asked for: the latest version of each workflow, in `sort`
/// order, the page `pagination` names.
#[must_use]
pub(crate) fn workflow_listing(
    sort: SortOrder<WorkflowSortField>,
    pagination: PageRequest,
) -> ListWorkflowsRequest {
    ListWorkflowsRequest {
        sort,
        page: pagination,
    }
}

/// A description, or none when it is left out or empty.
fn description(text: Option<String>) -> Result<Option<Text>, ApiError> {
    text.filter(|text| !text.trim().is_empty())
        .map(|text| Text::new("description", text).map_err(ApiError::validation))
        .transpose()
}

/// A layout from its positions.
fn layout(positions: Vec<StepPositionBody>) -> Result<CanvasLayout, ApiError> {
    let placed = positions
        .into_iter()
        .map(|position| {
            let key = NodeKey::new(&position.key).map_err(ApiError::validation)?;
            let at = StepPosition::new(position.x, position.y).map_err(ApiError::validation)?;
            Ok((key, at))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    CanvasLayout::new(placed).map_err(ApiError::validation)
}

/// Who is told of failed runs, from its name.
fn failure_alert(name: &str) -> Result<FailureAlert, ApiError> {
    match name {
        "administrators" => Ok(FailureAlert::Administrators),
        "also_authors" => Ok(FailureAlert::AlsoAuthors),
        _ => Err(ApiError::validation(DomainError::invalid(message!(
            "api-a-failure-alert-is-administrators-or",
            "a failure alert is administrators or also_authors"
        )))),
    }
}

/// The longest a run may take, from seconds. Refuses a length that is not
/// allowed.
fn run_limit(seconds: i64) -> Result<RunLimit, ApiError> {
    let lifetime = Lifetime::seconds(seconds).map_err(ApiError::validation)?;
    RunLimit::new(lifetime).map_err(ApiError::validation)
}
