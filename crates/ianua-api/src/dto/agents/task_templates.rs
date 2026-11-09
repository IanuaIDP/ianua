//! Task template bodies: the ceilings people approve for kinds of agent
//! task.

use ianua_app::use_cases::agents::task_templates::ProposeRequest;
use ianua_domain::domains::agents::authority::capability::{ActionApproval, ResourceScope};
use ianua_domain::domains::agents::authority::intent::{IntentEnvelope, IntentStatement};
use ianua_domain::domains::agents::authority::task_template::{TaskTemplate, TemplateLimits};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{ActionClass, Label, Seconds};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::capabilities::{BudgetDto, CapabilitySetDto};
use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// Request body for proposing a task template.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ProposeTaskTemplateBody {
    /// A short name people recognise the task by.
    pub name: String,
    /// What the task is for, in words.
    pub purpose: String,
    /// The most a delegation under the template may grant.
    pub ceiling: CapabilitySetDto,
    /// The kinds of action the task may take, such as `Read`. At least one.
    #[schema(schema_with = crate::dto::schemas::action_class_list)]
    pub action_classes: Vec<ActionClass>,
    /// The longest lifetime a delegation may have, in seconds.
    pub max_ttl_seconds: u32,
    /// The deepest sub-delegation chain allowed.
    #[serde(default)]
    pub max_depth: u8,
    /// The most sensitive data the agent may reach, such as `Internal`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_data_class: DataClassLevel,
    /// The URL path prefixes the agent is confined to.
    #[serde(default)]
    pub resource_scope: Option<Vec<String>>,
    /// The most the agent may spend.
    #[serde(default)]
    pub budget: Option<BudgetDto>,
    /// Whether every action waits for a person's approval.
    #[serde(default)]
    pub requires_approval: bool,
}

impl TryFrom<ProposeTaskTemplateBody> for ProposeRequest {
    type Error = ApiError;

    fn try_from(body: ProposeTaskTemplateBody) -> Result<Self, Self::Error> {
        let resource_scope = match body.resource_scope {
            Some(prefixes) => {
                Restriction::To(ResourceScope::new(prefixes).map_err(ApiError::validation)?)
            }
            None => Restriction::Unrestricted,
        };
        let budget = match &body.budget {
            Some(budget) => Restriction::To(budget.to_domain()?),
            None => Restriction::Unrestricted,
        };
        let approval = match body.requires_approval {
            true => ActionApproval::PerAction,
            false => ActionApproval::NotRequired,
        };
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            purpose: IntentStatement::new(body.purpose).map_err(ApiError::validation)?,
            ceiling: body.ceiling.to_domain()?,
            classes: IntentEnvelope::new(body.action_classes),
            limits: TemplateLimits {
                max_ttl_seconds: Seconds::new(body.max_ttl_seconds),
                max_depth: body.max_depth,
                max_data_class: body.max_data_class,
                resource_scope,
                budget,
                approval,
            },
        })
    }
}

/// The capability ceiling and lifecycle state governing grants for a task.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TaskTemplateResponse {
    /// The template.
    pub id: Uuid,
    /// The label shown when selecting a task to grant authority under.
    pub name: String,
    /// What the task is for.
    pub purpose: String,
    /// `proposed`, `approved` or `retired`. Only an approved template can
    /// be granted under.
    pub status: String,
    /// The most a delegation under it may grant.
    pub ceiling: CapabilitySetDto,
    /// The kinds of action the task may take.
    #[schema(schema_with = crate::dto::schemas::action_class_list)]
    pub action_classes: Vec<ActionClass>,
    /// The longest lifetime a delegation may have, in seconds.
    pub max_ttl_seconds: u32,
    /// The deepest sub-delegation chain allowed.
    pub max_depth: u8,
    /// The most sensitive data the agent may reach.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_data_class: DataClassLevel,
    /// The paths the agent is confined to, if any.
    pub resource_scope: Option<Vec<String>>,
    /// The most the agent may spend, if capped.
    pub budget: Option<BudgetDto>,
    /// Whether every action waits for a person's approval.
    pub requires_approval: bool,
    /// Who proposed it.
    pub proposed_by: OwnerDto,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub proposed_at: OffsetDateTime,
    /// Who approved it, once someone has.
    pub approved_by: Option<OwnerDto>,
    /// When.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub approved_at: Option<OffsetDateTime>,
    /// When it was retired, if it was.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub retired_at: Option<OffsetDateTime>,
}

impl From<&TaskTemplate<ResolvedTenant>> for TaskTemplateResponse {
    fn from(template: &TaskTemplate<ResolvedTenant>) -> Self {
        let limits = template.limits();
        Self {
            id: *template.id().as_uuid(),
            name: template.name().as_str().to_owned(),
            purpose: template.purpose().as_str().to_owned(),
            status: template.status().as_str().to_owned(),
            ceiling: CapabilitySetDto::from(template.ceiling()),
            action_classes: template.classes().allowed().to_vec(),
            max_ttl_seconds: limits.max_ttl_seconds.get(),
            max_depth: limits.max_depth,
            max_data_class: limits.max_data_class,
            resource_scope: limits.resource_scope.limit().map(|scope| {
                scope
                    .prefixes()
                    .iter()
                    .map(|prefix| prefix.as_str().to_owned())
                    .collect()
            }),
            budget: limits.budget.limit().and_then(BudgetDto::of),
            requires_approval: limits.approval == ActionApproval::PerAction,
            proposed_by: OwnerDto::from_human(template.proposed_by()),
            proposed_at: template.proposed_at(),
            approved_by: template.approved_by().map(OwnerDto::from_human),
            approved_at: template.approved_at(),
            retired_at: template.retired_at(),
        }
    }
}
