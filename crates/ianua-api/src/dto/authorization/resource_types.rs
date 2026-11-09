//! Permission catalogue bodies: the kinds of thing a tenant's own
//! application protects, the verbs each accepts, and its data class.

use ianua_app::error::AppError;
use ianua_app::listing::Page;
use ianua_app::use_cases::authorization::resource_types::{DeclareRequest, UpdateRequest};
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::resource_type::{ActionDefinition, ResourceType};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Label, ResourceTypeId, Text};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::response::PageResponse;

/// One verb a resource type accepts, and what holding it confers.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ActionBody {
    /// The action key, as it appears right of the colon in `resource:action`.
    pub key: String,
    /// What an operator sees in place of the key.
    pub display_name: String,
    /// Other actions on the same resource this one confers.
    #[serde(default)]
    pub implies: Vec<String>,
}

impl TryFrom<&ActionBody> for ActionDefinition {
    type Error = ApiError;

    fn try_from(body: &ActionBody) -> Result<Self, Self::Error> {
        let key = PermissionSegment::new("action_key", body.key.as_str())
            .map_err(ApiError::validation)?;
        let display_name = Label::new("action_display_name", body.display_name.as_str())
            .map_err(ApiError::validation)?;
        let implies = body
            .implies
            .iter()
            .map(|action| PermissionSegment::new("action_implies", action.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::validation)?;
        Ok(Self::new(key, display_name, implies))
    }
}

/// A resource type to declare in the tenant's catalogue.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DeclareResourceTypeBody {
    /// The key used left of the colon in `resource:action`. Unique per
    /// tenant.
    pub key: String,
    /// What an operator sees in place of the key.
    pub display_name: String,
    /// What the resource is, in the operator's words.
    #[serde(default)]
    pub description: Option<String>,
    /// The verbs this resource accepts.
    pub actions: Vec<ActionBody>,
    /// How sensitive every resource of this type is: `Public`, `Internal`,
    /// `Confidential` or `Restricted`. It decides where their data may be
    /// sent.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
}

impl TryFrom<DeclareResourceTypeBody> for DeclareRequest {
    type Error = ApiError;

    fn try_from(body: DeclareResourceTypeBody) -> Result<Self, Self::Error> {
        Ok(Self {
            key: PermissionSegment::new("resource_type_key", body.key.as_str())
                .map_err(ApiError::validation)?,
            display_name: display_name(&body.display_name)?,
            description: description(body.description.as_deref())?,
            actions: actions(&body.actions)?,
            data_class: body.data_class,
        })
    }
}

/// Fields to change on a resource type.
///
/// The key is absent by design: it is what every role and route already
/// refers to, so changing it in place would silently break each of them.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateResourceTypeBody {
    /// What an operator sees in place of the key.
    pub display_name: String,
    /// What the resource is, in the operator's words.
    #[serde(default)]
    pub description: Option<String>,
    /// The verbs this resource accepts, replacing the current ladder whole.
    pub actions: Vec<ActionBody>,
    /// How sensitive every resource of this type is.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
}

impl UpdateResourceTypeBody {
    /// The change this body asks for on the resource type `id`.
    ///
    /// # Errors
    ///
    /// A validation error when a name or an action is not acceptable.
    pub(crate) fn into_request(self, id: ResourceTypeId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            id,
            display_name: display_name(&self.display_name)?,
            description: description(self.description.as_deref())?,
            actions: actions(&self.actions)?,
            data_class: self.data_class,
        })
    }
}

/// One declared action, as the API returns it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActionResponse {
    /// The action key.
    pub key: String,
    /// What an operator sees in place of the key.
    pub display_name: String,
    /// Other actions this one directly confers.
    pub implies: Vec<String>,
    /// Everything holding this action confers, the action itself included,
    /// with the ladder already walked, so a client cannot disagree with the
    /// proxy about what a grant means.
    pub grants: Vec<String>,
}

/// A resource type, as the API returns it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ResourceTypeResponse {
    /// The resource type's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ResourceTypeId,
    /// The key used in `resource:action`.
    pub key: String,
    /// What an operator sees in place of the key.
    pub display_name: String,
    /// What the resource is, in the operator's words.
    pub description: Option<String>,
    /// The verbs this resource accepts.
    pub actions: Vec<ActionResponse>,
    /// How sensitive every resource of this type is.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
    /// When it was declared.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl TryFrom<&ResourceType<ResolvedTenant>> for ResourceTypeResponse {
    type Error = ApiError;

    fn try_from(resource_type: &ResourceType<ResolvedTenant>) -> Result<Self, Self::Error> {
        let actions = resource_type
            .actions()
            .iter()
            .map(|action| action_response(resource_type, action))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            id: *resource_type.id(),
            key: resource_type.key().to_string(),
            display_name: resource_type.display_name().as_str().to_owned(),
            description: resource_type
                .description()
                .map(|text| text.as_str().to_owned()),
            actions,
            data_class: resource_type.data_class(),
            created_at: resource_type.created_at(),
            updated_at: resource_type.updated_at(),
        })
    }
}

impl ResourceTypeResponse {
    /// A page of resource types, each action's ladder walked.
    ///
    /// # Errors
    ///
    /// An internal error when a stored resource type's ladder cannot be
    /// walked, which its own checks should have made impossible.
    pub(crate) fn page(
        page: &Page<ResourceType<ResolvedTenant>>,
    ) -> Result<PageResponse<Self>, ApiError> {
        let items = page
            .items
            .iter()
            .map(Self::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PageResponse::with_items(page, items))
    }
}

/// The id of a newly declared resource type.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeclareResourceTypeResponse {
    /// The resource type's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ResourceTypeId,
}

/// An action as the API sends it, with every action it grants once its
/// implied actions are followed.
fn action_response(
    resource_type: &ResourceType<ResolvedTenant>,
    action: &ActionDefinition,
) -> Result<ActionResponse, ApiError> {
    let grants = resource_type
        .expand(action.key().as_str())
        .map_err(|e| ApiError(AppError::from_domain(e)))?
        .iter()
        .map(ToString::to_string)
        .collect();
    Ok(ActionResponse {
        key: action.key().to_string(),
        display_name: action.display_name().as_str().to_owned(),
        implies: action.implies().iter().map(ToString::to_string).collect(),
        grants,
    })
}

/// The actions sent, refused when one is not valid.
fn actions(bodies: &[ActionBody]) -> Result<Vec<ActionDefinition>, ApiError> {
    bodies.iter().map(ActionDefinition::try_from).collect()
}

/// The display name sent, refused when it is not a valid label.
fn display_name(value: &str) -> Result<Label, ApiError> {
    Label::new("display_name", value).map_err(ApiError::validation)
}

/// The description given, where one was: blank counts as none.
fn description(value: Option<&str>) -> Result<Option<Text>, ApiError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| Text::new("description", value))
        .transpose()
        .map_err(ApiError::validation)
}
