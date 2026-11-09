//! The integration catalog on the wire: each integration as it presents
//! itself and how an account is connected to it, each operation a
//! workflow's builder may use, as the tenant treats it and as its
//! integration explains it, each service event a workflow may start on,
//! the options a step form's pickers offer, the apps a Protected apps step
//! may call ([`apps`]), the systems a Protected data step may reach
//! ([`data`]), and the risks a tenant raised ([`risk_overrides`]).

pub mod apps;
pub mod data;
pub mod risk_overrides;

use ianua_app::ports::workflows::PlaceAsked;
use ianua_app::use_cases::workflows::catalog::{
    Choices, Connecting, ListChoicesRequest, ListedIntegration, OfferedEvent, OfferedOperation,
};
use ianua_domain::domains::workflows::integration::form::{
    Block, Choice, InputForm, Picker, Preview,
};
use ianua_domain::domains::workflows::integration::guide::{InputNote, OperationGuide, OutputNote};
use ianua_domain::domains::workflows::integration::{AccountNeed, InputNeed, InputSpec};
use ianua_domain::types::IntegrationAccountId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::dto::workflows::data::flow_data;
use crate::error::ApiError;
use crate::extractors::paths::workflows::OperationInputPath;

/// One integration installed, as it presents itself.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct IntegrationResponse {
    /// The key it is installed under, which an operation and an account
    /// name, such as `github`.
    pub key: String,
    /// Its name for people, such as `GitHub`.
    pub title: String,
    /// What it lets a workflow do.
    pub description: String,
    /// The name of the icon shown beside it, such as `github`.
    pub icon: String,
    /// Where its own picture is served, SVG of shapes only, such as
    /// `/api/v1/files/integrations/github/picture.svg`; `null` for a step
    /// the platform itself offers, which the dashboard draws.
    pub picture: Option<String>,
    /// Its brand colour, such as `#24292f`: dark enough that a white mark
    /// on it stays readable.
    pub brand: String,
    /// How an account is connected to it: `sign_in` at its service, or
    /// `credential` handed over.
    pub connecting: &'static str,
    /// What signing in asks for besides the account's name, in the
    /// service's own word, such as `organization` for Azure DevOps; `null`
    /// for nothing more, and for an integration connected with a
    /// credential.
    pub sign_in_asks_for: Option<&'static str>,
}

impl From<&ListedIntegration> for IntegrationResponse {
    fn from(listed: &ListedIntegration) -> Self {
        let profile = &listed.profile;
        Self {
            key: profile.key().as_str().to_owned(),
            title: profile.title().as_str().to_owned(),
            description: profile.description().as_str().to_owned(),
            icon: profile.icon().as_str().to_owned(),
            picture: profile.picture().map(|_| {
                format!(
                    "/api/v1/files/integrations/{}/picture.svg",
                    profile.key().as_str()
                )
            }),
            brand: format!("#{}", profile.brand().as_str()),
            connecting: match listed.connecting {
                Connecting::SignIn(_) => "sign_in",
                Connecting::Credential => "credential",
            },
            sign_in_asks_for: match listed.connecting {
                Connecting::SignIn(PlaceAsked::Named(word)) => Some(word),
                Connecting::SignIn(PlaceAsked::Nothing) | Connecting::Credential => None,
            },
        }
    }
}

/// One operation an installed integration offers.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OperationResponse {
    /// The integration, such as `google-sheets`.
    pub integration: String,
    /// The operation, such as `append-row`.
    pub operation: String,
    /// Its name for people, such as `Open an issue`.
    pub title: String,
    /// What it does.
    pub description: String,
    /// The inputs it takes.
    pub inputs: Vec<OperationInputResponse>,
    /// The values it gives back, each at a path in the step's output that
    /// the steps after it may read.
    pub outputs: Vec<OperationOutputResponse>,
    /// The kind of action it takes, as the tenant counts it: `undeclared`
    /// or an action class. A tenant's raised risk shows here.
    pub effect: &'static str,
    /// Whether it acts through one of the tenant's accounts for its
    /// integration.
    pub needs_account: bool,
    /// The most sensitive data it may be handed, such as `internal`.
    pub ceiling: &'static str,
    /// How its inputs are previewed, shaped like the product it acts in;
    /// left out when it has no preview.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewResponse>,
}

/// One input an operation takes.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OperationInputResponse {
    /// Its field name.
    pub name: String,
    /// Whether the operation runs without it.
    pub required: bool,
    /// What it means.
    pub description: String,
    /// How the builder asks for it; left out when its integration does not
    /// explain it, and the builder asks with a plain text box.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<InputFormResponse>,
}

/// How the builder asks for one input, from the integration's fixed
/// building blocks. The dashboard draws each block in its own theme.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct InputFormResponse {
    /// The field's label.
    pub label: String,
    /// The building block: `text`, `long_text`, `number`, `switch`,
    /// `choices`, `picker`, `multi_picker`, `date_time`, `key_values`,
    /// `app_picker` (one of `GET .../workflows/apps`, by its `id`),
    /// `data_picker` (one of `GET .../workflows/data`, by its `id`) or
    /// `memory_picker` (one of `GET .../memories`, by its `id`).
    pub block: &'static str,
    /// The options of a `choices` block, in order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<ChoiceResponse>,
    /// What fills a `picker` or `multi_picker` block, through
    /// `.../operations/{integration}/{operation}/inputs/{input}/choices`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picker: Option<PickerResponse>,
    /// An example value, shown while the field is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    /// `main`, or `more_options` for a field kept folded away.
    pub group: &'static str,
    /// `normal`, `monospace`, `tall` or `compact`.
    pub style: &'static str,
    /// A warning shown beside the field, such as that a value is public.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl From<&InputForm> for InputFormResponse {
    fn from(form: &InputForm) -> Self {
        let choices = match form.block() {
            Block::Choices(choices) => choices.iter().map(ChoiceResponse::from).collect(),
            _ => Vec::new(),
        };
        Self {
            label: form.label().as_str().to_owned(),
            block: form.block().as_str(),
            choices,
            picker: form.block().picker().map(PickerResponse::from),
            example: form.example().map(|text| text.as_str().to_owned()),
            group: form.group().as_str(),
            style: form.style().as_str(),
            warning: form.warning().map(|text| text.as_str().to_owned()),
        }
    }
}

/// One option of a `choices` block.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ChoiceResponse {
    /// What the input is set to.
    pub value: String,
    /// How it is shown.
    pub label: String,
    /// `neutral`, `info`, `success`, `warning` or `danger`.
    pub tone: &'static str,
}

impl From<&Choice> for ChoiceResponse {
    fn from(choice: &Choice) -> Self {
        Self {
            value: choice.value().as_str().to_owned(),
            label: choice.label().as_str().to_owned(),
            tone: choice.tone().as_str(),
        }
    }
}

/// What fills a picker.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PickerResponse {
    /// The read operation listing its options.
    pub filled_by: String,
    /// The input that must be set first, such as `repository` for its
    /// labels; left out when it depends on none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<String>,
}

impl From<&Picker> for PickerResponse {
    fn from(picker: &Picker) -> Self {
        Self {
            filled_by: picker.filled_by().as_str().to_owned(),
            depends_on: picker.depends_on().map(|name| name.as_str().to_owned()),
        }
    }
}

/// How a step's inputs are previewed, shaped like the product it acts in.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PreviewResponse {
    /// `chat_message`, `issue`, `ticket_status`, `calendar_event`, `email`
    /// or `text_message`.
    pub kind: &'static str,
    /// Which input fills each part of the preview.
    pub parts: Vec<PreviewPartResponse>,
}

/// One part of a preview and the input filling it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PreviewPartResponse {
    /// `title`, `body`, `place`, `sender`, `labels`, `status`, `start` or
    /// `end`.
    pub part: &'static str,
    /// The operation field whose value fills this preview part.
    pub input: String,
}

impl From<&Preview> for PreviewResponse {
    fn from(preview: &Preview) -> Self {
        Self {
            kind: preview.kind().as_str(),
            parts: preview
                .parts()
                .iter()
                .map(|(part, input)| PreviewPartResponse {
                    part: part.as_str(),
                    input: input.as_str().to_owned(),
                })
                .collect(),
        }
    }
}

/// One value an operation gives back.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OperationOutputResponse {
    /// Where it is in the step's output, such as `json.number`.
    pub path: String,
    /// What it is.
    pub description: String,
}

impl OperationInputResponse {
    /// `input`, explained as `guide` says.
    fn explained(input: &InputSpec, guide: &OperationGuide) -> Self {
        Self::noted(input, guide.input(input.name()))
    }

    /// `input`, explained by `note` when there is one.
    fn noted(input: &InputSpec, note: Option<&InputNote>) -> Self {
        Self {
            name: input.name().as_str().to_owned(),
            required: matches!(input.need(), InputNeed::Required),
            description: note
                .map(|note| note.description().as_str().to_owned())
                .unwrap_or_default(),
            form: note.map(|note| InputFormResponse::from(note.form())),
        }
    }
}

impl From<&OutputNote> for OperationOutputResponse {
    fn from(note: &OutputNote) -> Self {
        Self {
            path: note.path().to_string(),
            description: note.description().as_str().to_owned(),
        }
    }
}

impl From<OfferedOperation> for OperationResponse {
    fn from(offered: OfferedOperation) -> Self {
        let spec = offered.operation.spec();
        let guide = &offered.guide;
        Self {
            integration: spec.integration().as_str().to_owned(),
            operation: spec.operation().as_str().to_owned(),
            title: guide.title().as_str().to_owned(),
            description: guide.description().as_str().to_owned(),
            inputs: spec
                .inputs()
                .iter()
                .map(|input| OperationInputResponse::explained(input, guide))
                .collect(),
            outputs: guide
                .outputs()
                .iter()
                .map(OperationOutputResponse::from)
                .collect(),
            effect: spec.effect().as_str(),
            needs_account: matches!(spec.account(), AccountNeed::Account),
            ceiling: spec.ceiling().as_str(),
            preview: guide.preview().map(PreviewResponse::from),
        }
    }
}

/// One event an installed integration's service sends that a workflow may
/// start on.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EventResponse {
    /// The integration, such as `github`.
    pub integration: String,
    /// The event, such as `issue-opened`.
    pub event: String,
    /// Its name for people, such as `An issue is opened`.
    pub title: String,
    /// When it happens.
    pub description: String,
    /// The filters a trigger may set, each narrowing which of these events
    /// start the workflow; a required one must be set.
    pub filters: Vec<OperationInputResponse>,
    /// The values it gives the workflow, each at a path in the trigger's
    /// output that the steps may read.
    pub outputs: Vec<OperationOutputResponse>,
}

impl From<OfferedEvent> for EventResponse {
    fn from(offered: OfferedEvent) -> Self {
        let spec = &offered.spec;
        let guide = &offered.guide;
        Self {
            integration: spec.integration().as_str().to_owned(),
            event: spec.event().as_str().to_owned(),
            title: guide.title().as_str().to_owned(),
            description: guide.description().as_str().to_owned(),
            filters: spec
                .filters()
                .iter()
                .map(|filter| {
                    let note = guide
                        .filters()
                        .iter()
                        .find(|note| note.name() == filter.name());
                    OperationInputResponse::noted(filter, note)
                })
                .collect(),
            outputs: guide
                .outputs()
                .iter()
                .map(OperationOutputResponse::from)
                .collect(),
        }
    }
}

/// Request body for filling a picker in a step's form.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ListChoicesBody {
    /// The account the read goes through: the caller's own, or one they
    /// may manage.
    pub account_id: Uuid,
    /// The value of the input the picker depends on, such as the chosen
    /// repository; left out when it depends on none.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub depends_on: Option<Value>,
}

impl ListChoicesBody {
    /// Filling the picker of the input `path` names, through this account.
    ///
    /// # Errors
    ///
    /// - `422` when a name in the path or the value depended on is not
    ///   valid.
    pub(crate) fn request(
        &self,
        path: &OperationInputPath,
    ) -> Result<ListChoicesRequest, ApiError> {
        Ok(ListChoicesRequest {
            integration: path.integration()?,
            operation: path.operation()?,
            input: path.input()?,
            account: IntegrationAccountId::from_uuid(self.account_id),
            depends_on: self.depends_on.as_ref().map(flow_data).transpose()?,
        })
    }
}

/// The options a picker offers now.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ChoicesResponse {
    /// The options, at most 200; empty when the service gave no list.
    pub choices: Vec<OfferedChoiceResponse>,
    /// What the service said instead of a list, as it said it; the builder
    /// shows it and lets the person type the value. Left out when it
    /// answered with a list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

/// One option a picker offers.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OfferedChoiceResponse {
    /// What the input is set to when it is picked.
    pub value: String,
    /// How it is shown.
    pub label: String,
}

impl From<Choices> for ChoicesResponse {
    fn from(choices: Choices) -> Self {
        match choices {
            Choices::Listed(listed) => Self {
                choices: listed
                    .into_iter()
                    .map(|choice| OfferedChoiceResponse {
                        value: choice.value,
                        label: choice.label,
                    })
                    .collect(),
                unavailable: None,
            },
            Choices::Unavailable(said) => Self {
                choices: Vec::new(),
                unavailable: Some(said.as_str().to_owned()),
            },
        }
    }
}
