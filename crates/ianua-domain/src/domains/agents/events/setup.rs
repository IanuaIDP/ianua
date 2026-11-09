//! Events about tools and model providers changed after they were added.

use time::OffsetDateTime;

use crate::domains::agents::execution::model_provider::{ModelName, ProviderEmbeddings};
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::AgentsEvent;
use crate::types::{ActionClass, AgentToolId, EventLabel, ModelProviderId};

/// A model provider was given a new API key.
///
/// It names the provider only. The key itself never leaves the sealed
/// store.
#[derive(Debug)]
pub(crate) struct AgentModelProviderKeyRotated {
    /// The model connection whose API credential was replaced.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// When the key was rotated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderKeyRotated => AgentsEvent::ModelProviderKeyRotated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "provider",
            Reference::new(
                RefKind::PROVIDER,
                self.provider_id.to_string(),
                self.provider_label.as_str(),
            ),
        )
    }
}

/// The most sensitive data a model provider may be sent changed.
///
/// Raising it lets runs that read more sensitive data reason with the
/// provider. The record keeps both levels, so a review sees what the
/// provider could be sent before and after.
#[derive(Debug)]
pub(crate) struct AgentModelProviderClearanceChanged {
    /// The model connection whose permitted input sensitivity changed.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// The clearance before.
    pub(crate) from: DataClassLevel,
    /// The clearance now.
    pub(crate) to: DataClassLevel,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderClearanceChanged => AgentsEvent::ModelProviderClearanceChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
            .change("clearance", self.from.as_str(), self.to.as_str())
    }
}

/// A model provider was switched to another model, or the model's price
/// changed.
#[derive(Debug)]
pub(crate) struct AgentModelProviderModelChanged {
    /// The connection whose configured model or pricing changed.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// The model before.
    pub(crate) from: ModelName,
    /// The model now.
    pub(crate) to: ModelName,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderModelChanged => AgentsEvent::ModelProviderModelChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
            .change("model", self.from.as_str(), self.to.as_str())
    }
}

/// A model provider started or stopped offering an embedding model, or
/// switched to another.
#[derive(Debug)]
pub(crate) struct AgentModelProviderEmbeddingsChanged {
    /// The connection whose embedding capability changed.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// The embedding model offered before.
    pub(crate) from: ProviderEmbeddings,
    /// The embedding model offered now.
    pub(crate) to: ProviderEmbeddings,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderEmbeddingsChanged => AgentsEvent::ModelProviderEmbeddingsChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
            .change_between(
                "embedding_model",
                self.from.model().map(|model| model.as_str().to_owned()),
                self.to.model().map(|model| model.as_str().to_owned()),
            )
    }
}

/// A tool's definition was edited, and its classes read again from its
/// route.
#[derive(Debug)]
pub(crate) struct AgentToolEdited {
    /// The callable operation whose definition was revised.
    pub(crate) tool_id: AgentToolId,
    /// The tool's name after the edit.
    pub(crate) name: ToolName,
    /// The kind of action the tool performs now.
    pub(crate) action_class: ActionClass,
    /// The tool's data class now.
    pub(crate) classification: DataClassLevel,
    /// When it was edited.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentToolEdited => AgentsEvent::ToolEdited,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "tool",
                Reference::new(RefKind::TOOL, self.tool_id.to_string(), self.name.as_str()),
            )
            .field("action_class", self.action_class.as_str().to_owned())
            .field("classification", self.classification.as_str().to_owned())
    }
}
