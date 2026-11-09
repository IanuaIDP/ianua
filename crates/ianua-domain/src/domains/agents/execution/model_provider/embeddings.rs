//! The embedding model a provider offers beside its chat model, which turns
//! text into vectors for a tenant's memory.
//!
//! A provider's chat model, such as `gpt-4o`, makes no vectors: an
//! embedding model does, such as OpenAI's `text-embedding-3-small`, served
//! at the same endpoint with the same key. So a provider may offer one by
//! name. Anthropic's API has no embeddings endpoint, so an Anthropic
//! provider offers none; a tenant on Anthropic alone uses the platform's
//! own embedding server.

use crate::domains::agents::execution::model_provider::{ModelName, ModelProviderKind};
use crate::message;
use crate::shared::errors::DomainError;

/// Whether a provider offers an embedding model.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProviderEmbeddings {
    /// None, as every provider starts.
    #[default]
    Off,
    /// This embedding model, served at the provider's endpoint.
    Model(ModelName),
}

impl ProviderEmbeddings {
    /// The embedding model offered, if any.
    #[must_use]
    pub fn model(&self) -> Option<&ModelName> {
        match self {
            Self::Model(model) => Some(model),
            Self::Off => None,
        }
    }
}

/// Whether `kind` may offer `embeddings`: any kind may offer none, and
/// every kind but Anthropic may offer a model.
pub(super) fn kind_embeds(kind: ModelProviderKind, embeddings: &ProviderEmbeddings) -> bool {
    match (kind, embeddings) {
        (_, ProviderEmbeddings::Off) => true,
        (
            ModelProviderKind::OpenAi | ModelProviderKind::SelfHosted,
            ProviderEmbeddings::Model(_),
        ) => true,
        (ModelProviderKind::Anthropic, ProviderEmbeddings::Model(_)) => false,
    }
}

/// Refuses an embedding model on a kind whose API serves none.
pub(super) fn ensure_kind_embeds(
    kind: ModelProviderKind,
    embeddings: &ProviderEmbeddings,
) -> Result<(), DomainError> {
    if kind_embeds(kind, embeddings) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "agents-anthropic-serves-no-embeddings",
        "Anthropic's API has no embeddings endpoint; use an OpenAI or self-hosted provider, or the platform's own embedding server"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::model_provider::{
        CreateModelProviderParams, ModelEndpoint, ModelProvider, ModelProviderRow, ProviderKey,
    };
    use crate::domains::agents::execution::usage::ModelPricing;
    use crate::domains::agents::identity::control::AgentControl;
    use crate::domains::authorization::permission::{AgentAction, SystemPermission};
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::raised;
    use crate::types::{Human, HumanAccount, Label, ModelProviderId, PersonKey, TenantId, UserId};

    const MANAGE: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Manage)];
    const VIEW: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::View)];

    fn bob() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("bob@corp.test").unwrap(),
        )
    }

    fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
        AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
    }

    fn connected(kind: ModelProviderKind) -> ModelProvider<ResolvedTenant> {
        let bob = bob();
        let mut provider = ModelProvider::create(
            &holding(&bob, &MANAGE),
            CreateModelProviderParams {
                id: ModelProviderId::new(),
                name: Label::new("name", "openai").unwrap(),
                kind,
                endpoint: ModelEndpoint::new("https://api.openai.com/v1").unwrap(),
                model: ModelName::new("gpt-4o-mini").unwrap(),
                pricing: ModelPricing::Unpriced,
                credential_ref: ProviderKey::Keyless,
                clearance: DataClassLevel::Internal,
            },
        )
        .unwrap();
        raised(&mut provider);
        provider
    }

    fn small() -> ProviderEmbeddings {
        ProviderEmbeddings::Model(ModelName::new("text-embedding-3-small").unwrap())
    }

    /// Bob offers OpenAI's `text-embedding-3-small` on the tenant's OpenAI
    /// provider. It offers it from now on, and the change is raised naming
    /// the model.
    #[test]
    fn a_manager_offers_an_embedding_model() {
        let bob = bob();
        let mut provider = connected(ModelProviderKind::OpenAi);

        provider
            .offer_embeddings(&holding(&bob, &MANAGE), small())
            .unwrap();

        assert_eq!(provider.embeddings(), &small());
        let events = raised(&mut provider);
        assert_eq!(
            events[0].event_type().as_str(),
            "agents.model_provider_embeddings_changed"
        );
        assert!(matches!(
            events[0].payload().value("embedding_model"),
            Some(FieldValue::Change(change)) if change.to() == Some("text-embedding-3-small")
        ));
    }

    /// Offering embeddings on an Anthropic provider is refused as invalid;
    /// the provider continues to offer none.
    #[test]
    fn an_anthropic_provider_offers_no_embedding_model() {
        let bob = bob();
        let mut provider = connected(ModelProviderKind::Anthropic);

        let offered = provider.offer_embeddings(&holding(&bob, &MANAGE), small());

        assert!(
            matches!(offered, Err(DomainError::Validation(_))),
            "{offered:?}"
        );
        assert_eq!(provider.embeddings(), &ProviderEmbeddings::Off);
    }

    /// A viewer cannot offer an embedding model on the tenant's provider.
    #[test]
    fn a_viewer_offers_nothing() {
        let sam = bob();
        let mut provider = connected(ModelProviderKind::OpenAi);

        let offered = provider.offer_embeddings(&holding(&sam, &VIEW), small());

        assert!(
            matches!(offered, Err(DomainError::Forbidden(_))),
            "{offered:?}"
        );
    }

    /// An Anthropic provider stored with an embedding model is refused as
    /// corrupt during reconstruction.
    #[test]
    fn a_stored_anthropic_provider_with_embeddings_is_corrupt() {
        let provider = connected(ModelProviderKind::Anthropic);
        let row = ModelProviderRow {
            id: *provider.id(),
            name: provider.name().clone(),
            kind: provider.kind(),
            endpoint: provider.endpoint().clone(),
            model: provider.model().clone(),
            pricing: provider.pricing(),
            credential_ref: provider.credential_ref().clone(),
            clearance: provider.clearance(),
            embeddings: small(),
            status: provider.status(),
            last_test: provider.last_test().clone(),
            created_at: provider.created_at,
            updated_at: provider.updated_at,
        };

        assert!(refused_as_corrupt(
            &ModelProvider::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
