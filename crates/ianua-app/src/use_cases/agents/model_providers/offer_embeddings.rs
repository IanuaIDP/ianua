//! Offer embeddings: a model provider offers an embedding model beside its
//! chat model, such as OpenAI's `text-embedding-3-small`, or stops
//! offering one.
//!
//! A tenant's memories may then be filled through it. Anthropic's API has
//! no embeddings endpoint, so an Anthropic provider offers none. A memory
//! already filled with another model stops taking texts, since its vectors
//! would no longer compare. Only someone allowed to manage agents changes
//! it.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::model_provider::ProviderEmbeddings;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ModelProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ModelProviderStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_model_provider;

/// Which provider offers which embedding model, or none.
#[derive(Debug)]
pub struct OfferEmbeddingsRequest {
    /// The configured endpoint whose embedding offer will change.
    pub provider_id: ModelProviderId,
    /// The embedding model it offers from now on, or none.
    pub embeddings: ProviderEmbeddings,
}

/// The ports [`OfferEmbeddingsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OfferEmbeddingsPorts {
    /// Loads and saves model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes the embedding model model providers offer.
pub struct OfferEmbeddingsUseCase {
    ports: OfferEmbeddingsPorts,
}

impl OfferEmbeddingsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OfferEmbeddingsPorts) -> Self {
        Self { ports }
    }
}

impl Command for OfferEmbeddingsUseCase {
    type Caller = CallerContext;
    type Input = OfferEmbeddingsRequest;
    type Output = Result<(), AppError>;

    /// Has the provider offer `request.embeddings`, and records
    /// `agents.model_provider_embeddings_changed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing management rights, before reading the provider.
    /// - `AppError::NotFound` when the provider is outside the tenant.
    /// - `AppError::Domain` for an Anthropic provider; `Conflict` when the offered embedding model is unchanged.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: OfferEmbeddingsRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut provider = existing_model_provider(
            self.ports.provider_store.as_ref(),
            &tenant,
            &request.provider_id,
        )
        .await?;
        provider
            .offer_embeddings(&AgentControl::new(&authority), request.embeddings)
            .map_err(AppError::from_domain)?;
        self.ports
            .provider_store
            .save(&tenant, &provider)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), provider.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::model_provider::ModelName;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::{
        FakeModelProviderStore, connected_provider, providers_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn offering(
        authorities: FakeTenantAuthorities,
        store: &Arc<FakeModelProviderStore>,
        sink: &Arc<FakeEventDispatcher>,
        provider_id: ModelProviderId,
    ) -> Result<(), AppError> {
        block_on(
            OfferEmbeddingsUseCase::new(OfferEmbeddingsPorts {
                provider_store: store.clone(),
                tenant_authorities: Arc::new(authorities),
            })
            .execute(
                &test_ctx(),
                &test_auditor(sink.clone()),
                OfferEmbeddingsRequest {
                    provider_id,
                    embeddings: ProviderEmbeddings::Model(
                        ModelName::new("nomic-embed-text").unwrap(),
                    ),
                },
            ),
        )
    }

    /// Bob has the tenant's self-hosted provider offer `nomic-embed-text`:
    /// it offers it, and the change is recorded.
    #[test]
    fn a_manager_has_a_provider_offer_an_embedding_model() {
        let provider = connected_provider("ollama");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let sink = Arc::new(FakeEventDispatcher::new());

        offering(
            FakeTenantAuthorities::holding_everything(),
            &store,
            &sink,
            id,
        )
        .unwrap();

        let kept = block_on(store.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(
            kept.embeddings().model().map(ModelName::as_str),
            Some("nomic-embed-text")
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.model_provider_embeddings_changed"]
        );
    }

    /// A caller without agent permissions cannot offer an embedding model,
    /// and no change is recorded.
    #[test]
    fn a_viewer_changes_nothing() {
        let provider = connected_provider("ollama");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let sink = Arc::new(FakeEventDispatcher::new());

        let offered = offering(FakeTenantAuthorities::holding(&[]), &store, &sink, id);

        assert!(
            matches!(offered, Err(AppError::Forbidden(_))),
            "{offered:?}"
        );
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
